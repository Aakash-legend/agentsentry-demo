#!/usr/bin/env python3
"""
gateway/loader.py

Loads the BPF LSM programs using BCC (python3-bpfcc).
Runs as root. Reads attacker cgroup ID from /opt/agentsentry/attacker_cgroup_id.txt
and programs the config_map so all hooks filter by that ID.

Toolchain choice: BCC (not CO-RE libbpf).
Rationale: BCC is pre-packaged on Linux Mint/Ubuntu as `python3-bpfcc`, requires
no separate BTF header generation step, and is perfectly adequate for a single-VM
demo where we know the running kernel. CO-RE libbpf is preferable for distributing
across multiple kernel versions; we call that out in README as a production gap.

BCC LSM hook attachment: BCC attaches LSM probes via BPF.LSM_PROBE type.
This requires kernel >= 5.7 with CONFIG_BPF_LSM=y and "bpf" in the LSM list.
"""
import os
import sys
import threading
import time
import ctypes
import json
from pathlib import Path

BPF_AVAILABLE = False
bpf_instance = None
events_lock = threading.Lock()
event_callbacks = []  # list of callables receiving event dicts

# Global state
_loaded = False
_enforce_mode = False

CGROUP_ID_FILE = "/opt/agentsentry/attacker_cgroup_id.txt"
BPF_SOURCE_FILE = os.path.join(os.path.dirname(__file__), "..", "ebpf", "lsm_policy.c")

KIND_NAMES = {0: "file_open", 1: "inode_create", 2: "exec", 3: "connect"}


def _try_import_bcc():
    global BPF_AVAILABLE
    try:
        from bcc import BPF  # noqa: F401
        BPF_AVAILABLE = True
        print("[loader] BCC available")
    except ImportError:
        print("[loader] WARNING: BCC not importable. Running in simulation mode.")
        BPF_AVAILABLE = False


_try_import_bcc()


def get_attacker_cgroup_id() -> int:
    """Read the attacker cgroup ID from file set by 02_cgroup_setup.sh."""
    try:
        with open(CGROUP_ID_FILE) as f:
            cid = int(f.read().strip())
            print(f"[loader] Attacker cgroup ID: {cid}")
            return cid
    except FileNotFoundError:
        print(f"[loader] WARNING: {CGROUP_ID_FILE} not found. Run 02_cgroup_setup.sh first.")
        return 0
    except ValueError:
        print(f"[loader] WARNING: Invalid cgroup ID in {CGROUP_ID_FILE}")
        return 0


class BPFLoader:
    """Manages BPF LSM program lifecycle."""

    def __init__(self):
        self.bpf = None
        self.cgroup_id = 0
        self._poll_thread = None
        self._running = False

    def load(self, enforce: bool = False) -> bool:
        """Load and attach BPF LSM programs."""
        global _loaded, _enforce_mode

        if not BPF_AVAILABLE:
            print("[loader] BCC not available – simulating load")
            _loaded = True
            _enforce_mode = enforce
            return True

        try:
            from bcc import BPF

            self.cgroup_id = get_attacker_cgroup_id()
            if self.cgroup_id == 0:
                print("[loader] ERROR: cgroup ID is 0, refusing to load (would affect all procs)")
                return False

            # Read BPF C source
            bpf_src_path = os.path.realpath(BPF_SOURCE_FILE)
            with open(bpf_src_path) as f:
                bpf_src = f.read()

            print("[loader] Compiling BPF LSM programs via BCC...")
            self.bpf = BPF(text=bpf_src)

            # Program the config map
            config_map = self.bpf["config_map"]
            config_map[ctypes.c_int(0)] = ctypes.c_uint64(self.cgroup_id)
            config_map[ctypes.c_int(1)] = ctypes.c_uint64(1 if enforce else 0)

            print(f"[loader] Config map set: cgroup_id={self.cgroup_id}, enforce={enforce}")

            # Note: BCC auto-attaches LSM probes defined with LSM_PROBE() macro
            # when they are compiled into the program. No explicit attach call needed
            # for BCC's LSM_PROBE – BCC handles it via bpf_program__attach_lsm().

            _loaded = True
            _enforce_mode = enforce

            # Start ring buffer polling
            self._running = True
            self._poll_thread = threading.Thread(
                target=self._poll_ring_buffer, daemon=True
            )
            self._poll_thread.start()

            print(f"[loader] ✓ BPF LSM loaded. Enforce={enforce}, cgroup={self.cgroup_id}")
            return True

        except Exception as e:
            print(f"[loader] ERROR loading BPF: {e}")
            import traceback; traceback.print_exc()
            return False

    def set_mode(self, enforce: bool):
        """Switch between log-only and enforce mode without reload."""
        global _enforce_mode
        _enforce_mode = enforce
        if self.bpf:
            try:
                config_map = self.bpf["config_map"]
                config_map[ctypes.c_int(1)] = ctypes.c_uint64(1 if enforce else 0)
                print(f"[loader] Mode switched to enforce={enforce}")
            except Exception as e:
                print(f"[loader] WARNING: could not update config_map: {e}")

    def unload(self) -> bool:
        """Detach BPF programs and clean up."""
        global _loaded, _enforce_mode
        self._running = False
        if self.bpf:
            try:
                self.bpf.cleanup()
                print("[loader] BPF programs detached (fail-open for demo)")
                print("[loader] NOTE: production design pins links and fails CLOSED.")
            except Exception as e:
                print(f"[loader] WARNING during unload: {e}")
            self.bpf = None
        _loaded = False
        _enforce_mode = False
        return True

    def _poll_ring_buffer(self):
        """Poll the BPF ring buffer and dispatch events to callbacks."""
        if not self.bpf:
            return

        def handle_event(ctx, data, size):
            try:
                evt = self.bpf["events"].event(data)
                event_dict = {
                    "pid": evt.pid,
                    "uid": evt.uid,
                    "cgroup_id": evt.cgroup_id,
                    "kind": KIND_NAMES.get(evt.kind, str(evt.kind)),
                    "verdict": "deny" if evt.verdict else "allow",
                    "path": evt.path.decode("utf-8", errors="replace"),
                    "comm": evt.comm.decode("utf-8", errors="replace").rstrip("\x00"),
                    "ts": time.time(),
                }
                with events_lock:
                    for cb in event_callbacks:
                        try:
                            cb(event_dict)
                        except Exception:
                            pass
            except Exception as e:
                print(f"[loader] Ring buffer parse error: {e}")

        self.bpf["events"].open_ring_buffer(handle_event)

        while self._running:
            try:
                self.bpf.ring_buffer_poll(timeout=100)
            except Exception as e:
                if self._running:
                    print(f"[loader] Ring buffer poll error: {e}")
                break

    @property
    def is_loaded(self):
        return _loaded

    @property
    def enforce_mode(self):
        return _enforce_mode


# Singleton loader instance
loader = BPFLoader()


def add_event_callback(cb):
    with events_lock:
        event_callbacks.append(cb)


def remove_event_callback(cb):
    with events_lock:
        if cb in event_callbacks:
            event_callbacks.remove(cb)
