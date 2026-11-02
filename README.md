# AgentSentry – Milestone 1 Demo

> **Platform**: Linux Mint (VirtualBox), kernel ≥ 6.14, BPF LSM enabled, cgroup v2.  
> **Goal**: Prove that a BPF LSM gateway can enforce per-agent workspace isolation in real-time.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│  Browser UI  (port 5000, static HTML/JS)            │
│  ┌──────────────┐   ┌──────────────────────────┐   │
│  │ Gateway ctrl │   │ Live attack feed (SSE)   │   │
│  └──────┬───────┘   └───────────┬──────────────┘   │
└─────────┼───────────────────────┼──────────────────┘
          │                       │
          ▼                       ▼
┌─────────────────┐   ┌───────────────────────────┐
│ Gateway Backend │   │ Attacker Backend           │
│ port 8002       │   │ port 8001                  │
│ (root / eBPF)   │   │ (runs as user "attacker")  │
│                 │   │                            │
│ Loads BPF LSM   │   │ Scripted attack steps 1-6  │
│ programs via    │   │ Each command runs inside   │
│ python-bcc      │   │ a cgroup v2 slice          │
│                 │   │                            │
│ Ring-buffer ──► │   │ SSE event stream ──────►   │
│ events → UI     │   │ attacker events → UI       │
└────────┬────────┘   └───────────────────────────┘
         │
         ▼
┌────────────────────────────────────────┐
│  Kernel: BPF LSM hooks                 │
│  bpf_lsm_file_open                     │
│  bpf_lsm_inode_create                  │
│  bpf_lsm_bprm_check_security           │
│  bpf_lsm_socket_connect                │
│  (scoped to attacker cgroup only)      │
└────────────────────────────────────────┘
```

---

## Directory Layout

```
agentsentry-milestone1/
├── README.md
├── setup/
│   ├── 00_prereqs.sh          # install packages, create user/dirs
│   ├── 01_fake_secrets.sh     # populate fake secret files
│   └── 02_cgroup_setup.sh     # create attacker cgroup v2 slice
├── ebpf/
│   ├── lsm_policy.c           # BPF LSM C source (CO-RE / BCC)
│   └── Makefile
├── gateway/
│   ├── main.py                # Gateway backend (Flask, root)
│   ├── loader.py              # BCC loader
│   ├── events.py              # ring-buffer reader → SSE
│   └── requirements.txt
├── attacker/
│   ├── main.py                # Attacker backend (Flask)
│   ├── attack_steps.py        # deterministic 6-step script
│   ├── explanations.py        # template-based explanation engine
│   └── requirements.txt
├── ui/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── collector/
│   └── mock_collector.py      # simple HTTP server logs POST bodies
├── scripts/
│   ├── start_all.sh           # one script: starts everything
│   ├── stop_all.sh
│   └── kill_switch.sh         # emergency: detach all BPF programs
└── demo/
    └── DEMO_SCRIPT.md
```

---

## Kernel Hook Verification

Verify on your VM before running:

```bash
# 1. BPF LSM active
cat /sys/kernel/security/lsm        # must contain "bpf"

# 2. Hooks in BTF
bpftool btf dump file /sys/kernel/btf/vmlinux \
  | grep -E "bpf_lsm_(file_open|inode_create|bprm_check_security|socket_connect)"

# 3. Kallsyms fallback
grep -E "bpf_lsm_(file_open|inode_create|bprm_check|socket_connect)" /proc/kallsyms

# 4. All available LSM attach points
bpftool feature probe | grep -i lsm
```

### Hooks Used and Why

| Hook | LSM Function | What We Enforce |
|------|-------------|-----------------|
| `bpf_lsm_file_open` | `security_file_open` | Block reads of `/home/demo/secrets/**` |
| `bpf_lsm_inode_create` | `security_inode_create` | Block file creation outside workspace |
| `bpf_lsm_bprm_check_security` | `security_bprm_check` | Block execution of non-allowlisted binaries |
| `bpf_lsm_socket_connect` | `security_socket_connect` | Block outbound TCP connections |

Path resolution: BPF LSM hooks receive a `struct path *` after the kernel has already resolved symlinks and `../` traversal. We walk the dentry parent chain up to 32 levels in BPF to reconstruct the absolute path. This is safe because symlink resolution happens before the LSM hook fires.

---

## What This Demo Does NOT Cover (Honest Limits)

| Gap | Risk | Prod Mitigation |
|-----|------|----------------|
| Gateway toggle is fail-open | Daemon crash = no enforcement | Pin BPF links; use watchdog |
| No ptrace hook | ptrace memory read bypasses file policy | Add `bpf_lsm_ptrace_access_check` |
| Bind mount bypass | remount could expose outside paths | Add `bpf_lsm_move_mount` |
| io_uring not hooked | Some file ops bypass LSM | Add `bpf_lsm_io_uring_cmd` |
| Path depth limit | BPF stack: 32 levels max | Use map for deeper paths |
| No event rate limiting | Attacker can flood ring buffer | Per-cgroup rate limit in BPF |

---

## Safety

- All "secrets" are **fake data** only. No real SSH keys or credentials are touched.
- BPF programs call `bpf_get_current_cgroup_id()` and return 0 immediately for any PID not in the attacker cgroup.
- `kill_switch.sh` detaches everything instantly.
- The attacker Linux user has no sudo and cannot kill root-owned processes.

---

## Quick Start (on the VM as root)

```bash
cd /opt/agentsentry
bash setup/00_prereqs.sh      # install deps
bash setup/01_fake_secrets.sh # create fake data
bash setup/02_cgroup_setup.sh # create cgroup
bash scripts/start_all.sh     # start all services
# Open: http://localhost:8001
```
