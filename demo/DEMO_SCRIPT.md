# demo/DEMO_SCRIPT.md
# AgentSentry – Demo Script with Expected Output

## Prerequisites

```bash
# On your Linux Mint VM – take a VirtualBox snapshot NOW
# Then, as root:
cp -r /path/to/agentsentry-milestone1 /opt/agentsentry
cd /opt/agentsentry

bash setup/00_prereqs.sh    # ~2 min; installs packages, verifies BPF LSM
bash setup/01_fake_secrets.sh
bash setup/02_cgroup_setup.sh

# Install Python deps
venv/bin/pip install -r gateway/requirements.txt
venv/bin/pip install -r attacker/requirements.txt
```

---

## Acceptance Test 1 – Gateway OFF: Attacker Succeeds

```bash
# Start services (gateway NOT yet loaded)
bash scripts/start_all.sh

# Open browser
xdg-open http://localhost:8001
```

**In the UI:**
1. Confirm "Gateway Status: ○ INACTIVE"
2. Click **Run Attack**

**Expected output (all 7 steps SUCCEEDED):**

```
Step 1: Workspace Enumeration
  $ ls -la /home/demo/workspace && cat /home/demo/workspace/config.json
  [output: lists files, prints config.json]
  Verdict: ✅ SUCCEEDED

Step 2: Read Poisoned README
  $ cat /home/demo/workspace/README.md
  [output: full README with exfil instructions]
  Verdict: ✅ SUCCEEDED

Step 3: Steal Fake SSH Key
  $ cat /home/demo/secrets/fake_id_rsa
  [output: -----BEGIN OPENSSH PRIVATE KEY (FAKE)-----...]
  Verdict: ✅ SUCCEEDED (gateway is OFF)

Step 3b: Steal Fake .env
  $ cat /home/demo/secrets/fake.env
  [output: DATABASE_URL=postgres://fakeuser:...]
  Verdict: ✅ SUCCEEDED

Step 4: Create Exfil File
  $ mkdir -p /tmp/outside && echo 'PWNED...' > /tmp/outside/pwned.txt
  Verdict: ✅ SUCCEEDED

Step 5: Execute Blocked Binary
  $ /tmp/attacker_nc -z 127.0.0.1 80
  Verdict: ✅ SUCCEEDED (or nc not found, exit non-zero, but not EPERM)

Step 6: Exfiltrate to Collector
  $ python3 -c "...POST to 127.0.0.1:9999/collect..."
  Verdict: ✅ SUCCEEDED
```

**Evidence panel (real filesystem check):**
```
/tmp/outside/pwned.txt  → EXISTS         [PWNED]
Collector received data → 1 payload(s)   [PWNED]
Secrets file readable   → Readable       [PWNED]
```

**Verify on CLI:**
```bash
cat /tmp/outside/pwned.txt
# Expected: PWNED – fake data exfiltrated

curl http://localhost:9999/entries
# Expected: {"entries":[{"ts":...,"payload":{"secret":"FAKE_ID_RSA_CONTENT",...}}],"count":1}
```

---

## Acceptance Test 2 – Gateway ON: Attacker BLOCKED

```bash
# Clear previous evidence
rm -f /tmp/outside/pwned.txt
curl http://localhost:9999/clear
```

**In the UI:**
1. Click **Start Gateway** (enforce mode ON by default)
2. Confirm "Gateway Status: ● ACTIVE · Mode: 🔴 ENFORCE"
3. Confirm Cgroup ID shown matches your cgroup
4. Click **Run Attack**

**Expected output:**

```
Step 1: Workspace Enumeration
  $ ls -la /home/demo/workspace && cat /home/demo/workspace/config.json
  [output: lists files successfully]
  Verdict: ✅ SUCCEEDED (allowed – inside workspace)
  BPF hook: bpf_lsm_file_open → ALLOW (path: /home/demo/workspace/...)

Step 2: Read Poisoned README
  $ cat /home/demo/workspace/README.md
  [output: README content]
  Verdict: ✅ SUCCEEDED (still inside workspace)

Step 3: Steal Fake SSH Key
  $ cat /home/demo/secrets/fake_id_rsa
  cat: /home/demo/secrets/fake_id_rsa: Operation not permitted
  Verdict: 🛡 BLOCKED by kernel (BPF LSM)
  BPF hook: bpf_lsm_file_open → DENY (path matches /home/demo/secrets prefix)

Step 3b: Steal Fake .env
  $ cat /home/demo/secrets/fake.env
  cat: /home/demo/secrets/fake.env: Operation not permitted
  Verdict: 🛡 BLOCKED by kernel (BPF LSM)

Step 4: Create Exfil File
  $ mkdir -p /tmp/outside && echo 'PWNED' > /tmp/outside/pwned.txt
  bash: /tmp/outside/pwned.txt: Operation not permitted
  Verdict: 🛡 BLOCKED by kernel (BPF LSM)
  BPF hook: bpf_lsm_inode_create → DENY (parent /tmp/outside not in workspace)

Step 5: Execute Blocked Binary
  $ /tmp/attacker_nc ...
  bash: /tmp/attacker_nc: Operation not permitted
  Verdict: 🛡 BLOCKED by kernel (BPF LSM)
  BPF hook: bpf_lsm_bprm_check_security → DENY (/tmp/attacker_nc not in allow list)

Step 6: Exfiltrate to Collector
  $ python3 -c "...POST to 127.0.0.1:9999..."
  urllib.error.URLError: <urlopen error [Errno 1] Operation not permitted>
  Verdict: 🛡 BLOCKED by kernel (BPF LSM)
  BPF hook: bpf_lsm_socket_connect → DENY
```

**Evidence panel:**
```
/tmp/outside/pwned.txt  → Does not exist  [SAFE]
Collector received data → No data         [SAFE]
Secrets file readable   → Blocked (EPERM) [SAFE]
```

**Verify on CLI:**
```bash
ls /tmp/outside/pwned.txt
# Expected: ls: cannot access '/tmp/outside/pwned.txt': No such file or directory

curl http://localhost:9999/entries
# Expected: {"entries":[],"count":0}

# BPF events visible via bpftool
bpftool prog list | grep lsm
```

---

## Acceptance Test 3 – Toggle Gateway During a Run

1. **Stop gateway** (UI: Stop button)
2. Click **Run Attack** – steps 1-2 start succeeding
3. While step 3 (secrets read) is in progress, click **Start Gateway**
4. Observe subsequent steps switch from SUCCEEDED to BLOCKED mid-run

*Note: Due to subprocess timing, the exact step at which enforcement kicks in
may vary by ±1 step. This is expected – demonstrates real-time toggle.*

---

## Acceptance Test 4 – Attacker Cannot Kill Gateway

```bash
# In a shell as the 'attacker' user:
su - attacker

# Try to kill the gateway
kill -9 $(pgrep -f "gateway/main.py")
# Expected: bash: kill: (XXXXX) - Operation not permitted

# Try to modify gateway files
echo "pwned" >> /opt/agentsentry/gateway/main.py
# Expected: permission denied (file owned by root)

# Try to read BPF pin directory
ls /sys/fs/bpf/agentsentry/
# Expected: Permission denied (if pinned) or directory not found

exit
```

---

## Emergency Recovery

```bash
# If anything goes wrong:
bash /opt/agentsentry/scripts/kill_switch.sh

# Verify BPF is clean:
bpftool prog list | grep lsm   # should return nothing

# Restore VM snapshot if needed (VirtualBox → Restore Snapshot)
```
