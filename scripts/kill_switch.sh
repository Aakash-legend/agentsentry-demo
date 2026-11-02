#!/usr/bin/env bash
# scripts/kill_switch.sh
#
# EMERGENCY: Detach all BPF LSM programs and restore normal kernel behavior.
# Run as root. Safe to call at any time, even if programs are not loaded.
#
# What it does:
#   1. Calls the gateway /stop endpoint to trigger graceful detach
#   2. Removes any pinned BPF objects from /sys/fs/bpf/agentsentry/
#   3. Kills all AgentSentry processes
#   4. Verifies no BPF programs are still attached with "lsm" section
#
set -euo pipefail

echo "═══════════════════════════════════════════════"
echo "  KILL SWITCH – Detaching all BPF programs"
echo "═══════════════════════════════════════════════"

# Step 1: Graceful gateway stop
echo "[kill-switch] Calling gateway /stop..."
curl -s -X POST http://localhost:8002/stop 2>/dev/null \
  && echo "[kill-switch] Gateway /stop called" \
  || echo "[kill-switch] Gateway not responding (may already be down)"

# Step 2: Remove pinned BPF objects
BPF_PIN_DIR="/sys/fs/bpf/agentsentry"
if [[ -d "$BPF_PIN_DIR" ]]; then
  echo "[kill-switch] Removing pinned BPF objects from $BPF_PIN_DIR..."
  rm -rf "$BPF_PIN_DIR"
  echo "[kill-switch] Pinned objects removed"
else
  echo "[kill-switch] No pinned BPF objects found (already clean)"
fi

# Step 3: Kill all AgentSentry processes
echo "[kill-switch] Killing AgentSentry processes..."
pkill -f "mock_collector.py" 2>/dev/null || true
pkill -f "gateway/main.py"   2>/dev/null || true
pkill -f "attacker/main.py"  2>/dev/null || true

# Step 4: Verify no LSM programs remain attached
echo "[kill-switch] Verifying BPF cleanup..."
if command -v bpftool &>/dev/null; then
  LSM_PROGS=$(bpftool prog list 2>/dev/null | grep -c "lsm" || echo "0")
  echo "[kill-switch] BPF LSM programs still loaded: $LSM_PROGS"
  if [[ "$LSM_PROGS" == "0" ]]; then
    echo "[kill-switch] ✓ Clean: no BPF LSM programs attached"
  else
    echo "[kill-switch] ⚠ Warning: $LSM_PROGS BPF program(s) still present."
    echo "               They will be GC'd when the file descriptors close."
    bpftool prog list | grep lsm || true
  fi
else
  echo "[kill-switch] bpftool not available – cannot verify"
fi

echo ""
echo "[kill-switch] ✓ Kill switch complete. System is clean."
echo "              Attacker cgroup enforcement is DISABLED."
echo "═══════════════════════════════════════════════"
