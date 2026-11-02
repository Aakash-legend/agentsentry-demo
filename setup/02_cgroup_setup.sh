#!/usr/bin/env bash
# setup/02_cgroup_setup.sh – create cgroup v2 slice for attacker user
# The attacker backend will move its subprocess into this cgroup before exec.
set -euo pipefail

CGROUP_PATH="/sys/fs/cgroup/agentsentry.slice/attacker.scope"

echo "[cgroup] Setting up cgroup v2 for attacker..."

# Create the cgroup hierarchy
mkdir -p "$CGROUP_PATH"

# Enable controllers
# First enable in root cgroup
echo "+pids +memory +cpu" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
echo "+pids +memory +cpu" > /sys/fs/cgroup/agentsentry.slice/cgroup.subtree_control 2>/dev/null || true

# Set memory limit (256MB) and PID limit for safety
echo "268435456" > "$CGROUP_PATH/memory.max" 2>/dev/null || true
echo "50" > "$CGROUP_PATH/pids.max" 2>/dev/null || true

# In cgroup v2, bpf_get_current_cgroup_id() returns the INODE NUMBER
# of the cgroup directory — not cgroup.id (which may not exist)
CGROUP_ID=$(stat -c %i "$CGROUP_PATH" 2>/dev/null || echo "UNKNOWN")
echo "[cgroup] ✓ Cgroup created: $CGROUP_PATH"
echo "[cgroup] ✓ Cgroup ID (inode): $CGROUP_ID"
echo "[cgroup] ✓ BPF programs will filter on cgroup ID: $CGROUP_ID"

# Save the cgroup ID for the gateway loader to use
echo "$CGROUP_ID" > /opt/agentsentry/attacker_cgroup_id.txt
echo "$CGROUP_PATH" > /opt/agentsentry/attacker_cgroup_path.txt

echo "[cgroup] Cgroup info saved to /opt/agentsentry/attacker_cgroup_id.txt"
