#!/usr/bin/env bash
# scripts/start_all.sh
# Start all AgentSentry services. Run as root.
# Services: mock collector, gateway backend, attacker backend.
# UI is served by the attacker backend on port 8001 at /
set -euo pipefail

cd /opt/agentsentry

VENV="venv/bin/python3"
LOGDIR="/var/log/agentsentry"
mkdir -p "$LOGDIR"

echo "═══════════════════════════════════════════════"
echo "  AgentSentry – Starting All Services"
echo "═══════════════════════════════════════════════"

# ── Verify prerequisites ──────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Must run as root (needed for BPF LSM loading)"
  exit 1
fi

if [[ ! -f /opt/agentsentry/attacker_cgroup_id.txt ]]; then
  echo "ERROR: /opt/agentsentry/attacker_cgroup_id.txt not found."
  echo "       Run: bash setup/02_cgroup_setup.sh"
  exit 1
fi

CGROUP_ID=$(cat /opt/agentsentry/attacker_cgroup_id.txt)
echo "[start] Attacker cgroup ID: $CGROUP_ID"

# Verify BPF LSM
if ! cat /sys/kernel/security/lsm | grep -q bpf; then
  echo "WARNING: BPF LSM not found in /sys/kernel/security/lsm"
  echo "         Gateway will start but BPF programs may fail to attach."
fi

# ── 1. Mock Collector (port 9999) ─────────────────────────────────────────
echo "[start] Starting mock collector on port 9999..."
# Clear previous log
rm -f /tmp/collector_log.json
pkill -f "mock_collector.py" 2>/dev/null || true
sleep 0.2
$VENV collector/mock_collector.py > "$LOGDIR/collector.log" 2>&1 &
COLLECTOR_PID=$!
echo "[start] Collector PID: $COLLECTOR_PID"
sleep 0.5
if ! kill -0 $COLLECTOR_PID 2>/dev/null; then
  echo "ERROR: Collector failed to start. Check $LOGDIR/collector.log"
  exit 1
fi
echo "[start] ✓ Collector running"

# ── 2. Gateway backend (port 8002) ───────────────────────────────────────
echo "[start] Starting gateway backend on port 8002..."
pkill -f "gateway/main.py" 2>/dev/null || true
sleep 0.2
$VENV gateway/main.py > "$LOGDIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
echo "[start] Gateway PID: $GATEWAY_PID"
sleep 1
if ! kill -0 $GATEWAY_PID 2>/dev/null; then
  echo "ERROR: Gateway failed to start. Check $LOGDIR/gateway.log"
  exit 1
fi
echo "[start] ✓ Gateway running (BPF not yet loaded – use UI to start)"

# ── 3. Attacker backend (port 8001) ──────────────────────────────────────
echo "[start] Starting attacker backend on port 8001..."
pkill -f "attacker/main.py" 2>/dev/null || true
sleep 0.2
$VENV attacker/main.py > "$LOGDIR/attacker.log" 2>&1 &
ATTACKER_PID=$!
echo "[start] Attacker PID: $ATTACKER_PID"
sleep 1
if ! kill -0 $ATTACKER_PID 2>/dev/null; then
  echo "ERROR: Attacker backend failed. Check $LOGDIR/attacker.log"
  exit 1
fi
echo "[start] ✓ Attacker backend running"

# Save PIDs
echo "$COLLECTOR_PID $GATEWAY_PID $ATTACKER_PID" > /tmp/agentsentry_pids.txt

echo ""
echo "═══════════════════════════════════════════════"
echo "  All services running!"
echo ""
echo "  UI:        http://localhost:8001"
echo "  Gateway:   http://localhost:8002"
echo "  Collector: http://localhost:9999"
echo ""
echo "  Logs:      $LOGDIR/"
echo "  PIDs:      /tmp/agentsentry_pids.txt"
echo ""
echo "  NEXT STEPS:"
echo "  1. Open http://localhost:8001 in browser"
echo "  2. Click 'Run Attack' (gateway OFF) → observe SUCCEEDED"
echo "  3. Click 'Start Gateway' → click 'Run Attack' → observe BLOCKED"
echo "═══════════════════════════════════════════════"
