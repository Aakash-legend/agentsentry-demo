#!/usr/bin/env bash
# scripts/stop_all.sh – Stop all AgentSentry services
set -euo pipefail

echo "[stop] Stopping AgentSentry services..."

pkill -f "mock_collector.py" 2>/dev/null && echo "[stop] Collector stopped" || echo "[stop] Collector was not running"
pkill -f "gateway/main.py"   2>/dev/null && echo "[stop] Gateway stopped"   || echo "[stop] Gateway was not running"
pkill -f "attacker/main.py"  2>/dev/null && echo "[stop] Attacker stopped"  || echo "[stop] Attacker was not running"

rm -f /tmp/agentsentry_pids.txt
echo "[stop] Done"
