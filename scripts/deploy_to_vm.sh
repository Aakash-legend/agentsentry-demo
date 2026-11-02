#!/usr/bin/env bash
# scripts/deploy_to_vm.sh
#
# Copies the project to /opt/agentsentry on the VM.
# Run from the HOST machine. Adjust SSH settings below.
#
# Usage: bash scripts/deploy_to_vm.sh [vm-ip]
#
VM_IP="${1:-192.168.56.101}"
VM_USER="root"
VM_DEST="/opt/agentsentry"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[deploy] Copying $SRC_DIR → $VM_USER@$VM_IP:$VM_DEST"
ssh "$VM_USER@$VM_IP" "mkdir -p $VM_DEST"
rsync -avz --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  "$SRC_DIR/" "$VM_USER@$VM_IP:$VM_DEST/"

echo "[deploy] Making scripts executable..."
ssh "$VM_USER@$VM_IP" "chmod +x $VM_DEST/setup/*.sh $VM_DEST/scripts/*.sh"

echo "[deploy] ✓ Done. On the VM, run:"
echo "  cd $VM_DEST && bash setup/00_prereqs.sh"
