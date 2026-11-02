#!/usr/bin/env bash
# setup/00_prereqs.sh – install all dependencies and create system user/dirs
# Run as root on Linux Mint / Ubuntu 22.04+ with kernel 6.14, BPF LSM, cgroup v2
set -euo pipefail

echo "[prereqs] Updating apt..."
apt-get update -qq

echo "[prereqs] Installing system packages..."
apt-get install -y --no-install-recommends \
  python3 python3-pip python3-venv \
  linux-headers-$(uname -r) \
  linux-tools-$(uname -r) linux-tools-common \
  clang llvm libelf-dev libbpf-dev \
  bpfcc-tools python3-bpfcc \
  libcap2-bin \
  curl wget \
  netcat-openbsd \
  iproute2 \
  cgroup-tools \
  sudo

echo "[prereqs] Installing bpftool (kernel-version-specific)..."
# bpftool is provided by linux-tools-$(uname -r) on Ubuntu/Mint
# Create a symlink so it's in PATH
BPFTOOL_BIN=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null | head -1)
if [[ -n "$BPFTOOL_BIN" ]]; then
  ln -sf "$BPFTOOL_BIN" /usr/local/bin/bpftool
  echo "[prereqs] ✓ bpftool linked from $BPFTOOL_BIN"
else
  echo "[prereqs] ⚠ bpftool not found via linux-tools, trying snap..."
  snap install bpftool 2>/dev/null || apt-get install -y bpftool 2>/dev/null || \
    echo "[prereqs] ⚠ bpftool unavailable – BTF check will use kallsyms fallback"
fi

echo "[prereqs] Verifying BPF LSM is active..."
LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "UNAVAILABLE")
if echo "$LSM_LIST" | grep -q "bpf"; then
  echo "[prereqs] ✓ BPF LSM active: $LSM_LIST"
else
  echo "[prereqs] ✗ BPF LSM NOT in LSM list: $LSM_LIST"
  echo "         Add lsm=landlock,lockdown,yama,integrity,apparmor,bpf to GRUB_CMDLINE_LINUX"
  exit 1
fi

echo "[prereqs] Verifying cgroup v2..."
if grep -q "cgroup2" /proc/mounts; then
  echo "[prereqs] ✓ cgroup v2 mounted"
else
  echo "[prereqs] ✗ cgroup v2 not mounted. Check systemd unified cgroup hierarchy."
  exit 1
fi

echo "[prereqs] Verifying BPF LSM hooks in BTF..."
for HOOK in bpf_lsm_file_open bpf_lsm_inode_create bpf_lsm_bprm_check_security bpf_lsm_socket_connect; do
  if bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -q "$HOOK"; then
    echo "[prereqs] ✓ Hook present in BTF: $HOOK"
  elif grep -q "$HOOK" /proc/kallsyms 2>/dev/null; then
    echo "[prereqs] ✓ Hook present in kallsyms: $HOOK"
  else
    echo "[prereqs] ✗ Hook NOT found: $HOOK (kernel may not support it)"
  fi
done

echo "[prereqs] Creating system user 'attacker'..."
if ! id attacker &>/dev/null; then
  useradd -m -s /bin/bash -d /home/attacker attacker
  echo "[prereqs] User 'attacker' created"
else
  echo "[prereqs] User 'attacker' already exists"
fi

echo "[prereqs] Creating demo directory structure..."
mkdir -p /home/demo/workspace
mkdir -p /home/demo/secrets
mkdir -p /tmp/outside

# Set ownership
chown -R attacker:attacker /home/demo/workspace || true
chmod 755 /home/demo/workspace

# secrets readable by owner (demo), NOT by attacker user directly
# BPF LSM will be what blocks the attacker, not Unix perms
# (We want to test kernel-level enforcement, not just chmod)
chown -R demo:demo /home/demo/secrets 2>/dev/null || chown -R root:root /home/demo/secrets
chmod 755 /home/demo/secrets   # readable by all – BPF LSM does the blocking

# /tmp/outside writable for creation test
chmod 1777 /tmp/outside

echo "[prereqs] Installing Python venvs..."
python3 -m venv /opt/agentsentry/venv
/opt/agentsentry/venv/bin/pip install -q --upgrade pip
/opt/agentsentry/venv/bin/pip install -q flask flask-cors requests

echo "[prereqs] ✓ Prerequisites complete"
