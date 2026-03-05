#!/usr/bin/env bash
set -euo pipefail

if mount | grep -q " on /sys/fs/bpf type bpf"; then
  echo "[*] bpffs already mounted at /sys/fs/bpf"
else
  echo "[*] Mounting bpffs at /sys/fs/bpf"
  sudo mount -t bpf bpf /sys/fs/bpf
fi

echo "[*] bpffs mount:"
mount | grep "/sys/fs/bpf" || true
