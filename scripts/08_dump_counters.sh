#!/usr/bin/env bash
set -euo pipefail

echo "[*] Dumping pinned counters..."
sudo bpftool map dump pinned /sys/fs/bpf/iw/counters
