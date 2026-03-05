#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

sudo mkdir -p /sys/fs/bpf/iw

# Remove old pinned objects (if present)
sudo rm -f /sys/fs/bpf/iw/xdp_tcp_bloom /sys/fs/bpf/iw/bloom /sys/fs/bpf/iw/counters 2>/dev/null || true

echo "[*] Loading and pinning program to /sys/fs/bpf/iw/xdp_tcp_bloom"
sudo bpftool prog load bpf/xdp_tcp_bloom.o /sys/fs/bpf/iw/xdp_tcp_bloom type xdp

echo "[*] Program pinned:"
sudo bpftool prog show pinned /sys/fs/bpf/iw/xdp_tcp_bloom

# Extract map IDs from pinned prog info
MAP_IDS=$(sudo bpftool prog show pinned /sys/fs/bpf/iw/xdp_tcp_bloom | sed -n 's/.*map_ids \(.*\)/\1/p' | head -n 1)
# MAP_IDS looks like "8,7" or "14,13"
A=$(echo "$MAP_IDS" | cut -d',' -f1 | tr -d ' ')
B=$(echo "$MAP_IDS" | cut -d',' -f2 | tr -d ' ')

echo "[*] Candidate map IDs: $A and $B"
NAME_A=$(sudo bpftool map show id "$A" | awk '/name/{print $2; exit}')
NAME_B=$(sudo bpftool map show id "$B" | awk '/name/{print $2; exit}')

echo "[*] Map $A name=$NAME_A"
echo "[*] Map $B name=$NAME_B"

# Pin appropriately
if [[ "$NAME_A" == "bloom" ]]; then
  BLOOM_ID=$A
  COUNTERS_ID=$B
else
  BLOOM_ID=$B
  COUNTERS_ID=$A
fi

echo "[*] Pinning bloom(id=$BLOOM_ID) and counters(id=$COUNTERS_ID)"
sudo bpftool map pin id "$BLOOM_ID" /sys/fs/bpf/iw/bloom
sudo bpftool map pin id "$COUNTERS_ID" /sys/fs/bpf/iw/counters

echo "[*] Pinned objects:"
sudo ls -l /sys/fs/bpf/iw
sudo bpftool map show pinned /sys/fs/bpf/iw/bloom
sudo bpftool map show pinned /sys/fs/bpf/iw/counters

echo "[*] Done load+pin."
