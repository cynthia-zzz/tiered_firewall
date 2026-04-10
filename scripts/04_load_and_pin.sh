#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODULE="${1:-bloom}"

case "$MODULE" in
  bloom)
    OBJ="bpf/xdp_tcp_bloom.o"
    PROG_PIN="/sys/fs/bpf/iw/xdp_tcp_bloom"
    EXPECTED_MAPS=("bloom" "counters")
    ;;
  exact|exact_v2)
    OBJ="bpf/xdp_tcp_exact_v2.o"
    PROG_PIN="/sys/fs/bpf/iw/xdp_tcp_exact_v2"
    EXPECTED_MAPS=("flows" "counters")
    ;;
  *)
    echo "Usage: $0 [bloom|exact]"
    exit 1
    ;;
esac

sudo mkdir -p /sys/fs/bpf/iw

echo "[*] Removing old pinned objects..."
sudo rm -f /sys/fs/bpf/iw/xdp_tcp_bloom \
           /sys/fs/bpf/iw/xdp_tcp_exact_v2 \
           /sys/fs/bpf/iw/bloom \
           /sys/fs/bpf/iw/flows \
           /sys/fs/bpf/iw/counters 2>/dev/null || true

echo "[*] Loading and pinning program: $OBJ -> $PROG_PIN"
sudo bpftool prog load "$OBJ" "$PROG_PIN" type xdp

echo "[*] Program pinned:"
sudo bpftool prog show pinned "$PROG_PIN"

MAP_IDS=$(sudo bpftool prog show pinned "$PROG_PIN" | sed -n 's/.*map_ids \(.*\)/\1/p' | head -n 1)

if [[ -z "${MAP_IDS:-}" ]]; then
  echo "[!] Could not extract map IDs from pinned program info"
  exit 1
fi

echo "[*] Candidate map IDs: $MAP_IDS"

IFS=',' read -ra IDS <<< "$MAP_IDS"

for raw_id in "${IDS[@]}"; do
  ID="$(echo "$raw_id" | tr -d ' ')"
  NAME=$(sudo bpftool map show id "$ID" | awk '/name/{print $2; exit}')
  echo "[*] Map id=$ID name=$NAME"

  case "$NAME" in
    bloom)
      sudo bpftool map pin id "$ID" /sys/fs/bpf/iw/bloom
      ;;
    flows)
      sudo bpftool map pin id "$ID" /sys/fs/bpf/iw/flows
      ;;
    counters)
      sudo bpftool map pin id "$ID" /sys/fs/bpf/iw/counters
      ;;
    *)
      echo "[*] Leaving unrecognized map '$NAME' unpinned"
      ;;
  esac
done

echo "[*] Pinned objects:"
sudo ls -l /sys/fs/bpf/iw

for m in "${EXPECTED_MAPS[@]}"; do
  if [[ -e "/sys/fs/bpf/iw/$m" ]]; then
    echo "[*] Found pinned map: /sys/fs/bpf/iw/$m"
    sudo bpftool map show pinned "/sys/fs/bpf/iw/$m"
  else
    echo "[!] Expected pinned map missing: /sys/fs/bpf/iw/$m"
    exit 1
  fi
done

echo "[*] Done load+pin for module '$MODULE'."
