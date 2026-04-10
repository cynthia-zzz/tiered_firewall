#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODULE="${1:-bloom}"

case "$MODULE" in
  bloom)
    OBJ="bpf/xdp_tcp_bloom.o"
    ;;
  exact|exact_v2)
    OBJ="bpf/xdp_tcp_exact_v2.o"
    ;;
  *)
    echo "Usage: $0 [bloom|exact]"
    exit 1
    ;;
esac

echo "[*] Detaching any existing XDP..."
sudo ip link set dev vethA xdp off 2>/dev/null || true
sudo ip netns exec nsS ip link set dev vethB xdp off 2>/dev/null || true

echo "[*] Attaching XDP object: $OBJ"
sudo ip link set dev vethA xdp obj "$OBJ" sec xdp
sudo ip netns exec nsS ip link set dev vethB xdp obj "$OBJ" sec xdp

echo "[*] Attach verification:"
ip link show vethA | sed -n '1,3p'
sudo ip netns exec nsS ip link show vethB | sed -n '1,3p'

echo "[*] Done attach for module '$MODULE'."
