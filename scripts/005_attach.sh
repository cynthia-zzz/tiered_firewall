#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[*] Detaching any existing XDP..."
sudo ip link set dev vethA xdp off 2>/dev/null || true
sudo ip netns exec nsS ip link set dev vethB xdp off 2>/dev/null || true

echo "[*] Attaching XDP by object:"
sudo ip link set dev vethA xdp obj bpf/xdp_tcp_bloom.o sec xdp
sudo ip netns exec nsS ip link set dev vethB xdp obj bpf/xdp_tcp_bloom.o sec xdp

echo "[*] Attach verification:"
ip link show vethA | sed -n '1,3p'
sudo ip netns exec nsS ip link show vethB | sed -n '1,3p'

echo "[*] Done attach."
