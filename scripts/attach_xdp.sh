#!/usr/bin/env bash
set -e

echo "Attaching XDP program..."

sudo ip netns exec ns2 ip link set dev veth2 xdp off 2>/dev/null || true
sudo ip netns exec ns2 ip link set dev veth2 xdp obj bpf/xdp_tcp_bloom.o sec xdp

echo "Attached."
