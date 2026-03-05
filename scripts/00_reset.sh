#!/usr/bin/env bash
set -euo pipefail

echo "[*] Detaching XDP from known interfaces (ignore errors)..."
sudo ip link set dev vethA xdp off 2>/dev/null || true
sudo ip link set dev vethB xdp off 2>/dev/null || true
sudo ip netns exec nsS ip link set dev vethB xdp off 2>/dev/null || true

echo "[*] Deleting veths (ignore errors)..."
sudo ip link del vethA 2>/dev/null || true
sudo ip link del vethB 2>/dev/null || true

echo "[*] Deleting namespace nsS (ignore errors)..."
sudo ip netns del nsS 2>/dev/null || true

echo "[*] Removing pinned BPF objects..."
sudo rm -rf /sys/fs/bpf/iw 2>/dev/null || true

echo "[*] Done reset."
