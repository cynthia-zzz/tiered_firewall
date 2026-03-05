#!/usr/bin/env bash
set -euo pipefail

# Clean leftovers if any
sudo ip link del vethA 2>/dev/null || true
sudo ip netns del nsS 2>/dev/null || true

echo "[*] Creating veth pair vethA <-> vethB"
sudo ip link add vethA type veth peer name vethB

echo "[*] Creating netns nsS and moving vethB into it"
sudo ip netns add nsS
sudo ip link set vethB netns nsS

echo "[*] Configuring client (root ns): vethA=10.0.0.1/24"
sudo ip addr add 10.0.0.1/24 dev vethA
sudo ip link set vethA up

echo "[*] Configuring server (nsS): vethB=10.0.0.2/24"
sudo ip netns exec nsS ip addr add 10.0.0.2/24 dev vethB
sudo ip netns exec nsS ip link set vethB up
sudo ip netns exec nsS ip link set lo up

echo "[*] Routing sanity check:"
ip route get 10.0.0.2 || true

echo "[*] Ping sanity check (should succeed):"
ping -c 1 -I vethA 10.0.0.2

echo "[*] Done network setup."
