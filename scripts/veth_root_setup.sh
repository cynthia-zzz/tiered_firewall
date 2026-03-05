#!/usr/bin/env bash
set -euo pipefail

sudo ip link del vethA 2>/dev/null || true
sudo ip link add vethA type veth peer name vethB

sudo ip addr add 10.0.0.1/24 dev vethA
sudo ip addr add 10.0.0.2/24 dev vethB

sudo ip link set vethA up
sudo ip link set vethB up

ip -br addr show vethA
ip -br addr show vethB

echo "Root veth pair ready:"
echo "  vethA = 10.0.0.1"
echo "  vethB = 10.0.0.2"
