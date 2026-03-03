#!/usr/bin/env bash
set -e

echo "Starting TCP listener in ns2..."

sudo ip netns exec ns2 pkill nc 2>/dev/null || true
sudo ip netns exec ns2 nc -l -p 1234 &
sleep 1

echo "Sending TCP traffic from ns1..."

sudo ip netns exec ns1 bash -c "echo hi | nc -w1 10.0.0.2 1234" || true

sleep 1

echo "Done."

