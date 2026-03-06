#!/usr/bin/env bash
set -e

echo "--------------------------------------"
echo "1. Rebuilding BPF program"
echo "--------------------------------------"
cd ~/iw

clang -O2 -g -Wall -target bpf \
  -c bpf/xdp_tcp_bloom.c \
  -o bpf/xdp_tcp_bloom.o \
  -I/usr/include/x86_64-linux-gnu

echo "BPF program rebuilt."

echo "--------------------------------------"
echo "2. Restarting loader"
echo "--------------------------------------"

echo "Stopping any existing loader..."
sudo pkill -f "./user/loader" 2>/dev/null || true

echo "Removing pinned BPF state..."
sudo rm -rf /sys/fs/bpf/iw

echo "Starting loader..."
sudo ./user/loader &

sleep 2

echo "--------------------------------------"
echo "3. Generating test traffic"
echo "--------------------------------------"

curl -4 --interface vethA http://10.0.0.2:8080/ > /dev/null

echo "Traffic generated."

echo "--------------------------------------"
echo "4. Dumping counters"
echo "--------------------------------------"

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters

echo "--------------------------------------"
echo "Test complete."
echo "--------------------------------------"
