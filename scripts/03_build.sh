#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[*] Building bpf/xdp_tcp_bloom.o"
clang -O2 -g -Wall -target bpf -c bpf/xdp_tcp_bloom.c -o bpf/xdp_tcp_bloom.o -I/usr/include/x86_64-linux-gnu

ls -l bpf/xdp_tcp_bloom.o
