#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

INCLUDE="-I/usr/include/x86_64-linux-gnu"

echo "[*] Building bpf/xdp_tcp_bloom.o"
clang -O2 -g -Wall -target bpf -c bpf/xdp_tcp_bloom.c -o bpf/xdp_tcp_bloom.o $INCLUDE

echo "[*] Building bpf/xdp_tcp_exact_v2.o"
clang -O2 -g -Wall -target bpf -c bpf/xdp_tcp_exact_v2.c -o bpf/xdp_tcp_exact_v2.o $INCLUDE

echo "[*] Build outputs:"
ls -l bpf/xdp_tcp_bloom.o bpf/xdp_tcp_exact_v2.o
