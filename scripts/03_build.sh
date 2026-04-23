#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[*] Building BPF programs..."
make bpf

echo "[*] Build outputs:"
ls -l bpf/xdp_tcp_bloom.o bpf/xdp_tcp_exact.o bpf/xdp_tcp_pipeline.o
