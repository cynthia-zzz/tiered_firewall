#!/usr/bin/env bash
set -euo pipefail

echo "[*] Listing counters maps:"
sudo bpftool map show | grep -w counters || true

echo
echo "[*] Dump each counters map id shown above, e.g.:"
echo "    sudo bpftool map dump id <ID>"
