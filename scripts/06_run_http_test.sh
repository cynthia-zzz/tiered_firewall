#!/usr/bin/env bash
set -euo pipefail

echo "[*] Starting HTTP server in nsS (10.0.0.2:8080)"
echo "    (Press Ctrl+C in this terminal to stop it)"
sudo ip netns exec nsS python3 -m http.server 8080 --bind 10.0.0.2
