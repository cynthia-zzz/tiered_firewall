#!/usr/bin/env bash
set -euo pipefail

echo "[*] Curling from root via vethA..."
for i in 1 2 3; do
  curl -4 --interface vethA http://10.0.0.2:8080/ > /dev/null
done
echo "[*] Done curl."
