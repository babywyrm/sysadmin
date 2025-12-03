#!/bin/bash

PORT="${1:-8000}"

echo "[*] Starting multi-protocol receiver on port $PORT"
echo "[*] Listening for HTTP, TCP, and raw connections..."

while true; do
  echo "[+] Ready to receive..."
  nc -lvnp "$PORT" | tee -a received_$(date +%s).bin
done
