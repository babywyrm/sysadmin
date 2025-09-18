#!/usr/bin/env bash
# rootkit-scan.sh — wrapper for chkrootkit & rkhunter
# 2025 update with optional systemd timer install

set -euo pipefail

LOG_DIR="/var/log/rootkit-scan"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTFILE="$LOG_DIR/scan-$TIMESTAMP.log"

mkdir -p "$LOG_DIR"

install_timer() {
    echo "[*] Installing systemd service + timer..."

    SERVICE_FILE="/etc/systemd/system/rootkit-scan.service"
    TIMER_FILE="/etc/systemd/system/rootkit-scan.timer"

    sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Rootkit Scan Wrapper

[Service]
Type=oneshot
ExecStart=$(realpath "$0")
EOF

    sudo tee "$TIMER_FILE" >/dev/null <<EOF
[Unit]
Description=Daily Rootkit Scan Timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable --now rootkit-scan.timer

    echo "[+] Systemd timer installed: runs daily"
    exit 0
}

if [[ "${1:-}" == "--install-timer" ]]; then
    install_timer
fi

echo "=== Rootkit Scan - $TIMESTAMP ===" | tee "$OUTFILE"

# Run chkrootkit
if command -v chkrootkit >/dev/null 2>&1; then
    echo "[*] Running chkrootkit..." | tee -a "$OUTFILE"
    sudo chkrootkit 2>&1 | tee -a "$OUTFILE"
else
    echo "[!] chkrootkit not installed" | tee -a "$OUTFILE"
fi

echo "" | tee -a "$OUTFILE"

# Run rkhunter
if command -v rkhunter >/dev/null 2>&1; then
    echo "[*] Updating rkhunter database..." | tee -a "$OUTFILE"
    sudo rkhunter --update || true
    sudo rkhunter --propupd || true

    echo "[*] Running rkhunter..." | tee -a "$OUTFILE"
    sudo rkhunter --check --sk 2>&1 | tee -a "$OUTFILE"
else
    echo "[!] rkhunter not installed" | tee -a "$OUTFILE"
fi

echo "=== Scan complete: $OUTFILE ==="
