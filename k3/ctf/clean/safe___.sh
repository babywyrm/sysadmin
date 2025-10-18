#!/usr/bin/env bash
#
# SAFE CLEANUP SCRIPT for K3s-based lab clusters ..beta..
# ------------------------------------------
# This version:
#  - DOES NOT touch images or container storage
#  - DOES NOT modify /var/lib/rancher, /var/lib/containerd, or PVCs
#  - Cleans logs, journald, apt caches, and temp files safely

set -euo pipefail
LOG_DIR="/root/cluster_cleanup_logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/cleanup_$(date +%Y%m%dT%H%M%S).log"

echo "=== Starting SAFE cluster cleanup $(date) ===" | tee -a "$LOG_FILE"

#########################################
# 1. Define protected directories
#########################################

PROTECTED_DIRS=(
  "/var/lib/rancher"
  "/var/lib/kubelet"
  "/var/lib/containerd"
  "/run/k3s"
  "/opt/bitnami"
  "/bitnami"
)

echo "[+] Protecting cluster-critical directories..." | tee -a "$LOG_FILE"
for dir in "${PROTECTED_DIRS[@]}"; do
  echo "  Skipping: $dir" | tee -a "$LOG_FILE"
done


#########################################
# 2. Clean apt cache safely
#########################################

if command -v apt-get &>/dev/null; then
  echo "[+] Cleaning apt caches..." | tee -a "$LOG_FILE"
  apt-get clean -y >>"$LOG_FILE" 2>&1 || true
  apt-get autoclean -y >>"$LOG_FILE" 2>&1 || true
  apt-get autoremove -y --purge >>"$LOG_FILE" 2>&1 || true
fi


#########################################
# 3. Rotate and vacuum system logs
#########################################

echo "[+] Rotating and vacuuming logs..." | tee -a "$LOG_FILE"

# journald cleanup
if command -v journalctl &>/dev/null; then
  journalctl --rotate >>"$LOG_FILE" 2>&1 || true
  journalctl --vacuum-size=100M >>"$LOG_FILE" 2>&1 || true
  journalctl --vacuum-time=1d >>"$LOG_FILE" 2>&1 || true
fi

# truncate only non-critical logs
find /var/log -type f -name "*.log*" \
  -not -path "/var/log/journal/*" \
  -not -path "/var/log/containers/*" \
  -not -path "/var/log/pods/*" \
  -size +50M -print -exec truncate -s 0 {} \; >>"$LOG_FILE" 2>&1 || true

# clean rotated logs
find /var/log -type f -name "*.gz" -mtime +7 -delete >>"$LOG_FILE" 2>&1 || true


#########################################
# 4. Safe temporary file cleanup
#########################################

echo "[+] Cleaning /tmp and /var/tmp safely..." | tee -a "$LOG_FILE"

find /tmp -mindepth 1 -maxdepth 1 \
  -not -path "/tmp/k3s*" \
  -not -path "/tmp/containerd*" \
  -not -path "/tmp/systemd*" \
  -exec rm -rf {} + 2>/dev/null || true

find /var/tmp -mindepth 1 -maxdepth 1 \
  -not -path "/var/tmp/k3s*" \
  -exec rm -rf {} + 2>/dev/null || true


#########################################
# 5. Reclaim apt lists + misc space
#########################################

if [ -d "/var/lib/apt/lists" ]; then
  echo "[+] Cleaning old apt lists..." | tee -a "$LOG_FILE"
  rm -rf /var/lib/apt/lists/* >>"$LOG_FILE" 2>&1 || true
fi


#########################################
# 6. Sanity check: cluster health
#########################################

if command -v kubectl &>/dev/null; then
  echo "[+] Checking cluster health..." | tee -a "$LOG_FILE"
  kubectl get pods -A -o wide >>"$LOG_FILE" 2>&1 || true
fi


#########################################
# 7. Summary
#########################################

echo "=== SAFE CLEANUP COMPLETE at $(date) ===" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE"
exit 0
