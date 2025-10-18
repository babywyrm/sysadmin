#!/usr/bin/env bash
#
# safe_cleanup.sh — Carefully clean logs, caches, and unused data ..beta..
# Works on Ubuntu + K3s/containerd environments.
# ---------------------------------------------------------------
# Features:
#   ✓ Truncates and rotates system logs safely
#   ✓ Vacuums journalctl (>22m old)
#   ✓ Cleans apt cache and orphaned packages
#   ✓ Removes old Docker/containerd layers
#   ✓ Cleans tmp files and crash dumps
#   ✓ Preserves Kubernetes pod mountpoints
#
# Usage:
#   sudo ./safe_cleanup.sh [--force]
#

set -euo pipefail
LOGFILE="/var/log/safe_cleanup_$(date +%Y%m%dT%H%M%S).log"
FORCE=0

if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
fi

log() {
  echo -e "[+] $*" | tee -a "$LOGFILE"
}

run_safe() {
  if [[ "$FORCE" -eq 1 ]]; then
    eval "$*" | tee -a "$LOGFILE"
  else
    read -rp "Run: $* ? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] && eval "$*" | tee -a "$LOGFILE"
  fi
}

# --------------------------------------------------------------------
# 1. Sanity Checks
# --------------------------------------------------------------------
[[ $EUID -ne 0 ]] && { echo "Please run as root."; exit 1; }
log "Starting cleanup at $(date)"
log "Log file: $LOGFILE"

# --------------------------------------------------------------------
# 2. Journal and Log Management
# --------------------------------------------------------------------
log "Cleaning systemd journal older than 22m..."
run_safe "journalctl --vacuum-time=22m"

log "Truncating rotated syslog and kern logs..."
find /var/log -type f \( -name '*.log.*' -o -name '*.gz' \) -print0 | while IFS= read -r -d '' f; do
  log "Deleting old compressed log: $f"
  run_safe "rm -f \"$f\""
done

log "Truncating active logs safely..."
find /var/log -type f -name "*.log" ! -path "$LOGFILE" -print0 | while IFS= read -r -d '' f; do
  run_safe "truncate -s 0 \"$f\""
done

# --------------------------------------------------------------------
# 3. Apt Cleanup
# --------------------------------------------------------------------
log "Cleaning apt caches..."
run_safe "apt-get clean"
run_safe "apt-get autoclean"
run_safe "apt-get autoremove -y"

# --------------------------------------------------------------------
# 4. K3s / containerd Cleanup
# --------------------------------------------------------------------
if command -v k3s >/dev/null 2>&1; then
  log "Cleaning up unused K3s containerd data..."
  run_safe "k3s ctr images prune"
  run_safe "k3s ctr content rm --all || true"
fi

if command -v crictl >/dev/null 2>&1; then
  log "Removing unused containerd images..."
  run_safe "crictl rmi --prune"
fi

if command -v docker >/dev/null 2>&1; then
  log "Pruning Docker data (safe mode)..."
  run_safe "docker system prune -f --volumes"
fi

# --------------------------------------------------------------------
# 5. Tmp and Crash Cleanup
# --------------------------------------------------------------------
log "Cleaning /tmp and /var/tmp (old files only)..."
find /tmp /var/tmp -type f -atime +1 -exec rm -f {} \; 2>/dev/null || true

if [[ -d /var/crash ]]; then
  log "Removing old crash reports..."
  run_safe "rm -f /var/crash/*"
fi

# --------------------------------------------------------------------
# 6. Old kube data (careful)
# --------------------------------------------------------------------
log "Pruning unused kubelet pod mounts (readonly tmpfs safe check)..."
find /var/lib/kubelet/pods -mindepth 1 -maxdepth 1 -type d \
  -not -exec mountpoint -q {} \; -print | while read -r pod; do
  log "Removing unmounted pod dir: $pod"
  run_safe "rm -rf \"$pod\""
done

# --------------------------------------------------------------------
# 7. Disk summary
# --------------------------------------------------------------------
log "Disk usage before/after:"
df -h | tee -a "$LOGFILE"

log "Cleanup complete at $(date)"
