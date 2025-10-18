#!/usr/bin/env bash
#
# DEEP_CLEAN__.sh — Carefully reclaim space from K3s/containerd  (..destructive..)
# ---------------------------------------------------------------
# WARNING:
#   - Safe for K3s production nodes if you confirm each step.
#   - Removes stopped pods, old images, unused layers, orphaned data.
#   - Will NOT delete live workloads or kubelet mounts.
#
# Usage:
#   sudo bash DEEP_CLEAN__.sh [--force]

set -euo pipefail
LOGFILE="/var/log/deep_cleanup_$(date +%Y%m%dT%H%M%S).log"
FORCE=0

[[ "${1:-}" == "--force" ]] && FORCE=1
[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

log() {
  echo "[+] $*" | tee -a "$LOGFILE"
}

run_safe() {
  if [[ "$FORCE" -eq 1 ]]; then
    eval "$*" | tee -a "$LOGFILE"
  else
    read -rp "Run: $* ? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] && eval "$*" | tee -a "$LOGFILE"
  fi
}

log "=== Deep Cleanup started at $(date) ==="

# 1. Show disk usage summary first
df -h | tee -a "$LOGFILE"

# 2. Clean K3s + containerd images
if command -v k3s >/dev/null 2>&1; then
  log "Pruning unused containerd images..."
  run_safe "k3s ctr images ls | tee -a \"$LOGFILE\""
  run_safe "k3s ctr images prune"
fi

if command -v crictl >/dev/null 2>&1; then
  log "Removing old sandbox and container data..."
  run_safe "crictl ps -a"
  run_safe "crictl rmi --prune"
fi

# 3. Cleanup K3s logs and tmp directories
if systemctl is-active --quiet k3s; then
  log "Truncating K3s logs..."
  find /var/lib/rancher/k3s -type f -name "*.log" -print0 | while IFS= read -r -d '' f; do
    run_safe "truncate -s 0 \"$f\""
  done
fi

# 4. Remove orphaned containerd snapshots
if [[ -d /var/lib/rancher/k3s/agent/containerd ]]; then
  log "Removing orphaned containerd snapshots (safe check)..."
  find /var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/ \
    -type d -mtime +2 -print | while read -r dir; do
    run_safe "rm -rf \"$dir\""
  done
fi

# 5. Clean kubelet garbage (not mounted)
if [[ -d /var/lib/kubelet/pods ]]; then
  log "Cleaning up unmounted pod directories..."
  find /var/lib/kubelet/pods -mindepth 1 -maxdepth 1 -type d \
    -not -exec mountpoint -q {} \; -print | while read -r pod; do
    run_safe "rm -rf \"$pod\""
  done
fi

# 6. Clean old Helm cache and manifests
if [[ -d /root/.cache/helm ]]; then
  log "Cleaning Helm cache..."
  run_safe "rm -rf /root/.cache/helm/*"
fi

# 7. Clean apt cache again (post-container prune)
log "Cleaning apt and snap caches..."
run_safe "apt-get clean && apt-get autoclean && apt-get autoremove -y"
run_safe "rm -rf /var/lib/snapd/cache/* || true"

# 8. Purge crash dumps and tmpfiles
log "Clearing crash reports and temporary files..."
run_safe "rm -rf /var/crash/* /tmp/* /var/tmp/*"

# 9. Vacuum journal again (last 15 minutes)
log "Vacuuming journal older than 15m..."
run_safe "journalctl --vacuum-time=15m"

# 10. Report results
log "Final disk usage:"
df -h | tee -a "$LOGFILE"

log "=== Deep Cleanup completed at $(date) ==="
