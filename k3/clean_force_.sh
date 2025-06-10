#!/bin/bash
# Kubernetes Full Pod Cleanup Script — Safe & Complete
# Deletes pods in Error, Unknown, or Init stuck states across all namespaces
# Also prunes logs and sets up logrotate
##
##
set -euo pipefail

LOG_RETENTION_DAYS=1
LOGFILE="/var/log/k8s_cleanup_full.log"
TIMESTAMP=$(date +'%Y-%m-%d %H:%M:%S')

log() {
  echo "[$TIMESTAMP] $*" | tee -a "$LOGFILE"
}

log "Starting full stuck pod and log cleanup..."

# Verify kubectl works
if ! kubectl version --request-timeout=10s &>/dev/null; then
  log "ERROR: Cannot contact Kubernetes API"
  exit 1
fi

# Find and delete all non-Running pods that are stuck
log "Scanning all namespaces for stuck pods..."
kubectl get pods --all-namespaces --no-headers | awk '
  $4 ~ /Error|Unknown/ || $3 ~ /Init/ {
    printf("%s %s\n", $1, $2)
  }
' | while read -r ns pod; do
  log "  → Deleting stuck pod: $pod (namespace: $ns)"
  kubectl delete pod "$pod" -n "$ns" --grace-period=0 --force --ignore-not-found
done

# Optional: clean completed pods older than 3 days (change as needed)
log "Checking for completed pods older than 3 days..."
kubectl get pods --all-namespaces --field-selector=status.phase=Succeeded \
  --no-headers -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,AGE:.metadata.creationTimestamp" | while read ns name age; do
    pod_age_days=$(echo $age | awk -F'T' '{print $1}' | xargs -I{} date -d {} +%s)
    now=$(date +%s)
    diff_days=$(( (now - pod_age_days) / 86400 ))
    if [[ "$diff_days" -gt 3 ]]; then
      log "  → Deleting old completed pod: $name (namespace: $ns)"
      kubectl delete pod "$name" -n "$ns" --ignore-not-found
    fi
done

# Log rotation: delete pod/container logs older than N days
log "Pruning pod logs older than $LOG_RETENTION_DAYS days..."

find /var/log/pods/ -type d -mtime +$LOG_RETENTION_DAYS -exec rm -rf {} + 2>/dev/null || true
find /var/log/containers/ -type f -name '*.log' -mtime +$LOG_RETENTION_DAYS -exec rm -f {} + 2>/dev/null || true

# Write logrotate config if it doesn't exist
if [ ! -f /etc/logrotate.d/k8s-pod-logs ]; then
  log "Creating logrotate config for container logs..."
  cat <<EOF > /etc/logrotate.d/k8s-pod-logs
/var/log/pods/*/*.log /var/log/containers/*.log {
    daily
    rotate 5
    compress
    missingok
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /bin/systemctl reload containerd 2>/dev/null || true
    endscript
}
EOF
fi

# Force run logrotate
log "Running logrotate..."
logrotate -f /etc/logrotate.d/k8s-pod-logs

log "[✓] Cleanup finished at $TIMESTAMP"
##
##
