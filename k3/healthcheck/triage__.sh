#!/usr/bin/env bash
# k3s-triage.sh
# Cluster triage and cleanup for K3s
# Run as root on a node with kubectl context

set -euo pipefail

AUTO_FIX=${1:-false}   # pass "fix" as first arg to auto-delete Unknown pods

echo "=== Cluster Triage Script ==="

# 1. Node health
echo -e "\n--- Nodes ---"
kubectl get nodes -o wide

# 2. Pod status summary
echo -e "\n--- Pod status summary ---"
kubectl get pods -A --no-headers | awk '{print $4}' | sort | uniq -c | sort -nr

# 3. List pods with ContainerStatusUnknown
echo -e "\n--- Pods in ContainerStatusUnknown ---"
kubectl get pods -A --field-selector=status.phase!=Running \
  -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,STATUS:.status.containerStatuses[*].state.waiting.reason" \
  | grep Unknown || echo "None found"

# 4. Sweep orphaned admission webhooks
echo -e "\n--- Checking for orphaned webhooks ---"
for w in $(kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations -o name 2>/dev/null); do
  svc=$(kubectl get $w -o jsonpath='{.webhooks[*].clientConfig.service.name}' 2>/dev/null || true)
  ns=$(kubectl get $w -o jsonpath='{.webhooks[*].clientConfig.service.namespace}' 2>/dev/null || true)
  if [[ -n "$svc" && -n "$ns" ]]; then
    if ! kubectl get svc -n "$ns" "$svc" &>/dev/null; then
      echo "Deleting orphaned webhook: $w (svc $ns/$svc missing)"
      kubectl delete $w
    fi
  fi
done
echo "Webhook cleanup complete."

# 5. Auto-fix ContainerStatusUnknown pods
if [[ "$AUTO_FIX" == "fix" ]]; then
  echo -e "\n--- Deleting ContainerStatusUnknown pods ---"
  pods=$(kubectl get pods -A --no-headers | awk '$4=="ContainerStatusUnknown" {print $1" "$2}')
  if [[ -n "$pods" ]]; then
    while read -r ns name; do
      echo "Deleting pod $ns/$name"
      kubectl delete pod -n "$ns" "$name"
    done <<< "$pods"
  else
    echo "No ContainerStatusUnknown pods found."
  fi
fi

# 6. Recent k3s log tail
echo -e "\n--- Recent k3s errors (last 50 lines) ---"
journalctl -u k3s -n 50 --no-pager || true

echo -e "\n=== Triage complete ==="
##
##
