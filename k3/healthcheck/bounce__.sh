#!/usr/bin/env bash
#
# bounce__.sh - Example script to check system load, and if above threshold,
#               rollout restart certain K8s workloads.

set -euo pipefail

# ---------------------------
# CONFIGURATION
# ---------------------------

LOAD_THRESHOLD=10.0

# Namespaces and resources to restart
NAMESPACE_KEYCLOAK="keycloak"
STATEFULSETS_TO_RESTART=("keycloak" "keycloak-postgresql")

NAMESPACE_KUBE_SYSTEM="kube-system"
DEPLOYMENTS_TO_RESTART=("traefik")

# ---------------------------
# SCRIPT LOGIC
# ---------------------------

# Parse the 1-minute load average from `uptime` (robust method)
CURRENT_LOAD=$(uptime | \
  awk -F 'load average:' '{ print $2 }' | \
  awk -F ',' '{ print $1 }' | \
  sed 's/^ *//;s/ *$//')

if (( $(echo "$CURRENT_LOAD > $LOAD_THRESHOLD" | bc -l) )); then
    echo "High load detected: $CURRENT_LOAD (threshold $LOAD_THRESHOLD). Rolling restarts..."

    for sts in "${STATEFULSETS_TO_RESTART[@]}"; do
        echo "Restarting StatefulSet: $sts in namespace: $NAMESPACE_KEYCLOAK"
        kubectl rollout restart statefulset/"$sts" -n "$NAMESPACE_KEYCLOAK"
        # Wait for rollout to complete (optional, if you'd like them to stabilize first)
        kubectl rollout status statefulset/"$sts" -n "$NAMESPACE_KEYCLOAK" --timeout=300s || true
    done

    for deploy in "${DEPLOYMENTS_TO_RESTART[@]}"; do
        echo "Restarting Deployment: $deploy in namespace: $NAMESPACE_KUBE_SYSTEM"
        kubectl rollout restart deployment/"$deploy" -n "$NAMESPACE_KUBE_SYSTEM"
        kubectl rollout status deployment/"$deploy" -n "$NAMESPACE_KUBE_SYSTEM" --timeout=300s || true
    done

    echo "Rollout restarts completed."
else
    echo "Load is within normal range: $CURRENT_LOAD (threshold $LOAD_THRESHOLD). No action taken."
fi
