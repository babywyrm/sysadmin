#!/bin/bash
# bounce__.sh - Example script to check system load, and if above threshold,
#                rollout restart certain K8s workloads.

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

# Function to log messages
log() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message"
}

# Function to check the current load average
get_current_load() {
    uptime | awk -F 'load average:' '{ print $2 }' | \
    awk -F ',' '{ print $1 }' | \
    sed 's/^ *//;s/ *$//'
}

# Function to restart a Kubernetes resource and check its rollout status
restart_k8s_resource() {
    local resource_type="$1"
    local resource_name="$2"
    local namespace="$3"

    log "Restarting $resource_type: $resource_name in namespace: $namespace"
    if ! kubectl rollout restart "$resource_type/$resource_name" -n "$namespace"; then
        log "Error: Failed to restart $resource_type: $resource_name in namespace: $namespace"
        return 1
    fi

    # Wait for rollout to complete
    if ! kubectl rollout status "$resource_type/$resource_name" -n "$namespace" --timeout=300s; then
        log "Warning: Rollout of $resource_type: $resource_name in namespace: $namespace did not complete in time."
        return 1
    fi

    log "$resource_type: $resource_name successfully restarted."
}

# Main logic
CURRENT_LOAD=$(get_current_load)

if (( $(echo "$CURRENT_LOAD > $LOAD_THRESHOLD" | bc -l) )); then
    log "High load detected: $CURRENT_LOAD (threshold $LOAD_THRESHOLD). Rolling restarts..."

    for sts in "${STATEFULSETS_TO_RESTART[@]}"; do
        restart_k8s_resource "statefulset" "$sts" "$NAMESPACE_KEYCLOAK" || {
            log "Failed to restart StatefulSet: $sts. Continuing with other resources."
        }
    done

    for deploy in "${DEPLOYMENTS_TO_RESTART[@]}"; do
        restart_k8s_resource "deployment" "$deploy" "$NAMESPACE_KUBE_SYSTEM" || {
            log "Failed to restart Deployment: $deploy. Continuing with other resources."
        }
    done

    log "Rollout restarts completed."
else
    log "Load is within normal range: $CURRENT_LOAD (threshold $LOAD_THRESHOLD). No action taken."
fi
