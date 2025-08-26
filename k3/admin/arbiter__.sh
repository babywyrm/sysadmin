#!/bin/bash
set -eo pipefail

# K3s CTF Cluster Maintenance Tool (v2 - More Robust), lol (..beta..)
# Modes:
#   (no flags)  - Health Check Only
#   --repair    - Fixes broken Kubernetes resources (pods, controllers)
#   --deep-clean - Performs host-level cleanup (images, logs, cache)

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
OVERALL_STATUS=0
REPAIR_MODE=false
DEEP_CLEAN_MODE=false
LOG_FILE="/var/log/k3s-maintainer.log"

# --- Configuration ---
PRESERVE_PODS=("flask-main" "coredns" "local-path-provisioner" "metrics-server" "traefik" "wordpress" "wordpress-mariadb")

# --- Argument Parsing (More Robust) ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --repair)
      REPAIR_MODE=true
      shift # consume the argument
      ;;
    --deep-clean)
      DEEP_CLEAN_MODE=true
      shift # consume the argument
      ;;
    *)
      # Silently ignore unknown arguments
      shift
      ;;
  esac
done

# --- Formatting & Logging ---
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; NC="\033[0m"
log() { echo -e "$1" | tee -a "$LOG_FILE"; }
ok() { log "${GREEN}[ OK ]${NC} $1"; }
fail() { log "${RED}[FAIL]${NC} $1"; OVERALL_STATUS=1; }
warn() { log "${YELLOW}[WARN]${NC} $1"; }
info() { log "\n--- $1 ---"; }

# --- Health Check Functions ---

check_k3s_service() {
    info "K3s Service Status"
    if systemctl is-active --quiet k3s.service; then ok "K3s service is active."; else fail "K3s service is NOT RUNNING."; exit 1; fi
}

check_nodes() {
    info "Node Status"
    local unhealthy_nodes
    unhealthy_nodes=$(kubectl get nodes --no-headers -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type | grep -v "Ready" || true)
    if [[ -z "$unhealthy_nodes" ]]; then ok "All nodes are Ready."; else fail "Found unhealthy nodes:\n$unhealthy_nodes"; fi
}

check_pods() {
    info "Pod Status"
    local bad_pods
    bad_pods=$(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded --no-headers)
    if [[ -z "$bad_pods" ]]; then ok "No pods in failed/pending/unknown states."; else warn "Found pods in non-running states:\n$bad_pods"; fi
}

check_controllers() {
    info "Controller Status (Deployments, StatefulSets, DaemonSets)"
    local broken_controllers=false
    # Check Deployments and StatefulSets
    local broken_replicas=$(kubectl get deployments,statefulsets -A -o json | jq -r '.items[] | select(.spec.replicas > .status.readyReplicas) | "\(.kind)/\(.metadata.namespace)/\(.metadata.name) (\(.status.readyReplicas // 0)/\(.spec.replicas) Ready)"')
    # Check DaemonSets
    local broken_daemons=$(kubectl get daemonsets -A -o json | jq -r '.items[] | select(.status.desiredNumberScheduled > .status.numberReady) | "\(.kind)/\(.metadata.namespace)/\(.metadata.name) (\(.status.numberReady // 0)/\(.status.desiredNumberScheduled) Ready)"')

    if [[ -n "$broken_replicas" ]]; then
        fail "Found broken Deployments/StatefulSets:\n$broken_replicas"
        broken_controllers=true
    fi
    if [[ -n "$broken_daemons" ]]; then
        fail "Found broken DaemonSets:\n$broken_daemons"
        broken_controllers=true
    fi
    [[ "$broken_controllers" == false ]] && ok "All controllers have the correct number of ready replicas."
}

check_pvc() {
    info "Persistent Volume Claim (PVC) Status"
    local pending_pvcs
    # Correct way: Get all PVCs and filter with grep
    pending_pvcs=$(kubectl get pvc -A --no-headers 2>/dev/null | grep "Pending" || true)
    if [[ -z "$pending_pvcs" ]]; then
        ok "No PVCs are stuck in Pending state."
    else
        warn "Found Pending PVCs that may need attention:\n$pending_pvcs"
    fi
}

check_events() {
    info "Recent Cluster Events"
    local warning_events
    warning_events=$(kubectl get events -A --field-selector type=Warning --sort-by='.lastTimestamp' | tail -n 5)
    if [[ -z "$warning_events" ]]; then ok "No recent warning events found."; else warn "Recent warning events detected:\n$warning_events"; fi
}

# --- Action Functions ---

repair_pods() {
    info "Repair Mode: Force Garbage Collecting Bad Pods"
    local preserve_filter=$(IFS='|'; echo "${PRESERVE_PODS[*]}")
    local pods_to_delete
    pods_to_delete=$(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded -o json | jq -r --arg filter "$preserve_filter" '.items[] | select(.metadata.name | test($filter) | not) | "\(.metadata.namespace)/\(.metadata.name)"')
    
    if [[ -z "$pods_to_delete" ]]; then ok "No non-preserved bad pods to delete."; return; fi
    
    echo "$pods_to_delete" | while read -r pod_path; do
        warn "Force deleting pod: $pod_path"
        kubectl delete pod -n "$(dirname "$pod_path")" "$(basename "$pod_path")" --force --grace-period=0 || true
    done
}

repair_controllers() {
    info "Repair Mode: Restarting Broken Controllers"
    local restarted=false
    for type in deployment statefulset daemonset; do
        local broken
        if [[ "$type" == "daemonset" ]]; then
            broken=$(kubectl get $type -A -o json | jq -r '.items[] | select(.status.desiredNumberScheduled > .status.numberReady) | "\(.metadata.namespace)/\(.metadata.name)"')
        else
            broken=$(kubectl get $type -A -o json | jq -r '.items[] | select(.spec.replicas > .status.readyReplicas) | "\(.metadata.namespace)/\(.metadata.name)"')
        fi

        if [[ -n "$broken" ]]; then
            echo "$broken" | while read -r path; do
                warn "Restarting broken $type: $path"
                kubectl rollout restart $type -n "$(dirname "$path")" "$(basename "$path")" || true
                restarted=true
            done
        fi
    done
    [[ "$restarted" == false ]] && ok "No broken controllers needed a restart."
}

deep_clean_host() {
    info "Deep Clean Mode: Cleaning Host System"
    
    log "  - Pruning unused container images..."
    k3s crictl rmi --prune &>/dev/null || true
    
    log "  - Removing old pod log files..."
    find /var/log/pods -type f -mtime +1 -delete &>/dev/null || true
    find /var/log/containers -type f -mtime +1 -delete &>/dev/null || true
    
    log "  - Vacuuming systemd journal..."
    journalctl --vacuum-size=100M &>/dev/null || true
    
    log "  - Clearing system memory caches..."
    sync; echo 3 > /proc/sys/vm/drop_caches
    
    ok "Host system cleanup complete."
    df -h / | tail -1 | xargs | awk '{printf "  - Disk usage: %s\n", $5}'
}

# --- Main Execution ---
echo "=========================================" > "$LOG_FILE"
log "  K3s CTF Cluster Maintenance Report"
log "  Timestamp: $(date)"
log "========================================="

if $REPAIR_MODE; then warn "REPAIR MODE ENABLED"; fi
if $DEEP_CLEAN_MODE; then warn "DEEP CLEAN MODE ENABLED"; fi

# --- Run Health Checks ---
check_k3s_service
check_nodes
check_pods
check_controllers
check_pvc
check_events

# --- Run Actions if Enabled ---
if $REPAIR_MODE; then
    repair_pods
    repair_controllers
fi
if $DEEP_CLEAN_MODE; then
    deep_clean_host
fi

info "Final Summary"
if [[ $OVERALL_STATUS -eq 0 ]]; then
    ok "Cluster health check PASSED."
else
    fail "Cluster health check FAILED. Issues detected."
fi
log "========================================="
