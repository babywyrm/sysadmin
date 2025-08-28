#!/bin/bash
set -eo pipefail

# K3s CTF Cluster Maintenance Tool (v4 - with Dry Run) ... testing ...
# Modes:
#   (no flags)    - Health Check Only
#   --repair      - Fixes broken Kubernetes resources (pods, controllers)
#   --deep-clean  - Performs host-level cleanup (images, logs, cache)
#   --nuke-logs   - Aggressively removes rotated/system logs (requires --deep-clean)
#   --dry-run     - Print actions instead of executing them

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
OVERALL_STATUS=0
REPAIR_MODE=false
DEEP_CLEAN_MODE=false
NUKE_LOGS_MODE=false
DRY_RUN=false
LOG_FILE="/var/log/k3s-maintainer.log"

# --- Configuration ---
PRESERVE_PODS=("flask-rage" "coredns" "local-path-provisioner" "metrics-server" "traefik" "wordpress-mariadb")

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --repair)      REPAIR_MODE=true ;;
    --deep-clean)  DEEP_CLEAN_MODE=true ;;
    --nuke-logs)   NUKE_LOGS_MODE=true ;;
    --dry-run)     DRY_RUN=true ;;
    *) ;; # ignore unknown
  esac
  shift
done

# --- Formatting & Logging ---
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; NC="\033[0m"
log() { echo -e "$1" | tee -a "$LOG_FILE"; }
ok() { log "${GREEN}[ OK ]${NC} $1"; }
fail() { log "${RED}[FAIL]${NC} $1"; OVERALL_STATUS=1; }
warn() { log "${YELLOW}[WARN]${NC} $1"; }
info() { log "\n--- $1 ---"; }
run_or_echo() {
    if $DRY_RUN; then
        echo "[DRY-RUN] $*"
    else
        eval "$@"
    fi
}

# --- Health Check Functions ---
check_k3s_service() {
    info "K3s Service Status"
    if systemctl is-active --quiet k3s.service; then
        ok "K3s service is active."
    else
        fail "K3s service is NOT RUNNING."
        exit 1
    fi
}

check_nodes() {
    info "Node Status"
    local unhealthy_nodes
    unhealthy_nodes=$(kubectl get nodes --no-headers -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type | grep -v "Ready" || true)
    if [[ -z "$unhealthy_nodes" ]]; then
        ok "All nodes are Ready."
    else
        fail "Found unhealthy nodes:\n$unhealthy_nodes"
    fi
}

check_pods() {
    info "Pod Status"
    local bad_pods
    bad_pods=$(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded --no-headers)
    if [[ -z "$bad_pods" ]]; then
        ok "No pods in failed/pending/unknown states."
    else
        warn "Found pods in non-running states:\n$bad_pods"
    fi
}

check_controllers() {
    info "Controller Status (Deployments, StatefulSets, DaemonSets)"
    local broken_controllers=false
    local broken_replicas=$(kubectl get deployments,statefulsets -A -o json | jq -r '.items[] | select(.spec.replicas > .status.readyReplicas) | "\(.kind)/\(.metadata.namespace)/\(.metadata.name) (\(.status.readyReplicas // 0)/\(.spec.replicas) Ready)"')
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
    if [[ -z "$warning_events" ]]; then
        ok "No recent warning events found."
    else
        warn "Recent warning events detected:\n$warning_events"
    fi
}

# --- Action Functions ---
repair_pods() {
    info "Repair Mode: Cleaning Up Dead/Failed Pods"
    local preserve_pattern=""
    for pod in "${PRESERVE_PODS[@]}"; do
        preserve_pattern="${preserve_pattern:+$preserve_pattern|}$pod"
    done

    kubectl get pods -A --no-headers | while read -r namespace pod_name rest; do
        status=$(echo "$rest" | awk '{print $2}')
        if [[ "$status" =~ ^(Error|Failed|Unknown|CrashLoopBackOff|ImagePullBackOff)$ ]]; then
            if [[ ! "$pod_name" =~ ($preserve_pattern) ]]; then
                warn "Force deleting failed pod: $namespace/$pod_name (Status: $status)"
                run_or_echo "kubectl delete pod -n $namespace $pod_name --force --grace-period=0"
            else
                log "  Skipping preserved pod: $namespace/$pod_name"
            fi
        fi
    done
}

repair_controllers() {
    info "Repair Mode: Restarting Broken Controllers"
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
                ns=$(dirname "$path"); name=$(basename "$path")
                run_or_echo "kubectl rollout restart $type -n $ns $name"
            done
        fi
    done
}

deep_clean_host() {
    info "Deep Clean Mode: Cleaning Host System"

    log "  - Pruning unused container images..."
    run_or_echo "k3s crictl rmi --prune"

    log "  - Removing old pod/containers log files..."
    run_or_echo "find /var/log/pods -type f -delete"
    run_or_echo "find /var/log/containers -type f -delete"

    if $NUKE_LOGS_MODE; then
        warn "NUKE LOGS MODE ENABLED - Aggressive log cleanup"
        run_or_echo "find /var/log -type f \\( -name '*.gz' -o -name '*.1' -o -name '*.old' \\) -delete"
        run_or_echo "journalctl --vacuum-time=20m"
        run_or_echo "find /var/log/journal -type f -mmin +20 -delete"
    else
        run_or_echo "journalctl --vacuum-size=100M"
    fi

    log "  - Flushing tmp directories..."
    run_or_echo "rm -rf /tmp/* /var/tmp/*"

    log "  - Clearing system memory caches..."
    run_or_echo "sync; echo 3 > /proc/sys/vm/drop_caches"

    ok "Host system cleanup complete."
    run_or_echo "df -h / | tail -1 | xargs | awk '{printf \"  - Disk usage: %s\\n\", \$5}'"
}

# --- Main Execution ---
echo "=========================================" > "$LOG_FILE"
log "  K3s CTF Cluster Maintenance Report"
log "  Timestamp: $(date)"
log "========================================="

if $REPAIR_MODE; then warn "REPAIR MODE ENABLED"; fi
if $DEEP_CLEAN_MODE; then warn "DEEP CLEAN MODE ENABLED"; fi
if $NUKE_LOGS_MODE; then warn "NUKE LOGS MODE ENABLED"; fi
if $DRY_RUN; then warn "DRY-RUN ENABLED (no changes will be applied)"; fi

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
