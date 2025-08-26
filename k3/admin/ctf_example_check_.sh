#!/bin/bash
set -eo pipefail

# K3s CTF Cluster Health & Repair Tool
# Checks cluster health and can optionally repair common issues.. (..beta..)

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
OVERALL_STATUS=0 # 0 = OK, 1 = FAIL
REPAIR_MODE=false

# --- Configuration: Define your critical components here ---
# Pods containing these names will NOT be force-deleted in repair mode
PRESERVE_PODS=("flask-rage" "coredns" "local-path-provisioner" "metrics-server" "traefik" "wordpress" "wordpress-mariadb")
# Check for services with active endpoints
REQUIRED_SERVICES=(
    "kube-system/kube-dns"
    "kube-system/traefik"
    "internal/flask-rage"
    "wordpress/wordpress"
    "wordpress/wordpress-mariadb"
)
# --- End Configuration ---

# --- Argument Parsing ---
if [[ "$1" == "--repair" ]]; then
    REPAIR_MODE=true
fi

# --- Color Formatting ---
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
NC="\033[0m" # No Color

ok() { echo -e "${GREEN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; OVERALL_STATUS=1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "\n--- $1 ---"; }

# --- Health Check Functions ---

check_k3s_service() {
    info "Checking K3s Service Status"
    if systemctl is-active --quiet k3s.service; then
        ok "K3s service is active and running."
    else
        fail "K3s service is NOT RUNNING."
        exit 1
    fi
}

check_nodes() {
    info "Checking Node Status"
    local unhealthy_nodes
    unhealthy_nodes=$(kubectl get nodes -o jsonpath='{range .items[?(@.status.conditions[-1].type=="Ready")].status.conditions[-1]}{@.type}{" "}{@.status}{"\n"}{end}' | grep -v "Ready True" || true)
    if [[ -z "$unhealthy_nodes" ]]; then
        ok "All nodes are in a 'Ready' state."
    else
        fail "Found unhealthy nodes:"
        kubectl get nodes
    fi
}

check_pods() {
    info "Checking Pod Status"
    local bad_pods
    bad_pods=$(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded --no-headers)
    if [[ -z "$bad_pods" ]]; then
        ok "No pods found in failed, pending, or unknown states."
    else
        warn "Found pods in non-running states:"
        echo "$bad_pods"
    fi
}

check_deployments() {
    info "Checking Deployment Status"
    local broken_deployments
    broken_deployments=$(kubectl get deployments -A -o json | jq -r '.items[] | select((.spec.replicas // 0) > 0 and .status.readyReplicas != .spec.replicas) | "\(.metadata.namespace)/\(.metadata.name)"')
    if [[ -z "$broken_deployments" ]]; then
        ok "All deployments have the correct number of ready replicas."
    else
        fail "Found deployments with incorrect replica counts:"
        echo "$broken_deployments"
    fi
}

# --- Repair Functions ---

force_gc_crashed_pods() {
    info "Repair Mode: Force Garbage Collecting Crashed Pods"
    local preserve_filter
    preserve_filter=$(IFS='|'; echo "${PRESERVE_PODS[*]}")

    # Find pods that are not Running or Succeeded, and are not part of the preserved list
    crashed_pods=$(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded -o json | jq -r --arg filter "$preserve_filter" '.items[] | select(.metadata.name | test($filter) | not) | "\(.metadata.namespace)/\(.metadata.name)"')

    if [[ -z "$crashed_pods" ]]; then
        ok "No crashed pods to garbage collect."
        return
    fi

    echo "$crashed_pods" | while read -r pod_path; do
        ns=$(dirname "$pod_path")
        pod=$(basename "$pod_path")
        warn "Force deleting crashed pod: $ns/$pod"
        kubectl delete pod "$pod" -n "$ns" --force --grace-period=0 || true
    done
}

repair_deployments() {
    info "Repair Mode: Restarting Broken Deployments"
    broken_deployments=$(kubectl get deployments -A -o json | jq -r '.items[] | select((.spec.replicas // 0) > 0 and .status.readyReplicas != .spec.replicas) | "\(.metadata.namespace)/\(.metadata.name)"')

    if [[ -z "$broken_deployments" ]]; then
        ok "No broken deployments to restart."
        return
    fi

    echo "$broken_deployments" | while read -r deploy_path; do
        ns=$(dirname "$deploy_path")
        deploy=$(basename "$deploy_path")
        warn "Restarting broken deployment: $ns/$deploy"
        kubectl rollout restart deployment "$deploy" -n "$ns" || true
    done
}

# --- Main Execution ---
echo "========================================="
echo "  K3s CTF Cluster Health & Repair Tool"
echo "========================================="

if [[ "$REPAIR_MODE" == true ]]; then
    warn "REPAIR MODE ENABLED. Actively fixing issues."
fi

# --- Run Health Checks ---
check_k3s_service
check_nodes
check_pods
check_deployments

# --- Run Repair Actions if Enabled ---
if [[ "$REPAIR_MODE" == true ]]; then
    force_gc_crashed_pods
    repair_deployments
    info "Repair actions completed. Re-run check without --repair to see final status."
fi

info "Final Summary"
if [[ $OVERALL_STATUS -eq 0 ]]; then
    ok "Cluster health check PASSED."
else
    fail "Cluster health check FAILED. Issues detected."
fi
echo "========================================="
