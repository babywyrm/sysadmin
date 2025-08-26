#!/bin/bash
set -eo pipefail

# K3s CTF Cluster Health Check
# Verifies that the CTF infrastructure is online and healthy.

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
OVERALL_STATUS=0 # 0 = OK, 1 = FAIL

# --- Configuration: Define your critical components here ---
REQUIRED_NAMESPACES=("internal" "kube-system" "wordpress")
# Check for pods containing these names
REQUIRED_PODS=("flask-rage" "coredns" "local-path-provisioner" "metrics-server" "traefik" "wordpress" "wordpress-mariadb")
# Check for services with active endpoints
REQUIRED_SERVICES=(
    "kube-system/kube-dns"
    "kube-system/traefik"
    "internal/flask-rage"
    "wordpress/wordpress"
    "wordpress/wordpress-mariadb"
)
# --- End Configuration ---

# --- Color Formatting ---
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
NC="\033[0m" # No Color

ok() { echo -e "${GREEN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; OVERALL_STATUS=1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "\n--- $1 ---"; }

# --- Health Checks ---

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
    # Add '|| true' to prevent the script from exiting if grep finds no matches
    unhealthy_nodes=$(kubectl get nodes -o jsonpath='{range .items[?(@.status.conditions[-1].type=="Ready")].status.conditions[-1]}{@.type}{" "}{@.status}{"\n"}{end}' | grep -v "Ready True" || true)
    
    if [[ -z "$unhealthy_nodes" ]]; then
        ok "All nodes are in a 'Ready' state."
    else
        fail "Found unhealthy nodes:"
        kubectl get nodes
    fi
}

check_pods() {
    info "Checking Critical Pods"
    local all_pods_ok=true
    for pod_name in "${REQUIRED_PODS[@]}"; do
        # Find the full pod name and its status
        pod_info=$(kubectl get pods -A --no-headers -o custom-columns=":metadata.namespace,:metadata.name,:status.phase" | grep "$pod_name" | head -n 1)
        if [[ -z "$pod_info" ]]; then
            fail "Required pod '$pod_name' is MISSING."
            all_pods_ok=false
            continue
        fi
        
        ns=$(echo "$pod_info" | awk '{print $1}')
        name=$(echo "$pod_info" | awk '{print $2}')
        phase=$(echo "$pod_info" | awk '{print $3}')

        if [[ "$phase" == "Running" ]]; then
            printf "%-50s %-10s\n" "  - Pod $ns/$name" "${GREEN}Running${NC}"
        else
            printf "%-50s %-10s\n" "  - Pod $ns/$name" "${RED}${phase}${NC}"
            all_pods_ok=false
        fi
    done
    [[ "$all_pods_ok" == true ]] && ok "All critical pods are running."

    info "Scanning for Other Problematic Pods"
    local bad_pods
    bad_pods=$(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded --no-headers)
    if [[ -z "$bad_pods" ]]; then
        ok "No pods found in failed, pending, or unknown states."
    else
        warn "Found pods in non-running states:"
        echo "$bad_pods"
    fi
}

check_services() {
    info "Checking Service Endpoints"
    local all_svcs_ok=true
    for svc_path in "${REQUIRED_SERVICES[@]}"; do
        ns=$(dirname "$svc_path")
        svc=$(basename "$svc_path")
        endpoints=$(kubectl get endpoints "$svc" -n "$ns" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)
        if [[ -n "$endpoints" ]]; then
            printf "%-50s %-10s\n" "  - Service $ns/$svc" "${GREEN}Active${NC}"
        else
            printf "%-50s %-10s\n" "  - Service $ns/$svc" "${RED}NO ENDPOINTS${NC}"
            all_svcs_ok=false
        fi
    done
    [[ "$all_svcs_ok" == true ]] && ok "All critical services have active endpoints."
}

check_host_resources() {
    info "Checking Host System Resources"
    # Disk Usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if (( disk_usage > 90 )); then
        fail "Disk usage is critical: ${disk_usage}%"
    elif (( disk_usage > 80 )); then
        warn "Disk usage is high: ${disk_usage}%"
    else
        ok "Disk usage is normal: ${disk_usage}%"
    fi

    # Memory Usage
    mem_usage=$(free | awk '/Mem/ {printf "%.0f", $3/$2 * 100.0}')
    if (( mem_usage > 90 )); then
        fail "Memory usage is critical: ${mem_usage}%"
    elif (( mem_usage > 80 )); then
        warn "Memory usage is high: ${mem_usage}%"
    else
        ok "Memory usage is normal: ${mem_usage}%"
    fi

    # CPU Load
    load_avg=$(uptime | awk -F'load average: ' '{print $2}' | awk -F, '{print $1}')
    cores=$(nproc)
    if (( $(echo "$load_avg > $cores" | bc -l) )); then
        warn "CPU load average ($load_avg) is higher than core count ($cores)."
    else
        ok "CPU load average ($load_avg) is normal for core count ($cores)."
    fi
}

# --- Main Execution ---
echo "========================================="
echo "  K3s CTF Cluster Health Report"
echo "========================================="
check_k3s_service
check_nodes
check_pods
check_services
check_host_resources

info "Final Summary"
if [[ $OVERALL_STATUS -eq 0 ]]; then
    ok "Cluster is HEALTHY and all critical services are operational."
else
    fail "Cluster has CRITICAL ISSUES that need attention."
fi
echo "========================================="
