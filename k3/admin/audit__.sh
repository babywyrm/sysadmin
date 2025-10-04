#!/bin/bash

# Enhanced Kubernetes Cluster Security Diagnostics Script
# Purpose: Comprehensive K8s cluster auditing for security assessment and CTF scenarios
# Author: Security Assessment Team, lol
# Version: 3.1 (Fixed)
# Dependencies: kubectl (required), jq (optional but recommended)

set -euo pipefail

# Script Configuration
readonly SCRIPT_VERSION="3.1"
readonly LOG_FILE="/tmp/k8s-audit-$(date +%Y%m%d-%H%M%S).log"

# Configuration with defaults
SKIP_METRICS=${SKIP_METRICS:-false}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-"console"}
NAMESPACE_FILTER=${NAMESPACE_FILTER:-""}
MAX_RESULTS=${MAX_RESULTS:-10}
INCLUDE_SYSTEM_NS=${INCLUDE_SYSTEM_NS:-true}
VERBOSE=${VERBOSE:-false}

# Color definitions for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;36m'
readonly PURPLE='\033[0;35m'
readonly PLAIN='\033[0m'
readonly BOLD=$(tput bold 2>/dev/null || echo "")
readonly NORMAL=$(tput sgr0 2>/dev/null || echo "")

# Global cache variables
ALL_PODS_JSON=""
ALL_NAMESPACES=""
ALL_NODES_JSON=""
ALL_SERVICES_JSON=""
ALL_SECRETS_JSON=""

# Show help
show_help() {
  cat << EOF
Kubernetes Cluster Security Diagnostics v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

OPTIONS:
    -o, --output FORMAT     Output format: console, json (default: console)
    -n, --namespace NS      Filter by namespace (default: all)
    --skip-metrics         Skip metrics collection
    --no-system           Exclude system namespaces
    -v, --verbose         Enable verbose logging
    -h, --help            Show this help

EXAMPLES:
    $0                                    # Full audit with default settings
    $0 -o json > audit-report.json      # JSON output for automation
    $0 -n production --skip-metrics     # Focus on production namespace
    $0 --no-system                      # Exclude system namespaces

EOF
}

# Parse command line arguments
parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --output|-o)
        OUTPUT_FORMAT="$2"
        shift 2
        ;;
      --namespace|-n)
        NAMESPACE_FILTER="$2"
        shift 2
        ;;
      --skip-metrics)
        SKIP_METRICS=true
        shift
        ;;
      --no-system)
        INCLUDE_SYSTEM_NS=false
        shift
        ;;
      --verbose|-v)
        VERBOSE=true
        shift
        ;;
      --help|-h)
        show_help
        exit 0
        ;;
      *)
        echo -e "${RED}Unknown option: $1${PLAIN}"
        show_help
        exit 1
        ;;
    esac
  done
}

# Logging function
log() {
  local level="$1"
  shift
  local message="$*"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  if [[ "$VERBOSE" == true ]] || [[ "$level" != "DEBUG" ]]; then
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    if [[ "$VERBOSE" == true ]]; then
      echo "[$timestamp] [$level] $message" >&2
    fi
  fi
}

# Dependency validation
check_dependencies() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] kubectl is required but not installed${PLAIN}"
    exit 1
  fi
  
  if ! command -v jq >/dev/null 2>&1; then
    echo -e "${YELLOW}[WARN] jq not installed — some analysis will be limited${PLAIN}"
  fi
  
  # Test kubectl connectivity
  if ! kubectl cluster-info >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Cannot connect to Kubernetes cluster${PLAIN}"
    exit 1
  fi
}

# Cache all data for performance (simplified)
cache_cluster_data() {
  log "INFO" "Caching cluster data for performance..."
  
  ALL_PODS_JSON=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  ALL_NAMESPACES=$(kubectl get ns --no-headers 2>/dev/null | awk '{print $1}' || echo "")
  ALL_NODES_JSON=$(kubectl get nodes -o json 2>/dev/null || echo '{"items":[]}')
  ALL_SERVICES_JSON=$(kubectl get svc --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  ALL_SECRETS_JSON=$(kubectl get secrets --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  
  log "INFO" "Data caching complete"
}

# Enhanced cluster information
cluster_info() {
  echo -e "${BOLD}${GREEN}=== CLUSTER INFORMATION ===${PLAIN}"
  
  # Kubernetes version
  echo -e "${BOLD}${GREEN}Cluster Version:${PLAIN}"
  kubectl version --short 2>/dev/null | grep -E 'Server Version|Client Version' || \
    echo -e "${RED}[ERROR] Unable to retrieve version information${PLAIN}"
  
  # Cluster info
  echo -e "\n${BOLD}${YELLOW}Cluster Details:${PLAIN}"
  kubectl cluster-info 2>/dev/null || \
    echo -e "${RED}[ERROR] Unable to retrieve cluster details${PLAIN}"
  
  # API server health
  echo -e "\n${BOLD}${YELLOW}API Server Health:${PLAIN}"
  if kubectl get --raw='/readyz?verbose' >/dev/null 2>&1; then
    echo -e "${GREEN}API server is ready${PLAIN}"
  else
    echo -e "${RED}[!] API server readiness check failed${PLAIN}"
  fi
  
  # Anonymous access test
  echo -e "\n${BOLD}${YELLOW}Anonymous Access Test:${PLAIN}"
  kubectl auth can-i --list --as=system:anonymous 2>/dev/null | head -3 || \
    echo -e "${GREEN}Anonymous access properly restricted${PLAIN}"
}

# Enhanced cluster objects inventory
cluster_objects() {
  echo -e "\n${BOLD}${BLUE}=== CLUSTER OBJECT INVENTORY ===${PLAIN}"
  
  declare -A resources=(
    [Deployments]=deployments
    [Pods]=pods
    [Services]=svc
    [Ingresses]=ingresses
    [StatefulSets]=statefulsets
    [DaemonSets]=daemonsets
    [ReplicaSets]=replicasets
    [Jobs]=jobs
    [CronJobs]=cronjobs
    [StorageClasses]=sc
    [HPAs]=hpa
    [PVCs]=pvc
    [PVs]=pv
    [NetworkPolicies]=networkpolicies
    [ServiceAccounts]=serviceaccounts
    [Secrets]=secrets
    [ConfigMaps]=configmaps
    [ClusterRoles]=clusterroles
    [ClusterRoleBindings]=clusterrolebindings
  )
  
  for label in "${!resources[@]}"; do
    if [[ "$NAMESPACE_FILTER" != "" ]]; then
      count=$(kubectl get "${resources[$label]}" -n "$NAMESPACE_FILTER" --no-headers 2>/dev/null | wc -l)
    else
      count=$(kubectl get "${resources[$label]}" --all-namespaces --no-headers 2>/dev/null | wc -l)
    fi
    printf "${BLUE}%-20s: ${GREEN}%s${PLAIN}\n" "$label" "$count"
  done
}

# Enhanced node analysis
cluster_nodes() {
  echo -e "\n${BOLD}${GREEN}=== CLUSTER NODES ANALYSIS ===${PLAIN}"
  
  # Node status
  echo -e "${BOLD}${GREEN}Node Status:${PLAIN}"
  kubectl get nodes -o wide 2>/dev/null || \
    echo -e "${RED}[ERROR] Unable to retrieve node information${PLAIN}"
  
  # Pod distribution
  echo -e "\n${BOLD}${YELLOW}Pod Distribution per Node:${PLAIN}"
  if [[ -n "$ALL_PODS_JSON" ]] && command -v jq >/dev/null 2>&1; then
    for node in $(echo "$ALL_NODES_JSON" | jq -r '.items[].metadata.name' 2>/dev/null); do
      count=$(echo "$ALL_PODS_JSON" | jq -r --arg node "$node" '.items[] | select(.spec.nodeName == $node) | .metadata.name' 2>/dev/null | wc -l)
      printf "${BLUE}%-30s: ${GREEN}%s pods${PLAIN}\n" "$node" "$count"
    done
  else
    kubectl get nodes --no-headers 2>/dev/null | while read node _; do
      count=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$node" --no-headers 2>/dev/null | wc -l)
      printf "${BLUE}%-30s: ${GREEN}%s pods${PLAIN}\n" "$node" "$count"
    done
  fi
  
  # Resource usage
  if [[ "$SKIP_METRICS" != true ]]; then
    echo -e "\n${BOLD}${YELLOW}Node Resource Usage:${PLAIN}"
    kubectl top nodes 2>/dev/null || \
      echo -e "${RED}[!] Metrics not available (metrics-server may not be running)${PLAIN}"
  fi
}

# Enhanced pod analysis
analyze_pods() {
  echo -e "\n${BOLD}${RED}=== POD HEALTH ANALYSIS ===${PLAIN}"
  
  # Non-healthy pods
  echo -e "${BOLD}${RED}Pods in Non-Healthy States:${PLAIN}"
  kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null || \
    echo -e "${GREEN}All pods are in healthy states${PLAIN}"
  
  # CrashLoopBackOff pods
  echo -e "\n${BOLD}${YELLOW}Pods in CrashLoopBackOff:${PLAIN}"
  kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep CrashLoopBackOff || \
    echo -e "${GREEN}No crash-looping pods found${PLAIN}"
  
  # High restart count pods
  echo -e "\n${BOLD}${YELLOW}Top Restarting Pods:${PLAIN}"
  kubectl get pods --all-namespaces --sort-by='.status.containerStatuses[0].restartCount' \
    -o custom-columns="NAMESPACE:.metadata.namespace,POD:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount" 2>/dev/null | \
    tail -n $MAX_RESULTS || echo -e "${YELLOW}Unable to retrieve restart information${PLAIN}"
  
  # OOMKilled containers
  if command -v jq >/dev/null 2>&1 && [[ -n "$ALL_PODS_JSON" ]]; then
    echo -e "\n${BOLD}${YELLOW}Recently OOMKilled Containers:${PLAIN}"
    oom_pods=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | select(.status.containerStatuses[]? | .state.terminated?.reason == "OOMKilled") | "\(.metadata.namespace)/\(.metadata.name)"')
    if [[ -n "$oom_pods" ]]; then
      echo "$oom_pods"
    else
      echo -e "${GREEN}No recently OOMKilled containers${PLAIN}"
    fi
  fi
}

# System services health check
system_services_health() {
  echo -e "\n${BOLD}${GREEN}=== SYSTEM COMPONENTS HEALTH ===${PLAIN}"
  
  # System deployments
  if [[ "$INCLUDE_SYSTEM_NS" == true ]]; then
    echo -e "${BOLD}${GREEN}System Deployments (kube-system):${PLAIN}"
    kubectl get deployments -n kube-system 2>/dev/null || \
      echo -e "${RED}[ERROR] Unable to access kube-system namespace${PLAIN}"
    
    # System pods status
    echo -e "\n${BOLD}${YELLOW}System Pods Status:${PLAIN}"
    kubectl get pods -n kube-system --no-headers 2>/dev/null | \
      awk '{printf "%-30s %s\n", $1, $3}' || \
      echo -e "${RED}[ERROR] Unable to retrieve system pod status${PLAIN}"
  fi
}

# Enhanced security context audit
security_contexts() {
  echo -e "\n${BOLD}${YELLOW}=== SECURITY CONTEXT AUDIT ===${PLAIN}"
  
  if command -v jq >/dev/null 2>&1 && [[ -n "$ALL_PODS_JSON" ]]; then
    # Privileged containers
    echo -e "${BOLD}${RED}Privileged Containers:${PLAIN}"
    privileged_containers=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | select(.spec.containers[]? | .securityContext?.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"')
    if [[ -n "$privileged_containers" ]]; then
      echo "$privileged_containers"
    else
      echo -e "${GREEN}No privileged containers found${PLAIN}"
    fi
    
    # Root containers
    echo -e "\n${BOLD}${YELLOW}Containers Running as Root (UID 0):${PLAIN}"
    root_containers=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | select(.spec.containers[]? | .securityContext?.runAsUser == 0) | "\(.metadata.namespace)/\(.metadata.name)"' | head -$MAX_RESULTS)
    if [[ -n "$root_containers" ]]; then
      echo "$root_containers"
    else
      echo -e "${GREEN}No containers explicitly running as root found${PLAIN}"
    fi
    
    # Host access
    echo -e "\n${BOLD}${RED}Pods with Host Access:${PLAIN}"
    host_access=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) | "\(.metadata.namespace)/\(.metadata.name) - Network:\(.spec.hostNetwork // false) PID:\(.spec.hostPID // false) IPC:\(.spec.hostIPC // false)"')
    if [[ -n "$host_access" ]]; then
      echo "$host_access"
    else
      echo -e "${GREEN}No pods with host access found${PLAIN}"
    fi
    
    # Containers without resource limits
    echo -e "\n${BOLD}${YELLOW}Containers without Resource Limits:${PLAIN}"
    no_limits=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | select(.spec.containers[] | .resources.limits == null) | "\(.metadata.namespace)/\(.metadata.name)"' | head -$MAX_RESULTS)
    if [[ -n "$no_limits" ]]; then
      echo "$no_limits"
    else
      echo -e "${GREEN}All containers have resource limits${PLAIN}"
    fi
  else
    echo -e "${YELLOW}jq required for detailed security context analysis${PLAIN}"
  fi
}

# Enhanced RBAC audit
rbac_audit() {
  echo -e "\n${BOLD}${RED}=== RBAC SECURITY AUDIT ===${PLAIN}"
  
  # Service accounts with cluster-admin
  echo -e "${BOLD}${RED}Service Accounts with cluster-admin:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    admin_sa=$(kubectl get clusterrolebindings -o json 2>/dev/null | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | select(.subjects[]? | .kind == "ServiceAccount") | .subjects[] | select(.kind == "ServiceAccount") | "\(.namespace // "cluster-wide")/\(.name)"')
    if [[ -n "$admin_sa" ]]; then
      echo "$admin_sa"
    else
      echo -e "${GREEN}No service accounts with cluster-admin found${PLAIN}"
    fi
  fi
  
  # Anonymous access check
  echo -e "\n${BOLD}${YELLOW}Anonymous User Role Bindings:${PLAIN}"
  kubectl get clusterrolebindings -o wide 2>/dev/null | grep anonymous || \
    echo -e "${GREEN}No anonymous user bindings found${PLAIN}"
  
  # Wildcard permissions
  echo -e "\n${BOLD}${RED}High-Privilege Roles:${PLAIN}"
  kubectl get clusterroles 2>/dev/null | grep -E "(admin|cluster-admin|edit)" | head -5 || \
    echo -e "${GREEN}No obvious high-privilege roles found${PLAIN}"
  
  # Default service account permissions
  echo -e "\n${BOLD}${YELLOW}Default Service Account Token Usage:${PLAIN}"
  default_sa_count=$(kubectl get pods --all-namespaces -o json 2>/dev/null | jq -r '.items[] | select(.spec.serviceAccountName == "default" or .spec.serviceAccountName == null) | .metadata.name' 2>/dev/null | wc -l)
  echo "Pods using default service account: $default_sa_count"
}

# Enhanced network security audit
network_security_audit() {
  echo -e "\n${BOLD}${YELLOW}=== NETWORK SECURITY AUDIT ===${PLAIN}"
  
  # Network policies
  echo -e "${BOLD}${YELLOW}Network Policy Coverage:${PLAIN}"
  policy_count=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)
  if [[ "$policy_count" -eq 0 ]]; then
    echo -e "${RED}No NetworkPolicies found - all pod-to-pod traffic allowed${PLAIN}"
  else
    echo -e "${GREEN}Found $policy_count NetworkPolicies${PLAIN}"
    kubectl get networkpolicies --all-namespaces 2>/dev/null | head -5
  fi
  
  # Exposed services
  echo -e "\n${BOLD}${RED}Externally Exposed Services:${PLAIN}"
  exposed_services=$(kubectl get svc --all-namespaces --no-headers 2>/dev/null | grep -E "(NodePort|LoadBalancer)")
  if [[ -n "$exposed_services" ]]; then
    echo "$exposed_services"
  else
    echo -e "${GREEN}No externally exposed services found${PLAIN}"
  fi
  
  # Ingress analysis
  echo -e "\n${BOLD}${YELLOW}Ingress Resources:${PLAIN}"
  ingress_count=$(kubectl get ingress --all-namespaces --no-headers 2>/dev/null | wc -l)
  if [[ "$ingress_count" -gt 0 ]]; then
    echo "Found $ingress_count ingress resources"
    kubectl get ingress --all-namespaces 2>/dev/null | head -5
  else
    echo -e "${GREEN}No ingress resources found${PLAIN}"
  fi
}

# Enhanced secrets audit
secrets_audit() {
  echo -e "\n${BOLD}${RED}=== SECRETS AND SENSITIVE DATA AUDIT ===${PLAIN}"
  
  # Secret count by type
  echo -e "${BOLD}${YELLOW}Secret Type Distribution:${PLAIN}"
  kubectl get secrets --all-namespaces --no-headers 2>/dev/null | \
    awk '{print $4}' | sort | uniq -c | \
    awk '{printf "%-40s: %s\n", $2, $1}' || \
    echo -e "${GREEN}No secrets found${PLAIN}"
  
  # Generic secrets
  echo -e "\n${BOLD}${YELLOW}Generic/Opaque Secrets (first 10):${PLAIN}"
  kubectl get secrets --all-namespaces --field-selector type=Opaque --no-headers 2>/dev/null | \
    head -$MAX_RESULTS || echo -e "${GREEN}No generic secrets found${PLAIN}"
  
  # Service account tokens
  echo -e "\n${BOLD}${YELLOW}Service Account Token Secrets:${PLAIN}"
  sa_token_count=$(kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/service-account-token --no-headers 2>/dev/null | wc -l)
  echo "Found $sa_token_count SA token secrets"
}

# Supply chain security audit
supply_chain_audit() {
  echo -e "\n${BOLD}${RED}=== SUPPLY CHAIN SECURITY AUDIT ===${PLAIN}"
  
  if command -v jq >/dev/null 2>&1 && [[ -n "$ALL_PODS_JSON" ]]; then
    # Images using latest tag
    echo -e "${BOLD}${YELLOW}Images using :latest tag:${PLAIN}"
    latest_images=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | .spec.containers[] | select(.image | test(":latest$")) | .image' | sort -u | head -$MAX_RESULTS)
    if [[ -n "$latest_images" ]]; then
      echo "$latest_images"
    else
      echo -e "${GREEN}No images using :latest tag${PLAIN}"
    fi
    
    # Third-party registries
    echo -e "\n${BOLD}${YELLOW}Non-standard Image Registries:${PLAIN}"
    third_party_images=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | .spec.containers[] | .image' | \
      grep -v -E "(gcr.io|k8s.gcr.io|registry.k8s.io|quay.io)" | \
      grep -v "^docker.io" | sort -u | head -$MAX_RESULTS)
    if [[ -n "$third_party_images" ]]; then
      echo "$third_party_images"
    else
      echo -e "${GREEN}All images from standard registries${PLAIN}"
    fi
    
    # Image summary
    echo -e "\n${BOLD}${YELLOW}Image Registry Summary:${PLAIN}"
    echo "$ALL_PODS_JSON" | jq -r '.items[] | .spec.containers[] | .image' | \
      sed 's|/.*||' | sort | uniq -c | sort -nr | head -5
  else
    echo -e "${YELLOW}jq required for supply chain analysis${PLAIN}"
  fi
}

# Resource usage analysis
resource_usage() {
  if [[ "$SKIP_METRICS" != true ]]; then
    echo -e "\n${BOLD}${YELLOW}=== RESOURCE CONSUMPTION ANALYSIS ===${PLAIN}"
    
    # Top resource consuming pods
    echo -e "${BOLD}${YELLOW}Top Memory Consumers:${PLAIN}"
    kubectl top pods --sort-by=memory --all-namespaces 2>/dev/null | head -$MAX_RESULTS || \
      echo -e "${RED}Memory metrics unavailable${PLAIN}"
    
    echo -e "\n${BOLD}${YELLOW}Top CPU Consumers:${PLAIN}"
    kubectl top pods --sort-by=cpu --all-namespaces 2>/dev/null | head -$MAX_RESULTS || \
      echo -e "${RED}CPU metrics unavailable${PLAIN}"
  fi
}

# Recent events analysis
events_analysis() {
  echo -e "\n${BOLD}${YELLOW}=== RECENT CLUSTER EVENTS ===${PLAIN}"
  
  # Warning events by namespace
  echo -e "${BOLD}${YELLOW}Recent Warning Events by Namespace:${PLAIN}"
  for ns in $(echo "$ALL_NAMESPACES" | head -5); do
    events=$(kubectl get events -n "$ns" --field-selector type=Warning --sort-by=.lastTimestamp 2>/dev/null | tail -3)
    if [[ -n "$events" && "$events" != *"No resources found"* ]]; then
      echo -e "${BLUE}Namespace: $ns${PLAIN}"
      echo "$events"
      echo ""
    fi
  done
}

# Generate summary
generate_summary() {
  echo -e "\n${BOLD}${GREEN}=== SECURITY AUDIT SUMMARY ===${PLAIN}"
  echo -e "Audit completed at: $(date)"
  echo -e "Cluster context: $(kubectl config current-context 2>/dev/null || echo 'Unknown')"
  echo -e "Script version: $SCRIPT_VERSION"
  
  if [[ -n "$ALL_PODS_JSON" ]] && command -v jq >/dev/null 2>&1; then
    total_pods=$(echo "$ALL_PODS_JSON" | jq -r '.items | length')
    running_pods=$(echo "$ALL_PODS_JSON" | jq -r '.items[] | select(.status.phase == "Running") | .metadata.name' | wc -l)
    echo -e "Total pods: $total_pods (Running: $running_pods)"
  fi
  
  if [[ -n "$ALL_NAMESPACES" ]]; then
    ns_count=$(echo "$ALL_NAMESPACES" | wc -w)
    echo -e "Total namespaces: $ns_count"
  fi
  
  echo -e "\n${BOLD}${YELLOW}Log file saved to: $LOG_FILE${PLAIN}"
}

# Main execution function
main() {
  echo -e "${BOLD}${GREEN}Kubernetes Cluster Security Diagnostics v${SCRIPT_VERSION}${PLAIN}"
  echo -e "${BOLD}${GREEN}=============================================${PLAIN}"
  echo -e "Timestamp: $(date)"
  echo -e "Cluster Context: $(kubectl config current-context 2>/dev/null || echo 'Unknown')"
  echo -e "Output Format: $OUTPUT_FORMAT"
  echo ""
  
  log "INFO" "Starting Kubernetes security audit"
  
  # Cache data for performance
  cache_cluster_data
  
  # Execute audit functions sequentially (reliable)
  cluster_info
  cluster_objects
  cluster_nodes
  analyze_pods
  system_services_health
  security_contexts
  rbac_audit
  network_security_audit
  secrets_audit
  supply_chain_audit
  resource_usage
  events_analysis
  generate_summary
  
  echo -e "\n${BOLD}${GREEN}=============================================${PLAIN}"
  echo -e "${BOLD}${GREEN}Security Diagnostics Complete${PLAIN}"
  log "INFO" "Kubernetes security audit completed"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  parse_args "$@"
  check_dependencies
  
  if [[ "$OUTPUT_FORMAT" == "console" ]]; then
    clear
  fi
  
  main
fi
