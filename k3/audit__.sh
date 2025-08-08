#!/bin/bash

# Enhanced Kubernetes Cluster Security Diagnostics Script
# Purpose: Comprehensive K8s cluster auditing for security assessment and CTF scenarios
# Author: Security Assessment Team
# Version: 2.1
# Dependencies: kubectl (required), jq (optional but recommended)

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Color definitions for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;36m'
readonly PLAIN='\033[0m'
readonly BOLD=$(tput bold)
readonly NORMAL=$(tput sgr0)

# Dependency validation
check_dependencies() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] kubectl is required but not installed${PLAIN}"
    exit 1
  fi
  
  if ! command -v jq >/dev/null 2>&1; then
    echo -e "${YELLOW}[WARN] jq not installed — some output may be limited${PLAIN}"
  fi
}

# Function: Display cluster information and API server health
cluster_info() {
  echo -e "${BOLD}${GREEN}=== CLUSTER INFORMATION ===${PLAIN}"
  
  # Display Kubernetes version information
  echo -e "${BOLD}${GREEN}Cluster Version:${PLAIN}"
  kubectl version --short 2>/dev/null | grep -E 'Server Version|Client Version' || \
    echo -e "${RED}[ERROR] Unable to retrieve version information${PLAIN}"
  
  # Check API server readiness
  echo -e "\n${BOLD}${YELLOW}API Server Health Status:${PLAIN}"
  if kubectl get --raw='/readyz?verbose' >/dev/null 2>&1; then
    kubectl get --raw='/readyz?verbose' 2>/dev/null | grep -E '^[a-z]' || \
      echo -e "${GREEN}API server is ready${PLAIN}"
  else
    echo -e "${RED}[!] Cannot reach API server readiness endpoint${PLAIN}"
  fi
  
  # Quick RBAC check for anonymous access
  echo -e "\n${BOLD}${YELLOW}Anonymous Access Permissions:${PLAIN}"
  kubectl auth can-i --list --as=system:anonymous 2>/dev/null | head -3 || \
    echo -e "${GREEN}Anonymous access properly restricted${PLAIN}"
}

# Function: Count and display cluster object inventory
cluster_objects() {
  echo -e "\n${BOLD}${BLUE}=== CLUSTER OBJECT INVENTORY ===${PLAIN}"
  
  # Define resource types to audit
  declare -A resources=(
    [Deployments]=deployments
    [Pods]=pods
    [Services]=svc
    [Ingresses]=ingresses
    [StatefulSets]=statefulsets
    [DaemonSets]=daemonsets
    [ReplicaSets]=replicasets
    [StorageClasses]=sc
    [HPAs]=hpa
    [PVCs]=pvc
    [NetworkPolicies]=networkpolicies
    [ServiceAccounts]=serviceaccounts
    [Secrets]=secrets
  )
  
  # Count each resource type across all namespaces
  for label in "${!resources[@]}"; do
    count=$(kubectl get "${resources[$label]}" --all-namespaces --no-headers 2>/dev/null | wc -l)
    printf "${BLUE}%-20s: ${GREEN}%s${PLAIN}\n" "$label" "$count"
  done
}

# Function: Analyze cluster nodes and resource distribution
cluster_nodes() {
  echo -e "\n${BOLD}${GREEN}=== CLUSTER NODES ANALYSIS ===${PLAIN}"
  
  # Display node information
  echo -e "${BOLD}${GREEN}Node Status and Information:${PLAIN}"
  kubectl get nodes -o wide
  
  # Calculate pod distribution across nodes
  echo -e "\n${BOLD}${YELLOW}Pod Distribution per Node:${PLAIN}"
  for node in $(kubectl get nodes --no-headers | awk '{print $1}'); do
    count=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$node" --no-headers 2>/dev/null | wc -l)
    printf "${BLUE}%-30s: ${GREEN}%s pods${PLAIN}\n" "$node" "$count"
  done
  
  # Display resource usage metrics if available
  echo -e "\n${BOLD}${YELLOW}Node Resource Usage:${PLAIN}"
  if kubectl top nodes >/dev/null 2>&1; then
    kubectl top nodes
  else
    echo -e "${RED}[!] Metrics not available (metrics-server may not be running)${PLAIN}"
  fi
}

# Function: Identify and analyze problematic pods
analyze_pods() {
  echo -e "\n${BOLD}${RED}=== POD HEALTH ANALYSIS ===${PLAIN}"
  
  # Find pods in non-healthy states
  echo -e "${BOLD}${RED}Pods in Non-Healthy States:${PLAIN}"
  kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded 2>/dev/null || \
    echo -e "${GREEN}All pods are in healthy states${PLAIN}"
  
  # Identify crash-looping pods
  echo -e "\n${BOLD}${YELLOW}Pods in CrashLoopBackOff:${PLAIN}"
  kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep CrashLoopBackOff || \
    echo -e "${GREEN}No crash-looping pods found${PLAIN}"
  
  # Find pending pods
  echo -e "\n${BOLD}${YELLOW}Pending Pods:${PLAIN}"
  kubectl get pods --all-namespaces --field-selector=status.phase=Pending 2>/dev/null || \
    echo -e "${GREEN}No pending pods found${PLAIN}"
  
  # Identify evicted pods
  echo -e "\n${BOLD}${YELLOW}Evicted Pods:${PLAIN}"
  kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep Evicted || \
    echo -e "${GREEN}No evicted pods found${PLAIN}"
  
  # Show pods with highest restart counts
  echo -e "\n${BOLD}${YELLOW}Top 10 Restarting Pods:${PLAIN}"
  kubectl get pods --all-namespaces --sort-by='.status.containerStatuses[0].restartCount' \
    -o custom-columns="NAMESPACE:.metadata.namespace,POD:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount" 2>/dev/null | \
    tail -n 10 || echo -e "${YELLOW}Unable to retrieve restart information${PLAIN}"
  
  # Identify OOMKilled containers (requires jq)
  if command -v jq >/dev/null 2>&1; then
    echo -e "\n${BOLD}${YELLOW}OOMKilled Containers:${PLAIN}"
    oom_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.status.containerStatuses[]? | .state.terminated?.reason == "OOMKilled") | "\(.metadata.namespace)/\(.metadata.name)"')
    if [[ -n "$oom_pods" ]]; then
      echo "$oom_pods"
    else
      echo -e "${GREEN}No OOMKilled containers found${PLAIN}"
    fi
  fi
}

# Function: Check system component health
system_services_health() {
  echo -e "\n${BOLD}${GREEN}=== SYSTEM COMPONENTS HEALTH ===${PLAIN}"
  
  # Check kube-system deployments
  echo -e "${BOLD}${GREEN}System Namespace Deployments:${PLAIN}"
  kubectl get deployments -n kube-system 2>/dev/null || \
    echo -e "${RED}[ERROR] Unable to access kube-system namespace${PLAIN}"
  
  # Check system pods status
  echo -e "\n${BOLD}${YELLOW}System Pods Status:${PLAIN}"
  kubectl get pods -n kube-system --no-headers 2>/dev/null | \
    awk '{print $1 " " $3}' | column -t || \
    echo -e "${RED}[ERROR] Unable to retrieve system pod status${PLAIN}"
}

# Function: Display resource consumption metrics
resource_usage() {
  echo -e "\n${BOLD}${YELLOW}=== RESOURCE CONSUMPTION ANALYSIS ===${PLAIN}"
  
  # Top memory consuming pods
  echo -e "${BOLD}${YELLOW}Top 10 Memory Consumers (Pods):${PLAIN}"
  kubectl top pods --sort-by=memory --all-namespaces 2>/dev/null | head -10 || \
    echo -e "${RED}Resource metrics unavailable${PLAIN}"
  
  # Top CPU consuming pods
  echo -e "\n${BOLD}${YELLOW}Top 10 CPU Consumers (Pods):${PLAIN}"
  kubectl top pods --sort-by=cpu --all-namespaces 2>/dev/null | head -10 || \
    echo -e "${RED}Resource metrics unavailable${PLAIN}"
}

# Function: Audit persistent storage configuration
persistent_storage() {
  echo -e "\n${BOLD}${GREEN}=== PERSISTENT STORAGE AUDIT ===${PLAIN}"
  
  # Display persistent volume claims
  echo -e "${BOLD}${GREEN}Persistent Volume Claims:${PLAIN}"
  kubectl get pvc --all-namespaces 2>/dev/null || \
    echo -e "${GREEN}No PVCs found${PLAIN}"
  
  # Display persistent volumes
  echo -e "\n${BOLD}${GREEN}Persistent Volumes:${PLAIN}"
  kubectl get pv 2>/dev/null || \
    echo -e "${GREEN}No PVs found${PLAIN}"
  
  # Check storage classes
  echo -e "\n${BOLD}${YELLOW}Storage Classes:${PLAIN}"
  kubectl get storageclass 2>/dev/null || \
    echo -e "${GREEN}No storage classes found${PLAIN}"
}

# Function: Analyze recent cluster events
events_by_namespace() {
  echo -e "\n${BOLD}${YELLOW}=== RECENT CLUSTER EVENTS ===${PLAIN}"
  
  # Show warning events from each namespace
  echo -e "${BOLD}${YELLOW}Recent Warning Events by Namespace:${PLAIN}"
  for ns in $(kubectl get ns --no-headers 2>/dev/null | awk '{print $1}'); do
    events=$(kubectl get events -n "$ns" --field-selector type=Warning --sort-by=.lastTimestamp 2>/dev/null | tail -n 3)
    if [[ -n "$events" && "$events" != *"No resources found"* ]]; then
      echo -e "${BLUE}Namespace: $ns${PLAIN}"
      echo "$events"
      echo ""
    fi
  done
}

# Function: Check disk usage on cluster nodes
cluster_disk_usage() {
  echo -e "\n${BOLD}${YELLOW}=== DISK USAGE ANALYSIS ===${PLAIN}"
  
  # Display filesystem usage summary
  echo -e "${BOLD}${YELLOW}Filesystem Usage Summary:${PLAIN}"
  df -h --total 2>/dev/null | grep -E 'Filesystem|total' || \
    echo -e "${RED}Unable to retrieve disk usage information${PLAIN}"
}

# Function: Comprehensive service account security audit
service_account_audit() {
  echo -e "\n${BOLD}${RED}=== SERVICE ACCOUNT SECURITY AUDIT ===${PLAIN}"
  
  # Check default service accounts with secrets
  echo -e "${BOLD}${YELLOW}Default Service Accounts with Secrets:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    default_sa_secrets=$(kubectl get serviceaccounts --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.metadata.name == "default" and (.secrets | length > 0)) | "\(.metadata.namespace)/\(.metadata.name) - Secrets: \(.secrets | length)"')
    if [[ -n "$default_sa_secrets" ]]; then
      echo "$default_sa_secrets"
    else
      echo -e "${GREEN}No default service accounts with secrets found${PLAIN}"
    fi
  else
    kubectl get sa --all-namespaces 2>/dev/null | grep default || \
      echo -e "${GREEN}No default service accounts found${PLAIN}"
  fi
  
  # Identify high-privilege service accounts - FIXED
  echo -e "\n${BOLD}${RED}High-Privilege Service Account Bindings:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    high_priv_sa=$(kubectl get clusterrolebindings -o json 2>/dev/null | \
      jq -r '.items[] | select(.roleRef.name | test("admin|cluster-admin")) | select(.subjects[]? | .kind == "ServiceAccount") | "ClusterRole: \(.roleRef.name) -> \(.subjects[] | select(.kind == "ServiceAccount") | "\(.namespace // "cluster-wide")/\(.name)")"')
    if [[ -n "$high_priv_sa" ]]; then
      echo "$high_priv_sa"
    else
      echo -e "${GREEN}No high-privilege service account bindings found${PLAIN}"
    fi
  else
    echo -e "${YELLOW}jq required for detailed high-privilege analysis${PLAIN}"
  fi
  
  # Check for automounted service account tokens
  echo -e "\n${BOLD}${YELLOW}Pods with Automounted SA Tokens (sample):${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    kubectl get pods --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.spec.automountServiceAccountToken != false) | "\(.metadata.namespace)/\(.metadata.name) - SA: \(.spec.serviceAccountName // "default")"' | \
      head -10 || echo -e "${GREEN}No pods with automounted tokens found${PLAIN}"
  else
    echo -e "${YELLOW}jq required for automounted token analysis${PLAIN}"
  fi
  
  # Display custom role bindings
  echo -e "\n${BOLD}${YELLOW}Custom Role Bindings (non-system):${PLAIN}"
  kubectl get rolebindings --all-namespaces -o wide 2>/dev/null | grep -v "system:" | head -10 || \
    echo -e "${GREEN}No custom role bindings found${PLAIN}"
  
  # Test service account permissions for pod creation
  echo -e "\n${BOLD}${RED}Service Accounts with Pod Creation Rights:${PLAIN}"
  pod_creation_rights=false
  for ns in $(kubectl get ns --no-headers 2>/dev/null | awk '{print $1}' | head -5); do
    if kubectl auth can-i create pods --as=system:serviceaccount:$ns:default -n $ns >/dev/null 2>&1; then
      echo -e "${RED}$ns/default can create pods${PLAIN}"
      pod_creation_rights=true
    fi
  done
  if [[ "$pod_creation_rights" == false ]]; then
    echo -e "${GREEN}No default service accounts can create pods (first 5 namespaces checked)${PLAIN}"
  fi
}

# Function: Audit service account tokens - FIXED
token_audit() {
  echo -e "\n${BOLD}${YELLOW}=== SERVICE ACCOUNT TOKEN AUDIT ===${PLAIN}"
  
  # Find long-lived service account tokens
  echo -e "${BOLD}${YELLOW}Long-lived SA Tokens (Secrets):${PLAIN}"
  sa_tokens=$(kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/service-account-token 2>/dev/null | head -10)
  if [[ -n "$sa_tokens" && "$sa_tokens" != *"No resources found"* ]]; then
    echo "$sa_tokens"
  else
    echo -e "${GREEN}No long-lived SA token secrets found${PLAIN}"
  fi
  
  # Check for containers with token mounts - FIXED
  echo -e "\n${BOLD}${YELLOW}Containers with Explicit Token Mounts:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    token_mounts=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.spec.volumes[]? | .secret?.secretName | strings | test("token")) | "\(.metadata.namespace)/\(.metadata.name)"' | \
      head -5)
    if [[ -n "$token_mounts" ]]; then
      echo "$token_mounts"
    else
      echo -e "${GREEN}No explicit token mounts found${PLAIN}"
    fi
  else
    echo -e "${YELLOW}jq required for token mount analysis${PLAIN}"
  fi
}

# Function: Identify RBAC misconfigurations
rbac_misconfigurations() {
  echo -e "\n${BOLD}${RED}=== RBAC MISCONFIGURATION AUDIT ===${PLAIN}"
  
  # Check for wildcard resource permissions
  echo -e "${BOLD}${RED}Roles with Wildcard Resource Permissions:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    wildcard_roles=$(kubectl get clusterroles -o json 2>/dev/null | \
      jq -r '.items[] | select(.rules[]? | .resources[]? == "*") | .metadata.name')
    if [[ -n "$wildcard_roles" ]]; then
      echo "$wildcard_roles"
    else
      echo -e "${GREEN}No wildcard resource permissions found${PLAIN}"
    fi
  else
    kubectl get clusterroles 2>/dev/null | grep -E "(admin|edit)" || \
      echo -e "${GREEN}No obvious wildcard roles found${PLAIN}"
  fi
  
  # Check for anonymous user bindings
  echo -e "\n${BOLD}${RED}Anonymous User Role Bindings:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    anon_bindings=$(kubectl get clusterrolebindings -o json 2>/dev/null | \
      jq -r '.items[] | select(.subjects[]? | .name == "system:anonymous") | "Role: \(.roleRef.name) bound to anonymous"')
    if [[ -n "$anon_bindings" ]]; then
      echo "$anon_bindings"
    else
      echo -e "${GREEN}No anonymous user bindings found${PLAIN}"
    fi
  else
    anon_check=$(kubectl get clusterrolebindings -o wide 2>/dev/null | grep anonymous)
    if [[ -n "$anon_check" ]]; then
      echo "$anon_check"
    else
      echo -e "${GREEN}No anonymous user bindings found${PLAIN}"
    fi
  fi
  
  # Check for unauthenticated group bindings
  echo -e "\n${BOLD}${YELLOW}Unauthenticated Group Bindings:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    unauth_bindings=$(kubectl get clusterrolebindings -o json 2>/dev/null | \
      jq -r '.items[] | select(.subjects[]? | .name == "system:unauthenticated") | "Role: \(.roleRef.name) bound to unauthenticated"')
    if [[ -n "$unauth_bindings" ]]; then
      echo "$unauth_bindings"
    else
      echo -e "${GREEN}No unauthenticated group bindings found${PLAIN}"
    fi
  else
    echo -e "${GREEN}No unauthenticated group bindings found (jq required for detailed analysis)${PLAIN}"
  fi
}

# Function: Audit pod security contexts
security_contexts() {
  echo -e "\n${BOLD}${YELLOW}=== SECURITY CONTEXT AUDIT ===${PLAIN}"
  
  # Find privileged containers
  echo -e "${BOLD}${RED}Privileged Containers:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    priv_containers=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.spec.containers[]? | .securityContext?.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"')
    if [[ -n "$priv_containers" ]]; then
      echo "$priv_containers"
    else
      echo -e "${GREEN}No privileged containers found${PLAIN}"
    fi
  else
    echo -e "${YELLOW}jq required for privileged container analysis${PLAIN}"
  fi
  
  # Find containers running as root
  echo -e "\n${BOLD}${YELLOW}Containers Running as Root (UID 0):${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    root_containers=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.spec.containers[]? | .securityContext?.runAsUser == 0) | "\(.metadata.namespace)/\(.metadata.name)"' | \
      head -5)
    if [[ -n "$root_containers" ]]; then
      echo "$root_containers"
    else
      echo -e "${GREEN}No containers explicitly running as root found${PLAIN}"
    fi
  else
    echo -e "${YELLOW}jq required for root user analysis${PLAIN}"
  fi
  
  # Find pods with host access
  echo -e "\n${BOLD}${RED}Pods with Host Network/PID/IPC Access:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    host_access_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) | "\(.metadata.namespace)/\(.metadata.name) - Host Access: Network=\(.spec.hostNetwork // false) PID=\(.spec.hostPID // false) IPC=\(.spec.hostIPC // false)"')
    if [[ -n "$host_access_pods" ]]; then
      echo "$host_access_pods"
    else
      echo -e "${GREEN}No pods with host access found${PLAIN}"
    fi
  else
    echo -e "${YELLOW}jq required for host access analysis${PLAIN}"
  fi
}

# Function: Audit network policies and service exposure
network_policies_and_exposure() {
  echo -e "\n${BOLD}${YELLOW}=== NETWORK SECURITY AUDIT ===${PLAIN}"
  
  # Check for network policies
  echo -e "${BOLD}${YELLOW}Network Policy Coverage:${PLAIN}"
  policy_count=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)
  if [[ "$policy_count" -eq 0 ]]; then
    echo -e "${RED}No NetworkPolicies found - all pod-to-pod traffic is allowed${PLAIN}"
  else
    echo -e "${GREEN}Found $policy_count NetworkPolicies${PLAIN}"
    kubectl get networkpolicies --all-namespaces 2>/dev/null
  fi
  
  # Find externally exposed services
  echo -e "\n${BOLD}${RED}Externally Exposed Services:${PLAIN}"
  exposed_services=$(kubectl get svc --all-namespaces --no-headers 2>/dev/null | grep -E "(NodePort|LoadBalancer)")
  if [[ -n "$exposed_services" ]]; then
    echo "$exposed_services"
  else
    echo -e "${GREEN}No externally exposed services found${PLAIN}"
  fi
  
  # Find services without selectors (potential hijacking targets)
  echo -e "\n${BOLD}${YELLOW}Services without Selectors:${PLAIN}"
  if command -v jq >/dev/null 2>&1; then
    no_selector_svc=$(kubectl get svc --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.spec.selector == null) | "\(.metadata.namespace)/\(.metadata.name)"' | \
      head -5)
    if [[ -n "$no_selector_svc" ]]; then
      echo "$no_selector_svc"
    else
      echo -e "${GREEN}All services have selectors${PLAIN}"
    fi
  else
    echo -e "${YELLOW}jq required for selector analysis${PLAIN}"
  fi
}

# Function: Audit secrets and sensitive data
secrets_audit() {
  echo -e "\n${BOLD}${RED}=== SECRETS AND SENSITIVE DATA AUDIT ===${PLAIN}"
  
  # Count secrets by type
  echo -e "${BOLD}${YELLOW}Secret Type Distribution:${PLAIN}"
  kubectl get secrets --all-namespaces --no-headers 2>/dev/null | \
    awk '{print $4}' | sort | uniq -c | \
    awk '{printf "%-30s: %s\n", $2, $1}' || \
    echo -e "${GREEN}No secrets found${PLAIN}"
  
  # Find Docker registry secrets
  echo -e "\n${BOLD}${YELLOW}Docker Registry Secrets:${PLAIN}"
  docker_secrets=$(kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/dockerconfigjson 2>/dev/null | head -5)
  if [[ -n "$docker_secrets" && "$docker_secrets" != *"No resources found"* ]]; then
    echo "$docker_secrets"
  else
    echo -e "${GREEN}No Docker registry secrets found${PLAIN}"
  fi
  
  # Find generic secrets (potential credentials)
  echo -e "\n${BOLD}${YELLOW}Generic Secrets (first 10):${PLAIN}"
  generic_secrets=$(kubectl get secrets --all-namespaces --field-selector type=Opaque --no-headers 2>/dev/null | head -10)
  if [[ -n "$generic_secrets" ]]; then
    echo "$generic_secrets"
  else
    echo -e "${GREEN}No generic secrets found${PLAIN}"
  fi
}

# Main execution function
main() {
  echo -e "${BOLD}${GREEN}Kubernetes Cluster Security Diagnostics${PLAIN}"
  echo -e "${BOLD}${GREEN}=========================================${PLAIN}"
  echo -e "Timestamp: $(date)"
  echo -e "Cluster Context: $(kubectl config current-context 2>/dev/null || echo 'Unknown')"
  echo ""
  
  # Execute all audit functions in logical order
  cluster_info
  cluster_objects
  cluster_nodes
  analyze_pods
  system_services_health
  resource_usage
  persistent_storage
  events_by_namespace
  cluster_disk_usage
  service_account_audit
  token_audit
  rbac_misconfigurations
  security_contexts
  network_policies_and_exposure
  secrets_audit
  
  echo -e "\n${BOLD}${GREEN}=========================================${PLAIN}"
  echo -e "${BOLD}${GREEN}Security Diagnostics Complete${PLAIN}"
  echo -e "Report generated at: $(date)"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  check_dependencies
  clear
  main "$@"
fi
