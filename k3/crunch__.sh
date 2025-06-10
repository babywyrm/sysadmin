#!/bin/bash

# Enhanced Kubernetes Cluster Diagnostics Script, (Updated, 2025) 
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

# Dependencies check
if ! command -v jq >/dev/null; then
  echo -e "${RED}[WARN] jq not installed — some output may be limited${PLAIN}"
fi

### --- Functions ---

cluster_info() {
  echo -e "${BOLD}${GREEN}Cluster Info:${PLAIN}"
  kubectl version --short | grep -E 'Server Version|Client Version'
  echo -e "\n${BOLD}${YELLOW}API Server Health:${PLAIN}"
  kubectl get --raw='/readyz?verbose' 2>/dev/null | grep -E '^[a-z]' || echo -e "${RED}  [!] Cannot reach API server readiness endpoint${PLAIN}"
}

cluster_objects() {
  echo -e "\n${BLUE}Collecting Cluster Object Counts:${PLAIN}"
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
  )
  for label in "${!resources[@]}"; do
    count=$(kubectl get "${resources[$label]}" --all-namespaces --no-headers 2>/dev/null | wc -l)
    echo -e "${BLUE}$label: ${GREEN}$count"
  done
}

cluster_nodes() {
  echo -e "\n${BOLD}${GREEN}Cluster Nodes:${PLAIN}"
  kubectl get nodes -o wide

  echo -e "\n${BOLD}${YELLOW}Pods per Node:${PLAIN}"
  for node in $(kubectl get nodes --no-headers | awk '{print $1}'); do
    count=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$node" --no-headers 2>/dev/null | wc -l)
    echo -e "${BLUE}$node: ${GREEN}${count} pods"
  done

  echo -e "\n${BOLD}${YELLOW}Node Resource Usage:${PLAIN}"
  if kubectl top nodes &>/dev/null; then
    kubectl top nodes
  else
    echo -e "${RED}  [!] Metrics not available (is metrics-server running?)${PLAIN}"
  fi
}

analyze_pods() {
  echo -e "\n${BOLD}${RED}Pods in Non-Healthy States:${PLAIN}"
  kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded

  echo -e "\n${BOLD}${YELLOW}Pods in CrashLoopBackOff:${PLAIN}"
  kubectl get pods --all-namespaces --no-headers | grep CrashLoopBackOff || echo -e "${GREEN}None"

  echo -e "\n${BOLD}${YELLOW}Pending Pods:${PLAIN}"
  kubectl get pods --all-namespaces --field-selector=status.phase=Pending || echo -e "${GREEN}None"

  echo -e "\n${BOLD}${YELLOW}Evicted Pods:${PLAIN}"
  kubectl get pods --all-namespaces --no-headers | grep Evicted || echo -e "${GREEN}None"

  echo -e "\n${BOLD}${YELLOW}Top Restarting Pods:${PLAIN}"
  kubectl get pods --all-namespaces --sort-by='.status.containerStatuses[0].restartCount' \
    -o custom-columns="NAMESPACE:.metadata.namespace,POD:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount" | tail -n 10

  if command -v jq >/dev/null; then
    echo -e "\n${BOLD}${YELLOW}OOMKilled Containers (from pod JSON):${PLAIN}"
    kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.status.containerStatuses[]? | .state.terminated?.reason == "OOMKilled") | "\(.metadata.namespace)/\(.metadata.name)"'
  fi
}

system_services_health() {
  echo -e "\n${BOLD}${GREEN}System Namespace Component Status:${PLAIN}"
  kubectl get deployments -n kube-system
}

resource_usage() {
  echo -e "\n${BOLD}${YELLOW}Top Memory Consumers (Pods):${PLAIN}"
  kubectl top pods --sort-by=memory --all-namespaces | head -10 || echo -e "${RED}Unavailable"

  echo -e "\n${BOLD}${YELLOW}Top CPU Consumers (Pods):${PLAIN}"
  kubectl top pods --sort-by=cpu --all-namespaces | head -10 || echo -e "${RED}Unavailable"
}

persistent_storage() {
  echo -e "\n${BOLD}${GREEN}Persistent Volumes and Claims:${PLAIN}"
  kubectl get pvc --all-namespaces
  kubectl get pv
}

events_by_namespace() {
  echo -e "\n${BOLD}${YELLOW}Recent Events (warnings only):${PLAIN}"
  for ns in $(kubectl get ns --no-headers | awk '{print $1}'); do
    echo -e "${BLUE}Namespace: $ns${PLAIN}"
    kubectl get events -n "$ns" --field-selector type=Warning --sort-by=.lastTimestamp | tail -n 5
  done
}

cluster_disk_usage() {
  echo -e "\n${BOLD}${YELLOW}Disk Usage on Cluster Nodes:${PLAIN}"
  df -h --total | grep -E 'Filesystem|total'
}

### --- Run Everything ---

clear
cluster_info
cluster_objects
cluster_nodes
analyze_pods
system_services_health
resource_usage
persistent_storage
events_by_namespace
cluster_disk_usage

echo -e "\n${GREEN}✅ Diagnostics Complete${PLAIN}"
