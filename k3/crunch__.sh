#!/bin/bash

# Enhanced Kubernetes Cluster Diagnostics Script (2026 Edition)
# Supports k3s, standard k8s, and modern observability tools

set -euo pipefail

# Colors & Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
MAGENTA='\033[0;35m'
PLAIN='\033[0m'
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

# Configuration
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./k8s-diagnostics-$(date +%Y%m%d-%H%M%S)}"
VERBOSE="${VERBOSE:-false}"

# Dependency checks
check_dependencies() {
  local missing=()
  for cmd in kubectl jq yq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${YELLOW}[WARN] Missing tools: ${missing[*]}${PLAIN}"
    echo -e "${YELLOW}       Some features will be limited${PLAIN}"
  fi
}

# Detect k3s vs standard k8s
detect_distribution() {
  if kubectl get nodes -o json 2>/dev/null | jq -e '.items[0].status.nodeInfo.osImage | contains("k3s")' >/dev/null 2>&1; then
    echo "k3s"
  else
    echo "kubernetes"
  fi
}

### --- Core Functions ---

cluster_info() {
  echo -e "\n${BOLD}${GREEN}=== Cluster Information ===${PLAIN}"
  
  # Version info
  echo -e "${BLUE}Version:${PLAIN}"
  kubectl version --output=json 2>/dev/null | jq -r '
    "Client: \(.clientVersion.gitVersion)",
    "Server: \(.serverVersion.gitVersion)"
  ' || kubectl version --short
  
  # Distribution
  DISTRO=$(detect_distribution)
  echo -e "${BLUE}Distribution: ${GREEN}${DISTRO}${PLAIN}"
  
  # Context
  CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "none")
  echo -e "${BLUE}Context: ${GREEN}${CURRENT_CONTEXT}${PLAIN}"
  
  # API Health
  echo -e "\n${BOLD}${YELLOW}API Server Health:${PLAIN}"
  if kubectl get --raw='/readyz?verbose' 2>/dev/null; then
    echo -e "${GREEN}✓ API server ready${PLAIN}"
  else
    echo -e "${RED}✗ Cannot reach API server${PLAIN}"
  fi
  
  # Control plane components
  echo -e "\n${BOLD}${YELLOW}Control Plane Components:${PLAIN}"
  kubectl get componentstatuses 2>/dev/null || \
    echo -e "${YELLOW}[INFO] ComponentStatus API deprecated in 1.19+${PLAIN}"
}

cluster_objects() {
  echo -e "\n${BOLD}${GREEN}=== Cluster Resources ===${PLAIN}"
  
  declare -A resources=(
    [Namespaces]=namespaces
    [Nodes]=nodes
    [Deployments]=deployments
    [StatefulSets]=statefulsets
    [DaemonSets]=daemonsets
    [Pods]=pods
    [Services]=svc
    [Ingresses]=ingresses
    [ConfigMaps]=configmaps
    [Secrets]=secrets
    [PVCs]=pvc
    [PVs]=pv
    [StorageClasses]=sc
    [HPAs]=hpa
    [NetworkPolicies]=networkpolicies
    [ServiceAccounts]=sa
    [Roles]=roles
    [ClusterRoles]=clusterroles
    [CRDs]=crds
  )
  
  printf "%-20s %s\n" "Resource" "Count"
  printf "%-20s %s\n" "--------" "-----"
  
  for label in "${!resources[@]}"; do
    count=$(kubectl get "${resources[$label]}" --all-namespaces \
      --no-headers 2>/dev/null | wc -l || echo "0")
    printf "${BLUE}%-20s${PLAIN} ${GREEN}%s${PLAIN}\n" "$label" "$count"
  done
}

cluster_nodes() {
  echo -e "\n${BOLD}${GREEN}=== Node Information ===${PLAIN}"
  
  kubectl get nodes -o wide
  
  echo -e "\n${BOLD}${YELLOW}Node Roles & Taints:${PLAIN}"
  kubectl get nodes -o json | jq -r '.items[] | 
    "\(.metadata.name) | Roles: \(
      [.metadata.labels | to_entries[] | 
       select(.key | startswith("node-role.kubernetes.io/")) | 
       .key | split("/")[1]] | join(",")
    ) | Taints: \([.spec.taints[]? | .key] | join(","))"'
  
  echo -e "\n${BOLD}${YELLOW}Pods per Node:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    [.items[] | .spec.nodeName] | 
    group_by(.) | 
    map({node: .[0], count: length}) | 
    .[] | "\(.node): \(.count) pods"
  '
  
  echo -e "\n${BOLD}${YELLOW}Node Capacity & Allocatable:${PLAIN}"
  kubectl get nodes -o json | jq -r '.items[] | 
    "\(.metadata.name):",
    "  CPU: \(.status.allocatable.cpu) / \(.status.capacity.cpu)",
    "  Memory: \(.status.allocatable.memory) / \(.status.capacity.memory)",
    "  Pods: \(.status.allocatable.pods) / \(.status.capacity.pods)"
  '
  
  echo -e "\n${BOLD}${YELLOW}Node Resource Usage:${PLAIN}"
  if kubectl top nodes &>/dev/null; then
    kubectl top nodes
  else
    echo -e "${RED}[!] Metrics unavailable (metrics-server not running?)${PLAIN}"
  fi
}

analyze_pods() {
  echo -e "\n${BOLD}${GREEN}=== Pod Analysis ===${PLAIN}"
  
  # Pod phase summary
  echo -e "${BOLD}${YELLOW}Pod Phase Summary:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    [.items[] | .status.phase] | 
    group_by(.) | 
    map({phase: .[0], count: length}) | 
    .[] | "\(.phase): \(.count)"
  '
  
  # Non-healthy pods
  echo -e "\n${BOLD}${RED}Pods in Non-Healthy States:${PLAIN}"
  kubectl get pods --all-namespaces \
    --field-selector=status.phase!=Running,status.phase!=Succeeded \
    -o wide 2>/dev/null || echo -e "${GREEN}None${PLAIN}"
  
  # Specific problem states
  echo -e "\n${BOLD}${YELLOW}CrashLoopBackOff Pods:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.status.containerStatuses[]? | 
      .state.waiting?.reason == "CrashLoopBackOff") | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' || echo -e "${GREEN}None${PLAIN}"
  
  echo -e "\n${BOLD}${YELLOW}ImagePullBackOff Pods:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.status.containerStatuses[]? | 
      .state.waiting?.reason == "ImagePullBackOff") | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' || echo -e "${GREEN}None${PLAIN}"
  
  echo -e "\n${BOLD}${YELLOW}Pending Pods:${PLAIN}"
  kubectl get pods --all-namespaces \
    --field-selector=status.phase=Pending \
    -o wide || echo -e "${GREEN}None${PLAIN}"
  
  echo -e "\n${BOLD}${YELLOW}Evicted Pods:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.status.reason == "Evicted") | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' || echo -e "${GREEN}None${PLAIN}"
  
  # High restart counts
  echo -e "\n${BOLD}${YELLOW}Top 10 Restarting Pods:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    {
      namespace: .metadata.namespace, 
      name: .metadata.name, 
      restarts: ([.status.containerStatuses[]?.restartCount] | add // 0)
    } | 
    select(.restarts > 0)
  ' | jq -s 'sort_by(.restarts) | reverse | .[0:10][] | 
    "\(.namespace)/\(.name): \(.restarts) restarts"'
  
  # OOMKilled containers
  echo -e "\n${BOLD}${RED}OOMKilled Containers:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.status.containerStatuses[]? | 
      .lastState.terminated?.reason == "OOMKilled") | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' || echo -e "${GREEN}None${PLAIN}"
  
  # Pods without resource limits
  echo -e "\n${BOLD}${YELLOW}Pods Without Resource Limits:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.spec.containers[] | 
      .resources.limits == null or 
      .resources.limits == {}) | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' | head -10
}

system_services_health() {
  echo -e "\n${BOLD}${GREEN}=== System Components ===${PLAIN}"
  
  # Common system namespaces
  for ns in kube-system kube-public kube-node-lease; do
    if kubectl get namespace "$ns" &>/dev/null; then
      echo -e "\n${BLUE}Namespace: $ns${PLAIN}"
      kubectl get deployments,daemonsets,statefulsets -n "$ns" 2>/dev/null || true
    fi
  done
  
  # Check for cert-manager, ingress controllers, etc.
  echo -e "\n${BOLD}${YELLOW}Common Add-ons Detected:${PLAIN}"
  declare -A addons=(
    [cert-manager]=cert-manager
    [ingress-nginx]=ingress-nginx
    [metrics-server]=kube-system
    [prometheus]=monitoring
    [linkerd]=linkerd
    [istio]=istio-system
  )
  
  for addon in "${!addons[@]}"; do
    ns="${addons[$addon]}"
    if kubectl get namespace "$ns" &>/dev/null; then
      count=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
      echo -e "${GREEN}✓${PLAIN} $addon (ns: $ns, pods: $count)"
    fi
  done
}

resource_usage() {
  echo -e "\n${BOLD}${GREEN}=== Resource Usage ===${PLAIN}"
  
  if ! kubectl top pods &>/dev/null; then
    echo -e "${RED}[!] Metrics unavailable - skipping resource usage${PLAIN}"
    return
  fi
  
  echo -e "\n${BOLD}${YELLOW}Top 10 Memory Consumers:${PLAIN}"
  kubectl top pods --all-namespaces --sort-by=memory | head -11
  
  echo -e "\n${BOLD}${YELLOW}Top 10 CPU Consumers:${PLAIN}"
  kubectl top pods --all-namespaces --sort-by=cpu | head -11
  
  echo -e "\n${BOLD}${YELLOW}Namespace Resource Usage:${PLAIN}"
  for ns in $(kubectl get ns --no-headers | awk '{print $1}'); do
    kubectl top pods -n "$ns" --no-headers 2>/dev/null | \
      awk -v ns="$ns" '
        {cpu+=$2; mem+=$3} 
        END {if(NR>0) printf "%-30s CPU: %s, Memory: %s\n", ns, cpu, mem}
      '
  done
}

persistent_storage() {
  echo -e "\n${BOLD}${GREEN}=== Persistent Storage ===${PLAIN}"
  
  echo -e "${BLUE}Persistent Volume Claims:${PLAIN}"
  kubectl get pvc --all-namespaces
  
  echo -e "\n${BLUE}Persistent Volumes:${PLAIN}"
  kubectl get pv
  
  echo -e "\n${BLUE}Storage Classes:${PLAIN}"
  kubectl get sc
  
  # Unbound PVCs
  echo -e "\n${BOLD}${YELLOW}Unbound PVCs:${PLAIN}"
  kubectl get pvc --all-namespaces -o json | jq -r '
    .items[] | 
    select(.status.phase != "Bound") | 
    "\(.metadata.namespace)/\(.metadata.name): \(.status.phase)"
  ' || echo -e "${GREEN}None${PLAIN}"
}

network_analysis() {
  echo -e "\n${BOLD}${GREEN}=== Network Analysis ===${PLAIN}"
  
  echo -e "${BLUE}Services (ClusterIP, NodePort, LoadBalancer):${PLAIN}"
  kubectl get svc --all-namespaces -o json | jq -r '
    [.items[] | {type: .spec.type}] | 
    group_by(.type) | 
    map({type: .[0].type, count: length}) | 
    .[] | "\(.type): \(.count)"
  '
  
  echo -e "\n${BLUE}Ingress Resources:${PLAIN}"
  kubectl get ingress --all-namespaces
  
  echo -e "\n${BLUE}NetworkPolicies:${PLAIN}"
  kubectl get networkpolicies --all-namespaces
  
  # Services without endpoints
  echo -e "\n${BOLD}${YELLOW}Services Without Endpoints:${PLAIN}"
  kubectl get endpoints --all-namespaces -o json | jq -r '
    .items[] | 
    select(.subsets == null or .subsets == []) | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' || echo -e "${GREEN}None${PLAIN}"
}

security_analysis() {
  echo -e "\n${BOLD}${GREEN}=== Security Analysis ===${PLAIN}"
  
  # Privileged pods
  echo -e "${BOLD}${RED}Privileged Pods:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.spec.containers[]? | .securityContext?.privileged == true) | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' || echo -e "${GREEN}None${PLAIN}"
  
  # Pods running as root
  echo -e "\n${BOLD}${YELLOW}Pods Running as Root (UID 0):${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.spec.containers[]? | 
      .securityContext?.runAsUser == 0 or 
      (.securityContext?.runAsUser == null and 
       .spec.securityContext?.runAsUser == 0)) | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' | head -10
  
  # Default service accounts in use
  echo -e "\n${BOLD}${YELLOW}Pods Using Default ServiceAccount:${PLAIN}"
  kubectl get pods --all-namespaces -o json | jq -r '
    .items[] | 
    select(.spec.serviceAccountName == "default" or 
           .spec.serviceAccountName == null) | 
    "\(.metadata.namespace)/\(.metadata.name)"
  ' | head -10
}

events_analysis() {
  echo -e "\n${BOLD}${GREEN}=== Recent Events ===${PLAIN}"
  
  echo -e "${BOLD}${RED}Warning Events (Last 1 Hour):${PLAIN}"
  kubectl get events --all-namespaces \
    --field-selector type=Warning \
    --sort-by='.lastTimestamp' | tail -20
  
  echo -e "\n${BOLD}${YELLOW}Event Summary by Type:${PLAIN}"
  kubectl get events --all-namespaces -o json | jq -r '
    [.items[] | .type] | 
    group_by(.) | 
    map({type: .[0], count: length}) | 
    .[] | "\(.type): \(.count)"
  '
}

etcd_health() {
  echo -e "\n${BOLD}${GREEN}=== etcd Health (if accessible) ===${PLAIN}"
  
  if [[ "$DISTRO" == "k3s" ]]; then
    if [[ -f /var/lib/rancher/k3s/server/tls/etcd/server-client.crt ]]; then
      echo -e "${BLUE}k3s embedded etcd detected${PLAIN}"
      
      ETCD_ENDPOINT='https://127.0.0.1:2379'
      ETCD_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt'
      ETCD_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt'
      ETCD_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key'
      
      if command -v etcdctl >/dev/null; then
        ETCDCTL_API=3 etcdctl \
          --endpoints="$ETCD_ENDPOINT" \
          --cacert="$ETCD_CACERT" \
          --cert="$ETCD_CERT" \
          --key="$ETCD_KEY" \
          endpoint health 2>/dev/null || \
          echo -e "${YELLOW}[WARN] Cannot connect to etcd${PLAIN}"
      else
        echo -e "${YELLOW}[INFO] etcdctl not installed${PLAIN}"
      fi
    fi
  else
    echo -e "${YELLOW}[INFO] Skipping etcd check (not k3s)${PLAIN}"
  fi
}

helm_deployments() {
  echo -e "\n${BOLD}${GREEN}=== Helm Releases ===${PLAIN}"
  
  if command -v helm >/dev/null; then
    helm list --all-namespaces
    
    echo -e "\n${BOLD}${YELLOW}Failed Helm Releases:${PLAIN}"
    helm list --all-namespaces --failed || echo -e "${GREEN}None${PLAIN}"
  else
    echo -e "${YELLOW}[INFO] Helm not installed${PLAIN}"
  fi
}

generate_report() {
  echo -e "\n${BOLD}${GREEN}=== Generating Report ===${PLAIN}"
  
  mkdir -p "$OUTPUT_DIR"
  
  echo -e "${BLUE}Saving detailed outputs to: ${OUTPUT_DIR}${PLAIN}"
  
  kubectl cluster-info dump --output-directory="$OUTPUT_DIR/cluster-dump" \
    >/dev/null 2>&1 || true
  
  kubectl get all --all-namespaces -o yaml > "$OUTPUT_DIR/all-resources.yaml" 2>/dev/null || true
  kubectl get events --all-namespaces -o yaml > "$OUTPUT_DIR/events.yaml" 2>/dev/null || true
  kubectl get nodes -o yaml > "$OUTPUT_DIR/nodes.yaml" 2>/dev/null || true
  
  echo -e "${GREEN}✓ Report saved to: ${OUTPUT_DIR}${PLAIN}"
}

### --- Main Execution ---

main() {
  clear
  
  echo -e "${BOLD}${MAGENTA}"
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║   Kubernetes Cluster Diagnostics (2026 Edition)            ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo -e "${PLAIN}"
  
  check_dependencies
  
  cluster_info
  cluster_objects
  cluster_nodes
  analyze_pods
  system_services_health
  resource_usage
  persistent_storage
  network_analysis
  security_analysis
  events_analysis
  etcd_health
  helm_deployments
  
  if [[ "${SAVE_REPORT:-false}" == "true" ]]; then
    generate_report
  fi
  
  echo -e "\n${BOLD}${GREEN}✅ Diagnostics Complete${PLAIN}"
  echo -e "${BLUE}Tip: Run with SAVE_REPORT=true to save detailed outputs${PLAIN}"
}

main "$@"
