#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# k8s_audit_ultra_v4.sh
# Unified Kubernetes Node + Cluster + Pod + RBAC + Network Audit
#
# MODE: SAFE-ONLY (READ-ONLY), OPERATOR OUTPUT, EXTENDED DEPTH (Option B)
# OUTPUT: Single file: k8s_audit_<host>_<timestamp>.txt
#
# PURPOSE:
#   This script provides a comprehensive operator-grade audit of:
#     - Node hardening
#     - Kubelet configuration
#     - API server exposure
#     - RBAC privilege risks
#     - Pod security posture
#     - Network isolation
#     - Secrets/configmap leakage
#     - Metadata server exposure
#     - Runtime, sysctl, filesystem, process tree
#     - Container runtime posture
#     - CRDs and attack surface
#     - Cluster type detection
#     - Severity scoring
#
# SAFE ONLY:
#   Does NOT modify cluster resources.
#   Does NOT exec into pods.
#   Does NOT create/delete/update anything.
#
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# OUTPUT SETUP
# ---------------------------------------------------------------------------
HOSTNAME=$(hostname | tr ' ' '_' | tr '/' '_')
TS=$(date +%Y%m%dT%H%M%S)
OUT="k8s_audit_${HOSTNAME}_${TS}.txt"

echo "Kubernetes Audit — Ultra v4 (Operator Mode, Deep Scan)" > "$OUT"
echo "Host: $HOSTNAME" >> "$OUT"
echo "Timestamp: $TS" >> "$OUT"
echo "SAFE MODE — READ ONLY" >> "$OUT"
echo "============================================================" >> "$OUT"

# ---------------------------------------------------------------------------
# FINDINGS STORAGE (SEVERITY ENGINE)
# ---------------------------------------------------------------------------
FIND_C=()   # critical
FIND_H=()   # high
FIND_M=()   # medium
FIND_L=()   # low
FIND_I=()   # info

add() {
  # usage: add <C|H|M|L|I> "message"
  case "$1" in
    C) FIND_C+=("$2");;
    H) FIND_H+=("$2");;
    M) FIND_M+=("$2");;
    L) FIND_L+=("$2");;
    I) FIND_I+=("$2");;
  esac
}

log() { echo "[*] $1" | tee -a "$OUT"; }
sec() { echo -e "\n==================== $1 ====================" | tee -a "$OUT"; }

# For commands that may not exist
exists() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# SECTION 1 — NODE BASELINE INFO
# ---------------------------------------------------------------------------
sec "1. Node Baseline"

log "Kernel:"
uname -a | tee -a "$OUT"
add I "Kernel: $(uname -r)"

log "Uptime:"
uptime 2>/dev/null | tee -a "$OUT"

log "CPU Info:"
grep -m1 'model name' /proc/cpuinfo 2>/dev/null | tee -a "$OUT"

log "Memory:"
free -h 2>/dev/null | tee -a "$OUT"

# ---------------------------------------------------------------------------
# SECTION 2 — SECURITY CONTROLS (SELinux / AppArmor / Lockdown)
# ---------------------------------------------------------------------------
sec "2. Node Security Controls"

if exists sestatus; then
  SE=$(sestatus | grep 'Current mode' || true)
  echo "$SE" | tee -a "$OUT"
  if ! echo "$SE" | grep -q enforcing; then
    add H "SELinux not enforcing"
  fi
else
  add I "SELinux not installed"
fi

if exists aa-status; then
  AA=$(aa-status 2>/dev/null | grep -i enforce || true)
  if [[ -z "$AA" ]]; then
    add H "AppArmor not enforcing"
  else
    add I "AppArmor enforcing detected"
  fi
else
  add I "AppArmor not installed"
fi

if [[ -f /sys/kernel/security/lockdown ]]; then
  LD=$(cat /sys/kernel/security/lockdown)
  echo "Kernel Lockdown: $LD" | tee -a "$OUT"
  if ! echo "$LD" | grep -q "integrity"; then
    add M "Kernel Lockdown is not in integrity/confidentiality mode"
  fi
else
  add I "Kernel Lockdown unsupported"
fi

# ---------------------------------------------------------------------------
# SECTION 3 — FILESYSTEM EXPOSURE & PERMISSIONS
# ---------------------------------------------------------------------------
sec "3. Filesystem Exposure"

log "Writable sensitive paths:"
WS=$(find /proc /sys /boot -maxdepth 1 -writable 2>/dev/null || true)
if [[ -n "$WS" ]]; then
  echo "$WS" | tee -a "$OUT"
  add H "Writable sensitive directories found"
else
  echo "None." | tee -a "$OUT"
fi

log "Mounted filesystems:"
cat /proc/self/mounts | tee -a "$OUT"

log "Cgroups:"
cat /proc/1/cgroup 2>/dev/null | tee -a "$OUT"

# ---------------------------------------------------------------------------
# SECTION 4 — PROCESS & NETWORK ENUMERATION
# ---------------------------------------------------------------------------
sec "4. Process and Network"

log "Processes:"
ps auxww 2>/dev/null | tee -a "$OUT"

log "Listening Ports:"
if exists ss; then
  ss -tulnp 2>/dev/null | tee -a "$OUT"
else
  netstat -tulnp 2>/dev/null | tee -a "$OUT"
fi

log "IP Routing:"
ip route 2>/dev/null | tee -a "$OUT"

log "ARP:"
arp -a 2>/dev/null | tee -a "$OUT"

# ---------------------------------------------------------------------------
# SECTION 5 — CONTAINER RUNTIME INSPECTION
# ---------------------------------------------------------------------------
sec "5. Container Runtime"

if exists containerd; then
  add I "containerd installed"
  echo "containerd version:" | tee -a "$OUT"
  containerd --version 2>/dev/null | tee -a "$OUT"
fi

if exists crictl; then
  add I "crictl detected — container runtime interface available"
  crictl info 2>/dev/null | tee -a "$OUT"
fi

if exists docker; then
  add I "docker runtime detected"
  docker info 2>/dev/null | tee -a "$OUT"
fi

# ---------------------------------------------------------------------------
# SECTION 6 — SERVICEACCOUNT / K8S API CONTEXT
# ---------------------------------------------------------------------------
sec "6. Kubernetes ServiceAccount Context"

SAT="/var/run/secrets/kubernetes.io/serviceaccount/token"
SANS="/var/run/secrets/kubernetes.io/serviceaccount/namespace"
API="https://kubernetes.default.svc"

if [[ -r "$SAT" ]]; then
  TOKEN=$(cat "$SAT")
  NS=$(cat "$SANS" 2>/dev/null || echo "unknown")
  add I "Running inside a pod - namespace=$NS"
  echo "SA namespace: $NS" | tee -a "$OUT"
else
  add I "Not running in a pod or SA token unavailable"
  NS="default"
fi

# ---------------------------------------------------------------------------
# SECTION 7 — CLUSTER TYPE DETECTION
# ---------------------------------------------------------------------------
sec "7. Cluster Type Detection"

CTYPE="unknown"

if kubectl get nodes -o wide 2>/dev/null | grep -qi eks; then
  CTYPE="EKS"
elif kubectl get nodes -o json 2>/dev/null | jq -e '.items[0].metadata.labels["cloud.google.com/gke-nodepool"]' >/dev/null; then
  CTYPE="GKE"
elif kubectl get nodes -o json 2>/dev/null | jq -e '.items[0].metadata.labels["agentpool"]' >/dev/null; then
  CTYPE="AKS"
elif exists k3s; then
  CTYPE="k3s"
else
  CTYPE="kubeadm/general"
fi

echo "Cluster Type: $CTYPE" | tee -a "$OUT"
add I "Cluster type detected: $CTYPE"

# ---------------------------------------------------------------------------
# SECTION 8 — KUBELET HARDENING
# ---------------------------------------------------------------------------
sec "8. Kubelet Security"

PORTS=$(ss -tulnp | grep kubelet || true)
echo "$PORTS" | tee -a "$OUT"

if echo "$PORTS" | grep -q 10255; then
  add C "Kubelet readOnlyPort (10255) exposed"
fi

if echo "$PORTS" | grep -q 10250; then
  add H "Kubelet secure port exposed externally"
fi

# ---------------------------------------------------------------------------
# SECTION 9 — API SERVER HARDENING
# ---------------------------------------------------------------------------
sec "9. API Server Hardening"

log "Checking anonymous access:"
if curl -sk "$API/api/" | grep -q "kind"; then
  add C "Anonymous API access may be enabled"
  echo "Anonymous API response indicates access!" | tee -a "$OUT"
else
  echo "Anonymous API blocked." | tee -a "$OUT"
fi

log "Checking audit logging based on running processes:"
APSP=$(ps aux | grep kube-apiserver | grep -v grep || true)
echo "$APSP" | tee -a "$OUT"

if ! echo "$APSP" | grep -q audit; then
  add C "API server audit logging not enabled"
fi

# ---------------------------------------------------------------------------
# SECTION 10 — RBAC HARDENING
# ---------------------------------------------------------------------------
sec "10. RBAC Hardening"

log "Wildcard Roles:"
WROLES=$(kubectl get clusterroles -o json 2>/dev/null | jq -r '.items[] | select(.rules[]?.verbs[]?=="*") | .metadata.name')
if [[ -n "$WROLES" ]]; then
  echo "$WROLES" | tee -a "$OUT"
  add C "Wildcard verbs in ClusterRoles: $WROLES"
fi

log "Cluster-Admin Bindings:"
CAB=$(kubectl get clusterrolebindings -o json 2>/dev/null | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name')
if [[ -n "$CAB" ]]; then
  echo "$CAB" | tee -a "$OUT"
  add C "cluster-admin rolebindings exist: $CAB"
fi

# ---------------------------------------------------------------------------
# SECTION 11 — POD SECURITY (privileged, caps, etc.)
# ---------------------------------------------------------------------------
sec "11. Pod Security & Runtime"

PODS=$(kubectl get pods -A -o json 2>/dev/null || echo "{}")

# privileged pods
PRIV=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"')
if [[ -n "$PRIV" ]]; then
  echo "$PRIV" | tee -a "$OUT"
  add C "Privileged pods detected: $PRIV"
fi

# hostNetwork pods
HN=$(echo "$PODS" | jq -r '.items[] | select(.spec.hostNetwork==true) | "\(.metadata.namespace)/\(.metadata.name)"')
if [[ -n "$HN" ]]; then
  echo "$HN" | tee -a "$OUT"
  add H "hostNetwork pods detected: $HN"
fi

# hostPID pods
HP=$(echo "$PODS" | jq -r '.items[] | select(.spec.hostPID==true) | "\(.metadata.namespace)/\(.metadata.name)"')
if [[ -n "$HP" ]]; then
  echo "$HP" | tee -a "$OUT"
  add H "hostPID pods detected: $HP"
fi

# hostPath mounts
HPATH=$(echo "$PODS" | jq -r '.items[] | select(.spec.volumes[]?.hostPath) | "\(.metadata.namespace)/\(.metadata.name)"')
if [[ -n "$HPATH" ]]; then
  echo "$HPATH" | tee -a "$OUT"
  add H "hostPath mounts detected: $HPATH"
fi

# capabilities
CAPS=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[].securityContext.capabilities.add[]?=="SYS_ADMIN" or .spec.containers[].securityContext.capabilities.add[]?=="NET_ADMIN") | "\(.metadata.namespace)/\(.metadata.name)"')
if [[ -n "$CAPS" ]]; then
  echo "$CAPS" | tee -a "$OUT"
  add H "Dangerous Linux capabilities detected: $CAPS"
fi

# ---------------------------------------------------------------------------
# SECTION 12 — NETWORKPOLICY AUDIT
# ---------------------------------------------------------------------------
sec "12. Network Isolation"

NAMESPACES=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')
for N in $NAMESPACES; do
  COUNT=$(kubectl get netpol -n "$N" -o json 2>/dev/null | jq '.items | length')
  if [[ "$COUNT" -eq 0 ]]; then
    add H "Namespace $N has zero NetworkPolicies"
    echo "[WARN] No NetworkPolicies in namespace: $N" | tee -a "$OUT"
  fi
done

# ---------------------------------------------------------------------------
# SECTION 13 — SECRETS & CONFIGMAP RISK SCAN
# ---------------------------------------------------------------------------
sec "13. Secrets / ConfigMap Leakage Scan"

SECRISK=$(kubectl get secrets -A -o json 2>/dev/null | jq -r '.items[] | select(.data | tostring | test("password|token|key|secret";"i")) | "\(.metadata.namespace)/\(.metadata.name)"')
if [[ -n "$SECRISK" ]]; then
  echo "$SECRISK" | tee -a "$OUT"
  add H "Secrets with sensitive patterns: $SECRISK"
fi

CMRISK=$(kubectl get configmaps -A -o json 2>/dev/null | jq -r '.items[] | select(.data|tostring|test("password|token|secret";"i")) | "\(.metadata.namespace)/\(.metadata.name)"')
if [[ -n "$CMRISK" ]]; then
  echo "$CMRISK" | tee -a "$OUT"
  add M "ConfigMaps with sensitive data patterns: $CMRISK"
fi

# ---------------------------------------------------------------------------
# SECTION 14 — METADATA SERVER CHECK
# ---------------------------------------------------------------------------
sec "14. Cloud Metadata Services"

# AWS
if curl -s --connect-timeout 1 http://169.254.169.254/latest/meta-data/ >/dev/null; then
  add C "AWS instance metadata accessible from container"
  echo "AWS metadata service reachable!" | tee -a "$OUT"
fi

# GCP
if curl -s --connect-timeout 1 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ >/dev/null; then
  add C "GCP metadata accessible from container"
  echo "GCP metadata service reachable!" | tee -a "$OUT"
fi

# Azure
if curl -s --connect-timeout 1 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null; then
  add C "Azure metadata accessible from container"
  echo "Azure metadata service reachable!" | tee -a "$OUT"
fi

# ---------------------------------------------------------------------------
# SECTION 15 — CRD ATTACK SURFACE
# ---------------------------------------------------------------------------
sec "15. CRD Attack Surface"

CRDS=$(kubectl get crds -o json 2>/dev/null | jq -r '.items[].metadata.name')
echo "$CRDS" | tee -a "$OUT"
add I "CRDs detected: $(echo "$CRDS" | wc -l)"

# ---------------------------------------------------------------------------
# SECTION 16 — API SURFACE ENUM (EXTENDED LITE)
# ---------------------------------------------------------------------------
sec "16. API Groups & Versions"

kubeapigroups=$(kubectl api-versions 2>/dev/null | sort)
echo "$kubeapigroups" | tee -a "$OUT"
add I "API groups: $(echo "$kubeapigroups" | wc -l)"

# ---------------------------------------------------------------------------
# SECTION 17 — SUMMARY REPORT
# ---------------------------------------------------------------------------
sec "17. Severity Summary"

echo "CRITICAL: ${#FIND_C[@]}" | tee -a "$OUT"
echo "HIGH:     ${#FIND_H[@]}" | tee -a "$OUT"
echo "MEDIUM:   ${#FIND_M[@]}" | tee -a "$OUT"
echo "LOW:      ${#FIND_L[@]}" | tee -a "$OUT"
echo "INFO:     ${#FIND_I[@]}" | tee -a "$OUT"

echo -e "\n--- CRITICAL FINDINGS ---" | tee -a "$OUT"
printf "%s\n" "${FIND_C[@]}" | tee -a "$OUT"

echo -e "\n--- HIGH FINDINGS ---" | tee -a "$OUT"
printf "%s\n" "${FIND_H[@]}" | tee -a "$OUT"

echo -e "\n--- MEDIUM FINDINGS ---" | tee -a "$OUT"
printf "%s\n" "${FIND_M[@]}" | tee -a "$OUT"

echo -e "\n--- LOW FINDINGS ---" | tee -a "$OUT"
printf "%s\n" "${FIND_L[@]}" | tee -a "$OUT"

echo -e "\n--- INFO ---" | tee -a "$OUT"
printf "%s\n" "${FIND_I[@]}" | tee -a "$OUT"

echo -e "\nReport complete: $OUT"
exit 0

##
##
