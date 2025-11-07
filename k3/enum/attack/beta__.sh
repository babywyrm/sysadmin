#!/bin/bash
# kubernetes-api-pentest.sh
# Generic Kubernetes API enumeration & analysis / tolerant version

set -uo pipefail   # <- no -e : don't exit on non‑zero in restricted envs

# ------------------------------------------------------------------------------
#  Settings & Colors
# ------------------------------------------------------------------------------
B='\033[0;34m'; Y='\033[1;33m'; G='\033[0;32m'; R='\033[0;31m'; N='\033[0m'
logi(){ echo -e "${B}[INFO]${N} $*" >&2; }
logw(){ echo -e "${Y}[WARN]${N} $*" >&2; }
logs(){ echo -e "${G}[SUCCESS]${N} $*" >&2; }
loge(){ echo -e "${R}[ERROR]${N} $*" >&2; }

APISERVER="${APISERVER:-https://kubernetes.default.svc.cluster.local}"
TOKEN_FILE="/var/run/secrets/kubernetes.io/serviceaccount/token"
NS_FILE="/var/run/secrets/kubernetes.io/serviceaccount/namespace"
TOKEN=$(<"$TOKEN_FILE")
CUR_NS=$(<"$NS_FILE")
OUT="./k8s-pentest-output"
mkdir -p "$OUT"

# ------------------------------------------------------------------------------
api(){
  curl -k -s -H "Authorization: Bearer $TOKEN" \
       -H "Accept: application/json" \
       "$APISERVER$1" 2>/dev/null
}

# ------------------------------------------------------------------------------
discover_namespaces(){
  logi "Discovering namespaces..."
  local found=()
  local defaults=(
    "default" "kube-system" "kube-public" "kube-node-lease"
    "monitoring" "logging" "prometheus" "grafana"
    "argocd" "ci" "cd" "staging" "dev" "test" "qa" "production"
    "internal" "ingress-nginx" "cert-manager" "security"
    "ops" "tools" "system" "$CUR_NS"
  )

  local r
  if r=$(api "/api/v1/namespaces") && echo "$r"|jq -e '.items' &>/dev/null; then
    mapfile -t found < <(echo "$r"|jq -r '.items[]?.metadata.name//empty')
    logs "API listed ${#found[@]} namespaces."
  else
    logw "Falling back to defaults."
    found=("${defaults[@]}")
  fi

  local reachable=()
  for ns in "${found[@]}"; do
    [[ -z "$ns" ]] && continue
    api "/api/v1/namespaces/$ns" >/dev/null && reachable+=("$ns")
  done
  readarray -t reachable < <(printf '%s\n' "${reachable[@]}"|sort -u)
  printf '%s\n' "${reachable[@]}" >"$OUT/accessible-namespaces.txt"
  logi "Accessible namespaces (${#reachable[@]}): ${reachable[*]}"
  printf '%s\n' "${reachable[@]}"
}

# ------------------------------------------------------------------------------
#  Resource analyzers
# ------------------------------------------------------------------------------
analyze_configmaps(){
  local ns="$1" r="$2"; local c
  c=$(echo "$r"|jq -r '.items|length' 2>/dev/null||echo 0)
  ((c==0)) && { logi "○ $ns/configmaps: 0"; return; }
  logs "✓ $ns/configmaps: $c"
  echo "$r" >"$OUT/$ns-configmaps.json"
  echo "$r"|jq -r \
    '.items[]|select(.data|to_entries[]?|
     .value|test("password|secret|key|token|admin|auth|database|cert";"i"))
     |.metadata.name' 2>/dev/null|while read -r n; do
       [[ -n "$n" ]] && logw "   suspicious: $n"
     done
}

analyze_generic(){
  local ns="$1" kind="$2" path="$3"
  local r
  r=$(api "$path") || return
  local c
  c=$(echo "$r"|jq -r '.items|length' 2>/dev/null||echo 0)
  ((c>0)) && logs "✓ $ns/$kind: $c" || logi "○ $ns/$kind: 0"
  echo "$r" >"$OUT/$ns-$kind.json"
}

# ------------------------------------------------------------------------------
namespace_enum(){
  logi "=== COMPREHENSIVE ENUMERATION ==="
  mapfile -t NS_LIST < <(discover_namespaces)
  local total=${#NS_LIST[@]}
  ((total==0)) && { NS_LIST=("$CUR_NS"); total=1; }
  local i=1
  for ns in "${NS_LIST[@]}"; do
    logi "--- Namespace [$i/$total]: $ns ---"
    ((i++))

    # Core
    r=$(api "/api/v1/namespaces/$ns/configmaps") && analyze_configmaps "$ns" "$r"
    r=$(api "/api/v1/namespaces/$ns/secrets") && analyze_generic "$ns" secrets "/api/v1/namespaces/$ns/secrets"
    r=$(api "/api/v1/namespaces/$ns/pods") && analyze_generic "$ns" pods "/api/v1/namespaces/$ns/pods"

    # Extended
    analyze_generic "$ns" pvc "/api/v1/namespaces/$ns/persistentvolumeclaims"
    analyze_generic "$ns" networkpolicies "/apis/networking.k8s.io/v1/namespaces/$ns/networkpolicies"
    analyze_generic "$ns" ingresses "/apis/networking.k8s.io/v1/namespaces/$ns/ingresses"
    analyze_generic "$ns" deployments "/apis/apps/v1/namespaces/$ns/deployments"
    analyze_generic "$ns" statefulsets "/apis/apps/v1/namespaces/$ns/statefulsets"
    analyze_generic "$ns" daemonsets "/apis/apps/v1/namespaces/$ns/daemonsets"
    analyze_generic "$ns" jobs "/apis/batch/v1/namespaces/$ns/jobs"
    analyze_generic "$ns" cronjobs "/apis/batch/v1/namespaces/$ns/cronjobs"
    analyze_generic "$ns" events "/api/v1/namespaces/$ns/events"
  done
  logs "Namespace enumeration complete → $OUT"
}

# ------------------------------------------------------------------------------
cluster_enum(){
  logi "=== CLUSTER-LEVEL ==="
  declare -A RES=(
    [nodes]="/api/v1/nodes"
    [persistentvolumes]="/api/v1/persistentvolumes"
    [storageclasses]="/apis/storage.k8s.io/v1/storageclasses"
    [clusterroles]="/apis/rbac.authorization.k8s.io/v1/clusterroles"
    [clusterrolebindings]="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
    [crds]="/apis/apiextensions.k8s.io/v1/customresourcedefinitions"
  )
  for r in "${!RES[@]}"; do
    local d
    d=$(api "${RES[$r]}") || { logw "Cannot access $r"; continue; }
    local c
    c=$(echo "$d"|jq -r '.items|length' 2>/dev/null||echo 0)
    logs "✓ $r: $c"
    echo "$d" >"$OUT/$r.json"
    if [[ "$r" == "clusterrolebindings" ]]; then
      echo "$d"|jq -r '.items[]|select(.roleRef.name=="cluster-admin")|.metadata.name' 2>/dev/null |
        while read -r n; do [[ -n "$n" ]] && logw "   cluster-admin binding: $n"; done
    fi
  done
  logi "Cluster enumeration done."
}

# ------------------------------------------------------------------------------
main(){
  local cmd="${1:-all}"
  case "$cmd" in
    all|comprehensive) namespace_enum; cluster_enum ;;
    namespaces) discover_namespaces ;;
    cluster) cluster_enum ;;
    *) echo "Usage: $0 [all|comprehensive|namespaces|cluster]" >&2; exit 1 ;;
  esac
}

main "$@"
