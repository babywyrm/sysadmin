#!/bin/bash
# kubernetes-api-pentest.sh
# Generic safe Kubernetes API enumeration script
set -euo pipefail

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
#  Helper: simple authenticated curl to the K8s API
# ------------------------------------------------------------------------------
api(){
  curl -k -s -H "Authorization: Bearer $TOKEN" \
       -H "Accept: application/json" \
       "$APISERVER$1" 2>/dev/null
}

# ------------------------------------------------------------------------------
#  Discover accessible namespaces
# ------------------------------------------------------------------------------
discover_namespaces(){
  logi "Discovering namespaces..."

  local found=()
  local default_list=(
    "default"
    "kube-system"
    "kube-public"
    "kube-node-lease"
    "monitoring"
    "logging"
    "prometheus"
    "grafana"
    "argocd"
    "ci"
    "cd"
    "staging"
    "dev"
    "test"
    "qa"
    "production"
    "internal"
    "ingress-nginx"
    "cert-manager"
    "security"
    "ops"
    "tools"
    "system"
    "$CUR_NS"
  )

  # try API call first
  local r
  if r=$(api "/api/v1/namespaces"); then
    if echo "$r" | jq -e '.items' &>/dev/null; then
      mapfile -t found < <(echo "$r" | jq -r '.items[]?.metadata.name // empty')
      logs "API returned ${#found[@]} namespaces."
    fi
  fi

  # fallback to static list if API not allowed
  if [[ ${#found[@]} -eq 0 ]]; then
    logw "Falling back to static default namespace list."
    found=("${default_list[@]}")
  fi

  # filter reachable ones
  local reachable=()
  for ns in "${found[@]}"; do
    if [[ -n "$ns" ]] && api "/api/v1/namespaces/$ns" >/dev/null; then
      reachable+=("$ns")
    fi
  done

  # unique, non‑empty
  readarray -t reachable < <(printf '%s\n' "${reachable[@]}" | sort -u)
  printf '%s\n' "${reachable[@]}" >"$OUT/accessible-namespaces.txt"

  logi "Accessible namespaces: ${#reachable[@]} (${reachable[*]})"
  printf '%s\n' "${reachable[@]}"
}

# ------------------------------------------------------------------------------
#  Resource analysis helpers
# ------------------------------------------------------------------------------
analyze_configmaps(){
  local ns="$1" result="$2"
  local count=$(echo "$result" | jq -r '.items|length')
  if ((count==0)); then logi "○ $ns/configmaps: 0 items"; return; fi
  logs "✓ $ns/configmaps: $count items"
  echo "$result" >"$OUT/$ns-configmaps.json"

  local suspicious
  suspicious=$(echo "$result" | jq -r \
    '.items[] | select(.data|to_entries[]?|.value|test("password|secret|key|token|admin|auth|database|cert";"i")) |
     .metadata.name')
  if [[ -n "$suspicious" ]]; then
    logw "Suspicious ConfigMaps detected in $ns:"
    echo "$suspicious" | sed 's/^/   - /'
  fi
}

analyze_secrets(){
  local ns="$1" result="$2"
  local count=$(echo "$result"|jq -r '.items|length')
  if ((count==0)); then logi "○ $ns/secrets: 0 items"; return; fi
  logs "✓ $ns/secrets: $count items"
  echo "$result" >"$OUT/$ns-secrets.json"
  echo "$result"|jq -r '.items[]|"\(.metadata.name) (\(.type))"'|sed 's/^/   - /'
}

analyze_pods(){
  local ns="$1" result="$2"
  local count=$(echo "$result"|jq -r '.items|length')
  if ((count==0)); then logi "○ $ns/pods: 0 items"; return; fi
  logs "✓ $ns/pods: $count items"
  echo "$result" >"$OUT/$ns-pods.json"
  local privileged
  privileged=$(echo "$result"|jq -r \
    '.items[]|select(.spec.hostNetwork==true or .spec.containers[]?.securityContext.privileged==true)
      |.metadata.name')
  if [[ -n "$privileged" ]]; then
    logw "Privileged/hostNetwork pods in $ns:"
    echo "$privileged"|sed 's/^/   - /'
  fi
}

# ------------------------------------------------------------------------------
#  Enumerate everything namespace by namespace
# ------------------------------------------------------------------------------
namespace_enum(){
  logi "=== COMPREHENSIVE ENUMERATION ==="
  mapfile -t NS_LIST < <(discover_namespaces)
  for ns in "${NS_LIST[@]}"; do
    logi "--- Namespace: $ns ---"
    for kind in configmaps secrets pods; do
      local ep="/api/v1/namespaces/$ns/$kind" r
      if r=$(api "$ep"); then
        case "$kind" in
          configmaps) analyze_configmaps "$ns" "$r" ;;
          secrets)    analyze_secrets    "$ns" "$r" ;;
          pods)       analyze_pods       "$ns" "$r" ;;
        esac
      else
        logw "Cannot access $ns/$kind"
      fi
    done
  done
  logs "Namespace enumeration complete. Output: $OUT"
}

# ------------------------------------------------------------------------------
#  Cluster-level enumeration
# ------------------------------------------------------------------------------
cluster_enum(){
  logi "=== CLUSTER‑LEVEL RESOURCES ==="
  declare -A RES=(
    [nodes]="/api/v1/nodes"
    [clusterroles]="/apis/rbac.authorization.k8s.io/v1/clusterroles"
    [clusterrolebindings]="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
  )
  for r in "${!RES[@]}"; do
    local data
    if data=$(api "${RES[$r]}"); then
      local c=$(echo "$data"|jq -r '.items|length')
      logs "✓ $r: $c items"
      echo "$data" >"$OUT/$r.json"
      if [[ "$r" == "clusterrolebindings" ]]; then
        local admins
        admins=$(echo "$data"|jq -r '.items[]|select(.roleRef.name=="cluster-admin")|.metadata.name')
        [[ -n "$admins" ]] && logw "Cluster‑admin bindings:\n$(echo "$admins"|sed 's/^/   - /')"
      fi
    else
      logw "Cannot access $r"
    fi
  done
}

# ------------------------------------------------------------------------------
#  Entry point
# ------------------------------------------------------------------------------
main(){
  local cmd="${1:-all}"
  case "$cmd" in
    all|comprehensive) namespace_enum; cluster_enum ;;
    namespaces)        discover_namespaces ;;
    cluster)           cluster_enum ;;
    *)
      echo "Usage: $0 [all|comprehensive|namespaces|cluster]" >&2
      exit 1 ;;
  esac
}

main "$@"
