#!/bin/sh
# Kubernetes RBAC Permission Enumerator (..actually better..)  *probably*
# Enumerates current ServiceAccount RBAC permissions via SelfSubjectAccessReviews
# --- Setup -----------------------------------------------------------------
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
AUTO_NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# --- Parse Arguments -------------------------------------------------------
NAMESPACE="$AUTO_NS"
ONLY_ALLOWED=false

for arg in "$@"; do
  case "$arg" in
    --allowed-only) ONLY_ALLOWED=true ;;
    -n|--namespace) shift; NAMESPACE="$1" ;;
    *)
      # If it's not a flag and NAMESPACE wasn't explicitly set yet
      [ "$arg" != "" ] && [ "$arg" != "--allowed-only" ] && NAMESPACE="$arg"
      ;;
  esac
done

# --- Colors ----------------------------------------------------------------
GREEN=$(printf '\033[1;32m')
RED=$(printf '\033[1;31m')
BLUE=$(printf '\033[1;34m')
YELLOW=$(printf '\033[1;33m')
CYAN=$(printf '\033[1;36m')
BOLD=$(printf '\033[1m')
NC=$(printf '\033[0m')

# --- Resources & Verbs -----------------------------------------------------
verbs="get list watch create update patch delete"
resources="pods deployments services configmaps secrets persistentvolumeclaims events endpoints ingresses jobs cronjobs statefulsets daemonsets replicasets nodes namespaces clusterroles clusterrolebindings"

get_api_group() {
  case "$1" in
    deployments|daemonsets|statefulsets|replicasets) echo "apps" ;;
    ingresses) echo "networking.k8s.io" ;;
    cronjobs|jobs) echo "batch" ;;
    clusterroles|clusterrolebindings) echo "rbac.authorization.k8s.io" ;;
    *) echo "" ;;
  esac
}

# --- Header ---------------------------------------------------------------
clear
echo ""
echo "${BLUE}${BOLD}╔════════════════════════════════════════════════════════╗${NC}"
echo "${BLUE}${BOLD}║           Kubernetes RBAC Permission Enumerator         ║${NC}"
echo "${BLUE}${BOLD}╚════════════════════════════════════════════════════════╝${NC}"
echo " API Server : ${CYAN}$API_SERVER${NC}"
echo " Namespace  : ${YELLOW}$NAMESPACE${NC}"
$ONLY_ALLOWED && echo " Mode       : ${GREEN}Allowed-only${NC}"
echo ""

# --- Work vars -------------------------------------------------------------
allowed_actions=""

# --- Core check ------------------------------------------------------------
check_permission() {
  verb="$1"
  resource="$2"
  group=$(get_api_group "$resource")

  payload=$(cat <<EOF
{
  "kind": "SelfSubjectAccessReview",
  "apiVersion": "authorization.k8s.io/v1",
  "spec": {
    "resourceAttributes": {
      "namespace": "$NAMESPACE",
      "verb": "$verb",
      "resource": "$resource",
      "group": "$group"
    }
  }
}
EOF
)

  response=$(curl -sk -X POST "$API_SERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$payload")

  if echo "$response" | grep -q '"allowed":[ ]*true'; then
    allowed_actions="${allowed_actions}\n$verb,$resource,$group"
    $ONLY_ALLOWED || printf "%-8s %-28s %-25s ${GREEN}✔ Allowed${NC}\n" "$verb" "$resource" "$group"
  else
    $ONLY_ALLOWED || printf "%-8s %-28s %-25s ${RED}✘ Denied${NC}\n" "$verb" "$resource" "$group"
  fi
}

# --- Execution -------------------------------------------------------------
echo "${BOLD}Enumerating permissions...${NC}"
printf "%-8s %-28s %-25s %s\n" "VERB" "RESOURCE" "GROUP" "RESULT"
echo "------------------------------------------------------------------------------------"

for res in $resources; do
  for verb in $verbs; do
    check_permission "$verb" "$res"
  done
done

# --- Summary ---------------------------------------------------------------
echo ""
echo "${BLUE}${BOLD}══════════════════════════════════════════════════════════════════${NC}"
echo "${YELLOW}${BOLD}Permission Enumeration Summary${NC}"

if [ -n "$allowed_actions" ]; then
  echo ""
  echo "${GREEN}Allowed actions:${NC}"
  printf "%-8s %-25s %-25s\n" "VERB" "RESOURCE" "GROUP"
  echo "---------------------------------------------------------------"
  echo -e "$allowed_actions" | sort | uniq | while IFS=, read -r verb resource group; do
    printf "%-8s %-25s %-25s\n" "$verb" "$resource" "$group"
  done
else
  echo "${RED}No allowed actions found.${NC}"
fi

# --- Logging ---------------------------------------------------------------
echo ""
echo "Saving summary to ${CYAN}permission_log.txt${NC}..."
{
  echo "Kubernetes RBAC Permission Enumeration Summary"
  echo "Namespace: $NAMESPACE"
  echo ""
  if [ -n "$allowed_actions" ]; then
    echo "Allowed actions:"
    echo -e "$allowed_actions" | sort | uniq | column -t -s,
  else
    echo "No allowed actions found."
  fi
} > permission_log.txt

echo ""
echo "${BLUE}${BOLD}Done.${NC}"
