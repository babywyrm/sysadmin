#!/bin/sh
# RBAC Permission Enumerator  ..(beta edition).. 
# Enumerates current ServiceAccount RBAC via SelfSubjectAccessReview (SSAR)
# Requires: curl + basic POSIX tools

# --- Setup -------------------------------------------------------------
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# ANSI colors for pretty output
GREEN="\033[1;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
NC="\033[0m"  # reset color

# --- Define resources/verbs -------------------------------------------
verbs="get list watch create update patch delete"
resources="pods deployments services configmaps secrets persistentvolumeclaims events endpoints ingresses jobs cronjobs statefulsets daemonsets replicasets nodes namespaces clusterroles clusterrolebindings"

# --- Helpers -----------------------------------------------------------
get_api_group() {
  case "$1" in
    deployments|daemonsets|statefulsets|replicasets) echo "apps" ;;
    ingresses) echo "networking.k8s.io" ;;
    cronjobs|jobs) echo "batch" ;;
    clusterroles|clusterrolebindings) echo "rbac.authorization.k8s.io" ;;
    *) echo "" ;;
  esac
}

# --- Banner ------------------------------------------------------------
echo -e "${BLUE}Kubernetes RBAC Permission Enumerator${NC}"
echo "API Server: $API_SERVER"
echo "Namespace : ${YELLOW}$NAMESPACE${NC}"
echo ""

# --- Core check function ----------------------------------------------
allowed_actions=""

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
    printf "%-8s %-25s %-20s ${GREEN}%s${NC}\n" "$verb" "$resource" "$group" "✔ Allowed"
    allowed_actions="${allowed_actions}\nVerb: $verb, Resource: $resource, Group: $group"
  else
    printf "%-8s %-25s %-20s ${RED}%s${NC}\n" "$verb" "$resource" "$group" "✘ Denied"
  fi
}

# --- Run enumeration --------------------------------------------------
echo -e "${BLUE}Enumerating permissions...${NC}"
printf "%-8s %-25s %-20s %s\n" "VERB" "RESOURCE" "GROUP" "RESULT"
echo "--------------------------------------------------------------------------"

for res in $resources; do
  for verb in $verbs; do
    check_permission "$verb" "$res"
  done
done

# --- Summary ----------------------------------------------------------
echo ""
echo -e "${BLUE}------------------------------------------${NC}"
echo -e "${YELLOW}Permission Enumeration Summary${NC}"
if [ -n "$allowed_actions" ]; then
  echo -e "${GREEN}The following permissions are allowed:${NC}"
  echo -e "$allowed_actions" | sort | uniq
else
  echo -e "${RED}No allowed actions were found.${NC}"
fi

echo ""
echo "Logging results to permission_log.txt..."
{
  echo "Permission Enumeration Summary:"
  if [ -n "$allowed_actions" ]; then
    echo "The following permissions are allowed:"
    echo -e "$allowed_actions" | sort | uniq
  else
    echo "No allowed actions were found."
  fi
} > permission_log.txt

echo -e "${BLUE}------------------------------------------${NC}"
echo -e "${YELLOW}Enumeration complete.${NC}"
