#!/bin/sh
# Still beta, lmao
# This script enumerates RBAC permissions via SelfSubjectAccessReviews,
# collects all allowed actions, and prints a summary at the end.
# Uses curl and basic text processing (no jq required).. yet

# Retrieve the service account token.
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Construct the API server URL using in-cluster environment variables.
API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
echo "API Server: $API_SERVER"
echo ""

# Define verbs and resources to check.
verbs="get list watch create update patch delete"
resources="pods deployments services configmaps secrets persistentvolumeclaims events endpoints ingresses jobs cronjobs statefulsets daemonsets replicasets nodes namespaces clusterroles clusterrolebindings"

# Function to get the API group for a given resource.
get_api_group() {
  case "$1" in
    deployments|daemonsets|statefulsets|replicasets)
      echo "apps"
      ;;
    ingresses)
      echo "networking.k8s.io"
      ;;
    cronjobs|jobs)
      echo "batch"
      ;;
    pods|services|configmaps|secrets|persistentvolumeclaims|events|endpoints)
      echo ""
      ;;
    nodes|namespaces)
      echo "core"
      ;;
    clusterroles|clusterrolebindings)
      echo "rbac.authorization.k8s.io"
      ;;
    *)
      echo ""
      ;;
  esac
}

# Allow the user to specify a namespace or use a default.
NS="${1:-internal}"

# Initialize a variable to store allowed actions.
allowed_actions=""

# Function to perform a SelfSubjectAccessReview.
check_permission() {
  verb="$1"
  resource="$2"
  group=$(get_api_group "$resource")
  
  echo "------------------------------------------"
  echo "Checking permission for resource '$resource' (group: '$group') in namespace '$NS' with verb '$verb':"
  
  payload=$(cat <<EOF
{
  "kind": "SelfSubjectAccessReview",
  "apiVersion": "authorization.k8s.io/v1",
  "spec": {
    "resourceAttributes": {
      "namespace": "$NS",
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
  
  # Check if the response contains "allowed": true
  if echo "$response" | grep -q '"allowed":[ ]*true'; then
    echo "=> Allowed"
    allowed_actions="${allowed_actions}\nVerb: $verb, Resource: $resource, Group: $group"
  else
    echo "=> Denied"
  fi

  echo "Raw response (truncated): $(echo "$response" | tr -d '\n' | cut -c1-200)..."
  echo ""
}

# Start checking permissions for each resource.
echo "Starting permission enumeration..."
for res in $resources; do
  for verb in $verbs; do
    check_permission "$verb" "$res"
  done
done

# Print summary
echo "------------------------------------------"
echo "Permission Enumeration Summary:"
if [ -n "$allowed_actions" ]; then
  echo "The following permissions are allowed:"
  echo -e "$allowed_actions"
else
  echo "No allowed actions were found."
fi

# Log the output to a file for later review.
echo "Logging results to permission_log.txt"
echo "Permission Enumeration Summary:" > permission_log.txt
if [ -n "$allowed_actions" ]; then
  echo "The following permissions are allowed:" >> permission_log.txt
  echo -e "$allowed_actions" >> permission_log.txt
else
  echo "No allowed actions were found." >> permission_log.txt
fi

echo "------------------------------------------"
echo "Permission enumeration complete."
