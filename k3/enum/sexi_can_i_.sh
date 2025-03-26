#!/bin/sh
# check_permissions.sh
# This script uses curl to POST SelfSubjectAccessReview objects to the API
# to enumerate allowed actions using the service account token.

# Read the service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Set the API server based on environment variables provided in-cluster.
API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# Function to check permission for a specific verb/resource.
check_permission() {
  local verb=$1
  local resource=$2
  local group=${3:-""}
  local namespace=${4:-""}
  
  echo "Checking permission: verb=${verb} resource=${resource} group=${group} namespace=${namespace}"
  
  RESPONSE=$(cat <<EOF | curl -sk -X POST "$API_SERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d @- )
{
  "kind": "SelfSubjectAccessReview",
  "apiVersion": "authorization.k8s.io/v1",
  "spec": {
    "resourceAttributes": {
      "namespace": "$namespace",
      "verb": "$verb",
      "resource": "$resource",
      "group": "$group"
    }
  }
}
EOF

  echo "$RESPONSE" | jq .
  echo ""
}

# Ensure jq is present. If not, try installing it (if allowed) or simply output the raw JSON response.
if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found, outputting raw JSON"
  alias jq=cat
fi

# Check if we can patch deployments (apps group)
check_permission "patch" "deployments" "apps" "internal"

# Check if we can create pods (core group, resource: pods)
check_permission "create" "pods" "" "internal"

# Check if we can list PVCs (core group, resource: persistentvolumeclaims)
check_permission "list" "persistentvolumeclaims" "" "internal"
