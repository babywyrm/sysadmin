#!/bin/sh
# check_all_permissions_summary.sh
# This script enumerates RBAC permissions via SelfSubjectAccessReviews,
# collects all allowed actions, and prints a summary at the end.
# It uses curl and basic text processing (no jq required).

# Retrieve the service account token.
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Construct the API server URL using in-cluster environment variables.
API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
echo "API Server: $API_SERVER"
echo ""

# Define verbs and resources to check.
verbs="get list watch create update patch delete"
resources="pods deployments services configmaps secrets persistentvolumeclaims events endpoints ingresses jobs cronjobs statefulsets daemonsets replicasets"

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
    *)
      echo ""
      ;;
  esac
}

NS="internal"

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
    # Store the allowed action in our summary variable.
    allowed_actions="${allowed_actions}\nVerb: $verb, Resource: $resource, Group: $group"
  else
    echo "=> Denied"
  fi

  echo "Raw response: $(echo "$response" | tr -d '\n' | cut -c1-200)..."
  echo ""
}

# Loop over each combination of verb and resource.
for res in $resources; do
  for verb in $verbs; do
    check_permission "$verb" "$res"
  done
done

echo "------------------------------------------"
echo "Permission Enumeration Summary:"
if [ -n "$allowed_actions" ]; then
  echo "The following permissions are allowed:"
  # Print the allowed actions.
  echo -e "$allowed_actions"
else
  echo "No allowed actions were found."
fi

echo "------------------------------------------"
echo "Permission enumeration complete."
