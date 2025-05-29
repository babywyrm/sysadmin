#!/usr/bin/env bash
# bootstrap.sh – Bootstrap Project-X on GKE or EKS
# Preconditions:
#   • Install CLI tools: gcloud, eksctl, aws, kubectl, helm, istioctl
#   • Create a `.env` file in this directory with required variables

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment variables from .env
if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
  echo "ERROR: .env file not found in ${SCRIPT_DIR}"
  exit 1
fi
# shellcheck disable=SC1090
source "${SCRIPT_DIR}/.env"

# Validate required environment variables
required_vars=(
  CLOUD_PROVIDER CLUSTER_NAME NODE_COUNT NODE_MACHINE_TYPE ENV
  PROJECT_X_DOMAIN TRUST_DOMAIN JWT_PRIVATE_KEY JWT_PUBLIC_KEY
  COSIGN_PUBKEY IMAGE_REGISTRY
)
for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: environment variable '$var' is not set"
    exit 1
  fi
done

# ------------------------------------------------------------------------------
# 1) Create or connect to Kubernetes cluster
# ------------------------------------------------------------------------------

if [[ "${CLOUD_PROVIDER}" == "gke" ]]; then
  # GKE configuration variables
  : "${GCP_PROJECT:?}"
  : "${GCP_ZONE:?}"

  echo "Creating or updating GKE cluster '${CLUSTER_NAME}' in zone ${GCP_ZONE}"
  gcloud container clusters create "${CLUSTER_NAME}" \
    --project="${GCP_PROJECT}" \
    --zone="${GCP_ZONE}" \
    --release-channel "regular" \
    --num-nodes="${NODE_COUNT}" \
    --machine-type="${NODE_MACHINE_TYPE}" \
    --enable-ip-alias \
    --enable-autoscaling --min-nodes=1 --max-nodes="${NODE_COUNT}"
  echo "Fetching GKE credentials"
  gcloud container clusters get-credentials "${CLUSTER_NAME}" \
    --zone="${GCP_ZONE}" --project="${GCP_PROJECT}"

elif [[ "${CLOUD_PROVIDER}" == "eks" ]]; then
  # EKS configuration variables
  : "${AWS_REGION:?}"

  echo "Creating or updating EKS cluster '${CLUSTER_NAME}' in region ${AWS_REGION}"
  eksctl create cluster \
    --name "${CLUSTER_NAME}" \
    --region "${AWS_REGION}" \
    --nodegroup-name "project-x-nodes" \
    --node-type "${NODE_MACHINE_TYPE}" \
    --nodes "${NODE_COUNT}" \
    --managed
  echo "Updating kubeconfig for EKS"
  aws eks update-kubeconfig \
    --region "${AWS_REGION}" \
    --name "${CLUSTER_NAME}"

else
  echo "ERROR: CLOUD_PROVIDER must be 'gke' or 'eks'"
  exit 1
fi

# ------------------------------------------------------------------------------
# 2) Create base namespaces
# ------------------------------------------------------------------------------
echo "Creating base namespaces"
namespaces=(
  spire-system
  istio-system
  ambassador
  gatekeeper-system
  project-x-challenges
  project-x-infra
)
for ns in "${namespaces[@]}"; do
  kubectl create namespace "${ns}" \
    --dry-run=client -o yaml | kubectl apply -f -
done

# ------------------------------------------------------------------------------
# 3) Create Kubernetes Secrets for JWT and Cosign keys
# ------------------------------------------------------------------------------
echo "Creating secrets for JWT and Cosign keys"
kubectl -n project-x-infra create secret generic jwt-keys \
  --from-file=private.key="${JWT_PRIVATE_KEY}" \
  --from-file=public.key="${JWT_PUBLIC_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n project-x-infra create secret generic cosign-pubkey \
  --from-file=cosign.pub="${COSIGN_PUBKEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

# ------------------------------------------------------------------------------
# 4) Install SPIRE (server and agent) via Helm
# ------------------------------------------------------------------------------
echo "Installing SPIRE Server and Agent"
helm repo add spire https://kubernetes-sigs.github.io/spire-charts
helm repo update

helm install spire-server spire/spire-server \
  --namespace spire-system \
  --values config/spire/server-values.yaml

helm install spire-agent spire/spire-agent \
  --namespace spire-system \
  --values config/spire/agent-values.yaml

# ------------------------------------------------------------------------------
# 5) Install Istio Service Mesh
# ------------------------------------------------------------------------------
echo "Installing Istio"
istioctl install --set profile=default -y

# Enable automatic sidecar injection for challenge namespace
kubectl label namespace project-x-challenges \
  istio-injection=enabled --overwrite

# ------------------------------------------------------------------------------
# 6) Install OPA Gatekeeper
# ------------------------------------------------------------------------------
echo "Installing OPA Gatekeeper"
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update

helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system

# Apply Gatekeeper ConstraintTemplates and Constraints
kubectl apply -f config/opa/templates/
kubectl apply -f config/opa/constraints/

# ------------------------------------------------------------------------------
# 7) Install Ambassador Edge Stack
# ------------------------------------------------------------------------------
echo "Installing Ambassador Edge Stack"
helm repo add datawire https://getambassador.io
helm repo update

helm install ambassador datawire/ambassador \
  --namespace ambassador

# Apply Ambassador AuthService and Mappings
kubectl apply -f config/ambassador/

# ------------------------------------------------------------------------------
# 8) Deploy base Kustomize manifests
# ------------------------------------------------------------------------------
echo "Applying base Kustomize configuration"
kubectl apply -k infra/kustomize/base

# Deploy environment-specific overlay (dev or prod)
echo "Applying '${ENV}' overlay"
kubectl apply -k "infra/kustomize/overlays/${ENV}"

echo "Bootstrap complete. Next steps:"
echo "  • Build and push your Docker images to ${IMAGE_REGISTRY}"
echo "  • Deploy Auth Service and Challenge Controller manifests"
echo "  • Proceed with Phase 1 acceptance tests (login → JWT → session)"

##
##
