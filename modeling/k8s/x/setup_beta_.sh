#!/usr/bin/env bash
# bootstrap.sh – Bootstrap Project-X on GKE or EKS .. v2 beta ..
# Preconditions:
#   • CLI tools: gcloud, eksctl, aws, kubectl, helm, istioctl
#   • .env[.${ENV}] file with required variables

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo -e "🔹 $*"; }
err() { echo -e "❌ $*" >&2; exit 1; }

# ------------------------------------------------------------------------------
# 0) Load environment variables
# ------------------------------------------------------------------------------
ENV_FILE="${SCRIPT_DIR}/.env"
[[ -n "${ENV:-}" && -f "${SCRIPT_DIR}/.env.${ENV}" ]] && ENV_FILE="${SCRIPT_DIR}/.env.${ENV}"

[[ -f "${ENV_FILE}" ]] || err ".env file not found in ${ENV_FILE}"
# shellcheck disable=SC1090
source "${ENV_FILE}"

required_vars=(
  CLOUD_PROVIDER CLUSTER_NAME NODE_COUNT NODE_MACHINE_TYPE ENV
  PROJECT_X_DOMAIN TRUST_DOMAIN JWT_PRIVATE_KEY JWT_PUBLIC_KEY
  COSIGN_PUBKEY IMAGE_REGISTRY
)
for var in "${required_vars[@]}"; do
  [[ -n "${!var:-}" ]] || err "Missing required environment variable: $var"
done

# ------------------------------------------------------------------------------
# 1) Cluster provisioning
# ------------------------------------------------------------------------------
if [[ "${CLOUD_PROVIDER}" == "gke" ]]; then
  : "${GCP_PROJECT:?}"; : "${GCP_ZONE:?}"
  log "Provisioning GKE cluster '${CLUSTER_NAME}' in zone ${GCP_ZONE}"

  gcloud container clusters create "${CLUSTER_NAME}" \
    --project="${GCP_PROJECT}" \
    --zone="${GCP_ZONE}" \
    --release-channel "regular" \
    --num-nodes="${NODE_COUNT}" \
    --machine-type="${NODE_MACHINE_TYPE}" \
    --enable-ip-alias \
    --enable-autoscaling --min-nodes=1 --max-nodes="${NODE_COUNT}" \
    --enable-shielded-nodes \
    --workload-pool="${GCP_PROJECT}.svc.id.goog" || log "Cluster may already exist"

  gcloud container clusters get-credentials "${CLUSTER_NAME}" \
    --zone="${GCP_ZONE}" --project="${GCP_PROJECT}"

elif [[ "${CLOUD_PROVIDER}" == "eks" ]]; then
  : "${AWS_REGION:?}"
  log "Provisioning EKS cluster '${CLUSTER_NAME}' in region ${AWS_REGION}"

  eksctl create cluster \
    --name "${CLUSTER_NAME}" \
    --region "${AWS_REGION}" \
    --nodegroup-name "project-x-nodes" \
    --node-type "${NODE_MACHINE_TYPE}" \
    --nodes "${NODE_COUNT}" \
    --with-oidc \
    --managed || log "Cluster may already exist"

  aws eks update-kubeconfig --region "${AWS_REGION}" --name "${CLUSTER_NAME}"

else
  err "CLOUD_PROVIDER must be 'gke' or 'eks'"
fi

# ------------------------------------------------------------------------------
# 2) Namespaces
# ------------------------------------------------------------------------------
log "Creating base namespaces"
namespaces=(
  spire-system:spire
  istio-system:mesh
  ambassador:edge
  gatekeeper-system:policy
  project-x-challenges:app
  project-x-infra:infra
)
for ns in "${namespaces[@]}"; do
  name="${ns%%:*}"; label="${ns##*:}"
  kubectl create namespace "${name}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl label namespace "${name}" purpose="${label}" --overwrite
done
kubectl label namespace project-x-challenges istio-injection=enabled --overwrite

# ------------------------------------------------------------------------------
# 3) Secrets
# ------------------------------------------------------------------------------
log "Creating secrets (JWT + Cosign)"
kubectl -n project-x-infra create secret generic jwt-keys \
  --from-file=private.key="${JWT_PRIVATE_KEY}" \
  --from-file=public.key="${JWT_PUBLIC_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n project-x-infra create secret generic cosign-pubkey \
  --from-file=cosign.pub="${COSIGN_PUBKEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

# ------------------------------------------------------------------------------
# 4) SPIRE
# ------------------------------------------------------------------------------
log "Installing SPIRE"
helm repo add spire https://kubernetes-sigs.github.io/spire-charts
helm repo update
helm upgrade --install spire-server spire/spire-server \
  --namespace spire-system \
  --values config/spire/server-values.yaml
helm upgrade --install spire-agent spire/spire-agent \
  --namespace spire-system \
  --values config/spire/agent-values.yaml

# ------------------------------------------------------------------------------
# 5) Istio
# ------------------------------------------------------------------------------
log "Installing Istio (profile=${ISTIO_PROFILE:-default})"
istioctl install --set profile="${ISTIO_PROFILE:-default}" -y

# ------------------------------------------------------------------------------
# 6) OPA Gatekeeper
# ------------------------------------------------------------------------------
log "Installing OPA Gatekeeper"
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update
helm upgrade --install gatekeeper gatekeeper/gatekeeper --namespace gatekeeper-system
kubectl apply -f config/opa/templates/ || true
kubectl apply -f config/opa/constraints/ || true

# ------------------------------------------------------------------------------
# 7) Ambassador
# ------------------------------------------------------------------------------
log "Installing Ambassador Edge Stack"
helm repo add datawire https://getambassador.io
helm repo update
helm upgrade --install ambassador datawire/ambassador --namespace ambassador --set enableAES=true
kubectl apply -f config/ambassador/ || true

# ------------------------------------------------------------------------------
# 8) Kustomize overlays
# ------------------------------------------------------------------------------
log "Applying Kustomize base and overlay: ${ENV}"
kubectl apply -k infra/kustomize/base
kubectl apply -k "infra/kustomize/overlays/${ENV}"

log "✅ Bootstrap complete!"
log "Next steps:"
log "  • Build and push Docker images to ${IMAGE_REGISTRY}"
log "  • Deploy Auth Service and Challenge Controller manifests"
log "  • Run Phase 1 acceptance tests (login → JWT → session)"

##
##
