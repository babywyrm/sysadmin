#!/usr/bin/env bash
# teardown.sh – Remove Project-X from GKE or EKS ..testing..testing..
# Preconditions:
#   • CLI tools: gcloud, eksctl, aws, kubectl, helm
#   • .env[.${ENV}] file in this directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[INFO] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1; }

# ------------------------------------------------------------------------------
# 0) Load environment variables
# ------------------------------------------------------------------------------
ENV_FILE="${SCRIPT_DIR}/.env"
[[ -n "${ENV:-}" && -f "${SCRIPT_DIR}/.env.${ENV}" ]] && ENV_FILE="${SCRIPT_DIR}/.env.${ENV}"

[[ -f "${ENV_FILE}" ]] || err ".env file not found in ${ENV_FILE}"
# shellcheck disable=SC1090
source "${ENV_FILE}"

required_vars=( CLOUD_PROVIDER CLUSTER_NAME ENV )
for var in "${required_vars[@]}"; do
  [[ -n "${!var:-}" ]] || err "Missing required environment variable: $var"
done

# ------------------------------------------------------------------------------
# 1) Delete Kustomize overlays
# ------------------------------------------------------------------------------
log "Deleting Kustomize overlay: ${ENV}"
kubectl delete -k "infra/kustomize/overlays/${ENV}" || true
kubectl delete -k infra/kustomize/base || true

# ------------------------------------------------------------------------------
# 2) Delete Ambassador
# ------------------------------------------------------------------------------
log "Uninstalling Ambassador Edge Stack"
helm uninstall ambassador -n ambassador || true
kubectl delete ns ambassador --ignore-not-found

# ------------------------------------------------------------------------------
# 3) Delete OPA Gatekeeper
# ------------------------------------------------------------------------------
log "Uninstalling OPA Gatekeeper"
helm uninstall gatekeeper -n gatekeeper-system || true
kubectl delete ns gatekeeper-system --ignore-not-found

# ------------------------------------------------------------------------------
# 4) Delete Istio
# ------------------------------------------------------------------------------
log "Uninstalling Istio"
istioctl uninstall -y --purge || true
kubectl delete ns istio-system --ignore-not-found

# ------------------------------------------------------------------------------
# 5) Delete SPIRE
# ------------------------------------------------------------------------------
log "Uninstalling SPIRE"
helm uninstall spire-server -n spire-system || true
helm uninstall spire-agent -n spire-system || true
kubectl delete ns spire-system --ignore-not-found

# ------------------------------------------------------------------------------
# 6) Delete project namespaces
# ------------------------------------------------------------------------------
log "Deleting Project-X namespaces"
for ns in project-x-challenges project-x-infra; do
  kubectl delete ns "${ns}" --ignore-not-found
done

# ------------------------------------------------------------------------------
# 7) Delete Kubernetes secrets
# (already removed with namespaces, but included for safety)
# ------------------------------------------------------------------------------
log "Cleaning up secrets (if any remain)"
kubectl delete secret jwt-keys -n project-x-infra --ignore-not-found || true
kubectl delete secret cosign-pubkey -n project-x-infra --ignore-not-found || true

# ------------------------------------------------------------------------------
# 8) Optionally delete the cluster itself
# ------------------------------------------------------------------------------
if [[ "${DELETE_CLUSTER:-false}" == "true" ]]; then
  if [[ "${CLOUD_PROVIDER}" == "gke" ]]; then
    : "${GCP_PROJECT:?}"; : "${GCP_ZONE:?}"
    log "Deleting GKE cluster '${CLUSTER_NAME}' in ${GCP_ZONE}"
    gcloud container clusters delete "${CLUSTER_NAME}" \
      --project "${GCP_PROJECT}" \
      --zone "${GCP_ZONE}" \
      --quiet || true

  elif [[ "${CLOUD_PROVIDER}" == "eks" ]]; then
    : "${AWS_REGION:?}"
    log "Deleting EKS cluster '${CLUSTER_NAME}' in ${AWS_REGION}"
    eksctl delete cluster \
      --name "${CLUSTER_NAME}" \
      --region "${AWS_REGION}" || true
  fi
else
  log "Cluster deletion skipped (set DELETE_CLUSTER=true to enable)"
fi

log "Teardown complete."
