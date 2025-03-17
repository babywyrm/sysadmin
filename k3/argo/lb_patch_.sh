#!/bin/bash
set -euo pipefail

# =========================================================
# This script will:
# 1. Create the Argo CD namespace.
# 2. Install Argo CD from the official manifests.
# 3. Wait for core components to come online.
# 4. Patch the Argo CD ConfigMap to set the external URL.
# 5. Patch the Argo CD server Service to type LoadBalancer.
#
# With MetalLB installed in your cluster, the LoadBalancer service
# will be assigned an external IP, allowing access from anywhere
# on your local network.
#
# =========================================================

# Variables - update these as needed.
ARGO_NAMESPACE="argocd"
DOMAIN="core.example.net"    # Set your external domain (or use an IP)
# Note: Do not include protocol (https://) here.

echo "===== Creating namespace '${ARGO_NAMESPACE}' ====="
kubectl create namespace "${ARGO_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "===== Installing Argo CD manifests ====="
# Install Argo CD (stable manifests from the official repository)
kubectl apply -n "${ARGO_NAMESPACE}" -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

echo "===== Waiting for Argo CD core pods to be available ====="
kubectl wait --namespace "${ARGO_NAMESPACE}" --for=condition=Ready pod \
  --selector=app.kubernetes.io/name=argocd-server --timeout=300s

echo "===== Patching Argo CD ConfigMap with external URL ====="
kubectl patch configmap argocd-cm -n "${ARGO_NAMESPACE}" \
  -p "{\"data\": {\"url\": \"https://${DOMAIN}\"}}"

echo "===== Patching Argo CD server Service to type LoadBalancer ====="
kubectl patch svc argocd-server -n "${ARGO_NAMESPACE}" -p '{"spec": {"type": "LoadBalancer"}}'

echo "===== Argo CD installation complete ====="
echo "Your Argo CD server is now exposed via a LoadBalancer."
echo "Wait for MetalLB to assign an external IP by running:"
echo "    kubectl get svc -n ${ARGO_NAMESPACE}"
echo "Then, access Argo CD at: https://${DOMAIN}"

##
##
