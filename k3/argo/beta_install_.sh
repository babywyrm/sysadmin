#!/bin/bash
set -euo pipefail

# Variables - adjust as needed
ARGO_NAMESPACE="argocd"
EXTERNAL_DOMAIN="core.example.net"  # Replace with your external domain or use your MetalLB external IP.
TLS_SECRET="argo-cd-tls"            # The pre-created TLS secret (with tls.crt and tls.key)

echo "===== Removing leftover Ingress resources ====="
kubectl delete ingress --all -n "${ARGO_NAMESPACE}" || true

echo "===== Creating namespace '${ARGO_NAMESPACE}' if not exists ====="
kubectl create namespace "${ARGO_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "===== Installing Argo CD from Official Manifests ====="
kubectl apply -n "${ARGO_NAMESPACE}" -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

echo "===== Waiting for Argo CD server pods to be ready ====="
kubectl wait --namespace "${ARGO_NAMESPACE}" --for=condition=Ready pod \
  --selector=app.kubernetes.io/name=argocd-server --timeout=300s

echo "===== Patching Argo CD ConfigMap with external URL ====="
kubectl patch configmap argocd-cm -n "${ARGO_NAMESPACE}" \
  -p "{\"data\": {\"url\": \"https://${EXTERNAL_DOMAIN}\"}}"

echo "===== Patching Argo CD Server Service to type LoadBalancer ====="
kubectl patch svc argocd-server -n "${ARGO_NAMESPACE}" -p '{"spec": {"type": "LoadBalancer"}}'

echo "===== Verifying LoadBalancer Service ====="
kubectl get svc -n "${ARGO_NAMESPACE}" argocd-server

# Check if TLS volume is mounted (expected at /app/config/tls)
echo "===== Verifying TLS Volume Mount in argocd-server Deployment ====="
kubectl get deployment argocd-server -n "${ARGO_NAMESPACE}" -o jsonpath='{.spec.template.spec.containers[0].volumeMounts[?(@.mountPath=="\/app\/config\/tls")].name}'
echo

# Since our deployment already mounts the TLS secret (named, e.g., "tls-certs"), we patch the deployment
# to add TLS certificate arguments. Adjust the mount path if your certificate is mounted elsewhere.
echo "===== Patching Argo CD Server Deployment for TLS ====="
kubectl patch deployment argocd-server -n "${ARGO_NAMESPACE}" --type=json -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/args/-",
    "value": "--tls-cert=/app/config/tls/tls.crt"
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/args/-",
    "value": "--tls-key=/app/config/tls/tls.key"
  }
]'

echo "===== Restarting Argo CD Server Deployment ====="
kubectl rollout restart deployment argocd-server -n "${ARGO_NAMESPACE}"
kubectl rollout status deployment argocd-server -n "${ARGO_NAMESPACE}"

echo "===== Argo CD Reinstallation/Configuration Complete ====="
echo "Check the external IP (assigned by MetalLB) for the argocd-server service:"
kubectl get svc -n "${ARGO_NAMESPACE}" argocd-server

echo "Now, try accessing Argo CD:"
echo "HTTP:  http://${EXTERNAL_DOMAIN} or the external IP on port 80"
echo "HTTPS: https://${EXTERNAL_DOMAIN} or the external IP on port 443 (use -k with curl if self-signed)"
