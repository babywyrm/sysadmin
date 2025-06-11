#!/bin/bash
set -e

# --- Configuration ---
# The path to your HelmChart manifest.
GATEKEEPER_MANIFEST_SRC="./gatekeeper-helm-chart.yaml"
# The K3s auto-deploy directory.
K3S_MANIFESTS_DIR="/var/lib/rancher/k3s/server/manifests"
# Namespace where Gatekeeper will be installed.
GATEKEEPER_NAMESPACE="gatekeeper-system"

# --- Colors for better output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---
info() {
  echo -e "${BLUE}INFO: $1${NC}"
}

success() {
  echo -e "${GREEN}SUCCESS: $1${NC}"
}

warn() {
  echo -e "${YELLOW}WARN: $1${NC}"
}

# --- Script Logic ---

main() {
  preflight_checks
  install_k3s_with_gatekeeper
  verify_installation
  show_next_steps
}

preflight_checks() {
  info "Running pre-flight checks..."
  if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root or with sudo." >&2
    exit 1
  fi

  if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed. Please install it first." >&2
    exit 1
  fi

  if [[ ! -f "${GATEKEEPER_MANIFEST_SRC}" ]]; then
    echo "Error: Gatekeeper manifest not found at '${GATEKEEPER_MANIFEST_SRC}'" >&2
    exit 1
  fi
  success "Pre-flight checks passed."
}

install_k3s_with_gatekeeper() {
  info "--- Starting K3s and Gatekeeper Installation ---"

  info "Preparing K3s auto-deploy directory at ${K3S_MANIFESTS_DIR}..."
  mkdir -p "${K3S_MANIFESTS_DIR}"

  info "Copying Gatekeeper HelmChart manifest..."
  cp "${GATEKEEPER_MANIFEST_SRC}" "${K3S_MANIFESTS_DIR}/"

  info "Installing K3s server via the official installer..."
  info "K3s will automatically detect the manifest and deploy Gatekeeper."
  curl -sfL https://get.k3s.io | sh -

  success "K3s installation script has finished."
}

verify_installation() {
  info "--- Verifying Gatekeeper Installation ---"
  info "K3s is starting. This may take a minute..."
  info "Making kubeconfig readable..."
  chmod 644 /etc/rancher/k3s/k3s.yaml

  # Wait for the Kubernetes API to be ready
  until kubectl get nodes &> /dev/null; do
    info "Waiting for Kubernetes API server to be available..."
    sleep 5
  done

  info "Waiting for Gatekeeper pods to be ready in namespace '${GATEKEEPER_NAMESPACE}'..."
  # Timeout after 3 minutes (180 seconds)
  local timeout=180
  local end_time=$((SECONDS + timeout))

  while [[ $SECONDS -lt $end_time ]]; do
    # Check if the namespace exists yet
    if ! kubectl get namespace "${GATEKEEPER_NAMESPACE}" &> /dev/null; then
      sleep 5
      continue
    fi

    # Get the status of pods
    local ready_pods
    ready_pods=$(
      kubectl get pods -n "${GATEKEEPER_NAMESPACE}" -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null |
        grep -o True |
        wc -l
    )
    local total_pods
    total_pods=$(
      kubectl get pods -n "${GATEKEEPER_NAMESPACE}" -o 'jsonpath={.items[*].metadata.name}' 2>/dev/null |
        wc -w
    )

    if [[ "${total_pods}" -gt 0 && "${ready_pods}" -eq "${total_pods}" ]]; then
      success "All ${total_pods} Gatekeeper pods are running and ready!"
      kubectl get pods -n "${GATEKEEPER_NAMESPACE}"
      return
    fi

    info "Waiting... (${ready_pods}/${total_pods} pods ready)"
    sleep 10
  done

  warn "Verification timed out after ${timeout} seconds."
  echo "Please check the status of the pods manually:"
  echo "  kubectl get pods -n ${GATEKEEPER_NAMESPACE}"
  echo "And check the K3s logs for errors:"
  echo "  sudo journalctl -u k3s -f"
  exit 1
}

show_next_steps() {
  KUBECONFIG_PATH="/etc/rancher/k3s/k3s.yaml"
  info "--- Your K3s Cluster with Gatekeeper is Ready! ---"
  echo
  success "Gatekeeper was successfully deployed via the K3s auto-deploy mechanism."
  echo
  info "To manage your cluster, use kubectl. You can either:"
  echo "1. Use the full path:"
  echo "   sudo kubectl get pods --all-namespaces"
  echo
  echo "2. Or, export the KUBECONFIG environment variable for your session:"
  warn "   export KUBECONFIG=${KUBECONFIG_PATH}"
  echo "   kubectl get nodes"
  echo
  info "--- Test Gatekeeper with a Policy ---"
  echo "1. Create a ConstraintTemplate (e.g., k8srequiredlabels.yaml) to require labels."
  echo "2. Create a Constraint (e.g., ns-must-have-owner.yaml) to enforce the template on namespaces."
  echo "3. Try to create a namespace that violates the policy:"
  warn "   kubectl create namespace my-test-ns"
  echo "   (This should be DENIED by Gatekeeper)"
  echo
  success "Bootstrap complete. Happy governing!"
}

# --- Run the main function ---
main
