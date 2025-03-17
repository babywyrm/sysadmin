#!/bin/bash
set -e

# --- Configuration ---
K3S_VERSION="v1.29.3+k3s1"
INTERFACE_NAME="eth0" # Replace with your actual interface name
NODE_IP=$(ip addr show "$INTERFACE_NAME" | grep "inet " | awk '{print $2}' | cut -d'/' -f1)

# --- Helper Functions ---
section() {
    echo -e "\n\033[1;32m[+] $1\033[0m"
}

error() {
    echo -e "\e[1;31m[ERROR] $1\e[0m"
    exit 1
}

# --- Installation Functions ---

rollback_k3s() {
    section "Rolling back K3s"
    # Stop the k3s service if it's running
    sudo systemctl stop k3s.service 2>/dev/null || true

    # Uninstall k3s (using the official uninstall script)
    if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
        sudo /usr/local/bin/k3s-uninstall.sh 2>/dev/null || true
    fi

    # Remove k3s directories and files (be CAREFUL with this)
    sudo rm -rf /etc/rancher/k3s /var/lib/rancher/k3s /usr/local/bin/k3s*

    # Reset systemd
    sudo systemctl reset-failed 2>/dev/null || true
    sudo systemctl daemon-reload 2>/dev/null || true

    echo "K3s rollback complete."
}

install_k3s() {
    section "Installing K3s"

    # Check if NODE_IP is empty
    if [ -z "$NODE_IP" ]; then
        echo "NODE_IP is empty!  Please set it manually."
        read -p "Enter the IP address for the K3s node: " NODE_IP
        if [ -z "$NODE_IP" ]; then
          error "NODE_IP is still empty! Cannot proceed."
        fi
    fi

    curl -sLS https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_VERSION="$K3S_VERSION" sh -s server --disable traefik --node-ip="$NODE_IP"

    # Verify K3s is running
    sleep 30 # give it time to come up
    kubectl get nodes
    if [[ $? -ne 0 ]]; then
      error "K3s installation failed. Check logs."
    fi
}

install_kubectl_kustomize() {
  section "Installing kubectl and kustomize"
  # Check if kubectl is already installed
  if ! command -v kubectl &> /dev/null; then
    echo "kubectl not found. Installing..."
    curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/
  else
    echo "kubectl already installed."
  fi

  # Check if kustomize is already installed
  if ! command -v kustomize &> /dev/null; then
    echo "kustomize not found. Installing..."
    curl -LO "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.2.1/kustomize_v5.2.1_linux_amd64"
    chmod +x kustomize_v5.2.1_linux_amd64
    mv kustomize_v5.2.1_linux_amd64 /usr/local/bin/kustomize
  else
    echo "kustomize already installed."
  fi
}

# --- Main Script ---
main() {
    section "Starting Bootstrap Script"

    rollback_k3s
    install_k3s
    install_kubectl_kustomize

    section "Bootstrap Complete!"
    echo "Next steps:"
    echo "Run the deploy.sh script to install the remaining components."
}

main  # Run main lol
