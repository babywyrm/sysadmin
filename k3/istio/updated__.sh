#!/bin/bash

############
# Description: K3s and Istio installation script with enhanced flexibility and security.
# not tested nearly enough
############

# Check for root permissions
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Please run as root."
    exit 1
fi

# Function to get the latest release from GitHub
get_latest_release() {
    local repo="$1"
    curl --silent "https://api.github.com/repos/$repo/releases/latest" | 
    grep '"tag_name":' | 
    sed -E 's/.*"([^"]+)".*/\1/'
}

# Function to clear the Trivy cache
clear_trivy_cache() {
    echo "Clearing Trivy cache..."
    if ! trivy clean --all; then
        echo "Failed to clean Trivy cache."
        exit 1
    fi
}

# Function to install K3s
install_k3s() {
    echo "Installing K3s..."
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--no-deploy=servicelb --disable traefik --disable local-storage" sh -s - --cluster-cidr=10.240.0.0/16 --service-cidr=10.110.0.0/16 --node-name="$(hostname)" --tls-san="$(curl -s ifconfig.me)" --kube-proxy-arg proxy-mode=ipvs
}

# Function to check if K3s is installed
check_k3s_installed() {
    if [ -f /etc/rancher/k3s/k3s.yaml ]; then
        echo "K3s is already installed."
        return 0
    fi
    return 1
}

# Function to configure K3s
configure_k3s() {
    echo "Configuring K3s..."
    # Additional configuration steps can be added here
}

# Function to install Istio
install_istio() {
    local istio_ver
    istio_ver=$(get_latest_release istio/istio)
    echo "Installing Istio version $istio_ver..."
    wget "https://github.com/istio/istio/releases/download/$istio_ver/istio-$istio_ver-linux-amd64.tar.gz"
    tar -xvzf "istio-$istio_ver-linux-amd64.tar.gz"
    cp -r "istio-$istio_ver/bin/istioctl" /usr/local/bin/
}

# Function to create a service account and role binding
create_service_account() {
    local namespace="$1"
    echo "Creating service account in namespace: $namespace..."
    kubectl -n "$namespace" create serviceaccount "$(hostname)"
    kubectl create clusterrolebinding "$(hostname)" --clusterrole=cluster-admin --serviceaccount="$namespace:$(hostname)"
}

# Main script execution
main() {
    # Check if K3s is installed
    if check_k3s_installed; then
        echo "K3s installation check passed."
    else
        install_k3s
        configure_k3s
    fi

    # Install Istio
    install_istio

    # Create service accounts and role bindings
    create_service_account "argo"  # Example namespace, adjust as needed

    echo "Installation and configuration complete."
}

# Run the main function
main "$@"

##
##
