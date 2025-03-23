#!/bin/bash

##
## you might want to do something else with loadbalancer + wordpress + patch it with traefik
## or use something else entirely (metallb, nginx-ingress)
## 

set -e

echo "==== CTF Environment Bootstrapper ===="
echo "Setting up K3s, kubectl, Helm and WordPress"
echo "========================================"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to display progress
progress() {
    echo ""
    echo "🔄 $1"
    echo "----------------------------------------"
}

# Function for success message
success() {
    echo "✅ $1"
}

# Function for health check
health_check() {
    echo ""
    echo "🔍 HEALTH CHECK: $1"
    echo "----------------------------------------"
    $2
    if [ $? -eq 0 ]; then
        success "$1 check passed"
    else
        echo "❌ $1 check failed"
        exit 1
    fi
}

# Update system
progress "[1/8] Updating system packages..."
apt-get update && apt-get upgrade -y
success "System updated"

# Install prerequisites
progress "[2/8] Installing prerequisites..."
apt-get install -y curl wget apt-transport-https gnupg lsb-release ca-certificates jq
success "Prerequisites installed"

# Install K3s
progress "[3/8] Installing K3s..."
curl -sfL https://get.k3s.io | sh -

# Wait for K3s to be ready
progress "Waiting for K3s to be ready..."
timeout 120s bash -c 'until systemctl is-active --quiet k3s; do sleep 2; echo -n "."; done'
echo ""
success "K3s installed and running"

# Set up kubectl config
progress "[4/8] Configuring kubectl..."
mkdir -p /root/.kube
cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
chmod 600 /root/.kube/config
export KUBECONFIG=/root/.kube/config
echo "export KUBECONFIG=/root/.kube/config" >> /root/.bashrc

# Health check: K3s nodes
health_check "K3s cluster" "k3s kubectl get nodes"

# Install kubectl
progress "[5/8] Installing kubectl..."
if ! command_exists kubectl; then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/
    success "kubectl installed"
else
    success "kubectl already installed"
fi

# Health check: kubectl
health_check "kubectl" "kubectl version --client"

# Install Helm
progress "[6/8] Installing Helm..."
if ! command_exists helm; then
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 get_helm.sh
    ./get_helm.sh
    rm get_helm.sh
    success "Helm installed"
else
    success "Helm already installed"
fi

# Health check: Helm
health_check "Helm" "helm version"

# Add Bitnami repo for WordPress
progress "[7/8] Adding Bitnami Helm repository..."
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
success "Bitnami repo added"

# Install WordPress
progress "[8/8] Installing WordPress chart..."
# Create namespace
kubectl create namespace wordpress 2>/dev/null || true

# Generate random but memorable passwords
WP_ADMIN_PASS="CTFadmin$(date +%s | sha256sum | base64 | head -c 8)"
WP_DB_ROOT_PASS="CTFdbroot$(date +%s | sha256sum | base64 | head -c 8)"
WP_DB_PASS="CTFdbpass$(date +%s | sha256sum | base64 | head -c 8)"

# Install WordPress with configuration
helm install wordpress bitnami/wordpress \
  --namespace wordpress \
  --set service.type=NodePort \
  --set wordpressUsername=admin \
  --set wordpressPassword="$WP_ADMIN_PASS" \
  --set mariadb.auth.rootPassword="$WP_DB_ROOT_PASS" \
  --set mariadb.auth.password="$WP_DB_PASS" \
  --set persistence.size=1Gi \
  --set mariadb.primary.persistence.size=1Gi
  
success "WordPress Helm chart installed"

# Wait for WordPress to be ready with a nice progress indicator
progress "Waiting for WordPress pods to be ready (this may take a few minutes)..."
echo -n "WordPress MariaDB: "
kubectl -n wordpress wait --for=condition=ready pod --selector=app.kubernetes.io/name=mariadb --timeout=300s
echo -n "WordPress application: "
kubectl -n wordpress wait --for=condition=ready pod --selector=app.kubernetes.io/name=wordpress --timeout=300s

# Health check: WordPress pods
health_check "WordPress pods" "kubectl get pods -n wordpress"

# Health check: WordPress services
health_check "WordPress services" "kubectl get svc -n wordpress"

# Get WordPress access information
NODE_PORT=$(kubectl -n wordpress get svc wordpress -o jsonpath="{.spec.ports[0].nodePort}")
NODE_IP=$(hostname -I | awk '{print $1}')

# Save credentials to a file
CREDS_FILE="/root/wordpress-credentials.txt"
echo "==== WordPress Credentials ====" > $CREDS_FILE
echo "URL: http://$NODE_IP:$NODE_PORT" >> $CREDS_FILE
echo "Admin URL: http://$NODE_IP:$NODE_PORT/wp-admin" >> $CREDS_FILE
echo "Username: admin" >> $CREDS_FILE
echo "Password: $WP_ADMIN_PASS" >> $CREDS_FILE
echo "Database Root Password: $WP_DB_ROOT_PASS" >> $CREDS_FILE
echo "Database Password: $WP_DB_PASS" >> $CREDS_FILE
echo "===========================" >> $CREDS_FILE
chmod 600 $CREDS_FILE

# Display summary
echo ""
echo "🏁 ==== Setup Complete ==== 🏁"
echo ""
echo "📊 WORDPRESS DASHBOARD"
echo "----------------------------------------"
echo "URL: http://$NODE_IP:$NODE_PORT"
echo "Admin URL: http://$NODE_IP:$NODE_PORT/wp-admin"
echo "Username: admin"
echo "Password: $WP_ADMIN_PASS"
echo ""
echo "💾 CREDENTIALS"
echo "----------------------------------------"
echo "All credentials saved to: $CREDS_FILE"
echo ""
echo "🔧 USEFUL COMMANDS"
echo "----------------------------------------"
echo "Check pods: kubectl get pods -n wordpress"
echo "Check services: kubectl get svc -n wordpress"
echo "WordPress logs: kubectl logs -n wordpress \$(kubectl get pods -n wordpress -l app.kubernetes.io/name=wordpress -o jsonpath='{.items[0].metadata.name}')"
echo "Database logs: kubectl logs -n wordpress \$(kubectl get pods -n wordpress -l app.kubernetes.io/name=mariadb -o jsonpath='{.items[0].metadata.name}')"
echo ""
echo "To monitor WordPress container health:"
echo "kubectl exec -n wordpress \$(kubectl get pods -n wordpress -l app.kubernetes.io/name=wordpress -o jsonpath='{.items[0].metadata.name}') -- curl -s localhost:8080"
echo ""
echo "🚀 This environment is now ready for CTF activities!"
echo "========================================================"

# Test WordPress connectivity (nonfatal)
echo ""
echo "🔄 Testing WordPress accessibility..."
if command_exists curl; then
    if curl -s --max-time 5 "http://$NODE_IP:$NODE_PORT" | grep -q "WordPress"; then
        echo "✅ WordPress is accessible! You can log in now."
    else
        echo "⚠️ WordPress site exists but still initializing. Try accessing it in a few minutes."
    fi
else
    echo "⚠️ curl not available. Please check manually: http://$NODE_IP:$NODE_PORT"
fi
