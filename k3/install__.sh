#!/usr/bin/env bash

##
## Enhanced K3s Installation Script
## Supports: Master/Worker nodes, HA clusters, optional Rancher deployment
##

set -euo pipefail

# Logging setup
readonly LOG_FILE="/var/log/k3s-install-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "${LOG_FILE}")
exec 2>&1

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

error() {
    log "ERROR: $*" >&2
    exit 1
}

# Check root privileges
if (( EUID != 0 )); then
    error "Script must be run as root. Use: sudo -E $0"
fi

# Configuration variables
readonly K3S_VERSION="${K3S_VERSION:-v1.30.0+k3s1}"
readonly CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.14.0}"
readonly RANCHER_VERSION="${RANCHER_VERSION:-2.8.0}"

# State options
readonly MOUNTPOINT="${MOUNTPOINT:-/data1}"
readonly STATE_DIR="${MOUNTPOINT}/k3s"

# Rancher configuration
readonly RANCHER_LETSENCRYPT_ENV="${RANCHER_LETSENCRYPT_ENVIRONMENT:-staging}"
readonly RANCHER_LETSENCRYPT_EMAIL="${RANCHER_LETSENCRYPT_EMAIL:-admin@example.com}"
readonly RANCHER_HOSTNAME="${RANCHER_HOSTNAME:-rancher.local}"
readonly RANCHER_TLS_SOURCE="${RANCHER_TLS_SOURCE:-letsEncrypt}"

# Feature flags
readonly SKIP_RANCHER_INSTALL="${SKIP_RANCHER_INSTALL:-false}"
readonly DISABLE_DISTRIBUTED_DB="${DISABLE_DISTRIBUTED_DB:-false}"
readonly ENABLE_SELINUX="${ENABLE_SELINUX:-false}"

# Network configuration
readonly K3S_HOST="${K3S_HOST:-}"
readonly K3S_TOKEN="${K3S_TOKEN:-}"
readonly K3S_URL="${K3S_URL:-}"

: <<'USAGE'
# Master/Server Node Installation
sudo -E MOUNTPOINT=/data1 ./install-k3s-enhanced.sh

# Skip Rancher Installation
sudo -E SKIP_RANCHER_INSTALL=true ./install-k3s-enhanced.sh

# Worker/Agent Node Installation
export K3S_HOST=192.168.1.10
export K3S_TOKEN=K10abc123...
export SKIP_RANCHER_INSTALL=true
sudo -E ./install-k3s-enhanced.sh

# HA Cluster (Additional Server Nodes)
export K3S_HOST=192.168.1.10
export K3S_TOKEN=K10abc123...
sudo -E ./install-k3s-enhanced.sh

# Single Node (No Embedded Distributed DB)
sudo -E DISABLE_DISTRIBUTED_DB=true ./install-k3s-enhanced.sh
USAGE

#------------------------------------------------------------------------------
# Pre-flight Checks
#------------------------------------------------------------------------------

preflight_checks() {
    log "Running pre-flight checks..."
    
    # Check if mountpoint exists and is mounted
    if ! mountpoint -q "${MOUNTPOINT}"; then
        error "Mountpoint ${MOUNTPOINT} is not mounted"
    fi
    
    # Check available disk space (minimum 10GB)
    local available_space
    available_space=$(df -BG "${MOUNTPOINT}" | awk 'NR==2 {print $4}' | sed 's/G//')
    if (( available_space < 10 )); then
        error "Insufficient disk space. Minimum 10GB required, found ${available_space}GB"
    fi
    
    # Check network connectivity
    if ! curl -sf --max-time 5 https://get.k3s.io > /dev/null; then
        error "Cannot reach K3s installation endpoint. Check network connectivity"
    fi
    
    log "Pre-flight checks passed"
}

#------------------------------------------------------------------------------
# System Preparation
#------------------------------------------------------------------------------

install_prerequisites() {
    log "Installing prerequisites..."
    
    if command -v yum &>/dev/null; then
        yum clean all
        yum install -y \
            iscsi-initiator-utils \
            nfs-utils \
            curl \
            wget \
            tar \
            gzip
        
        if [[ "${ENABLE_SELINUX}" == "true" ]]; then
            yum install -y container-selinux selinux-policy-base
            rpm -i https://rpm.rancher.io/k3s-selinux-0.2-2.el7.noarch.rpm || true
        fi
    elif command -v apt-get &>/dev/null; then
        apt-get update
        apt-get install -y \
            open-iscsi \
            nfs-common \
            curl \
            wget \
            tar \
            gzip
    else
        error "Unsupported package manager. Only yum and apt-get are supported"
    fi
    
    # Enable and start iSCSI service
    systemctl enable --now iscsid || true
    
    log "Prerequisites installed successfully"
}

#------------------------------------------------------------------------------
# K3s Installation
#------------------------------------------------------------------------------

determine_node_type() {
    if [[ -z "${K3S_HOST}" ]]; then
        echo "server"
    else
        if [[ "${DISABLE_DISTRIBUTED_DB}" == "true" ]]; then
            echo "agent"
        else
            echo "server"
        fi
    fi
}

configure_k3s_installation() {
    local node_type
    node_type=$(determine_node_type)
    
    export INSTALL_K3S_VERSION="${K3S_VERSION}"
    export INSTALL_K3S_SKIP_START=true
    
    if [[ "${node_type}" == "server" ]]; then
        if [[ -z "${K3S_HOST}" ]]; then
            # First server node
            if [[ "${DISABLE_DISTRIBUTED_DB}" != "true" ]]; then
                export INSTALL_K3S_EXEC="server --cluster-init"
            else
                export INSTALL_K3S_EXEC="server"
            fi
        else
            # Additional server node (HA)
            export INSTALL_K3S_EXEC="server --server https://${K3S_HOST}:6443"
            export K3S_URL="https://${K3S_HOST}:6443"
            
            if [[ -z "${K3S_TOKEN}" ]]; then
                error "K3S_TOKEN required for joining additional server nodes"
            fi
        fi
    else
        # Agent node
        export INSTALL_K3S_EXEC="agent"
        export K3S_URL="https://${K3S_HOST}:6443"
        
        if [[ -z "${K3S_TOKEN}" ]]; then
            error "K3S_TOKEN required for agent installation"
        fi
    fi
    
    # Disable Traefik if installing Rancher
    if [[ "${SKIP_RANCHER_INSTALL}" != "true" ]]; then
        export INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --disable traefik"
    fi
    
    log "Installation mode: ${node_type}"
    log "K3s exec params: ${INSTALL_K3S_EXEC}"
}

install_k3s() {
    log "Installing K3s ${K3S_VERSION}..."
    
    curl -sfL https://get.k3s.io | sh -
    
    log "K3s binaries installed"
}

migrate_state_directory() {
    log "Migrating K3s state to ${STATE_DIR}..."
    
    # Migrate /var/lib/rancher/k3s
    if [[ ! -d "${STATE_DIR}" ]]; then
        if [[ -d /var/lib/rancher/k3s ]]; then
            mv /var/lib/rancher/k3s "${STATE_DIR}"
            log "Migrated /var/lib/rancher/k3s to ${STATE_DIR}"
        else
            mkdir -p "${STATE_DIR}"
        fi
    fi
    
    rm -rf /var/lib/rancher/k3s
    ln -sf "${STATE_DIR}" /var/lib/rancher/k3s
    
    # Migrate /etc/rancher
    if [[ ! -d "${STATE_DIR}/etc" ]]; then
        if [[ -d /etc/rancher ]]; then
            mv /etc/rancher "${STATE_DIR}/etc"
            log "Migrated /etc/rancher to ${STATE_DIR}/etc"
        else
            mkdir -p "${STATE_DIR}/etc"
        fi
    fi
    
    rm -rf /etc/rancher
    ln -sf "${STATE_DIR}/etc" /etc/rancher
    
    log "State migration completed"
}

start_k3s_service() {
    log "Starting K3s service..."
    
    local service_name
    if systemctl is-enabled --quiet k3s 2>/dev/null || [[ -f /etc/systemd/system/k3s.service ]]; then
        service_name="k3s"
    else
        service_name="k3s-agent"
    fi
    
    systemctl daemon-reload
    systemctl enable "${service_name}"
    systemctl restart "${service_name}"
    
    # Wait for K3s to be ready
    log "Waiting for K3s to be ready..."
    local retries=0
    local max_retries=30
    
    while (( retries < max_retries )); do
        if systemctl is-active --quiet "${service_name}"; then
            log "K3s service is active"
            break
        fi
        sleep 2
        (( retries++ ))
    done
    
    if (( retries == max_retries )); then
        error "K3s service failed to start"
    fi
}

#------------------------------------------------------------------------------
# Helm Installation
#------------------------------------------------------------------------------

install_helm() {
    if command -v helm &>/dev/null; then
        log "Helm already installed: $(helm version --short)"
        return
    fi
    
    log "Installing Helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    log "Helm installed: $(helm version --short)"
}

#------------------------------------------------------------------------------
# Rancher Installation
#------------------------------------------------------------------------------

wait_for_kubeconfig() {
    local kubeconfig="/etc/rancher/k3s/k3s.yaml"
    local retries=0
    local max_retries=30
    
    log "Waiting for kubeconfig..."
    
    while (( retries < max_retries )); do
        if [[ -f "${kubeconfig}" ]]; then
            export KUBECONFIG="${kubeconfig}"
            if kubectl get nodes &>/dev/null; then
                log "Kubeconfig is ready"
                return 0
            fi
        fi
        sleep 2
        (( retries++ ))
    done
    
    error "Kubeconfig not available after ${max_retries} retries"
}

install_cert_manager() {
    log "Installing cert-manager ${CERT_MANAGER_VERSION}..."
    
    kubectl create namespace cert-manager || true
    
    # Install CRDs
    kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml"
    
    # Install cert-manager
    helm repo add jetstack https://charts.jetstack.io
    helm repo update
    
    helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace cert-manager \
        --version "${CERT_MANAGER_VERSION}" \
        --set installCRDs=false \
        --wait
    
    log "cert-manager installed successfully"
}

install_rancher() {
    log "Installing Rancher ${RANCHER_VERSION}..."
    
    kubectl create namespace cattle-system || true
    
    helm repo add rancher-stable https://releases.rancher.com/server-charts/stable
    helm repo update
    
    helm upgrade --install rancher rancher-stable/rancher \
        --namespace cattle-system \
        --version "${RANCHER_VERSION}" \
        --set hostname="${RANCHER_HOSTNAME}" \
        --set ingress.tls.source="${RANCHER_TLS_SOURCE}" \
        --set letsEncrypt.environment="${RANCHER_LETSENCRYPT_ENV}" \
        --set letsEncrypt.email="${RANCHER_LETSENCRYPT_EMAIL}" \
        --set bootstrapPassword="admin" \
        --set replicas=1 \
        --wait \
        --timeout=10m
    
    kubectl -n cattle-system rollout status deploy/rancher
    
    log "Rancher installed successfully"
    log "Access Rancher at: https://${RANCHER_HOSTNAME}"
    log "Bootstrap password: admin (change immediately)"
}

#------------------------------------------------------------------------------
# Post-Installation
#------------------------------------------------------------------------------

generate_join_script() {
    local node_type
    node_type=$(determine_node_type)
    
    if [[ "${node_type}" == "server" ]] && [[ -z "${K3S_HOST}" ]]; then
        local host_ip
        host_ip=$(ip route get 1 | awk '{print $(NF-2);exit}')
        
        local token
        token=$(cat /var/lib/rancher/k3s/server/node-token)
        
        cat > ~/join-worker-node.sh <<EOF
#!/usr/bin/env bash
# K3s Worker Node Join Script
# Generated: $(date)

export K3S_HOST=${host_ip}
export K3S_TOKEN=${token}
export SKIP_RANCHER_INSTALL=true

sudo -E ./install-k3s-enhanced.sh
EOF
        
        cat > ~/join-server-node.sh <<EOF
#!/usr/bin/env bash
# K3s Server Node Join Script (HA)
# Generated: $(date)

export K3S_HOST=${host_ip}
export K3S_TOKEN=${token}
export SKIP_RANCHER_INSTALL=true

sudo -E ./install-k3s-enhanced.sh
EOF
        
        chmod +x ~/join-worker-node.sh ~/join-server-node.sh
        
        log "Join scripts generated:"
        log "  Worker: ~/join-worker-node.sh"
        log "  Server: ~/join-server-node.sh"
    fi
}

display_summary() {
    log "=========================================="
    log "K3s Installation Complete"
    log "=========================================="
    log "K3s Version: ${K3S_VERSION}"
    log "Node Type: $(determine_node_type)"
    log "State Directory: ${STATE_DIR}"
    log "Log File: ${LOG_FILE}"
    
    if [[ -f /etc/rancher/k3s/k3s.yaml ]]; then
        log "Kubeconfig: /etc/rancher/k3s/k3s.yaml"
        log ""
        log "Quick commands:"
        log "  kubectl get nodes"
        log "  kubectl get pods -A"
    fi
    
    if [[ "${SKIP_RANCHER_INSTALL}" != "true" ]]; then
        log ""
        log "Rancher URL: https://${RANCHER_HOSTNAME}"
        log "Initial password: admin"
    fi
    
    log "=========================================="
}

#------------------------------------------------------------------------------
# Main Execution
#------------------------------------------------------------------------------

main() {
    log "Starting K3s installation..."
    
    preflight_checks
    install_prerequisites
    configure_k3s_installation
    install_k3s
    migrate_state_directory
    start_k3s_service
    
    # Only install Helm and Rancher on server nodes
    if [[ $(determine_node_type) == "server" ]] && [[ -z "${K3S_URL}" ]]; then
        wait_for_kubeconfig
        install_helm
        
        if [[ "${SKIP_RANCHER_INSTALL}" != "true" ]]; then
            install_cert_manager
            install_rancher
        fi
        
        generate_join_script
    fi
    
    display_summary
}

# Execute main function
main "$@"
