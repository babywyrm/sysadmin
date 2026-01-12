#!/usr/bin/env bash

##
## Enhanced K3s Installation Script with Interactive Configuration
## Supports: Master/Worker nodes, HA clusters, optional Rancher deployment
##
## Version: 2.6.9
## Author: DevOps Team, & Skynet, lol
## License: MIT
##

set -euo pipefail

#------------------------------------------------------------------------------
# SCRIPT HELP AND DOCUMENTATION
#------------------------------------------------------------------------------

show_help() {
    cat << 'EOF'
K3s Installation Script - Enhanced Edition
==========================================

DESCRIPTION:
    Production-ready installation script for K3s with optional Rancher deployment.
    Supports single-node, HA clusters, and worker nodes with interactive or 
    non-interactive configuration.

USAGE:
    # Interactive mode (recommended for first-time users)
    sudo ./install-k3s-enhanced.sh

    # Show this help message
    ./install-k3s-enhanced.sh --help

    # Non-interactive mode with environment variables
    sudo -E [VARIABLES] ./install-k3s-enhanced.sh

INSTALLATION MODES:

    1. Primary Server Node (First node in cluster)
       - Default mode when no K3S_HOST is set
       - Can enable distributed database (etcd) for HA
       - Optionally installs Rancher management UI

    2. Additional Server Node (HA cluster)
       - Requires K3S_HOST and K3S_TOKEN from primary node
       - Joins as control plane node
       - Shares cluster state via distributed database

    3. Worker/Agent Node
       - Requires K3S_HOST and K3S_TOKEN from primary node
       - Joins as worker node (no control plane)
       - Set DISABLE_DISTRIBUTED_DB=true

CONFIGURATION VARIABLES:

    K3s Configuration:
    ------------------
    K3S_VERSION              K3s version to install
                             Default: v1.30.0+k3s1
                             Example: v1.28.5+k3s1

    MOUNTPOINT               Base directory for K3s state
                             Default: /var/lib/rancher
                             Example: /data1, /mnt/storage

    DISABLE_DISTRIBUTED_DB   Disable embedded etcd (single node only)
                             Default: false
                             Values: true, false

    ENABLE_SELINUX           Enable SELinux support (RHEL/CentOS)
                             Default: false
                             Values: true, false

    Cluster Join Configuration:
    ---------------------------
    K3S_HOST                 Primary node IP for joining cluster
                             Required for: worker/additional nodes
                             Example: 192.168.1.10

    K3S_TOKEN                Cluster join token
                             Required for: worker/additional nodes
                             Location: /var/lib/rancher/k3s/server/node-token
                             Example: K10abc123def456...

    Rancher Configuration:
    ----------------------
    SKIP_RANCHER_INSTALL     Skip Rancher installation
                             Default: false
                             Values: true, false

    RANCHER_VERSION          Rancher version to install
                             Default: 2.8.0
                             Example: 2.7.9

    RANCHER_HOSTNAME         Hostname for Rancher UI
                             Default: rancher.local
                             Example: rancher.mycompany.com

    RANCHER_TLS_SOURCE       TLS certificate source
                             Default: letsEncrypt
                             Values: letsEncrypt, rancher, secret

    RANCHER_LETSENCRYPT_ENV  Let's Encrypt environment
                             Default: staging
                             Values: staging, production

    RANCHER_LETSENCRYPT_EMAIL
                             Email for Let's Encrypt notifications
                             Default: admin@example.com
                             Example: devops@mycompany.com

    CERT_MANAGER_VERSION     cert-manager version (for Rancher)
                             Default: v1.14.0
                             Example: v1.13.3

EXAMPLES:

    Example 1: Interactive Installation (Primary Server)
    ----------------------------------------------------
    sudo ./install-k3s-enhanced.sh
    
    # Follow the prompts to configure:
    # - K3s version
    # - Storage location
    # - Rancher installation
    # - TLS certificates
    # - etc.

    Example 2: Quick Single-Node Install (No Rancher)
    --------------------------------------------------
    sudo -E \
      SKIP_RANCHER_INSTALL=true \
      ./install-k3s-enhanced.sh

    Example 3: Production Primary Server with Rancher
    --------------------------------------------------
    sudo -E \
      K3S_VERSION=v1.30.0+k3s1 \
      MOUNTPOINT=/data1 \
      RANCHER_HOSTNAME=rancher.mycompany.com \
      RANCHER_TLS_SOURCE=letsEncrypt \
      RANCHER_LETSENCRYPT_ENV=production \
      RANCHER_LETSENCRYPT_EMAIL=devops@mycompany.com \
      ./install-k3s-enhanced.sh

    Example 4: HA Cluster - Additional Server Node
    -----------------------------------------------
    # On primary node, get the token:
    sudo cat /var/lib/rancher/k3s/server/node-token

    # On additional server node:
    sudo -E \
      K3S_HOST=192.168.1.10 \
      K3S_TOKEN=K10abc123def456... \
      MOUNTPOINT=/data1 \
      ./install-k3s-enhanced.sh

    Example 5: Worker Node
    ----------------------
    sudo -E \
      K3S_HOST=192.168.1.10 \
      K3S_TOKEN=K10abc123def456... \
      DISABLE_DISTRIBUTED_DB=true \
      SKIP_RANCHER_INSTALL=true \
      ./install-k3s-enhanced.sh

    Example 6: Custom Versions
    --------------------------
    sudo -E \
      K3S_VERSION=v1.28.5+k3s1 \
      RANCHER_VERSION=2.7.9 \
      CERT_MANAGER_VERSION=v1.13.3 \
      ./install-k3s-enhanced.sh

    Example 7: Self-Signed Certificates
    ------------------------------------
    sudo -E \
      RANCHER_TLS_SOURCE=rancher \
      RANCHER_HOSTNAME=rancher.local \
      ./install-k3s-enhanced.sh

WORKFLOW:

    Primary Server Installation:
    1. Run script in interactive mode
    2. Configure options (or accept defaults)
    3. Review configuration summary
    4. Confirm installation
    5. After completion, join scripts are generated:
       - ~/join-worker-node.sh
       - ~/join-server-node.sh

    Worker/Additional Node Installation:
    1. Copy join script from primary node, OR
    2. Manually export K3S_HOST and K3S_TOKEN
    3. Run installation script
    4. Node automatically joins cluster

POST-INSTALLATION:

    Verify Installation:
    -------------------
    kubectl get nodes
    kubectl get pods -A
    kubectl cluster-info

    Access Rancher (if installed):
    ------------------------------
    URL: https://<RANCHER_HOSTNAME>
    Initial Password: admin
    
    IMPORTANT: Change the default password immediately!

    Join Additional Nodes:
    ---------------------
    Use the generated join scripts:
    - ~/join-worker-node.sh (for worker nodes)
    - ~/join-server-node.sh (for HA server nodes)

    Get Cluster Token:
    -----------------
    sudo cat /var/lib/rancher/k3s/server/node-token

    Check Logs:
    ----------
    Installation log: /var/log/k3s-install-YYYYMMDD-HHMMSS.log
    K3s service logs: journalctl -u k3s -f

TROUBLESHOOTING:

    Issue: Installation fails with "cannot reach K3s endpoint"
    Solution: Check network connectivity and firewall rules

    Issue: K3s service won't start
    Solution: Check logs with: journalctl -u k3s -xe

    Issue: Worker node can't join cluster
    Solution: Verify K3S_HOST is accessible and K3S_TOKEN is correct

    Issue: Rancher UI not accessible
    Solution: Check ingress status: kubectl get ingress -n cattle-system

    Issue: Let's Encrypt staging certificates
    Solution: Reinstall with RANCHER_LETSENCRYPT_ENV=production

    Issue: Disk space errors
    Solution: Ensure at least 10GB available on MOUNTPOINT

REQUIREMENTS:

    - Root/sudo access
    - Minimum 10GB disk space
    - Network connectivity
    - Supported OS: RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+
    - Open ports: 6443 (API), 443 (Rancher if installed)

SECURITY NOTES:

    - Script requires root privileges for system configuration
    - Default Rancher password is 'admin' - CHANGE IMMEDIATELY
    - Use Let's Encrypt production for real deployments
    - Review firewall rules for your environment
    - Store K3S_TOKEN securely (cluster admin access)

SUPPORT:

    Documentation: https://docs.k3s.io
    Issues: https://github.com/k3s-io/k3s/issues
    Rancher Docs: https://rancher.com/docs

EOF
}

# Show version information
show_version() {
    cat << EOF
K3s Installation Script - Enhanced Edition
Version: 2.0.0
K3s Default Version: v1.30.0+k3s1
Rancher Default Version: 2.8.0
cert-manager Default Version: v1.14.0
EOF
}

#------------------------------------------------------------------------------
# ARGUMENT PARSING
#------------------------------------------------------------------------------

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
        shift
    done
}

# Parse arguments before anything else
parse_arguments "$@"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging setup
readonly LOG_FILE="/var/log/k3s-install-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "${LOG_FILE}")
exec 2>&1

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    exit 1
}

# Check root privileges
if (( EUID != 0 )); then
    error "Script must be run as root. Use: sudo -E $0"
fi

#------------------------------------------------------------------------------
# Configuration Defaults
#------------------------------------------------------------------------------

declare -A CONFIG=(
    [K3S_VERSION]="v1.30.0+k3s1"
    [CERT_MANAGER_VERSION]="v1.14.0"
    [RANCHER_VERSION]="2.8.0"
    [MOUNTPOINT]="/var/lib/rancher"
    [RANCHER_HOSTNAME]="rancher.local"
    [RANCHER_LETSENCRYPT_ENV]="staging"
    [RANCHER_LETSENCRYPT_EMAIL]="admin@example.com"
    [RANCHER_TLS_SOURCE]="letsEncrypt"
    [SKIP_RANCHER_INSTALL]="false"
    [DISABLE_DISTRIBUTED_DB]="false"
    [ENABLE_SELINUX]="false"
    [INTERACTIVE_MODE]="true"
    [K3S_HOST]=""
    [K3S_TOKEN]=""
)

#------------------------------------------------------------------------------
# Interactive Configuration
#------------------------------------------------------------------------------

prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    local user_input
    
    read -p "$(echo -e "${BLUE}${prompt}${NC} [${default}]: ")" user_input
    CONFIG["${var_name}"]="${user_input:-$default}"
}

prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    local user_input
    
    while true; do
        read -p "$(echo -e "${BLUE}${prompt}${NC} (y/n) [${default}]: ")" user_input
        user_input="${user_input:-$default}"
        case "${user_input,,}" in
            y|yes) 
                CONFIG["${var_name}"]="true"
                break
                ;;
            n|no) 
                CONFIG["${var_name}"]="false"
                break
                ;;
            *) 
                echo "Please answer yes (y) or no (n)"
                ;;
        esac
    done
}

detect_node_mode() {
    if [[ -n "${K3S_HOST}" ]] || [[ -n "${CONFIG[K3S_HOST]}" ]]; then
        return 1  # Worker/Additional node
    else
        return 0  # Primary server node
    fi
}

show_quick_help() {
    cat << 'EOF'

Quick Start Guide:
------------------
This script will guide you through K3s installation.

For detailed help, run: ./install-k3s-enhanced.sh --help

Common scenarios:
1. First server (with Rancher):    Just press Enter for defaults
2. First server (without Rancher): Answer 'n' to "Install Rancher?"
3. Worker node:                    Set K3S_HOST and K3S_TOKEN first
4. Additional server (HA):         Set K3S_HOST and K3S_TOKEN first

EOF
}

configure_interactive() {
    if [[ "${CONFIG[INTERACTIVE_MODE]}" != "true" ]]; then
        return
    fi
    
    echo ""
    log "K3s Interactive Installation Configuration"
    echo "=========================================="
    
    show_quick_help
    
    # Detect installation mode
    if detect_node_mode; then
        info "Detected: Primary server node installation"
        echo ""
        
        # K3s Version
        prompt_with_default "K3s version" "${CONFIG[K3S_VERSION]}" "K3S_VERSION"
        
        # Storage location
        prompt_with_default "K3s state directory (mountpoint)" "${CONFIG[MOUNTPOINT]}" "MOUNTPOINT"
        
        # Cluster configuration
        prompt_yes_no "Enable distributed embedded database (etcd)?" "y" "ENABLE_DISTRIBUTED_DB"
        if [[ "${CONFIG[ENABLE_DISTRIBUTED_DB]}" == "true" ]]; then
            CONFIG[DISABLE_DISTRIBUTED_DB]="false"
        else
            CONFIG[DISABLE_DISTRIBUTED_DB]="true"
        fi
        
        # Rancher installation
        prompt_yes_no "Install Rancher?" "y" "INSTALL_RANCHER"
        if [[ "${CONFIG[INSTALL_RANCHER]}" == "true" ]]; then
            CONFIG[SKIP_RANCHER_INSTALL]="false"
            
            prompt_with_default "Rancher version" "${CONFIG[RANCHER_VERSION]}" "RANCHER_VERSION"
            prompt_with_default "Rancher hostname" "${CONFIG[RANCHER_HOSTNAME]}" "RANCHER_HOSTNAME"
            prompt_with_default "Rancher admin email (for Let's Encrypt)" "${CONFIG[RANCHER_LETSENCRYPT_EMAIL]}" "RANCHER_LETSENCRYPT_EMAIL"
            
            # TLS source
            echo ""
            info "TLS Certificate Options:"
            info "  1) letsEncrypt - Automatic Let's Encrypt certificates"
            info "  2) rancher - Self-signed Rancher certificates"
            info "  3) secret - Use your own certificates"
            read -p "$(echo -e "${BLUE}Select TLS source${NC} [1]: ")" tls_choice
            case "${tls_choice:-1}" in
                1) CONFIG[RANCHER_TLS_SOURCE]="letsEncrypt" ;;
                2) CONFIG[RANCHER_TLS_SOURCE]="rancher" ;;
                3) CONFIG[RANCHER_TLS_SOURCE]="secret" ;;
                *) CONFIG[RANCHER_TLS_SOURCE]="letsEncrypt" ;;
            esac
            
            if [[ "${CONFIG[RANCHER_TLS_SOURCE]}" == "letsEncrypt" ]]; then
                prompt_with_default "Let's Encrypt environment (staging/production)" "${CONFIG[RANCHER_LETSENCRYPT_ENV]}" "RANCHER_LETSENCRYPT_ENV"
            fi
            
            prompt_with_default "cert-manager version" "${CONFIG[CERT_MANAGER_VERSION]}" "CERT_MANAGER_VERSION"
        else
            CONFIG[SKIP_RANCHER_INSTALL]="true"
        fi
        
        # SELinux
        if command -v getenforce &>/dev/null; then
            prompt_yes_no "Enable SELinux support?" "n" "ENABLE_SELINUX"
        fi
        
    else
        info "Detected: Worker/Additional node installation"
        echo ""
        warn "This appears to be a worker or additional server node installation."
        warn "Make sure K3S_HOST and K3S_TOKEN are set in your environment."
        echo ""
        
        prompt_with_default "K3s version" "${CONFIG[K3S_VERSION]}" "K3S_VERSION"
        prompt_with_default "K3s state directory (mountpoint)" "${CONFIG[MOUNTPOINT]}" "MOUNTPOINT"
    fi
    
    # Confirmation
    echo ""
    echo "=========================================="
    log "Configuration Summary"
    echo "=========================================="
    echo "K3s Version:        ${CONFIG[K3S_VERSION]}"
    echo "Mountpoint:         ${CONFIG[MOUNTPOINT]}"
    echo "Install Rancher:    $([ "${CONFIG[SKIP_RANCHER_INSTALL]}" == "false" ] && echo "Yes" || echo "No")"
    
    if [[ "${CONFIG[SKIP_RANCHER_INSTALL]}" == "false" ]]; then
        echo "Rancher Version:    ${CONFIG[RANCHER_VERSION]}"
        echo "Rancher Hostname:   ${CONFIG[RANCHER_HOSTNAME]}"
        echo "TLS Source:         ${CONFIG[RANCHER_TLS_SOURCE]}"
    fi
    
    echo "Distributed DB:     $([ "${CONFIG[DISABLE_DISTRIBUTED_DB]}" == "false" ] && echo "Enabled" || echo "Disabled")"
    echo "SELinux Support:    $([ "${CONFIG[ENABLE_SELINUX]}" == "true" ] && echo "Enabled" || echo "Disabled")"
    echo "=========================================="
    echo ""
    
    read -p "$(echo -e "${BLUE}Proceed with installation?${NC} (y/n): ")" confirm
    if [[ "${confirm,,}" != "y" ]] && [[ "${confirm,,}" != "yes" ]]; then
        error "Installation cancelled by user"
    fi
    echo ""
}

#------------------------------------------------------------------------------
# Load Configuration from Environment
#------------------------------------------------------------------------------

load_environment_config() {
    # Override defaults with environment variables if set
    [[ -n "${K3S_VERSION:-}" ]] && CONFIG[K3S_VERSION]="${K3S_VERSION}"
    [[ -n "${CERT_MANAGER_VERSION:-}" ]] && CONFIG[CERT_MANAGER_VERSION]="${CERT_MANAGER_VERSION}"
    [[ -n "${RANCHER_VERSION:-}" ]] && CONFIG[RANCHER_VERSION]="${RANCHER_VERSION}"
    [[ -n "${MOUNTPOINT:-}" ]] && CONFIG[MOUNTPOINT]="${MOUNTPOINT}"
    [[ -n "${RANCHER_HOSTNAME:-}" ]] && CONFIG[RANCHER_HOSTNAME]="${RANCHER_HOSTNAME}"
    [[ -n "${RANCHER_LETSENCRYPT_ENVIRONMENT:-}" ]] && CONFIG[RANCHER_LETSENCRYPT_ENV]="${RANCHER_LETSENCRYPT_ENVIRONMENT}"
    [[ -n "${RANCHER_LETSENCRYPT_EMAIL:-}" ]] && CONFIG[RANCHER_LETSENCRYPT_EMAIL]="${RANCHER_LETSENCRYPT_EMAIL}"
    [[ -n "${RANCHER_TLS_SOURCE:-}" ]] && CONFIG[RANCHER_TLS_SOURCE]="${RANCHER_TLS_SOURCE}"
    [[ -n "${SKIP_RANCHER_INSTALL:-}" ]] && CONFIG[SKIP_RANCHER_INSTALL]="${SKIP_RANCHER_INSTALL}"
    [[ -n "${DISABLE_DISTRIBUTED_DB:-}" ]] && CONFIG[DISABLE_DISTRIBUTED_DB]="${DISABLE_DISTRIBUTED_DB}"
    [[ -n "${ENABLE_SELINUX:-}" ]] && CONFIG[ENABLE_SELINUX]="${ENABLE_SELINUX}"
    [[ -n "${K3S_HOST:-}" ]] && CONFIG[K3S_HOST]="${K3S_HOST}"
    [[ -n "${K3S_TOKEN:-}" ]] && CONFIG[K3S_TOKEN]="${K3S_TOKEN}"
    
    # If any critical env vars are set, disable interactive mode
    if [[ -n "${K3S_VERSION:-}" ]] || [[ -n "${MOUNTPOINT:-}" ]] || [[ -n "${SKIP_RANCHER_INSTALL:-}" ]]; then
        CONFIG[INTERACTIVE_MODE]="false"
        info "Non-interactive mode detected (environment variables set)"
    fi
    
    # Set derived state directory
    CONFIG[STATE_DIR]="${CONFIG[MOUNTPOINT]}/k3s"
}

#------------------------------------------------------------------------------
# Pre-flight Checks
#------------------------------------------------------------------------------

preflight_checks() {
    log "Running pre-flight checks..."
    
    # Check if mountpoint directory exists
    if [[ ! -d "${CONFIG[MOUNTPOINT]}" ]]; then
        warn "Mountpoint directory ${CONFIG[MOUNTPOINT]} does not exist"
        read -p "$(echo -e "${BLUE}Create directory?${NC} (y/n): ")" create_dir
        if [[ "${create_dir,,}" == "y" ]] || [[ "${create_dir,,}" == "yes" ]]; then
            mkdir -p "${CONFIG[MOUNTPOINT]}"
            log "Created directory ${CONFIG[MOUNTPOINT]}"
        else
            error "Mountpoint directory required for installation"
        fi
    fi
    
    # Check available disk space (minimum 10GB)
    local available_space
    available_space=$(df -BG "${CONFIG[MOUNTPOINT]}" | awk 'NR==2 {print $4}' | sed 's/G//')
    if (( available_space < 10 )); then
        warn "Low disk space: ${available_space}GB available (10GB minimum recommended)"
        read -p "$(echo -e "${BLUE}Continue anyway?${NC} (y/n): ")" continue_install
        if [[ "${continue_install,,}" != "y" ]] && [[ "${continue_install,,}" != "yes" ]]; then
            error "Installation cancelled due to insufficient disk space"
        fi
    fi
    
    # Check network connectivity
    if ! curl -sf --max-time 5 https://get.k3s.io > /dev/null; then
        error "Cannot reach K3s installation endpoint. Check network connectivity"
    fi
    
    # Validate versions format
    if [[ ! "${CONFIG[K3S_VERSION]}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]]; then
        error "Invalid K3s version format: ${CONFIG[K3S_VERSION]}. Expected format: v1.30.0+k3s1"
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
        
        if [[ "${CONFIG[ENABLE_SELINUX]}" == "true" ]]; then
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
    if [[ -z "${CONFIG[K3S_HOST]}" ]] && [[ -z "${K3S_HOST:-}" ]]; then
        echo "server"
    else
        if [[ "${CONFIG[DISABLE_DISTRIBUTED_DB]}" == "true" ]]; then
            echo "agent"
        else
            echo "server"
        fi
    fi
}

configure_k3s_installation() {
    local node_type
    node_type=$(determine_node_type)
    
    export INSTALL_K3S_VERSION="${CONFIG[K3S_VERSION]}"
    export INSTALL_K3S_SKIP_START=true
    
    # Use environment K3S_HOST and K3S_TOKEN if set
    local k3s_host="${CONFIG[K3S_HOST]:-${K3S_HOST:-}}"
    local k3s_token="${CONFIG[K3S_TOKEN]:-${K3S_TOKEN:-}}"
    
    if [[ "${node_type}" == "server" ]]; then
        if [[ -z "${k3s_host}" ]]; then
            # First server node
            if [[ "${CONFIG[DISABLE_DISTRIBUTED_DB]}" != "true" ]]; then
                export INSTALL_K3S_EXEC="server --cluster-init"
            else
                export INSTALL_K3S_EXEC="server"
            fi
        else
            # Additional server node (HA)
            export INSTALL_K3S_EXEC="server --server https://${k3s_host}:6443"
            export K3S_URL="https://${k3s_host}:6443"
            export K3S_TOKEN="${k3s_token}"
            
            if [[ -z "${k3s_token}" ]]; then
                error "K3S_TOKEN required for joining additional server nodes"
            fi
        fi
    else
        # Agent node
        export INSTALL_K3S_EXEC="agent"
        export K3S_URL="https://${k3s_host}:6443"
        export K3S_TOKEN="${k3s_token}"
        
        if [[ -z "${k3s_token}" ]]; then
            error "K3S_TOKEN required for agent installation"
        fi
    fi
    
    # Disable Traefik if installing Rancher
    if [[ "${CONFIG[SKIP_RANCHER_INSTALL]}" != "true" ]]; then
        export INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --disable traefik"
    fi
    
    log "Installation mode: ${node_type}"
    log "K3s exec params: ${INSTALL_K3S_EXEC}"
}

install_k3s() {
    log "Installing K3s ${CONFIG[K3S_VERSION]}..."
    
    curl -sfL https://get.k3s.io | sh -
    
    log "K3s binaries installed"
}

migrate_state_directory() {
    log "Migrating K3s state to ${CONFIG[STATE_DIR]}..."
    
    # Migrate /var/lib/rancher/k3s
    if [[ ! -d "${CONFIG[STATE_DIR]}" ]]; then
        if [[ -d /var/lib/rancher/k3s ]]; then
            mv /var/lib/rancher/k3s "${CONFIG[STATE_DIR]}"
            log "Migrated /var/lib/rancher/k3s to ${CONFIG[STATE_DIR]}"
        else
            mkdir -p "${CONFIG[STATE_DIR]}"
        fi
    fi
    
    rm -rf /var/lib/rancher/k3s
    ln -sf "${CONFIG[STATE_DIR]}" /var/lib/rancher/k3s
    
    # Migrate /etc/rancher
    if [[ ! -d "${CONFIG[STATE_DIR]}/etc" ]]; then
        if [[ -d /etc/rancher ]]; then
            mv /etc/rancher "${CONFIG[STATE_DIR]}/etc"
            log "Migrated /etc/rancher to ${CONFIG[STATE_DIR]}/etc"
        else
            mkdir -p "${CONFIG[STATE_DIR]}/etc"
        fi
    fi
    
    rm -rf /etc/rancher
    ln -sf "${CONFIG[STATE_DIR]}/etc" /etc/rancher
    
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
    log "Installing cert-manager ${CONFIG[CERT_MANAGER_VERSION]}..."
    
    kubectl create namespace cert-manager || true
    
    # Install CRDs
    kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CONFIG[CERT_MANAGER_VERSION]}/cert-manager.crds.yaml"
    
    # Install cert-manager
    helm repo add jetstack https://charts.jetstack.io
    helm repo update
    
    helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace cert-manager \
        --version "${CONFIG[CERT_MANAGER_VERSION]}" \
        --set installCRDs=false \
        --wait
    
    log "cert-manager installed successfully"
}

install_rancher() {
    log "Installing Rancher ${CONFIG[RANCHER_VERSION]}..."
    
    kubectl create namespace cattle-system || true
    
    helm repo add rancher-stable https://releases.rancher.com/server-charts/stable
    helm repo update
    
    local helm_args=(
        --namespace cattle-system
        --version "${CONFIG[RANCHER_VERSION]}"
        --set hostname="${CONFIG[RANCHER_HOSTNAME]}"
        --set ingress.tls.source="${CONFIG[RANCHER_TLS_SOURCE]}"
        --set bootstrapPassword="admin"
        --set replicas=1
        --wait
        --timeout=10m
    )
    
    if [[ "${CONFIG[RANCHER_TLS_SOURCE]}" == "letsEncrypt" ]]; then
        helm_args+=(
            --set letsEncrypt.environment="${CONFIG[RANCHER_LETSENCRYPT_ENV]}"
            --set letsEncrypt.email="${CONFIG[RANCHER_LETSENCRYPT_EMAIL]}"
        )
    fi
    
    helm upgrade --install rancher rancher-stable/rancher "${helm_args[@]}"
    
    kubectl -n cattle-system rollout status deploy/rancher
    
    log "Rancher installed successfully"
    log "Access Rancher at: https://${CONFIG[RANCHER_HOSTNAME]}"
    log "Bootstrap password: admin (change immediately)"
}

#------------------------------------------------------------------------------
# Post-Installation
#------------------------------------------------------------------------------

generate_join_script() {
    local node_type
    node_type=$(determine_node_type)
    
    if [[ "${node_type}" == "server" ]] && [[ -z "${CONFIG[K3S_HOST]}" ]] && [[ -z "${K3S_HOST:-}" ]]; then
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
export K3S_VERSION=${CONFIG[K3S_VERSION]}
export MOUNTPOINT=${CONFIG[MOUNTPOINT]}

sudo -E ./install-k3s-enhanced.sh
EOF
        
        cat > ~/join-server-node.sh <<EOF
#!/usr/bin/env bash
# K3s Server Node Join Script (HA)
# Generated: $(date)

export K3S_HOST=${host_ip}
export K3S_TOKEN=${token}
export SKIP_RANCHER_INSTALL=true
export K3S_VERSION=${CONFIG[K3S_VERSION]}
export MOUNTPOINT=${CONFIG[MOUNTPOINT]}

sudo -E ./install-k3s-enhanced.sh
EOF
        
        chmod +x ~/join-worker-node.sh ~/join-server-node.sh
        
        log "Join scripts generated:"
        log "  Worker: ~/join-worker-node.sh"
        log "  Server: ~/join-server-node.sh"
    fi
}

display_summary() {
    echo ""
    echo "=========================================="
    log "K3s Installation Complete"
    echo "=========================================="
    echo "K3s Version:        ${CONFIG[K3S_VERSION]}"
    echo "Node Type:          $(determine_node_type)"
    echo "State Directory:    ${CONFIG[STATE_DIR]}"
    echo "Log File:           ${LOG_FILE}"
    
    if [[ -f /etc/rancher/k3s/k3s.yaml ]]; then
        echo "Kubeconfig:         /etc/rancher/k3s/k3s.yaml"
        echo ""
        info "Quick commands:"
        echo "  kubectl get nodes"
        echo "  kubectl get pods -A"
    fi
    
    if [[ "${CONFIG[SKIP_RANCHER_INSTALL]}" != "true" ]]; then
        echo ""
        echo "Rancher URL:        https://${CONFIG[RANCHER_HOSTNAME]}"
        echo "Initial password:   admin"
        warn "Change the Rancher admin password immediately!"
    fi
    
    echo ""
    info "For detailed help: ./install-k3s-enhanced.sh --help"
    echo "=========================================="
    echo ""
}

#------------------------------------------------------------------------------
# Main Execution
#------------------------------------------------------------------------------

main() {
    log "Starting K3s installation..."
    
    # Load configuration
    load_environment_config
    
    # Interactive configuration if enabled
    configure_interactive
    
    # Installation steps
    preflight_checks
    install_prerequisites
    configure_k3s_installation
    install_k3s
    migrate_state_directory
    start_k3s_service
    
    # Only install Helm and Rancher on primary server nodes
    if [[ $(determine_node_type) == "server" ]] && [[ -z "${K3S_URL:-}" ]]; then
        wait_for_kubeconfig
        install_helm
        
        if [[ "${CONFIG[SKIP_RANCHER_INSTALL]}" != "true" ]]; then
            install_cert_manager
            install_rancher
        fi
        
        generate_join_script
    fi
    
    display_summary
}

# Execute main function
main "$@"
