#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    log_info "Detected platform: $OS/$ARCH"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install kubectl if not present
install_kubectl() {
    if command_exists kubectl; then
        log_info "kubectl already installed: $(kubectl version --client -o json 2>/dev/null | grep gitVersion || echo 'version unknown')"
        return 0
    fi
    
    log_info "Installing kubectl..."
    KUBECTL_VERSION=$(curl -Ls https://dl.k8s.io/release/stable.txt)
    curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/${OS}/${ARCH}/kubectl"
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/
    log_info "kubectl ${KUBECTL_VERSION} installed"
}

# Setup k3s kubeconfig
setup_k3s_kubeconfig() {
    K3S_CONFIG="/etc/rancher/k3s/k3s.yaml"
    KUBE_DIR="$HOME/.kube"
    KUBE_CONFIG="$KUBE_DIR/config"
    
    if [[ ! -f "$K3S_CONFIG" ]]; then
        log_warn "k3s config not found at $K3S_CONFIG"
        log_warn "Skipping kubeconfig setup"
        return 0
    fi
    
    log_info "Setting up kubeconfig for k3s..."
    mkdir -p "$KUBE_DIR"
    
    # Copy and fix k3s config
    sudo cp "$K3S_CONFIG" "$KUBE_CONFIG"
    sudo chown "$USER:$USER" "$KUBE_CONFIG"
    chmod 600 "$KUBE_CONFIG"
    
    # Replace 127.0.0.1 with actual hostname if needed
    if grep -q "server: https://127.0.0.1" "$KUBE_CONFIG"; then
        log_warn "kubeconfig uses 127.0.0.1 - may need manual adjustment for remote access"
    fi
    
    log_info "Kubeconfig setup complete"
}

# Install krew
install_krew() {
    if command_exists kubectl-krew; then
        log_info "krew already installed"
        return 0
    fi
    
    log_info "Installing krew..."
    
    cd "$(mktemp -d)"
    KREW_TAR="krew-${OS}_${ARCH}.tar.gz"
    KREW_URL="https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW_TAR}"
    
    curl -fsSLO "$KREW_URL"
    tar zxvf "$KREW_TAR"
    ./"krew-${OS}_${ARCH}" install krew
    
    # Add krew to PATH
    KREW_ROOT="${KREW_ROOT:-$HOME/.krew}"
    export PATH="${KREW_ROOT}/bin:$PATH"
    
    log_info "krew installed successfully"
}

# Setup shell configuration
setup_shell_config() {
    SHELL_RC=""
    
    if [[ -n "${BASH_VERSION:-}" ]] || [[ "$SHELL" == *"bash"* ]]; then
        SHELL_RC="$HOME/.bashrc"
    elif [[ -n "${ZSH_VERSION:-}" ]] || [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_RC="$HOME/.zshrc"
    else
        log_warn "Unknown shell, skipping PATH setup"
        return 0
    fi
    
    log_info "Configuring $SHELL_RC..."
    
    # Add krew to PATH
    if ! grep -q 'KREW_ROOT' "$SHELL_RC" 2>/dev/null; then
        cat >> "$SHELL_RC" << 'EOF'

# Krew (kubectl plugin manager)
export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"

# Kubectl aliases
alias k="kubectl"
alias kgp="kubectl get pods"
alias kgs="kubectl get services"
alias kgn="kubectl get nodes"
alias kd="kubectl describe"
alias kl="kubectl logs"
alias kx="kubectl ctx"
alias kn="kubectl ns"
EOF
        log_info "Shell configuration updated"
        log_warn "Run 'source $SHELL_RC' or restart your shell"
    else
        log_info "Shell already configured"
    fi
}

# Install krew plugins
install_krew_plugins() {
    log_info "Installing krew plugins..."
    
    PLUGINS=(
        "ctx"                  # context switching
        "ns"                   # namespace switching
        "tree"                 # resource hierarchy
        "resource-capacity"    # node capacity
        "get-all"              # get all resources
        "neat"                 # clean yaml output
        "whoami"               # current user info
        "view-secret"          # decode secrets
        "access-matrix"        # RBAC visualization
        "tail"                 # multi-pod logs
        "sick-pods"            # find unhealthy pods
    )
    
    for plugin in "${PLUGINS[@]}"; do
        if kubectl krew list 2>/dev/null | grep -q "^${plugin}$"; then
            log_info "Plugin '$plugin' already installed"
        else
            log_info "Installing plugin: $plugin"
            kubectl krew install "$plugin" || log_warn "Failed to install $plugin"
        fi
    done
    
    log_info "Krew plugins installed"
}

# Install additional tools
install_additional_tools() {
    log_info "Checking for additional tools..."
    
    # Install helm
    if ! command_exists helm; then
        log_info "Installing helm..."
        curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    else
        log_info "helm already installed"
    fi
    
    # Install k9s (if not present)
    if ! command_exists k9s; then
        log_warn "k9s not found - install manually:"
        log_warn "  curl -sS https://webinstall.dev/k9s | bash"
    else
        log_info "k9s already installed"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    if ! kubectl version --client &>/dev/null; then
        log_error "kubectl verification failed"
        return 1
    fi
    
    if ! kubectl krew version &>/dev/null; then
        log_error "krew verification failed"
        return 1
    fi
    
    log_info "Testing k3s connection..."
    if kubectl get nodes &>/dev/null; then
        log_info "✓ Successfully connected to k3s cluster"
    else
        log_warn "Could not connect to cluster - check kubeconfig"
    fi
    
    log_info "Installed krew plugins:"
    kubectl krew list 2>/dev/null || log_warn "Could not list plugins"
}

# Main installation
main() {
    log_info "Starting k3s/krew installation script..."
    
    detect_platform
    install_kubectl
    setup_k3s_kubeconfig
    install_krew
    
    # Source krew for current session
    export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"
    
    install_krew_plugins
    install_additional_tools
    setup_shell_config
    verify_installation
    
    log_info "Installation complete!"
    log_info ""
    log_info "Next steps:"
    log_info "  1. Run: source ~/.bashrc (or ~/.zshrc)"
    log_info "  2. Test: kubectl krew list"
    log_info "  3. Explore: kubectl krew search"
    log_info "  4. Use aliases: k, kgp, kgs, kx, kn"
}

main "$@"
