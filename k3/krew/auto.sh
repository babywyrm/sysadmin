#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
test_pass() { echo -e "${GREEN}✓${NC} $1"; ((PASSED++)); }
test_fail() { echo -e "${RED}✗${NC} $1"; ((FAILED++)); }
test_warn() { echo -e "${YELLOW}⚠${NC} $1"; }

print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

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
        log_info "kubectl already installed"
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
    
    sudo cp "$K3S_CONFIG" "$KUBE_CONFIG"
    sudo chown "$USER:$USER" "$KUBE_CONFIG"
    chmod 600 "$KUBE_CONFIG"
    
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
    tar zxvf "$KREW_TAR" 2>/dev/null || tar zxf "$KREW_TAR"
    ./"krew-${OS}_${ARCH}" install krew
    
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
    else
        log_info "Shell already configured"
    fi
    
    # Source the config for current session
    source "$SHELL_RC" 2>/dev/null || true
}

# Install krew plugins
install_krew_plugins() {
    log_info "Installing krew plugins..."
    
    PLUGINS=(
        "ctx"
        "ns"
        "tree"
        "resource-capacity"
        "get-all"
        "neat"
        "whoami"
        "view-secret"
        "access-matrix"
        "tail"
        "sick-pods"
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

# Install k9s
install_k9s() {
    if command_exists k9s; then
        log_info "k9s already installed"
        return 0
    fi
    
    log_info "Installing k9s..."
    
    # Try webinstall first
    if curl -sS https://webinstall.dev/k9s | bash; then
        log_info "k9s installed via webinstall"
        # Add webinstall path to current session
        export PATH="$HOME/.local/bin:$PATH"
    else
        log_warn "k9s installation failed - install manually later"
    fi
}

# Install helm
install_helm() {
    if command_exists helm; then
        log_info "helm already installed"
        return 0
    fi
    
    log_info "Installing helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
}

# ============ TEST FUNCTIONS ============

test_kubectl_connection() {
    print_header "Testing kubectl connection"
    
    if timeout 5 kubectl cluster-info >/dev/null 2>&1; then
        test_pass "Connected to Kubernetes cluster"
        
        local nodes=$(timeout 3 kubectl get nodes --no-headers 2>/dev/null)
        if [[ -n "$nodes" ]]; then
            local node_count=$(echo "$nodes" | wc -l)
            echo "  Nodes: $node_count"
        fi
    else
        test_fail "Cannot connect to cluster"
        return 1
    fi
}

test_krew() {
    print_header "Testing krew"
    
    if command_exists kubectl-krew; then
        test_pass "krew is installed"
        
        if echo "$PATH" | grep -q ".krew/bin"; then
            test_pass "krew is in PATH"
        else
            test_fail "krew not in PATH"
        fi
        
        local plugin_count=$(kubectl krew list 2>/dev/null | tail -n +2 | wc -l)
        echo "  Installed plugins: $plugin_count"
    else
        test_fail "krew is NOT installed"
        return 1
    fi
}

test_krew_plugins() {
    print_header "Testing krew plugins"
    
    local plugins=("ctx" "ns" "tree" "neat" "get-all" "whoami")
    local installed=$(kubectl krew list 2>/dev/null)
    
    for plugin in "${plugins[@]}"; do
        if echo "$installed" | grep -q "^${plugin}$"; then
            test_pass "Plugin '$plugin' is installed"
        else
            test_warn "Plugin '$plugin' not installed"
        fi
    done
}

test_shell_aliases() {
    print_header "Testing shell aliases"
    
    # Re-source shell config
    if [[ -f "$HOME/.bashrc" ]]; then
        source "$HOME/.bashrc" 2>/dev/null || true
    elif [[ -f "$HOME/.zshrc" ]]; then
        source "$HOME/.zshrc" 2>/dev/null || true
    fi
    
    local aliases=("k" "kgp" "kgs" "kx" "kn")
    
    for alias_name in "${aliases[@]}"; do
        if alias "$alias_name" >/dev/null 2>&1; then
            test_pass "Alias '$alias_name' works"
        else
            test_warn "Alias '$alias_name' not loaded"
        fi
    done
}

test_additional_tools() {
    print_header "Testing additional tools"
    
    if command_exists helm; then
        local helm_ver=$(helm version --short 2>/dev/null | head -n1)
        test_pass "Helm is installed ($helm_ver)"
    else
        test_fail "Helm is NOT installed"
    fi
    
    if command_exists k9s; then
        test_pass "k9s is installed"
    else
        test_fail "k9s is NOT installed"
    fi
}

test_k3s_service() {
    print_header "Testing k3s service"
    
    if systemctl is-active --quiet k3s 2>/dev/null || \
       sudo systemctl is-active --quiet k3s 2>/dev/null; then
        test_pass "k3s service is running"
    else
        test_warn "k3s service status unknown"
    fi
}

# Generate test report
generate_test_report() {
    print_header "Installation Test Summary"
    
    local total=$((PASSED + FAILED))
    local pass_rate=0
    
    if [[ $total -gt 0 ]]; then
        pass_rate=$(( (PASSED * 100) / total ))
    fi
    
    echo ""
    echo "Total tests: $total"
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo "Pass rate: ${pass_rate}%"
    echo ""
    
    if [[ $pass_rate -ge 90 ]]; then
        echo -e "${GREEN}✓ Installation successful!${NC}"
    elif [[ $pass_rate -ge 70 ]]; then
        echo -e "${YELLOW}⚠ Installation mostly successful with warnings${NC}"
    else
        echo -e "${RED}✗ Installation had issues${NC}"
    fi
}

# Main installation with tests
main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║  k3s/krew Installation & Test Suite   ║"
    echo "╔════════════════════════════════════════╗"
    echo -e "${NC}"
    
    print_header "INSTALLATION PHASE"
    
    detect_platform
    install_kubectl
    setup_k3s_kubeconfig
    install_krew
    
    # Export krew path for current session
    export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"
    
    install_krew_plugins
    install_helm
    install_k9s
    setup_shell_config
    
    # Add k9s path if installed via webinstall
    export PATH="$HOME/.local/bin:$PATH"
    
    log_info "Installation phase complete!"
    
    # Run tests
    print_header "TESTING PHASE"
    
    # Check for timeout command
    if ! command_exists timeout; then
        log_warn "'timeout' command not found, some tests may hang"
    fi
    
    test_k3s_service
    test_kubectl_connection
    test_krew
    test_krew_plugins
    test_shell_aliases
    test_additional_tools
    
    generate_test_report
    
    echo ""
    log_info "Next steps:"
    log_info "  1. Start a new shell: exec \$SHELL"
    log_info "  2. Test commands: k get nodes, kubectl ctx, k9s"
    log_info "  3. Explore plugins: kubectl krew search"
}

main "$@"
