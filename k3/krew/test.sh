#!/usr/bin/env bash
set -uo pipefail  # Removed -e to prevent early exit

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0

print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

test_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED++))
}

test_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED++))
}

test_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Test command exists
test_command() {
    local cmd=$1
    local name=${2:-$cmd}
    
    if command -v "$cmd" >/dev/null 2>&1; then
        local version=$($cmd version --short 2>/dev/null || 
                       $cmd version --client --short 2>/dev/null || 
                       $cmd --version 2>/dev/null | head -n1 || 
                       echo "installed")
        test_pass "$name is installed ($version)"
        return 0
    else
        test_fail "$name is NOT installed"
        return 1
    fi
}

# Test kubectl connection with timeout
test_kubectl_connection() {
    print_header "Testing kubectl connection"
    
    echo "  Attempting to connect (timeout: 5s)..."
    
    if timeout 5 kubectl cluster-info >/dev/null 2>&1; then
        test_pass "Connected to Kubernetes cluster"
        
        # Get cluster version
        local server_version=$(timeout 3 kubectl version -o json 2>/dev/null | 
                              grep -o '"gitVersion":"[^"]*"' | 
                              head -n1 | cut -d'"' -f4 || echo "unknown")
        echo "  Server version: $server_version"
        
        # Get nodes
        local nodes=$(timeout 3 kubectl get nodes --no-headers 2>/dev/null)
        if [[ -n "$nodes" ]]; then
            local node_count=$(echo "$nodes" | wc -l)
            echo "  Nodes: $node_count"
            echo "$nodes" | sed 's/^/    /'
        fi
    else
        test_fail "Cannot connect to cluster (timeout or connection error)"
        echo "  Try: kubectl config view"
        echo "  Try: kubectl config get-contexts"
        return 1
    fi
}

# Test kubeconfig
test_kubeconfig() {
    print_header "Testing kubeconfig"
    
    if [[ -f "$HOME/.kube/config" ]]; then
        test_pass "Kubeconfig exists at ~/.kube/config"
        
        local contexts=$(timeout 2 kubectl config get-contexts \
                        --no-headers 2>/dev/null | wc -l || echo "0")
        echo "  Contexts available: $contexts"
        
        local current=$(timeout 2 kubectl config current-context \
                       2>/dev/null || echo "none")
        echo "  Current context: $current"
    else
        test_fail "Kubeconfig not found at ~/.kube/config"
    fi
    
    # Check k3s config
    if [[ -f "/etc/rancher/k3s/k3s.yaml" ]]; then
        test_pass "k3s config exists at /etc/rancher/k3s/k3s.yaml"
    else
        test_warn "k3s config not found (may not be installed)"
    fi
}

# Test krew
test_krew() {
    print_header "Testing krew"
    
    if command -v kubectl-krew >/dev/null 2>&1; then
        test_pass "krew is installed"
        
        # Check PATH
        if echo "$PATH" | grep -q ".krew/bin"; then
            test_pass "krew is in PATH"
        else
            test_fail "krew NOT in PATH"
            echo "  Add to shell: export PATH=\"\${KREW_ROOT:-\$HOME/.krew}/bin:\$PATH\""
        fi
        
        # List plugins
        local plugin_list=$(timeout 3 kubectl krew list 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            local plugin_count=$(echo "$plugin_list" | tail -n +2 | wc -l)
            echo "  Installed plugins: $plugin_count"
            
            if [[ $plugin_count -gt 0 ]]; then
                echo "$plugin_list" | tail -n +2 | sed 's/^/    /'
            fi
        else
            test_warn "Could not list krew plugins"
        fi
    else
        test_fail "krew is NOT installed"
        return 1
    fi
}

# Test krew plugins
test_krew_plugins() {
    print_header "Testing krew plugins"
    
    local plugins=("ctx" "ns" "tree" "neat" "get-all" "whoami")
    
    local installed=$(timeout 3 kubectl krew list 2>/dev/null)
    
    for plugin in "${plugins[@]}"; do
        if echo "$installed" | grep -q "^${plugin}$"; then
            test_pass "Plugin '$plugin' is installed"
        else
            test_warn "Plugin '$plugin' not installed"
        fi
    done
}

# Test shell aliases
test_shell_aliases() {
    print_header "Testing shell aliases"
    
    local aliases=("k" "kgp" "kgs" "kgn" "kx" "kn")
    
    for alias_name in "${aliases[@]}"; do
        if alias "$alias_name" >/dev/null 2>&1; then
            test_pass "Alias '$alias_name' is configured"
        else
            test_warn "Alias '$alias_name' not found"
        fi
    done
    
    if [[ $(alias 2>/dev/null | grep -c "^alias k") -eq 0 ]]; then
        echo "  Run: source ~/.bashrc (or restart shell)"
    fi
}

# Test additional tools
test_additional_tools() {
    print_header "Testing additional tools"
    
    test_command "helm" "Helm"
    test_command "k9s" "k9s"
}

# Test k3s service
test_k3s_service() {
    print_header "Testing k3s service"
    
    if systemctl is-active --quiet k3s 2>/dev/null; then
        test_pass "k3s service is running"
    elif sudo systemctl is-active --quiet k3s 2>/dev/null; then
        test_pass "k3s service is running"
    else
        test_fail "k3s service is NOT running"
        echo "  Try: sudo systemctl status k3s"
        echo "  Try: sudo systemctl start k3s"
    fi
}

# Generate report
generate_report() {
    print_header "Test Summary"
    
    local total=$((PASSED + FAILED))
    local pass_rate=0
    
    if [[ $total -gt 0 ]]; then
        pass_rate=$(( (PASSED * 100) / total ))
    fi
    
    echo ""
    echo "Total tests run: $total"
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo "Pass rate: ${pass_rate}%"
    echo ""
    
    if [[ $FAILED -eq 0 && $PASSED -gt 0 ]]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        return 0
    elif [[ $FAILED -gt 0 ]]; then
        echo -e "${YELLOW}Some tests failed - check output above${NC}"
        return 1
    else
        echo -e "${RED}No tests completed successfully${NC}"
        return 1
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║   k3s/krew Installation Test Suite    ║"
    echo "╔════════════════════════════════════════╗"
    echo -e "${NC}"
    
    # Check if timeout command exists
    if ! command -v timeout >/dev/null 2>&1; then
        echo -e "${RED}Error: 'timeout' command not found${NC}"
        echo "Install: apt-get install coreutils"
        exit 1
    fi
    
    test_command kubectl "kubectl"
    test_kubeconfig
    test_k3s_service
    test_kubectl_connection
    test_krew
    test_krew_plugins
    test_shell_aliases
    test_additional_tools
    
    generate_report
}

main "$@"
