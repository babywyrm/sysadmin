#!/bin/bash

# K3s Security Scanner for Ubuntu Jammy
# probably terrible, for now
# Version: 1.0.0
# Description: Performs security checks on K3s installation and configuration

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging setup
LOG_FILE="/var/log/k3s-security-scan-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

echo "Starting K3s Security Scan at $(date)"
echo "----------------------------------------"

# Function to check status and print result
check_status() {
    local check_name="$1"
    local status="$2"
    local details="$3"
    
    printf "%-50s" "$check_name"
    if [ "$status" = "PASS" ]; then
        echo -e "[${GREEN}PASS${NC}]"
    elif [ "$status" = "WARN" ]; then
        echo -e "[${YELLOW}WARN${NC}]"
        echo -e "${YELLOW}Details: $details${NC}"
    else
        echo -e "[${RED}FAIL${NC}]"
        echo -e "${RED}Details: $details${NC}"
    fi
}

# 1. System Configuration Checks
echo -e "\n${YELLOW}1. System Configuration Checks${NC}"

# Check if K3s is installed
if command -v k3s >/dev/null 2>&1; then
    check_status "K3s Installation" "PASS" ""
    K3S_VERSION=$(k3s --version)
else
    check_status "K3s Installation" "FAIL" "K3s not found"
fi

# Check kernel parameters
check_kernel_params() {
    local param="$1"
    local expected="$2"
    local actual=$(sysctl -n "$param" 2>/dev/null)
    
    if [ "$actual" = "$expected" ]; then
        check_status "Kernel Parameter: $param" "PASS" ""
    else
        check_status "Kernel Parameter: $param" "FAIL" "Expected: $expected, Got: $actual"
    fi
}

check_kernel_params "vm.panic_on_oom" "0"
check_kernel_params "vm.overcommit_memory" "1"
check_kernel_params "kernel.panic" "10"
check_kernel_params "net.ipv4.ip_forward" "1"

# 2. Directory Permission Checks
echo -e "\n${YELLOW}2. Directory Permission Checks${NC}"

check_directory_permissions() {
    local dir="$1"
    local expected_perms="$2"
    
    if [ -d "$dir" ]; then
        local actual_perms=$(stat -c %a "$dir")
        if [ "$actual_perms" = "$expected_perms" ]; then
            check_status "Directory Permissions: $dir" "PASS" ""
        else
            check_status "Directory Permissions: $dir" "FAIL" "Expected: $expected_perms, Got: $actual_perms"
        fi
    else
        check_status "Directory Permissions: $dir" "FAIL" "Directory not found"
    fi
}

check_directory_permissions "/etc/k3s" "700"
check_directory_permissions "/var/lib/rancher/k3s" "700"
check_directory_permissions "/var/lib/rancher/k3s/server/logs" "700"

# 3. Configuration File Checks
echo -e "\n${YELLOW}3. Configuration File Checks${NC}"

check_config_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local perms=$(stat -c %a "$file")
        if [ "$perms" = "600" ]; then
            check_status "Config File: $file" "PASS" ""
        else
            check_status "Config File: $file" "FAIL" "Incorrect permissions: $perms"
        fi
    else
        check_status "Config File: $file" "WARN" "File not found"
    fi
}

check_config_file "/etc/k3s/config.yaml"
check_config_file "/var/lib/rancher/k3s/server/audit.yaml"

# 4. Network Security Checks
echo -e "\n${YELLOW}4. Network Security Checks${NC}"

# Check if NetworkPolicies are enabled
if kubectl get networkpolicies --all-namespaces 2>/dev/null | grep -q .; then
    check_status "NetworkPolicies Enabled" "PASS" ""
else
    check_status "NetworkPolicies Enabled" "WARN" "No NetworkPolicies found"
fi

# 5. Pod Security Checks
echo -e "\n${YELLOW}5. Pod Security Checks${NC}"

# Check Pod Security Standards
if kubectl get podsecuritystandards 2>/dev/null | grep -q .; then
    check_status "Pod Security Standards" "PASS" ""
else
    check_status "Pod Security Standards" "WARN" "No Pod Security Standards found"
fi

# 6. API Server Security Checks
echo -e "\n${YELLOW}6. API Server Security Checks${NC}"

check_api_server_arg() {
    local arg="$1"
    local expected="$2"
    
    if ps aux | grep kube-apiserver | grep -q "$arg=$expected"; then
        check_status "API Server Arg: $arg" "PASS" ""
    else
        check_status "API Server Arg: $arg" "WARN" "Argument not found or incorrect value"
    fi
}

check_api_server_arg "--audit-log-maxage" "30"
check_api_server_arg "--audit-log-maxbackup" "10"
check_api_server_arg "--audit-log-maxsize" "100"

# 7. Service Account Checks
echo -e "\n${YELLOW}7. Service Account Checks${NC}"

check_service_accounts() {
    local namespace="$1"
    if kubectl get serviceaccount default -n "$namespace" -o yaml 2>/dev/null | grep -q "automountServiceAccountToken: false"; then
        check_status "Default SA Token Mount ($namespace)" "PASS" ""
    else
        check_status "Default SA Token Mount ($namespace)" "WARN" "automountServiceAccountToken not disabled"
    fi
}

check_service_accounts "default"
check_service_accounts "kube-system"

# 8. Resource Limits Check
echo -e "\n${YELLOW}8. Resource Limits Check${NC}"

if kubectl get limitranges --all-namespaces 2>/dev/null | grep -q .; then
    check_status "Resource Limits Configured" "PASS" ""
else
    check_status "Resource Limits Configured" "WARN" "No LimitRanges found"
fi

# 9. Encryption Configuration Check
echo -e "\n${YELLOW}9. Encryption Configuration Check${NC}"

if [ -f "/etc/k3s/encryption-config.yaml" ]; then
    check_status "Secrets Encryption Config" "PASS" ""
else
    check_status "Secrets Encryption Config" "WARN" "No encryption configuration found"
fi

# Summary
echo -e "\n${YELLOW}Scan Summary${NC}"
echo "----------------------------------------"
echo "Scan completed at $(date)"
echo "Log file: $LOG_FILE"
echo "Please review the findings and take appropriate action."

# Recommendations
echo -e "\n${YELLOW}Recommendations${NC}"
echo "1. Review all WARN and FAIL status items"
echo "2. Implement NetworkPolicies if not present"
echo "3. Enable Pod Security Standards"
echo "4. Configure resource limits for all namespaces"
echo "5. Enable secrets encryption if not configured"
echo "6. Regular security audits and updates"

exit 0
