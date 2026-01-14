#!/usr/bin/env bash
#
# kubernetes-api-pentest.sh - Comprehensive Kubernetes API Enumeration Tool ..beta..
#
# DESCRIPTION:
#   Performs read-only reconnaissance of Kubernetes clusters via API server.
#   Discovers namespaces, RBAC configurations, secrets, pods, and potential
#   security misconfigurations.
#
# USAGE:
#   bash kubernetes-api-pentest.sh [OPTIONS]
#
# OPTIONS:
#   --deep          Perform deep scan with detailed resource extraction
#   --stealth       Add random delays between requests (evasion)
#   --output DIR    Specify custom output directory (default: ./k8s-pentest-output)
#   --namespace NS  Target specific namespace only
#   --help          Display this help message
#
# EXAMPLES:
#   # Quick scan from inside a pod
#   bash kubernetes-api-pentest.sh
#
#   # Deep scan with stealth mode
#   bash kubernetes-api-pentest.sh --deep --stealth
#
#   # External scan with custom output
#   export TOKEN="eyJhbGci..."
#   export APISERVER="https://k8s.example.com:6443"
#   bash kubernetes-api-pentest.sh --output /tmp/scan
#
# DISCLAIMER:
#   Use only on systems you are authorized to test. Unauthorized access is illegal.
#

set -euo pipefail

#------------------------------------------------------------------------------
# CONFIGURATION & GLOBALS
#------------------------------------------------------------------------------

# Script version
VERSION="2.0"

# Operation modes
DEEP_MODE=false           # Extract full resource details
STEALTH_MODE=false        # Add delays between requests
TARGET_NAMESPACE=""       # Empty = all namespaces

# Output configuration
OUTPUT_DIR="./k8s-pentest-output"
DELAY=0                   # Delay between requests in stealth mode

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#------------------------------------------------------------------------------
# ARGUMENT PARSING
#------------------------------------------------------------------------------

show_help() {
  head -n 35 "$0" | grep "^#" | sed 's/^# \?//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --deep)
      DEEP_MODE=true
      shift
      ;;
    --stealth)
      STEALTH_MODE=true
      DELAY=5
      shift
      ;;
    --output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --namespace)
      TARGET_NAMESPACE="$2"
      shift 2
      ;;
    --help|-h)
      show_help
      ;;
    *)
      echo -e "${RED}[!] Unknown option: $1${NC}"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

#------------------------------------------------------------------------------
# SETUP & INITIALIZATION
#------------------------------------------------------------------------------

# Create timestamped scan directory
TS=$(date +%Y%m%d_%H%M%S)
SCAN_DIR="$OUTPUT_DIR/scan_$TS"
mkdir -p "$SCAN_DIR"/{raw,analysis,reports}

# Detect and load Kubernetes credentials
# Priority: 1) In-cluster service account, 2) Environment variables
if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
  # Running inside a Kubernetes pod - use mounted service account
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo "default")
  APISERVER="https://kubernetes.default.svc.cluster.local"
  CONTEXT="in-cluster"
  echo -e "${GREEN}[+] Using in-cluster service account${NC}"
  echo -e "${BLUE}    Namespace: $NAMESPACE${NC}"
else
  # External access - require TOKEN and APISERVER environment variables
  if [[ -z "${TOKEN:-}" ]] || [[ -z "${APISERVER:-}" ]]; then
    echo -e "${RED}[!] Not running in cluster and TOKEN/APISERVER not set${NC}"
    echo ""
    echo "For external access, set environment variables:"
    echo "  export TOKEN='eyJhbGci...'"
    echo "  export APISERVER='https://k8s-api.example.com:6443'"
    exit 1
  fi
  NAMESPACE="${NAMESPACE:-default}"
  CONTEXT="external"
  echo -e "${GREEN}[+] Using external credentials${NC}"
  echo -e "${BLUE}    API Server: $APISERVER${NC}"
fi

# Validate jq is available (required for JSON parsing)
if ! command -v jq &> /dev/null; then
  echo -e "${RED}[!] jq is required but not installed${NC}"
  echo "Install with: apt-get install jq  or  yum install jq"
  exit 1
fi

#------------------------------------------------------------------------------
# HELPER FUNCTIONS
#------------------------------------------------------------------------------

# log() - Write timestamped log message to console and log file
# Args: $@ - Log message
log() {
  local timestamp=$(date +'%H:%M:%S')
  echo -e "${GREEN}[$timestamp]${NC} $*" | tee -a "$SCAN_DIR/scan.log"
}

# log_error() - Write error message
# Args: $@ - Error message
log_error() {
  local timestamp=$(date +'%H:%M:%S')
  echo -e "${RED}[$timestamp] [ERROR]${NC} $*" | tee -a "$SCAN_DIR/scan.log"
}

# log_warning() - Write warning message
# Args: $@ - Warning message
log_warning() {
  local timestamp=$(date +'%H:%M:%S')
  echo -e "${YELLOW}[$timestamp] [WARN]${NC} $*" | tee -a "$SCAN_DIR/scan.log"
}

# log_info() - Write info message
# Args: $@ - Info message
log_info() {
  local timestamp=$(date +'%H:%M:%S')
  echo -e "${BLUE}[$timestamp] [INFO]${NC} $*" | tee -a "$SCAN_DIR/scan.log"
}

# api_get() - Make GET request to Kubernetes API
# Args:
#   $1 - API endpoint path (e.g., /api/v1/namespaces)
#   $2 - Output file path
# Returns: 0 on success, 1 on failure
api_get() {
  local endpoint="$1"
  local output="$2"
  
  # Apply stealth delay if enabled
  if [[ $STEALTH_MODE == true ]]; then
    local delay=$((RANDOM % DELAY + 1))
    sleep "$delay"
  fi
  
  # Make API request with timeout and error handling
  if curl -sk --max-time 30 \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/json" \
    -H "User-Agent: kubectl/v1.28.0" \
    "$APISERVER$endpoint" > "$output" 2>/dev/null; then
    
    # Check if response is valid JSON and not an error
    if jq -e . >/dev/null 2>&1 < "$output"; then
      # Check for API error responses
      if jq -e '.kind == "Status" and .status == "Failure"' >/dev/null 2>&1 < "$output"; then
        local reason=$(jq -r '.reason // "Unknown"' < "$output")
        echo "{\"error\": \"API Error: $reason\"}" > "$output"
        return 1
      fi
      return 0
    else
      echo "{\"error\": \"Invalid JSON response\"}" > "$output"
      return 1
    fi
  else
    echo "{\"error\": \"Request failed or timed out\"}" > "$output"
    return 1
  fi
}

# check_permission() - Test if current service account has specific permission
# Args:
#   $1 - Verb (get, list, create, delete, etc.)
#   $2 - Resource (pods, secrets, etc.)
#   $3 - Namespace (optional, empty for cluster-wide)
#   $4 - Subresource (optional, e.g., "exec" for pods/exec)
# Returns: Prints "true" or "false"
check_permission() {
  local verb="$1"
  local resource="$2"
  local namespace="${3:-}"
  local subresource="${4:-}"
  
  # Build SelfSubjectAccessReview request body
  local body='{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": {
      "resourceAttributes": {
        "verb": "'$verb'",
        "resource": "'$resource'"'
  
  # Add namespace if specified
  [[ -n "$namespace" ]] && body="$body"',
        "namespace": "'$namespace'"'
  
  # Add subresource if specified
  [[ -n "$subresource" ]] && body="$body"',
        "subresource": "'$subresource'"'
  
  body="$body"'
      }
    }
  }'
  
  # Make permission check request
  curl -sk --max-time 10 \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "User-Agent: kubectl/v1.28.0" \
    -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
    -d "$body" 2>/dev/null | \
    jq -r '.status.allowed // false' 2>/dev/null || echo "false"
}

# safe_jq() - Run jq with error handling
# Args: $@ - jq arguments
# Returns: jq output or empty string on error
safe_jq() {
  jq "$@" 2>/dev/null || echo ""
}

# count_items() - Count items in API response
# Args: $1 - JSON file path
# Returns: Number of items or 0
count_items() {
  local file="$1"
  if [[ -f "$file" ]]; then
    jq -r '.items | length' "$file" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

#------------------------------------------------------------------------------
# ANALYSIS FUNCTIONS
#------------------------------------------------------------------------------

# analyze_secrets() - Find sensitive data in secrets
# Args: $1 - secrets JSON file
analyze_secrets() {
  local secrets_file="$1"
  local output="$SCAN_DIR/analysis/sensitive-secrets.txt"
  
  log_info "Analyzing secrets for sensitive data..."
  
  {
    echo "=== Potentially Sensitive Secrets ==="
    echo ""
    
    # Find secrets with common sensitive keywords
    jq -r '.items[] | select(
      .metadata.name | test("password|token|key|secret|credential|admin|root|aws|gcp|azure|private"; "i")
    ) | "\(.metadata.namespace)/\(.metadata.name) (Type: \(.type))"' \
    "$secrets_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Service Account Token Secrets ==="
    jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | 
    "\(.metadata.namespace)/\(.metadata.name)"' \
    "$secrets_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Docker Registry Secrets ==="
    jq -r '.items[] | select(.type == "kubernetes.io/dockerconfigjson") | 
    "\(.metadata.namespace)/\(.metadata.name)"' \
    "$secrets_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== TLS Secrets ==="
    jq -r '.items[] | select(.type == "kubernetes.io/tls") | 
    "\(.metadata.namespace)/\(.metadata.name)"' \
    "$secrets_file" 2>/dev/null | sort -u || echo "None found"
    
  } > "$output"
  
  log "  Saved to: analysis/sensitive-secrets.txt"
}

# analyze_pods() - Find pods with security misconfigurations
# Args: $1 - pods JSON file
analyze_pods() {
  local pods_file="$1"
  local output="$SCAN_DIR/analysis/risky-pods.txt"
  
  log_info "Analyzing pods for security issues..."
  
  {
    echo "=== Privileged Pods ==="
    jq -r '.items[] | select(
      .spec.containers[].securityContext.privileged == true
    ) | "\(.metadata.namespace)/\(.metadata.name)"' \
    "$pods_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Pods with hostNetwork ==="
    jq -r '.items[] | select(.spec.hostNetwork == true) | 
    "\(.metadata.namespace)/\(.metadata.name)"' \
    "$pods_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Pods with hostPID ==="
    jq -r '.items[] | select(.spec.hostPID == true) | 
    "\(.metadata.namespace)/\(.metadata.name)"' \
    "$pods_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Pods with hostIPC ==="
    jq -r '.items[] | select(.spec.hostIPC == true) | 
    "\(.metadata.namespace)/\(.metadata.name)"' \
    "$pods_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Pods with Host Path Mounts ==="
    jq -r '.items[] | select(.spec.volumes[]?.hostPath) | 
    "\(.metadata.namespace)/\(.metadata.name): \([.spec.volumes[]?.hostPath.path] | join(", "))"' \
    "$pods_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Pods with Dangerous Capabilities ==="
    jq -r '.items[] | select(
      .spec.containers[].securityContext.capabilities.add[]? | 
      test("SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH")
    ) | "\(.metadata.namespace)/\(.metadata.name)"' \
    "$pods_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Pods Running as Root (UID 0) ==="
    jq -r '.items[] | select(
      (.spec.containers[].securityContext.runAsUser == 0) or
      (.spec.securityContext.runAsUser == 0)
    ) | "\(.metadata.namespace)/\(.metadata.name)"' \
    "$pods_file" 2>/dev/null | sort -u || echo "None found"
    
  } > "$output"
  
  log "  Saved to: analysis/risky-pods.txt"
}

# analyze_rbac() - Analyze RBAC for privilege escalation paths
# Args: $1 - clusterrolebindings file, $2 - rolebindings file
analyze_rbac() {
  local crb_file="$1"
  local rb_file="$2"
  local output="$SCAN_DIR/analysis/rbac-analysis.txt"
  
  log_info "Analyzing RBAC configurations..."
  
  {
    echo "=== Cluster-Admin Bindings ==="
    jq -r '.items[] | select(.roleRef.name == "cluster-admin") | 
    "Binding: \(.metadata.name)\nSubjects: \(.subjects | @json)\n"' \
    "$crb_file" 2>/dev/null || echo "None found"
    
    echo ""
    echo "=== Service Accounts with Cluster Roles ==="
    jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | 
    "Role: \(.roleRef.name) -> SA: \(.subjects[] | select(.kind == "ServiceAccount") | "\(.namespace)/\(.name)")"' \
    "$crb_file" 2>/dev/null | sort -u || echo "None found"
    
    echo ""
    echo "=== Anonymous Bindings ==="
    jq -r '.items[] | select(
      .subjects[]?.name == "system:anonymous" or 
      .subjects[]?.name == "system:unauthenticated"
    ) | "Binding: \(.metadata.name) -> Role: \(.roleRef.name)"' \
    "$crb_file" 2>/dev/null | sort -u || echo "None found"
    
  } > "$output"
  
  log "  Saved to: analysis/rbac-analysis.txt"
}

# generate_summary_report() - Create executive summary
generate_summary_report() {
  local report="$SCAN_DIR/reports/executive-summary.txt"
  
  log "Generating executive summary..."
  
  {
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║        Kubernetes Security Assessment Summary              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Scan Date: $(date)"
    echo "Context: $CONTEXT"
    echo "API Server: $APISERVER"
    echo "Mode: $([ "$DEEP_MODE" = true ] && echo "Deep" || echo "Quick")"
    echo ""
    echo "─────────────────────────────────────────────────────────────"
    echo "RESOURCE COUNTS"
    echo "─────────────────────────────────────────────────────────────"
    
    # Count resources
    for resource in namespaces pods services secrets configmaps deployments daemonsets; do
      local file="$SCAN_DIR/raw/${resource}.json"
      if [[ -f "$file" ]]; then
        local count=$(count_items "$file")
        printf "%-20s : %s\n" "$resource" "$count"
      fi
    done
    
    echo ""
    echo "─────────────────────────────────────────────────────────────"
    echo "PERMISSION SUMMARY"
    echo "─────────────────────────────────────────────────────────────"
    
    if [[ -f "$SCAN_DIR/raw/dangerous-permissions.csv" ]]; then
      echo "Dangerous Permissions Granted:"
      grep ",true," "$SCAN_DIR/raw/dangerous-permissions.csv" 2>/dev/null | \
        cut -d, -f1,3 | sed 's/,/ - /' || echo "  None detected"
    fi
    
    echo ""
    echo "─────────────────────────────────────────────────────────────"
    echo "SECURITY FINDINGS"
    echo "─────────────────────────────────────────────────────────────"
    
    # Count security issues
    if [[ -f "$SCAN_DIR/analysis/risky-pods.txt" ]]; then
      local priv_count=$(grep -c "." "$SCAN_DIR/analysis/risky-pods.txt" 2>/dev/null || echo 0)
      echo "Risky Pod Configurations: $priv_count"
    fi
    
    if [[ -f "$SCAN_DIR/analysis/sensitive-secrets.txt" ]]; then
      local secret_count=$(grep "^[a-z]" "$SCAN_DIR/analysis/sensitive-secrets.txt" 2>/dev/null | wc -l)
      echo "Sensitive Secrets Found: $secret_count"
    fi
    
    echo ""
    echo "─────────────────────────────────────────────────────────────"
    echo "RECOMMENDATIONS"
    echo "─────────────────────────────────────────────────────────────"
    echo "1. Review all privileged pods and host mounts"
    echo "2. Audit service account permissions (principle of least privilege)"
    echo "3. Rotate exposed secrets and credentials"
    echo "4. Implement network policies for namespace isolation"
    echo "5. Enable Pod Security Standards (PSS/PSA)"
    echo ""
    echo "Full details available in: $SCAN_DIR/"
    echo ""
    
  } > "$report"
  
  # Display summary to console
  cat "$report"
}

#------------------------------------------------------------------------------
# MAIN EXECUTION
#------------------------------------------------------------------------------

# Display banner
cat <<'EOF' | tee "$SCAN_DIR/banner.txt"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║       Kubernetes API Penetration Testing Tool v2.0            ║
║                   Mi Familia Edition                          ║
║                                                               ║
║   Comprehensive API enumeration and security assessment       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF

log "Scan started at $(date)"
log "Output directory: $SCAN_DIR"
log "Deep mode: $DEEP_MODE | Stealth mode: $STEALTH_MODE"
echo ""

#------------------------------------------------------------------------------
# PHASE 1: INITIAL RECONNAISSANCE
#------------------------------------------------------------------------------

log "=== Phase 1: Initial Reconnaissance ==="
echo ""

# Get cluster version and basic info
log_info "Discovering cluster version..."
if api_get "/version" "$SCAN_DIR/raw/cluster-version.json"; then
  VERSION_INFO=$(jq -r '.gitVersion // "unknown"' "$SCAN_DIR/raw/cluster-version.json")
  log "  Cluster version: $VERSION_INFO"
else
  log_error "  Failed to get cluster version"
fi

# Get available API resources
log_info "Enumerating API resources..."
api_get "/api/v1" "$SCAN_DIR/raw/core-api.json"
api_get "/apis" "$SCAN_DIR/raw/api-groups.json"

# List all API groups for reference
if [[ -f "$SCAN_DIR/raw/api-groups.json" ]]; then
  jq -r '.groups[]?.name // empty' "$SCAN_DIR/raw/api-groups.json" 2>/dev/null | \
    sort > "$SCAN_DIR/raw/available-api-groups.txt"
  local group_count=$(wc -l < "$SCAN_DIR/raw/available-api-groups.txt")
  log "  Found $group_count API groups"
fi

# Enumerate namespaces
log_info "Enumerating namespaces..."
if api_get "/api/v1/namespaces" "$SCAN_DIR/raw/namespaces.json"; then
  # Extract namespace list
  if [[ -n "$TARGET_NAMESPACE" ]]; then
    NAMESPACES="$TARGET_NAMESPACE"
    log "  Targeting specific namespace: $TARGET_NAMESPACE"
  else
    NAMESPACES=$(jq -r '.items[]?.metadata.name // empty' \
      "$SCAN_DIR/raw/namespaces.json" 2>/dev/null | sort)
    local ns_count=$(echo "$NAMESPACES" | wc -l)
    log "  Found $ns_count namespaces"
  fi
  
  # Save namespace list
  echo "$NAMESPACES" > "$SCAN_DIR/raw/namespace-list.txt"
else
  log_warning "  Failed to enumerate namespaces, using default"
  NAMESPACES="default"
  echo "$NAMESPACES" > "$SCAN_DIR/raw/namespace-list.txt"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 2: PERMISSION ASSESSMENT
#------------------------------------------------------------------------------

log "=== Phase 2: Permission Assessment ==="
echo ""

# Test basic permissions across common resources
log_info "Testing basic permissions..."
{
  echo "Resource,Verb,Allowed"
  
  # Test common resources and verbs
  for resource in pods secrets services deployments daemonsets nodes configmaps; do
    for verb in get list create delete update patch; do
      allowed=$(check_permission "$verb" "$resource")
      echo "$resource,$verb,$allowed"
      
      # Log critical permissions
      if [[ "$allowed" == "true" ]] && [[ "$verb" =~ ^(create|delete|update)$ ]]; then
        log_warning "  ⚠ Write permission: $verb $resource"
      fi
    done
  done
  
} > "$SCAN_DIR/raw/permissions.csv"

log "  Saved to: raw/permissions.csv"

# Test dangerous/high-risk permissions
log_info "Testing dangerous permissions..."
{
  echo "Permission,Allowed,Risk Level,Description"
  
  # Critical permissions that indicate potential compromise paths
  while IFS='|' read -r verb resource subresource risk desc; do
    if [[ -n "$subresource" ]]; then
      allowed=$(check_permission "$verb" "$resource" "" "$subresource")
      perm="${verb}:${resource}/${subresource}"
    else
      allowed=$(check_permission "$verb" "$resource")
      perm="${verb}:${resource}"
    fi
    
    echo "$perm,$allowed,$risk,$desc"
    
    # Alert on critical permissions
    if [[ "$allowed" == "true" ]] && [[ "$risk" == "CRITICAL" ]]; then
      log_error "  🔴 CRITICAL permission granted: $perm"
    elif [[ "$allowed" == "true" ]] && [[ "$risk" == "HIGH" ]]; then
      log_warning "  🟠 HIGH risk permission granted: $perm"
    fi
    
  done <<'DANGEROUS_PERMS'
create|pods|exec|CRITICAL|Remote code execution in pods
get|secrets||HIGH|Read secret data (credentials)
list|secrets||HIGH|Enumerate all secrets
create|pods||HIGH|Create malicious pods
delete|pods||MEDIUM|Pod disruption capability
create|persistentvolumeclaims||MEDIUM|Claim persistent storage
update|rolebindings||CRITICAL|Modify RBAC permissions
create|rolebindings||CRITICAL|Grant new permissions
update|clusterrolebindings||CRITICAL|Modify cluster-wide RBAC
create|clusterrolebindings||CRITICAL|Grant cluster-wide permissions
get|nodes||LOW|Infrastructure reconnaissance
list|nodes||LOW|Cluster topology discovery
create|daemonsets||HIGH|Deploy to all nodes
create|cronjobs||MEDIUM|Schedule recurring tasks
escalate|pods||CRITICAL|Privilege escalation capability
impersonate|users||CRITICAL|Impersonate other users
impersonate|serviceaccounts||CRITICAL|Impersonate service accounts
DANGEROUS_PERMS
  
} > "$SCAN_DIR/raw/dangerous-permissions.csv"

log "  Saved to: raw/dangerous-permissions.csv"

echo ""

#------------------------------------------------------------------------------
# PHASE 3: RBAC ENUMERATION
#------------------------------------------------------------------------------

log "=== Phase 3: RBAC Enumeration ==="
echo ""

# Service Accounts
log_info "Enumerating service accounts..."
if api_get "/api/v1/serviceaccounts" "$SCAN_DIR/raw/serviceaccounts.json"; then
  local sa_count=$(count_items "$SCAN_DIR/raw/serviceaccounts.json")
  log "  Found $sa_count service accounts"
else
  log_error "  Failed to enumerate service accounts"
fi

# Roles (namespace-scoped)
log_info "Enumerating roles..."
if api_get "/apis/rbac.authorization.k8s.io/v1/roles" "$SCAN_DIR/raw/roles.json"; then
  local role_count=$(count_items "$SCAN_DIR/raw/roles.json")
  log "  Found $role_count roles"
else
  log_error "  Failed to enumerate roles"
fi

# ClusterRoles (cluster-scoped)
log_info "Enumerating cluster roles..."
if api_get "/apis/rbac.authorization.k8s.io/v1/clusterroles" "$SCAN_DIR/raw/clusterroles.json"; then
  local cr_count=$(count_items "$SCAN_DIR/raw/clusterroles.json")
  log "  Found $cr_count cluster roles"
  
  # Find roles with wildcard permissions
  log_info "Finding wildcard roles..."
  jq -r '.items[] | select(
    .rules[]? | 
    (.verbs[]? == "*") or 
    (.resources[]? == "*") or 
    (.apiGroups[]? == "*")
  ) | .metadata.name' "$SCAN_DIR/raw/clusterroles.json" 2>/dev/null | \
    sort -u > "$SCAN_DIR/analysis/wildcard-roles.txt"
  
  local wildcard_count=$(wc -l < "$SCAN_DIR/analysis/wildcard-roles.txt" 2>/dev/null || echo 0)
  if [[ $wildcard_count -gt 0 ]]; then
    log_warning "  Found $wildcard_count roles with wildcard permissions"
  fi
else
  log_error "  Failed to enumerate cluster roles"
fi

# RoleBindings (namespace-scoped)
log_info "Enumerating role bindings..."
if api_get "/apis/rbac.authorization.k8s.io/v1/rolebindings" "$SCAN_DIR/raw/rolebindings.json"; then
  local rb_count=$(count_items "$SCAN_DIR/raw/rolebindings.json")
  log "  Found $rb_count role bindings"
else
  log_error "  Failed to enumerate role bindings"
fi

# ClusterRoleBindings (cluster-scoped)
log_info "Enumerating cluster role bindings..."
if api_get "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" "$SCAN_DIR/raw/clusterrolebindings.json"; then
  local crb_count=$(count_items "$SCAN_DIR/raw/clusterrolebindings.json")
  log "  Found $crb_count cluster role bindings"
  
  # Find cluster-admin bindings
  log_info "Finding cluster-admin bindings..."
  jq -r '.items[] | select(.roleRef.name == "cluster-admin") | 
    "Binding: \(.metadata.name)\nSubjects:\n\(.subjects[] | "  - \(.kind): \(.namespace // "cluster")/\(.name)")\n"' \
    "$SCAN_DIR/raw/clusterrolebindings.json" 2>/dev/null > "$SCAN_DIR/analysis/cluster-admin-bindings.txt"
  
  local admin_binding_count=$(grep -c "^Binding:" "$SCAN_DIR/analysis/cluster-admin-bindings.txt" 2>/dev/null || echo 0)
  if [[ $admin_binding_count -gt 0 ]]; then
    log_warning "  Found $admin_binding_count cluster-admin bindings"
  fi
else
  log_error "  Failed to enumerate cluster role bindings"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 4: SECRET & CREDENTIAL DISCOVERY
#------------------------------------------------------------------------------

log "=== Phase 4: Secret & Credential Discovery ==="
echo ""

# Secrets
log_info "Enumerating secrets..."
if api_get "/api/v1/secrets" "$SCAN_DIR/raw/secrets.json"; then
  local secret_count=$(count_items "$SCAN_DIR/raw/secrets.json")
  log "  Found $secret_count secrets"
  
  # Analyze secrets for sensitive data
  analyze_secrets "$SCAN_DIR/raw/secrets.json"
  
  # In deep mode, try to extract secret values
  if [[ "$DEEP_MODE" == true ]]; then
    log_info "Extracting secret details (deep mode)..."
    mkdir -p "$SCAN_DIR/raw/secrets"
    
    while IFS= read -r ns_name; do
      IFS='/' read -r ns name <<< "$ns_name"
      local secret_file="$SCAN_DIR/raw/secrets/${ns}_${name}.json"
      
      if api_get "/api/v1/namespaces/$ns/secrets/$name" "$secret_file"; then
        # Decode base64 values
        jq -r '.data | to_entries[] | "\(.key): \(.value)"' "$secret_file" 2>/dev/null | \
          while IFS=: read -r key value; do
            echo "$key: $(echo "$value" | base64 -d 2>/dev/null || echo "[decode failed]")"
          done > "$SCAN_DIR/raw/secrets/${ns}_${name}_decoded.txt"
      fi
      
      [[ $STEALTH_MODE == true ]] && sleep 1
    done < <(jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"' "$SCAN_DIR/raw/secrets.json" 2>/dev/null)
    
    log "  Extracted secret details to raw/secrets/"
  fi
else
  log_error "  Failed to enumerate secrets"
fi

# ConfigMaps (often contain credentials)
log_info "Enumerating config maps..."
if api_get "/api/v1/configmaps" "$SCAN_DIR/raw/configmaps.json"; then
  local cm_count=$(count_items "$SCAN_DIR/raw/configmaps.json")
  log "  Found $cm_count config maps"
  
  # Search for credentials in ConfigMaps
  log_info "Searching ConfigMaps for credentials..."
  jq -r '.items[] | select(
    .data | to_entries[]? | .value | 
    test("password|token|secret|key|credential|apikey|api_key|api-key"; "i")
  ) | "\(.metadata.namespace)/\(.metadata.name)"' \
  "$SCAN_DIR/raw/configmaps.json" 2>/dev/null | \
  sort -u > "$SCAN_DIR/analysis/configmaps-with-credentials.txt"
  
  local cred_cm_count=$(wc -l < "$SCAN_DIR/analysis/configmaps-with-credentials.txt" 2>/dev/null || echo 0)
  if [[ $cred_cm_count -gt 0 ]]; then
    log_warning "  Found $cred_cm_count ConfigMaps with potential credentials"
  fi
else
  log_error "  Failed to enumerate config maps"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 5: POD & WORKLOAD DISCOVERY
#------------------------------------------------------------------------------

log "=== Phase 5: Pod & Workload Discovery ==="
echo ""

# Pods
log_info "Enumerating pods..."
if api_get "/api/v1/pods" "$SCAN_DIR/raw/pods.json"; then
  local pod_count=$(count_items "$SCAN_DIR/raw/pods.json")
  log "  Found $pod_count pods"
  
  # Analyze pods for security issues
  analyze_pods "$SCAN_DIR/raw/pods.json"
else
  log_error "  Failed to enumerate pods"
fi

# Deployments
log_info "Enumerating deployments..."
if api_get "/apis/apps/v1/deployments" "$SCAN_DIR/raw/deployments.json"; then
  local deploy_count=$(count_items "$SCAN_DIR/raw/deployments.json")
  log "  Found $deploy_count deployments"
else
  log_error "  Failed to enumerate deployments"
fi

# DaemonSets (often privileged)
log_info "Enumerating daemon sets..."
if api_get "/apis/apps/v1/daemonsets" "$SCAN_DIR/raw/daemonsets.json"; then
  local ds_count=$(count_items "$SCAN_DIR/raw/daemonsets.json")
  log "  Found $ds_count daemon sets"
  
  # DaemonSets often run with elevated privileges
  if [[ $ds_count -gt 0 ]]; then
    log_warning "  DaemonSets often run privileged - review carefully"
  fi
else
  log_error "  Failed to enumerate daemon sets"
fi

# StatefulSets
log_info "Enumerating stateful sets..."
if api_get "/apis/apps/v1/statefulsets" "$SCAN_DIR/raw/statefulsets.json"; then
  local sts_count=$(count_items "$SCAN_DIR/raw/statefulsets.json")
  log "  Found $sts_count stateful sets"
else
  log_error "  Failed to enumerate stateful sets"
fi

# Jobs
log_info "Enumerating jobs..."
if api_get "/apis/batch/v1/jobs" "$SCAN_DIR/raw/jobs.json"; then
  local job_count=$(count_items "$SCAN_DIR/raw/jobs.json")
  log "  Found $job_count jobs"
else
  log_error "  Failed to enumerate jobs"
fi

# CronJobs (good for persistence)
log_info "Enumerating cron jobs..."
if api_get "/apis/batch/v1/cronjobs" "$SCAN_DIR/raw/cronjobs.json"; then
  local cron_count=$(count_items "$SCAN_DIR/raw/cronjobs.json")
  log "  Found $cron_count cron jobs"
  
  if [[ $cron_count -gt 0 ]]; then
    log_info "  CronJobs can be modified for persistence"
  fi
else
  log_error "  Failed to enumerate cron jobs"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 6: NETWORK & SERVICE DISCOVERY
#------------------------------------------------------------------------------

log "=== Phase 6: Network & Service Discovery ==="
echo ""

# Services
log_info "Enumerating services..."
if api_get "/api/v1/services" "$SCAN_DIR/raw/services.json"; then
  local svc_count=$(count_items "$SCAN_DIR/raw/services.json")
  log "  Found $svc_count services"
  
  # Find externally exposed services
  log_info "Finding externally exposed services..."
  jq -r '.items[] | select(
    .spec.type == "LoadBalancer" or .spec.type == "NodePort"
  ) | "\(.metadata.namespace)/\(.metadata.name) (\(.spec.type))"' \
  "$SCAN_DIR/raw/services.json" 2>/dev/null | \
  sort -u > "$SCAN_DIR/analysis/external-services.txt"
  
  local ext_svc_count=$(wc -l < "$SCAN_DIR/analysis/external-services.txt" 2>/dev/null || echo 0)
  if [[ $ext_svc_count -gt 0 ]]; then
    log_warning "  Found $ext_svc_count externally exposed services"
  fi
else
  log_error "  Failed to enumerate services"
fi

# Endpoints
log_info "Enumerating endpoints..."
if api_get "/api/v1/endpoints" "$SCAN_DIR/raw/endpoints.json"; then
  local ep_count=$(count_items "$SCAN_DIR/raw/endpoints.json")
  log "  Found $ep_count endpoints"
else
  log_error "  Failed to enumerate endpoints"
fi

# Ingresses
log_info "Enumerating ingresses..."
if api_get "/apis/networking.k8s.io/v1/ingresses" "$SCAN_DIR/raw/ingresses.json"; then
  local ing_count=$(count_items "$SCAN_DIR/raw/ingresses.json")
  log "  Found $ing_count ingresses"
  
  # Extract TLS secret names from ingresses
  if [[ $ing_count -gt 0 ]]; then
    log_info "Extracting TLS secrets from ingresses..."
    jq -r '.items[] | select(.spec.tls) | 
      "\(.metadata.namespace)/\(.metadata.name): \([.spec.tls[].secretName] | join(", "))"' \
      "$SCAN_DIR/raw/ingresses.json" 2>/dev/null > "$SCAN_DIR/analysis/ingress-tls-secrets.txt"
  fi
else
  log_error "  Failed to enumerate ingresses"
fi

# Network Policies
log_info "Enumerating network policies..."
if api_get "/apis/networking.k8s.io/v1/networkpolicies" "$SCAN_DIR/raw/networkpolicies.json"; then
  local np_count=$(count_items "$SCAN_DIR/raw/networkpolicies.json")
  log "  Found $np_count network policies"
  
  if [[ $np_count -eq 0 ]]; then
    log_warning "  No network policies found - flat network topology"
  fi
  
  # Find namespaces without network policies
  if [[ -f "$SCAN_DIR/raw/namespace-list.txt" ]]; then
    local namespaces_with_policy=$(jq -r '.items[].metadata.namespace' \
      "$SCAN_DIR/raw/networkpolicies.json" 2>/dev/null | sort -u)
    
    comm -23 "$SCAN_DIR/raw/namespace-list.txt" \
      <(echo "$namespaces_with_policy") > "$SCAN_DIR/analysis/namespaces-without-netpol.txt"
    
    local no_policy_count=$(wc -l < "$SCAN_DIR/analysis/namespaces-without-netpol.txt")
    if [[ $no_policy_count -gt 0 ]]; then
      log_warning "  $no_policy_count namespaces have no network policies"
    fi
  fi
else
  log_error "  Failed to enumerate network policies"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 7: STORAGE & PERSISTENCE
#------------------------------------------------------------------------------

log "=== Phase 7: Storage & Persistence ==="
echo ""

# Persistent Volumes
log_info "Enumerating persistent volumes..."
if api_get "/api/v1/persistentvolumes" "$SCAN_DIR/raw/persistentvolumes.json"; then
  local pv_count=$(count_items "$SCAN_DIR/raw/persistentvolumes.json")
  log "  Found $pv_count persistent volumes"
else
  log_error "  Failed to enumerate persistent volumes"
fi

# Persistent Volume Claims
log_info "Enumerating persistent volume claims..."
if api_get "/api/v1/persistentvolumeclaims" "$SCAN_DIR/raw/persistentvolumeclaims.json"; then
  local pvc_count=$(count_items "$SCAN_DIR/raw/persistentvolumeclaims.json")
  log "  Found $pvc_count persistent volume claims"
else
  log_error "  Failed to enumerate persistent volume claims"
fi

# Storage Classes
log_info "Enumerating storage classes..."
if api_get "/apis/storage.k8s.io/v1/storageclasses" "$SCAN_DIR/raw/storageclasses.json"; then
  local sc_count=$(count_items "$SCAN_DIR/raw/storageclasses.json")
  log "  Found $sc_count storage classes"
  
  # Identify default storage class
  local default_sc=$(jq -r '.items[] | select(
    .metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true"
  ) | .metadata.name' "$SCAN_DIR/raw/storageclasses.json" 2>/dev/null)
  
  if [[ -n "$default_sc" ]]; then
    log "  Default storage class: $default_sc"
  fi
else
  log_error "  Failed to enumerate storage classes"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 8: NODE RECONNAISSANCE
#------------------------------------------------------------------------------

log "=== Phase 8: Node Reconnaissance ==="
echo ""

log_info "Enumerating nodes..."
if api_get "/api/v1/nodes" "$SCAN_DIR/raw/nodes.json"; then
  local node_count=$(count_items "$SCAN_DIR/raw/nodes.json")
  log "  Found $node_count nodes"
  
  # Extract node details
  {
    echo "Node,Role,Version,OS,Container Runtime"
    jq -r '.items[] | 
      "\(.metadata.name),\(
        .metadata.labels["node-role.kubernetes.io/master"] // 
        .metadata.labels["node-role.kubernetes.io/control-plane"] // 
        "worker"
      ),\(.status.nodeInfo.kubeletVersion),\(
        .status.nodeInfo.osImage
      ),\(.status.nodeInfo.containerRuntimeVersion)"' \
      "$SCAN_DIR/raw/nodes.json" 2>/dev/null
  } > "$SCAN_DIR/analysis/node-inventory.csv"
  
  log "  Node inventory saved to: analysis/node-inventory.csv"
else
  log_error "  Failed to enumerate nodes"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 9: EVENTS & AUDIT TRAIL
#------------------------------------------------------------------------------

log "=== Phase 9: Events & Audit Trail ==="
echo ""

log_info "Collecting recent events..."
if api_get "/api/v1/events" "$SCAN_DIR/raw/events.json"; then
  local event_count=$(count_items "$SCAN_DIR/raw/events.json")
  log "  Found $event_count events"
  
  # Extract warning/error events
  jq -r '.items[] | select(.type == "Warning" or .type == "Error") | 
    "\(.lastTimestamp // .eventTime) [\(.type)] \(.involvedObject.namespace)/\(.involvedObject.name): \(.message)"' \
    "$SCAN_DIR/raw/events.json" 2>/dev/null | \
    sort -r > "$SCAN_DIR/analysis/warning-events.txt"
  
  local warning_count=$(wc -l < "$SCAN_DIR/analysis/warning-events.txt" 2>/dev/null || echo 0)
  if [[ $warning_count -gt 0 ]]; then
    log_warning "  Found $warning_count warning/error events"
  fi
else
  log_error "  Failed to collect events"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 10: CUSTOM RESOURCES & EXTENSIONS
#------------------------------------------------------------------------------

log "=== Phase 10: Custom Resources & Extensions ==="
echo ""

log_info "Enumerating custom resource definitions..."
if api_get "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" "$SCAN_DIR/raw/crds.json"; then
  local crd_count=$(count_items "$SCAN_DIR/raw/crds.json")
  log "  Found $crd_count custom resource definitions"
  
  if [[ $crd_count -gt 0 ]]; then
    # List CRD names
    jq -r '.items[].metadata.name' "$SCAN_DIR/raw/crds.json" 2>/dev/null | \
      sort > "$SCAN_DIR/analysis/crd-list.txt"
    log "  CRD list saved to: analysis/crd-list.txt"
  fi
else
  log_error "  Failed to enumerate CRDs"
fi

echo ""

#------------------------------------------------------------------------------
# PHASE 11: ADDITIONAL ANALYSIS
#------------------------------------------------------------------------------

log "=== Phase 11: Additional Analysis ==="
echo ""

# Analyze RBAC configurations
if [[ -f "$SCAN_DIR/raw/clusterrolebindings.json" ]] && [[ -f "$SCAN_DIR/raw/rolebindings.json" ]]; then
  analyze_rbac "$SCAN_DIR/raw/clusterrolebindings.json" "$SCAN_DIR/raw/rolebindings.json"
fi

# Find pods without resource limits (resource exhaustion risk)
if [[ -f "$SCAN_DIR/raw/pods.json" ]]; then
  log_info "Finding pods without resource limits..."
  jq -r '.items[] | select(
    .spec.containers[].resources.limits == null
  ) | "\(.metadata.namespace)/\(.metadata.name)"' \
  "$SCAN_DIR/raw/pods.json" 2>/dev/null | \
  sort -u > "$SCAN_DIR/analysis/pods-without-limits.txt"
  
  local no_limit_count=$(wc -l < "$SCAN_DIR/analysis/pods-without-limits.txt" 2>/dev/null || echo 0)
  if [[ $no_limit_count -gt 0 ]]; then
    log_warning "  Found $no_limit_count pods without resource limits"
  fi
fi

# Extract image information
if [[ -f "$SCAN_DIR/raw/pods.json" ]]; then
  log_info "Extracting container images..."
  jq -r '.items[].spec.containers[].image' "$SCAN_DIR/raw/pods.json" 2>/dev/null | \
    sort -u > "$SCAN_DIR/analysis/container-images.txt"
  
  local image_count=$(wc -l < "$SCAN_DIR/analysis/container-images.txt")
  log "  Found $image_count unique container images"
fi

echo ""

#------------------------------------------------------------------------------
# FINAL REPORTING
#------------------------------------------------------------------------------

log "=== Generating Reports ==="
echo ""

# Generate executive summary
generate_summary_report

# Create findings summary
{
  echo "SECURITY FINDINGS SUMMARY"
  echo "========================="
  echo ""
  
  echo "HIGH-RISK CONFIGURATIONS:"
  [[ -f "$SCAN_DIR/analysis/risky-pods.txt" ]] && \
    echo "  - Risky pods: $(grep -c "." "$SCAN_DIR/analysis/risky-pods.txt" 2>/dev/null || echo 0)"
  
  [[ -f "$SCAN_DIR/analysis/cluster-admin-bindings.txt" ]] && \
    echo "  - Cluster-admin bindings: $(grep -c "^Binding:" "$SCAN_DIR/analysis/cluster-admin-bindings.txt" 2>/dev/null || echo 0)"
  
  [[ -f "$SCAN_DIR/analysis/wildcard-roles.txt" ]] && \
    echo "  - Wildcard roles: $(wc -l < "$SCAN_DIR/analysis/wildcard-roles.txt" 2>/dev/null || echo 0)"
  
  echo ""
  echo "CREDENTIAL EXPOSURE:"
  [[ -f "$SCAN_DIR/analysis/sensitive-secrets.txt" ]] && \
    echo "  - Sensitive secrets: $(grep "^[a-z]" "$SCAN_DIR/analysis/sensitive-secrets.txt" 2>/dev/null | wc -l)"
  
  [[ -f "$SCAN_DIR/analysis/configmaps-with-credentials.txt" ]] && \
    echo "  - ConfigMaps with credentials: $(wc -l < "$SCAN_DIR/analysis/configmaps-with-credentials.txt" 2>/dev/null || echo 0)"
  
  echo ""
  echo "NETWORK EXPOSURE:"
  [[ -f "$SCAN_DIR/analysis/external-services.txt" ]] && \
    echo "  - External services: $(wc -l < "$SCAN_DIR/analysis/external-services.txt" 2>/dev/null || echo 0)"
  
  [[ -f "$SCAN_DIR/analysis/namespaces-without-netpol.txt" ]] && \
    echo "  - Namespaces without network policies: $(wc -l < "$SCAN_DIR/analysis/namespaces-without-netpol.txt" 2>/dev/null || echo 0)"
  
  echo ""
  echo "Full details in: $SCAN_DIR/"
  
} > "$SCAN_DIR/reports/findings-summary.txt"

# Create CSV summary for easy parsing
{
  echo "Category,Finding,Count,Risk,File"
  
  # Add all findings with counts
  echo "RBAC,Cluster-Admin Bindings,$(grep -c "^Binding:" "$SCAN_DIR/analysis/cluster-admin-bindings.txt" 2>/dev/null || echo 0),CRITICAL,analysis/cluster-admin-bindings.txt"
  echo "RBAC,Wildcard Roles,$(wc -l < "$SCAN_DIR/analysis/wildcard-roles.txt" 2>/dev/null || echo 0),HIGH,analysis/wildcard-roles.txt"
  echo "Pods,Privileged Pods,$(grep -c "Privileged Pods" "$SCAN_DIR/analysis/risky-pods.txt" 2>/dev/null || echo 0),CRITICAL,analysis/risky-pods.txt"
  echo "Pods,Host Network Pods,$(grep -c "hostNetwork" "$SCAN_DIR/analysis/risky-pods.txt" 2>/dev/null || echo 0),HIGH,analysis/risky-pods.txt"
  echo "Pods,Pods without Limits,$(wc -l < "$SCAN_DIR/analysis/pods-without-limits.txt" 2>/dev/null || echo 0),MEDIUM,analysis/pods-without-limits.txt"
  echo "Secrets,Sensitive Secrets,$(grep -c "^[a-z]" "$SCAN_DIR/analysis/sensitive-secrets.txt" 2>/dev/null || echo 0),HIGH,analysis/sensitive-secrets.txt"
  echo "Network,External Services,$(wc -l < "$SCAN_DIR/analysis/external-services.txt" 2>/dev/null || echo 0),MEDIUM,analysis/external-services.txt"
  echo "Network,Namespaces without NetworkPolicy,$(wc -l < "$SCAN_DIR/analysis/namespaces-without-netpol.txt" 2>/dev/null || echo 0),MEDIUM,analysis/namespaces-without-netpol.txt"
  
} > "$SCAN_DIR/reports/findings.csv"

log "Reports generated:"
log "  - Executive summary: reports/executive-summary.txt"
log "  - Findings summary: reports/findings-summary.txt"
log "  - Findings CSV: reports/findings.csv"

echo ""

#------------------------------------------------------------------------------
# CLEANUP & FINALIZATION
#------------------------------------------------------------------------------

# Create archive of results if tar is available
if command -v tar &> /dev/null; then
  log "Creating archive of results..."
  tar -czf "$OUTPUT_DIR/scan_${TS}.tar.gz" -C "$OUTPUT_DIR" "scan_$TS" 2>/dev/null && \
    log "  Archive created: $OUTPUT_DIR/scan_${TS}.tar.gz"
fi

# Final summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Scan Complete                              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
log "Scan completed at $(date)"
log "Total duration: $SECONDS seconds"
log "Results location: $SCAN_DIR"
echo ""
echo "Next steps:"
echo "  1. Review executive summary: cat $SCAN_DIR/reports/executive-summary.txt"
echo "  2. Check dangerous permissions: cat $SCAN_DIR/raw/dangerous-permissions.csv"
echo "  3. Analyze risky pods: cat $SCAN_DIR/analysis/risky-pods.txt"
echo "  4. Review sensitive secrets: cat $SCAN_DIR/analysis/sensitive-secrets.txt"
echo ""
echo "⚠️  Remember: Use findings responsibly and only on authorized systems"
echo ""
