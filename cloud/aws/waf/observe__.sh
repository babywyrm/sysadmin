#!/usr/bin/env bash
#
# WAF Observer - Unified Read-Only WAF Observability Tool
#
# Purpose: Audit, monitor, and report on AWS WAF configurations
# Access: Read-only (safe for production environments)
# Version: 2.0.0
# Author: DevOps Team
# Last Updated: 2026-01-07
#
# Dependencies:
#   - aws-cli (v2.x recommended)
#   - jq (v1.6+)
#   - bash 4.0+
#
# Usage:
#   ./waf-observer.sh coverage --profile PROFILE --region REGION
#   ./waf-observer.sh audit --profile PROFILE --region REGION
#   ./waf-observer.sh metrics --webacl NAME --profile PROFILE --region REGION
#   ./waf-observer.sh dump --profile PROFILE --region REGION
#
# Exit Codes:
#   0 - Success
#   1 - General error
#   2 - Missing dependencies
#   3 - Invalid arguments
#   4 - AWS API error
#

set -euo pipefail

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly MIN_BASH_VERSION=4

# AWS Configuration
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
MODE=""
WEBACL_NAME=""
OUTPUT_FORMAT="text"  # text or csv

# ANSI Color Codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Rule Priority Classifications
readonly -a HIGH_PRIORITY_RULES=(
  "AWSManagedRulesCommonRuleSet"
  "AWSManagedRulesLinuxRuleSet"
)

readonly -a MEDIUM_PRIORITY_RULES=(
  "AWSManagedRulesKnownBadInputsRuleSet"
  "AWSManagedRulesSQLiRuleSet"
  "AWSManagedRulesAmazonIpReputationList"
)

readonly -a OPTIONAL_RULES=(
  "AWSManagedRulesAnonymousIpList"
)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

#
# @description Log an error message and exit with specified code
# @param $1 Error message
# @param $2 Exit code (default: 1)
#
error_exit() {
  local message="${1:-Unknown error}"
  local exit_code="${2:-1}"
  echo -e "${RED}ERROR:${NC} ${message}" >&2
  exit "${exit_code}"
}

#
# @description Log a warning message
# @param $1 Warning message
#
warn() {
  local message="${1:-}"
  echo -e "${YELLOW}WARNING:${NC} ${message}" >&2
}

#
# @description Log an info message
# @param $1 Info message
#
info() {
  local message="${1:-}"
  echo -e "${CYAN}INFO:${NC} ${message}"
}

#
# @description Log a success message
# @param $1 Success message
#
success() {
  local message="${1:-}"
  echo -e "${GREEN}✓${NC} ${message}"
}

#
# @description Check if a command exists
# @param $1 Command name
# @return 0 if exists, 1 otherwise
#
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

#
# @description Validate required dependencies
#
check_dependencies() {
  local missing_deps=()

  if ! command_exists aws; then
    missing_deps+=("aws-cli")
  fi

  if ! command_exists jq; then
    missing_deps+=("jq")
  fi

  if [[ ${#missing_deps[@]} -gt 0 ]]; then
    error_exit "Missing required dependencies: ${missing_deps[*]}\nPlease install them and try again." 2
  fi

  # Check bash version
  if [[ "${BASH_VERSINFO[0]}" -lt ${MIN_BASH_VERSION} ]]; then
    error_exit "Bash ${MIN_BASH_VERSION}.0 or higher is required. Current version: ${BASH_VERSION}" 2
  fi
}

#
# @description Validate AWS credentials and region
#
validate_aws_config() {
  info "Validating AWS configuration..."
  
  if ! aws sts get-caller-identity --profile "${PROFILE}" --region "${REGION}" >/dev/null 2>&1; then
    error_exit "Failed to authenticate with AWS using profile '${PROFILE}' in region '${REGION}'\nPlease check your credentials and try again." 4
  fi

  success "AWS authentication successful"
}

#
# @description Calculate percentage safely (avoids division by zero)
# @param $1 Numerator
# @param $2 Denominator
# @return Percentage as integer (0 if denominator is 0)
#
safe_percentage() {
  local numerator="${1:-0}"
  local denominator="${2:-0}"
  
  if [[ "${denominator}" -eq 0 ]]; then
    echo "0"
  else
    echo $(( numerator * 100 / denominator ))
  fi
}

#
# @description Print a horizontal separator line
# @param $1 Character to use (default: ━)
# @param $2 Length (default: 110)
#
print_separator() {
  local char="${1:-━}"
  local length="${2:-110}"
  printf '%*s\n' "${length}" '' | tr ' ' "${char}"
}

#
# @description Print a section header
# @param $1 Header text
#
print_header() {
  local header_text="${1:-}"
  echo ""
  print_separator "━"
  echo -e "${BOLD}${header_text}${NC}"
  echo "Region: ${REGION} | Profile: ${PROFILE} | Date: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  print_separator "━"
  echo ""
}

# ============================================================================
# AWS API WRAPPER FUNCTIONS
# ============================================================================

#
# @description Fetch all WebACLs in the region
# @return JSON array of WebACLs
#
fetch_webacls() {
  local webacls_json
  
  webacls_json=$(aws wafv2 list-web-acls \
    --scope REGIONAL \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --output json 2>&1)
  
  if [[ $? -ne 0 ]]; then
    error_exit "Failed to fetch WebACLs: ${webacls_json}" 4
  fi

  local count
  count=$(echo "${webacls_json}" | jq -r '.WebACLs | length // 0')
  
  if [[ "${count}" -eq 0 ]]; then
    warn "No WebACLs found in region ${REGION}"
    echo "[]"
    return 0
  fi

  echo "${webacls_json}"
}

#
# @description Fetch rules for a specific WebACL
# @param $1 WebACL ID
# @param $2 WebACL Name
# @return Newline-separated list of rule names
#
fetch_webacl_rules() {
  local webacl_id="${1}"
  local webacl_name="${2}"
  
  local rules_json
  rules_json=$(aws wafv2 get-web-acl \
    --scope REGIONAL \
    --id "${webacl_id}" \
    --name "${webacl_name}" \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --output json 2>/dev/null)
  
  if [[ $? -ne 0 ]]; then
    warn "Failed to fetch rules for WebACL: ${webacl_name}"
    echo ""
    return 1
  fi

  echo "${rules_json}" | jq -r '.WebACL.Rules[]?.Name // empty' || echo ""
}

#
# @description Check if a rule is present in the rules list
# @param $1 Rules list (newline-separated)
# @param $2 Rule name to check
# @return 0 if found, 1 otherwise
#
rule_exists() {
  local rules="${1}"
  local rule_name="${2}"
  
  if [[ "${rules}" =~ ${rule_name} ]]; then
    return 0
  else
    return 1
  fi
}

# ============================================================================
# HELP AND USAGE
# ============================================================================

#
# @description Display help message and exit
#
usage() {
  cat << EOF
${BOLD}WAF Observer - Read-Only WAF Observability Tool${NC}
Version: ${SCRIPT_VERSION}

${BOLD}DESCRIPTION:${NC}
  Audit, monitor, and report on AWS WAF configurations in a read-only manner.
  Safe for production environments with no modification capabilities.

${BOLD}MODES:${NC}
  coverage    Show coverage matrix of AWS managed rules across all WebACLs
  audit       Audit all WebACLs for missing high-priority rules
  metrics     Show CloudWatch metrics for a specific WebACL
  dump        Dump all rules for all WebACLs
  list        List all WebACLs in the region
  available   List all available AWS managed rule groups

${BOLD}OPTIONS:${NC}
  --profile PROFILE    AWS profile (default: default or \$AWS_PROFILE)
  --region REGION      AWS region (default: us-east-1 or \$AWS_DEFAULT_REGION)
  --webacl NAME        WebACL name (required for 'metrics' mode)
  --format FORMAT      Output format: text|csv (default: text, for coverage mode)
  --version            Show version information
  --help               Show this help message

${BOLD}EXAMPLES:${NC}
  # Show coverage matrix
  ${SCRIPT_NAME} coverage --profile my-readonly-profile --region us-east-1

  # Export coverage to CSV
  ${SCRIPT_NAME} coverage --profile my-profile --format csv > coverage.csv

  # Audit for missing rules
  ${SCRIPT_NAME} audit --profile my-readonly-profile --region us-west-2

  # Check metrics for a specific WebACL
  ${SCRIPT_NAME} metrics --webacl my-webacl --profile my-profile

  # List available AWS managed rule groups
  ${SCRIPT_NAME} available --profile my-profile --region eu-west-1

${BOLD}EXIT CODES:${NC}
  0 - Success
  1 - General error
  2 - Missing dependencies
  3 - Invalid arguments
  4 - AWS API error

${BOLD}REQUIREMENTS:${NC}
  - aws-cli v2.x (recommended)
  - jq v1.6+
  - bash 4.0+
  - Valid AWS credentials with WAF read permissions

${BOLD}PERMISSIONS REQUIRED:${NC}
  - wafv2:ListWebACLs
  - wafv2:GetWebACL
  - wafv2:ListAvailableManagedRuleGroups
  - cloudwatch:GetMetricStatistics (for metrics mode)

EOF
  exit 0
}

#
# @description Display version information
#
show_version() {
  echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
  echo "Bash version: ${BASH_VERSION}"
  echo "AWS CLI version: $(aws --version 2>&1 | head -n1)"
  echo "jq version: $(jq --version 2>&1)"
  exit 0
}

# ============================================================================
# MODE: coverage - Show coverage matrix
# ============================================================================

#
# @description Generate coverage matrix showing which rules are enabled per WebACL
#
mode_coverage() {
  print_header "WAF Rule Coverage Matrix"

  info "Fetching WebACLs..."
  
  local webacls_json
  webacls_json=$(fetch_webacls)
  
  local webacl_count
  webacl_count=$(echo "${webacls_json}" | jq -r '. | length // 0')
  
  if [[ "${webacl_count}" -eq 0 ]]; then
    warn "No WebACLs to analyze"
    return 0
  fi

  success "Found ${webacl_count} WebACLs. Building coverage matrix..."
  echo ""

  # CSV output
  if [[ "${OUTPUT_FORMAT}" == "csv" ]]; then
    echo "WebACL Name,Common Rule Set,Linux Rule Set,Bad Inputs Rule Set,SQLi Rule Set,IP Reputation List"
    
    echo "${webacls_json}" | jq -r '.WebACLs[] | "\(.Name)|\(.Id)"' | while IFS='|' read -r name id; do
      [[ -z "${name}" ]] && continue
      
      local rules
      rules=$(fetch_webacl_rules "${id}" "${name}")
      
      local common="No"
      local linux="No"
      local badinput="No"
      local sqli="No"
      local iprep="No"
      
      rule_exists "${rules}" "AWSManagedRulesCommonRuleSet" && common="Yes"
      rule_exists "${rules}" "AWSManagedRulesLinuxRuleSet" && linux="Yes"
      rule_exists "${rules}" "AWSManagedRulesKnownBadInputsRuleSet" && badinput="Yes"
      rule_exists "${rules}" "AWSManagedRulesSQLiRuleSet" && sqli="Yes"
      rule_exists "${rules}" "AWSManagedRulesAmazonIpReputationList" && iprep="Yes"
      
      echo "${name},${common},${linux},${badinput},${sqli},${iprep}"
    done
    
    return 0
  fi

  # Text output with table formatting
  printf "%-40s | %-8s | %-8s | %-8s | %-8s | %-8s\n" \
    "WebACL Name" \
    "Common" \
    "Linux" \
    "BadInput" \
    "SQLi" \
    "IpRep"
  printf "%.40s-+-%.8s-+-%.8s-+-%.8s-+-%.8s-+-%.8s\n" \
    "----------------------------------------" \
    "--------" \
    "--------" \
    "--------" \
    "--------" \
    "--------"

  local current=0
  echo "${webacls_json}" | jq -r '.WebACLs[] | "\(.Name)|\(.Id)"' | while IFS='|' read -r name id; do
    [[ -z "${name}" ]] && continue
    current=$((current + 1))
    
    local rules
    rules=$(fetch_webacl_rules "${id}" "${name}")
    
    local common="❌"
    local linux="❌"
    local badinput="❌"
    local sqli="❌"
    local iprep="❌"
    
    rule_exists "${rules}" "AWSManagedRulesCommonRuleSet" && common="✅"
    rule_exists "${rules}" "AWSManagedRulesLinuxRuleSet" && linux="✅"
    rule_exists "${rules}" "AWSManagedRulesKnownBadInputsRuleSet" && badinput="✅"
    rule_exists "${rules}" "AWSManagedRulesSQLiRuleSet" && sqli="✅"
    rule_exists "${rules}" "AWSManagedRulesAmazonIpReputationList" && iprep="✅"
    
    printf "%-40s | %-8s | %-8s | %-8s | %-8s | %-8s\n" \
      "${name}" "${common}" "${linux}" "${badinput}" "${sqli}" "${iprep}"
  done

  echo ""
  print_separator "─"
  echo ""
  echo "${BOLD}Legend:${NC}"
  echo "  Common   = AWSManagedRulesCommonRuleSet (OWASP Top-10)"
  echo "  Linux    = AWSManagedRulesLinuxRuleSet (RCE protection)"
  echo "  BadInput = AWSManagedRulesKnownBadInputsRuleSet"
  echo "  SQLi     = AWSManagedRulesSQLiRuleSet"
  echo "  IpRep    = AWSManagedRulesAmazonIpReputationList"
  echo ""
  echo "  ✅ = Enabled    ❌ = Missing"
  echo ""
}

# ============================================================================
# MODE: audit - Audit for missing high-priority rules
# ============================================================================

#
# @description Audit all WebACLs for security compliance
#
mode_audit() {
  print_header "WAF Security Audit - Missing High-Priority Rules"

  info "Fetching WebACLs..."
  
  local webacls_json
  webacls_json=$(fetch_webacls)
  
  local webacl_count
  webacl_count=$(echo "${webacls_json}" | jq -r '. | length // 0')
  
  if [[ "${webacl_count}" -eq 0 ]]; then
    warn "No WebACLs to audit"
    return 0
  fi

  success "Found ${webacl_count} WebACLs. Starting audit..."
  echo ""
  
  local total=0
  local at_risk=0
  local partial=0
  local protected=0

  echo "${webacls_json}" | jq -r '.WebACLs[] | "\(.Name)|\(.Id)"' | while IFS='|' read -r name id; do
    [[ -z "${name}" ]] && continue
    total=$((total + 1))
    
    local rules
    rules=$(fetch_webacl_rules "${id}" "${name}")
    
    # Check all recommended rules
    local has_common=false
    local has_linux=false
    local has_badinput=false
    local has_sqli=false
    local has_iprep=false
    local has_anon=false
    
    rule_exists "${rules}" "AWSManagedRulesCommonRuleSet" && has_common=true
    rule_exists "${rules}" "AWSManagedRulesLinuxRuleSet" && has_linux=true
    rule_exists "${rules}" "AWSManagedRulesKnownBadInputsRuleSet" && has_badinput=true
    rule_exists "${rules}" "AWSManagedRulesSQLiRuleSet" && has_sqli=true
    rule_exists "${rules}" "AWSManagedRulesAmazonIpReputationList" && has_iprep=true
    rule_exists "${rules}" "AWSManagedRulesAnonymousIpList" && has_anon=true
    
    # Count missing rules by priority
    local missing_high_pri=0
    local missing_med_pri=0
    
    [[ "${has_common}" == "false" ]] && missing_high_pri=$((missing_high_pri + 1))
    [[ "${has_linux}" == "false" ]] && missing_high_pri=$((missing_high_pri + 1))
    [[ "${has_badinput}" == "false" ]] && missing_med_pri=$((missing_med_pri + 1))
    [[ "${has_sqli}" == "false" ]] && missing_med_pri=$((missing_med_pri + 1))
    [[ "${has_iprep}" == "false" ]] && missing_med_pri=$((missing_med_pri + 1))
    
    # Determine risk level and display
    if [[ ${missing_high_pri} -gt 0 ]]; then
      at_risk=$((at_risk + 1))
      echo -e "${RED}⚠  [${total}/${webacl_count}] ${name} - AT RISK${NC}"
      echo "   └─ Missing ${missing_high_pri} high-priority + ${missing_med_pri} medium-priority rules:"
      [[ "${has_common}" == "false" ]] && echo -e "      ${RED}✗ HIGH${NC}   AWSManagedRulesCommonRuleSet (OWASP Top-10)"
      [[ "${has_linux}" == "false" ]] && echo -e "      ${RED}✗ HIGH${NC}   AWSManagedRulesLinuxRuleSet (RCE protection)"
      [[ "${has_badinput}" == "false" ]] && echo -e "      ${YELLOW}✗ MEDIUM${NC} AWSManagedRulesKnownBadInputsRuleSet"
      [[ "${has_sqli}" == "false" ]] && echo -e "      ${YELLOW}✗ MEDIUM${NC} AWSManagedRulesSQLiRuleSet"
      [[ "${has_iprep}" == "false" ]] && echo -e "      ${YELLOW}✗ MEDIUM${NC} AWSManagedRulesAmazonIpReputationList"
      [[ "${has_anon}" == "false" ]] && echo -e "      ${BLUE}ℹ OPTIONAL${NC} AWSManagedRulesAnonymousIpList (may impact legitimate users)"
      echo ""
    elif [[ ${missing_med_pri} -gt 0 ]]; then
      partial=$((partial + 1))
      echo -e "${YELLOW}⚡ [${total}/${webacl_count}] ${name} - PARTIAL PROTECTION${NC}"
      echo "   └─ Has high-priority rules, missing ${missing_med_pri} medium-priority:"
      [[ "${has_badinput}" == "false" ]] && echo -e "      ${YELLOW}✗${NC} AWSManagedRulesKnownBadInputsRuleSet"
      [[ "${has_sqli}" == "false" ]] && echo -e "      ${YELLOW}✗${NC} AWSManagedRulesSQLiRuleSet"
      [[ "${has_iprep}" == "false" ]] && echo -e "      ${YELLOW}✗${NC} AWSManagedRulesAmazonIpReputationList"
      [[ "${has_anon}" == "false" ]] && echo -e "      ${BLUE}ℹ OPTIONAL${NC} AWSManagedRulesAnonymousIpList"
      echo ""
    else
      protected=$((protected + 1))
      echo -e "${GREEN}✓  [${total}/${webacl_count}] ${name} - FULLY PROTECTED${NC}"
      [[ "${has_anon}" == "false" ]] && echo -e "      ${BLUE}ℹ${NC}  Optional: AWSManagedRulesAnonymousIpList not enabled"
    fi
  done

  echo ""
  print_separator "━"
  
  # Calculate percentages safely
  local protected_pct
  local partial_pct
  local at_risk_pct
  
  protected_pct=$(safe_percentage "${protected}" "${total}")
  partial_pct=$(safe_percentage "${partial}" "${total}")
  at_risk_pct=$(safe_percentage "${at_risk}" "${total}")
  
  echo "${BOLD}Summary:${NC}"
  echo "  Total WebACLs:           ${total}"
  echo -e "  ${GREEN}Fully Protected:${NC}         ${protected} (${protected_pct}%)"
  echo -e "  ${YELLOW}Partial Protection:${NC}      ${partial} (${partial_pct}%)"
  echo -e "  ${RED}At Risk:${NC}                 ${at_risk} (${at_risk_pct}%) - Missing HIGH-priority rules"
  echo ""
  echo "${BOLD}Recommended Rule Priority:${NC}"
  echo -e "  ${RED}HIGH${NC}     AWSManagedRulesCommonRuleSet, AWSManagedRulesLinuxRuleSet"
  echo -e "  ${YELLOW}MEDIUM${NC}   AWSManagedRulesKnownBadInputsRuleSet, SQLiRuleSet, IpReputationList"
  echo -e "  ${BLUE}OPTIONAL${NC} AWSManagedRulesAnonymousIpList (may block legitimate users)"
  echo ""
  echo "${BOLD}Next Steps:${NC}"
  echo "  1. Enable HIGH-priority rules in COUNT mode first (observe for 7 days)"
  echo "  2. Promote to BLOCK mode if no false positives detected"
  echo "  3. Enable MEDIUM-priority rules incrementally"
  echo "  4. Evaluate OPTIONAL rules based on business requirements"
  print_separator "━"
  echo ""
}

# ============================================================================
# MODE: dump - Dump all rules for all WebACLs
# ============================================================================

#
# @description Dump complete rule configurations for all WebACLs
#
mode_dump() {
  print_header "WAF Rules Dump - All Configurations"

  info "Fetching WebACLs..."
  
  local webacls_json
  webacls_json=$(fetch_webacls)
  
  local webacl_count
  webacl_count=$(echo "${webacls_json}" | jq -r '. | length // 0')
  
  if [[ "${webacl_count}" -eq 0 ]]; then
    warn "No WebACLs to dump"
    return 0
  fi

  success "Found ${webacl_count} WebACLs. Dumping configurations..."
  echo ""
  
  local current=0
  echo "${webacls_json}" | jq -r '.WebACLs[] | "\(.Name)|\(.Id)"' | while IFS='|' read -r name id; do
    [[ -z "${name}" ]] && continue
    current=$((current + 1))
    
    print_separator "─" 50
    echo -e "${BOLD}WebACL [${current}/${webacl_count}]: ${name}${NC}"
    echo "ID: ${id}"
    print_separator "─" 50
    
    local rules
    rules=$(fetch_webacl_rules "${id}" "${name}")
    
    if [[ -z "${rules}" ]]; then
      echo "  ${YELLOW}(No rules configured)${NC}"
    else
      local rule_count=0
      while IFS= read -r rule; do
        [[ -z "${rule}" ]] && continue
        rule_count=$((rule_count + 1))
        if [[ "${rule}" =~ ^AWSManaged ]]; then
          echo -e "  [${rule_count}] ${GREEN}AWS MANAGED:${NC} ${rule}"
        else
          echo -e "  [${rule_count}] ${CYAN}CUSTOM:${NC} ${rule}"
        fi
      done <<< "${rules}"
    fi
    
    echo ""
  done

  print_separator "━"
}

# ============================================================================
# MODE: list - List all WebACLs
# ============================================================================

#
# @description List all WebACLs with basic information
#
mode_list() {
  print_header "Available WebACLs"

  info "Fetching WebACLs..."
  
  local webacls_json
  webacls_json=$(fetch_webacls)
  
  local webacl_count
  webacl_count=$(echo "${webacls_json}" | jq -r '. | length // 0')
  
  if [[ "${webacl_count}" -eq 0 ]]; then
    warn "No WebACLs found"
    return 0
  fi

  success "Found ${webacl_count} WebACLs"
  echo ""

  echo "${webacls_json}" | jq -r '.WebACLs[] | "  • \(.Name)\n    ID: \(.Id)\n    ARN: \(.ARN)\n"'

  print_separator "━"
}

# ============================================================================
# MODE: metrics - Show CloudWatch metrics
# ============================================================================

#
# @description Display CloudWatch metrics for a specific WebACL
#
mode_metrics() {
  if [[ -z "${WEBACL_NAME}" ]]; then
    error_exit "--webacl NAME is required for metrics mode" 3
  fi

  print_header "WAF Metrics - ${WEBACL_NAME}"

  # Check if check-waf-metrics.sh exists
  if [[ ! -f "./check-waf-metrics.sh" ]]; then
    error_exit "check-waf-metrics.sh not found in current directory\nMetrics mode requires check-waf-metrics.sh to be present" 1
  fi

  if [[ ! -x "./check-waf-metrics.sh" ]]; then
    warn "check-waf-metrics.sh is not executable, attempting to make it executable..."
    chmod +x "./check-waf-metrics.sh" || error_exit "Failed to make check-waf-metrics.sh executable" 1
  fi

  info "Fetching CloudWatch metrics for last 7 days..."
  echo ""

  # Execute the metrics script
  ./check-waf-metrics.sh "${WEBACL_NAME}" --profile "${PROFILE}" --region "${REGION}" --weekly || \
    error_exit "Failed to fetch metrics" 4
}

# ============================================================================
# MODE: available - List available AWS managed rule groups
# ============================================================================

#
# @description List all available AWS managed rule groups with recommendations
#
mode_available() {
  print_header "Available AWS Managed Rule Groups"

  info "Fetching available AWS managed rule groups..."
  echo ""

  local rule_groups
  rule_groups=$(aws wafv2 list-available-managed-rule-groups \
    --scope REGIONAL \
    --profile "${PROFILE}" \
    --region "${REGION}" \
    --output json 2>&1)
  
  if [[ $? -ne 0 ]]; then
    error_exit "Failed to fetch managed rule groups: ${rule_groups}" 4
  fi

  local aws_rules
  aws_rules=$(echo "${rule_groups}" | jq -r '.ManagedRuleGroups[] | select(.VendorName == "AWS") | "\(.Name)|\(.Description)"')

  # Display HIGH priority rules
  print_separator "=" 67
  echo -e "${RED}${BOLD}🔴 HIGH PRIORITY - Recommended for All WebACLs${NC}"
  print_separator "=" 67
  
  for rule in "${HIGH_PRIORITY_RULES[@]}"; do
    while IFS='|' read -r name desc; do
      [[ -z "${name}" ]] && continue
      if [[ "${name}" == "${rule}" ]]; then
        echo ""
        echo -e "${RED}• ${name}${NC}"
        echo "  └─ ${desc}"
      fi
    done <<< "${aws_rules}"
  done

  # Display MEDIUM priority rules
  echo ""
  print_separator "=" 67
  echo -e "${YELLOW}${BOLD}🟡 MEDIUM PRIORITY - Defense-in-Depth${NC}"
  print_separator "=" 67
  
  for rule in "${MEDIUM_PRIORITY_RULES[@]}"; do
    while IFS='|' read -r name desc; do
      [[ -z "${name}" ]] && continue
      if [[ "${name}" == "${rule}" ]]; then
        echo ""
        echo -e "${YELLOW}• ${name}${NC}"
        echo "  └─ ${desc}"
      fi
    done <<< "${aws_rules}"
  done

  # Display OPTIONAL rules
  echo ""
  print_separator "=" 67
  echo -e "${BLUE}${BOLD}🔵 OPTIONAL - Evaluate Based on Business Requirements${NC}"
  print_separator "=" 67
  
  for rule in "${OPTIONAL_RULES[@]}"; do
    while IFS='|' read -r name desc; do
      [[ -z "${name}" ]] && continue
      if [[ "${name}" == "${rule}" ]]; then
        echo ""
        echo -e "${BLUE}• ${name}${NC}"
        echo "  └─ ${desc}"
        echo "  ⚠️  May block legitimate users behind VPNs/TOR"
      fi
    done <<< "${aws_rules}"
  done

  # Display OTHER available rules
  echo ""
  print_separator "=" 67
  echo -e "${BOLD}ℹ️  OTHER AVAILABLE RULES (Not Currently Recommended)${NC}"
  print_separator "=" 67
  echo ""
  echo "The following AWS managed rules are available but not in our"
  echo "standard recommendation (specialized use cases only):"
  echo ""
  
  while IFS='|' read -r name desc; do
    [[ -z "${name}" ]] && continue
    
    local is_recommended=false
    for rule in "${HIGH_PRIORITY_RULES[@]}" "${MEDIUM_PRIORITY_RULES[@]}" "${OPTIONAL_RULES[@]}"; do
      if [[ "${name}" == "${rule}" ]]; then
        is_recommended=true
        break
      fi
    done
    
    if [[ "${is_recommended}" == "false" ]]; then
      echo "• ${name}"
      echo "  └─ ${desc}"
      echo ""
    fi
  done <<< "${aws_rules}"

  print_separator "━"
  echo ""
  echo "${BOLD}Note:${NC} Rule availability may vary by region. Showing results for: ${REGION}"
  echo ""
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

#
# @description Parse and validate command-line arguments
#
parse_arguments() {
  if [[ $# -eq 0 ]]; then
    usage
  fi

  MODE="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case $1 in
      --profile)
        [[ -z "${2:-}" ]] && error_exit "Missing value for --profile" 3
        PROFILE="$2"
        shift 2
        ;;
      --region)
        [[ -z "${2:-}" ]] && error_exit "Missing value for --region" 3
        REGION="$2"
        shift 2
        ;;
      --webacl)
        [[ -z "${2:-}" ]] && error_exit "Missing value for --webacl" 3
        WEBACL_NAME="$2"
        shift 2
        ;;
      --format)
        [[ -z "${2:-}" ]] && error_exit "Missing value for --format" 3
        OUTPUT_FORMAT="$2"
        if [[ ! "${OUTPUT_FORMAT}" =~ ^(text|csv)$ ]]; then
          error_exit "Invalid format: ${OUTPUT_FORMAT}. Must be 'text' or 'csv'" 3
        fi
        shift 2
        ;;
      --version)
        show_version
        ;;
      --help)
        usage
        ;;
      *)
        error_exit "Unknown option: $1\nUse --help for usage information" 3
        ;;
    esac
  done
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

#
# @description Main entry point
#
main() {
  # Check dependencies first
  check_dependencies

  # Parse arguments
  parse_arguments "$@"

  # Validate AWS configuration
  validate_aws_config

  # Execute the requested mode
  case "${MODE}" in
    coverage)
      mode_coverage
      ;;
    audit)
      mode_audit
      ;;
    dump)
      mode_dump
      ;;
    list)
      mode_list
      ;;
    metrics)
      mode_metrics
      ;;
    available)
      mode_available
      ;;
    *)
      error_exit "Unknown mode: ${MODE}\nUse --help for valid modes" 3
      ;;
  esac
}

# Execute main function with all arguments
main "$@"
