
### 🛡️ Microservice Security Review Checklist (..Strict..)

**Service Name:** ___________________

**Review Date:** ___________________

**Reviewer:** ___________________


#### 🚨 1. Critical Hardening (Blockers - Cannot Deploy if "No")
| Control Category | Requirement | Verified (Y/N) | Evidence / Config Ref |
| :--- | :--- | :---: | :--- |
| **Identity (mTLS)** | Is Strict mTLS enabled via Service Mesh (Sidecar injected)? | [ ] | `PeerAuthentication: STRICT` |
| **Authentication** | Does the service validate JWTs (aud/iss/exp) for *every* request? | [ ] | `RequestAuthentication` |
| **Secrets Mgmt** | Are **ALL** secrets injected via Vault/KMS/CSI? (Zero env vars) | [ ] | `SecretProviderClass` |
| **Container Root** | Does the container run as **non-root** user? | [ ] | `runAsNonRoot: true` |
| **Read-Only FS** | Is the root filesystem mounted **Read-Only**? | [ ] | `readOnlyRootFilesystem: true` |
| **Image Signing** | Is the container image signed (Cosign/Notary)? | [ ] | `ImagePolicy` check |
| **Network Egress** | Is Egress traffic blocked by default (NetworkPolicy)? | [ ] | `default-deny-egress` |
| **Database Auth** | Does it use IAM/Workload Identity (no hardcoded DB pass)? | [ ] | `ServiceAccount` mapping |

#### ⚠️ 2. High Risk (Must Fix Before GA / Public Release)
| Control Category | Requirement | Verified (Y/N) | Evidence / Config Ref |
| :--- | :--- | :---: | :--- |
| **Authorization** | Is RBAC/ABAC enforced at the endpoint/method level? | [ ] | `AuthorizationPolicy` |
| **Input Validation** | Is there a strict schema validation (OpenAPI/gRPC)? | [ ] | Swagger/Proto definition |
| **Logging (PII)** | is PII **redacted** from logs (headers, bodies, query params)? | [ ] | Log config / Filter |
| **Resilience** | Are timeouts and circuit breakers configured? | [ ] | `DestinationRule` |
| **Vulnerabilities** | zero "High" or "Critical" CVEs in the container image? | [ ] | Scan Report (Trivy/Snyk) |
| **Health Checks** | Are Liveness and Readiness probes defined safely? | [ ] | `livenessProbe` |
| **Resource Limits** | Are CPU/RAM limits set (preventing DoS)? | [ ] | `resources.limits` |

#### 📝 3. Architecture & Data Flow (Documentation)
| Control Category | Requirement | Verified (Y/N) | Details |
| :--- | :--- | :---: | :--- |
| **Data Class** | What is the highest data classification handled? | [ ] | ☐ Public ☐ Internal ☐ Conf. ☐ Restricted |
| **Trust Boundary** | Does this service cross a Trust Boundary? | [ ] | ☐ Internet-Facing ☐ Internal-Only |
| **Data Storage** | Is data encrypted at rest (DB/Volume)? | [ ] | ☐ KMS Key ID Verified |
| **Audit Trail** | Are "write" actions logged to the centralized audit system? | [ ] | ☐ Audit Log Topic |

#### 📉 4. Threat Model Summary (STRIDE Check)
*Quick check: Did we consider these specifically for this service?*

| Threat | Check | Mitigation Strategy (Brief) |
| :--- | :---: | :--- |
| **S**poofing | [ ] | mTLS + JWT Validation |
| **T**ampering | [ ] | Signed Images + Read-Only FS |
| **R**epudiation | [ ] | Centralized Audit Logging |
| **I**nformation Disc.| [ ] | TLS 1.3 + PII Redaction + Secrets Mgmt |
| **D**enial of Service| [ ] | Rate Limiting + Resource Quotas |
| **E**levation of Priv.| [ ] | Least Privilege RBAC + Non-Root User |

---

**Approval Decision:**
[ ] **APPROVED** (Ready for Production)
[ ] **CONDITIONAL** (Fix "High" items within sprint, deploy to Staging only)
[ ] **REJECTED** (Critical items failed, return to development)


**Security Architect Signature:** ___________________

**Service Owner Signature:** ___________________

##
##

```
#!/bin/bash

# ==============================================================================
# Microservice Security Audit Tool (Staging)
# Usage: ./audit-service.sh <NAMESPACE> <DEPLOYMENT_NAME>
# ==============================================================================

NAMESPACE=$1
DEPLOYMENT=$2
EXIT_CODE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

if [[ -z "$NAMESPACE" || -z "$DEPLOYMENT" ]]; then
    echo "Usage: $0 <namespace> <deployment_name>"
    exit 1
fi

echo -e "\n🔍 ${YELLOW}Starting Audit for Service: ${NC} $DEPLOYMENT in $NAMESPACE"
echo "============================================================"

# Helper function for pass/fail
check_result() {
    if [[ "$1" == "PASS" ]]; then
        echo -e "[ ${GREEN}PASS${NC} ] $2"
    else
        echo -e "[ ${RED}FAIL${NC} ] $2"
        EXIT_CODE=1
    fi
}

# Get Deployment JSON once
DEP_JSON=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o json 2>/dev/null)

if [[ -z "$DEP_JSON" ]]; then
    echo -e "${RED}Error: Deployment not found!${NC}"
    exit 1
fi

# ==============================================================================
# 🚨 1. CRITICAL HARDENING CHECKS
# ==============================================================================
echo -e "\n🚨 Checking Critical Hardening..."

# 1.1 Non-Root User
# Check securityContext.runAsNonRoot at Pod or Container level
RUN_AS_NON_ROOT=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.securityContext.runAsNonRoot // .spec.template.spec.containers[0].securityContext.runAsNonRoot')
if [[ "$RUN_AS_NON_ROOT" == "true" ]]; then
    check_result "PASS" "Container runs as non-root"
else
    # Check strict user ID > 1000
    RUN_AS_USER=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.securityContext.runAsUser // .spec.template.spec.containers[0].securityContext.runAsUser')
    if [[ "$RUN_AS_USER" -gt 0 ]]; then
         check_result "PASS" "Container runs as UID $RUN_AS_USER (Non-Root)"
    else
         check_result "FAIL" "Container allows Root (runAsNonRoot not true or runAsUser 0)"
    fi
fi

# 1.2 Read-Only Filesystem
READ_ONLY=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem')
if [[ "$READ_ONLY" == "true" ]]; then
    check_result "PASS" "Root filesystem is Read-Only"
else
    check_result "FAIL" "Root filesystem is Writable"
fi

# 1.3 Service Account Token Automount (Should be false or strictly scoped)
SA_NAME=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.serviceAccountName')
if [[ "$SA_NAME" == "default" ]]; then
    check_result "FAIL" "Using 'default' ServiceAccount (Least Privilege Violation)"
else
    check_result "PASS" "Using custom ServiceAccount: $SA_NAME"
fi

# 1.4 Environment Variables for Secrets (We want explicit secretRef or Vault injection)
# This checks if there are raw "value" fields that look like secrets (simple heuristic)
RAW_SECRETS=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.containers[0].env[]? | select(.name | test("PASS|SECRET|KEY|TOKEN")) | select(.value != null) | .name')
if [[ -n "$RAW_SECRETS" ]]; then
    check_result "FAIL" "Potential raw secrets in Env Vars: $RAW_SECRETS"
else
    check_result "PASS" "No obvious raw secrets in Environment Variables"
fi

# 1.5 Strict mTLS (Istio)
# Check if a PeerAuthentication policy exists for the workload or namespace
MTLS_MODE=$(kubectl get peerauthentication -n "$NAMESPACE" -o json | jq -r '.items[] | select(.spec.mtls.mode == "STRICT") | .metadata.name' | head -n 1)
if [[ -n "$MTLS_MODE" ]]; then
    check_result "PASS" "Strict mTLS enabled in namespace (Policy: $MTLS_MODE)"
else
    # Check if global mesh policy is strict (optional, assuming checking namespace here)
    check_result "FAIL" "No Strict PeerAuthentication found in namespace"
fi

# ==============================================================================
# ⚠️ 2. HIGH RISK CHECKS
# ==============================================================================
echo -e "\n⚠️  Checking High Risk Configurations..."

# 2.1 Resource Limits
CPU_LIMIT=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.containers[0].resources.limits.cpu')
MEM_LIMIT=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.containers[0].resources.limits.memory')

if [[ "$CPU_LIMIT" != "null" && "$MEM_LIMIT" != "null" ]]; then
    check_result "PASS" "Resource limits defined (CPU: $CPU_LIMIT, Mem: $MEM_LIMIT)"
else
    check_result "FAIL" "Missing Resource Limits (DoS Risk)"
fi

# 2.2 Liveness/Readiness Probes
LIVENESS=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.containers[0].livenessProbe')
READINESS=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.containers[0].readinessProbe')

if [[ "$LIVENESS" != "null" && "$READINESS" != "null" ]]; then
    check_result "PASS" "Health probes configured"
else
    check_result "FAIL" "Missing Liveness or Readiness probes"
fi

# 2.3 Image Scanning (Using Trivy)
IMAGE=$(echo "$DEP_JSON" | jq -r '.spec.template.spec.containers[0].image')
echo -e "   ℹ️  Scanning image: $IMAGE (This might take a moment...)"

if command -v trivy &> /dev/null; then
    # Scan for Critical/High vulnerabilities only, ignore unfixed
    TRIVY_RESULT=$(trivy image --severity CRITICAL,HIGH --ignore-unfixed --quiet --format json "$IMAGE")
    CRITICAL_COUNT=$(echo "$TRIVY_RESULT" | jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length')
    
    if [[ "$CRITICAL_COUNT" -eq 0 ]]; then
        check_result "PASS" "Image Scan passed (0 Critical)"
    else
        check_result "FAIL" "Image Scan failed ($CRITICAL_COUNT Critical vulnerabilities found)"
    fi
else
    echo -e "[ ${YELLOW}SKIP${NC} ] Trivy not installed, skipping image scan."
fi

# 2.4 Network Policies (Egress)
# Check if any NetworkPolicy in the namespace affects this app
NET_POL=$(kubectl get networkpolicy -n "$NAMESPACE" -o name 2>/dev/null)
if [[ -n "$NET_POL" ]]; then
    check_result "PASS" "Network Policies exist in namespace"
else
    check_result "FAIL" "No Network Policies found in namespace (Open Network)"
fi

# ==============================================================================
# 📝 SUMMARY
# ==============================================================================
echo -e "\n============================================================"
if [[ "$EXIT_CODE" -eq 0 ]]; then
    echo -e "${GREEN}✅ AUDIT PASSED: Service $DEPLOYMENT is ready for production review.${NC}"
else
    echo -e "${RED}❌ AUDIT FAILED: Please fix the issues above before deploying.${NC}"
fi

exit $EXIT_CODE
```
