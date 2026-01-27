
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
