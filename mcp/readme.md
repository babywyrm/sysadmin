## 🛡️ MCP Blue Team Defensive Structure

A vendor-neutral, repeatable defensive program for **Model Context Protocol (MCP)** + **Agent architectures** that mirrors your pentest framework, but from the **prevent / detect / respond** side.

---

## 1) Defensive Operating Model

### Core principle

Treat **tools + tool outputs** as **untrusted inputs** and treat **tool execution** as **production code execution** (because it is).

### Blue Team lanes (who owns what)

* **Platform Security (Owner)**: gateway policy, tool registry controls, identity/audience binding, egress/mTLS, baseline hardening
* **Detection Engineering**: telemetry, alert rules, canaries, anomaly detection, exfil/loop detection
* **AppSec / Agent Security**: prompt-injection defenses, context sanitation, RAG tenancy controls, agent policy tests
* **SRE / Infra**: Kubernetes security contexts, image scanning, runtime controls, secrets management, patching
* **Incident Response**: playbooks, containment switches, forensics, post-incident control improvements

---

## 2) Defense-in-Depth Architecture (Blue Team View)

```
[ POLICY & IDENTITY PLANE ]
- AuthN/Z, audience binding, scopes, tool RBAC, request signing, key rotation

[ TOOL GOVERNANCE PLANE ]
- Tool registry approval, signing, SBOM, provenance, allowlists, version pinning

[ RUNTIME SAFETY PLANE ]
- Sandbox execution, seccomp/apparmor, rootless, read-only FS, quotas, recursion guards

[ NETWORK & TRANSPORT PLANE ]
- mTLS everywhere, egress allowlist, metadata/IP blocks, DNS controls

[ DATA & CONTEXT INTEGRITY PLANE ]
- Tenant isolation, RAG filters, output sanitization, DLP, secrets redaction

[ OBSERVABILITY & RESPONSE PLANE ]
- Structured logs, traces, audit trails, canaries, alerting, kill-switches
```

---

## 3) “MCP-SHIELD” Blue Team Modules

Mirror your “MCP-SLAYER” pentest engine with a defensive structure that can ship as policy + detection packs.

### ✅ MCP-SHIELD Modules

1. **GUARDRAIL MODULE (Injection + Context Integrity)**

* Tool-output → LLM **sanitization**
* Untrusted content labeling + instruction-stripping
* Prompt-injection policy tests (unit tests for agents)

2. **IDENTITY MODULE (AuthN/Z + Confused Deputy)**

* JWT **audience binding** + tool-specific scopes
* Signed internal headers / claims (no unsigned role headers)
* Step-up auth / HITL for write/destructive tools

3. **TOOLCHAIN MODULE (Tool Registry + Supply Chain)**

* Tool definitions must be **signed** and **approved**
* Container image provenance (SBOM + digest pinning)
* Runtime deny of unsigned/unregistered tools

4. **NETWORK MODULE (SSRF + Insecure Comms)**

* Mandatory **mTLS**
* Egress allowlist by tool
* Block: `169.254.169.254`, RFC1918 (as needed), internal control-plane ranges

5. **RUNTIME MODULE (Pod Escape + DoS)**

* Rootless, seccomp, drop capabilities, read-only FS
* CPU/mem quotas + concurrency caps
* Recursion/loop detection + cost budgets

6. **DATA MODULE (Leaks + Exfil + Memory)**

* Secret redaction at every logging boundary
* DLP policies for Slack/email tools
* Tenant-bound vector DB queries + session scoping

---

## 4) Control Matrix: Prevent / Detect / Respond (Mapped to Your Risks)

| ID | Risk             | Prevent (Hard Controls)                                                                   | Detect (Signals)                                                                     | Respond (Containment)                                                            |
| -: | ---------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| 01 | Prompt Injection | Tool-output sanitization; instruction-stripping; allowlist tool actions; “untrusted” tags | LLM output contains “ask user for key”; unusual tool chain triggered by file content | Disable risky tools; rotate exposed secrets; add regression test for the payload |
| 02 | Confused Deputy  | Enforce `aud` + tool scopes; per-tool tokens; bound sessions                              | 401/403 anomalies; same token used across tools; scope mismatch logs                 | Revoke token; add gateway policy to hard-fail audience mismatch                  |
| 03 | Tool Poisoning   | Signed tool manifests; admin approval; registry ACLs                                      | New tool registration events; outbound traffic to unknown domains                    | Quarantine tool; block domain; review tool supply chain                          |
| 04 | Credential Leak  | Redact auth headers; structured logging w/ sensitive fields dropped                       | Secrets patterns in logs/traces; spikes in “Authorization:” appearances              | Purge logs; rotate keys; patch sanitizer + add CI check                          |
| 05 | Insecure Config  | Disable debug endpoints in prod; auth-gate swagger/metrics                                | Scans show `/swagger` `/debug` reachable; WAF/ALB logs                               | Block at ingress; redeploy hardened config                                       |
| 06 | Excessive Perms  | Least privilege RBAC/IAM; tool-specific SA; deny list secrets APIs                        | K8s API calls for secrets; unusual namespaces queried                                | Rebind SA; revoke cluster-admin; IR on secret exposure                           |
| 07 | Insecure Comm    | mTLS required; HSTS/HTTPS only                                                            | Cleartext traffic detection; cert/mTLS handshake failures                            | Block non-mTLS routes; rotate tokens; enforce mesh policy                        |
| 08 | SSRF via Tool    | Egress allowlist; URL fetch proxy; metadata IP blocks                                     | Requests to metadata ranges; DNS to internal-only zones                              | Block egress; rotate cloud creds; add SSRF regression test                       |
| 09 | Pod Escape       | Rootless; seccomp; no hostPath; runtime class restrictions                                | Syscall anomalies; attempts to access `/proc` privileged paths                       | Kill pod; cordon node; forensics + image rebuild                                 |
| 10 | Data Exfil       | Rate limits; payload caps; DLP gates; “bulk export” approvals                             | High-volume Slack posts; repeated chunked outputs                                    | Disable egress tool; block channel/webhook; audit exported content               |
| 11 | Memory Leak      | Tenant_id filters; per-tenant encryption keys; session partitioning                       | Cross-tenant retrieval anomalies; canary “secret strings” queried                    | Invalidate index; reindex with filters; notify impacted tenants                  |
| 12 | Context Spoofing | Sign internal headers; zero trust service auth                                            | Role/header changes mid-flight; proxy tampering indicators                           | Rotate signing keys; enforce signature checks; update mesh policy                |
| 13 | Supply Chain     | Pin digests; SBOM; provenance attestations; dependency allowlist                          | New deps; CVE spikes; unknown outbound connections                                   | Yank version; rebuild image; block hashes/domains                                |
| 14 | Resource DoS     | Loop guards; per-user/tool budgets; concurrency caps                                      | Repeated tool calls; high cost per session; throttling events                        | Kill session; temporary block user; tune budgets + heuristics                    |

---

## 5) Blue Team Telemetry Requirements (Non-negotiable)

To defend agents, you need **chain-of-custody** visibility.

### Must-log fields (structured)

* `request_id`, `session_id`, `tenant_id`, `user_id` (or pseudonymous), `agent_id`
* `tool_name`, `tool_version`, `tool_action`, `tool_target`
* `auth_subject`, `auth_audience`, `scope`, `decision` (allow/deny + reason)
* `egress_dest_ip`, `egress_dest_host`, `mTLS_peer`, `cert_fp`
* `prompt_hash` (NOT raw prompt by default), `tool_output_hash`
* `tokens_in`, `tokens_out`, `tool_runtime_ms`, `cost_estimate`

### High-signal detections (start here)

* **Audience mismatch attempts** (02)
* **Metadata IP access** (08)
* **Chunked high-volume outputs** (10)
* **Secrets regex hits in logs/tool outputs** (04)
* **Cross-tenant retrieval attempts / canary hits** (11)
* **Recursive tool-call patterns** (14)

---

## 6) Blue Team “Kill Switches” (Fast Containment Controls)

Have these toggles ready **before** production incidents:

* **Tool disable switch**: immediately disable Slack/email/webhook tools org-wide
* **Egress lockdown**: default-deny outbound except required allowlist
* **Write-action gate**: force HITL for destructive/write operations
* **Session breaker**: terminate sessions triggering recursion/DoS heuristics
* **Emergency token revoke**: revoke signing keys / rotate JWKs quickly

---

## 7) Defensive Testing Cadence (Make it repeatable)

### CI/CD security gates

* Tool manifest signing verification
* Image policy: digest pinning, SBOM present, vuln thresholds
* Regression tests for your 14 scenarios (unit/integration):

  * “Trojan README” injection test must fail safely (01)
  * Token reuse across tool audiences must hard-fail (02)
  * SSRF attempts to metadata must be blocked (08)
  * Cross-tenant canary retrieval must fail (11)

### Continuous validation (production-safe)

* Canary docs/strings per tenant
* Synthetic SSRF probes to blocked ranges (should alert + deny)
* Synthetic exfil attempt (rate-limit verification)
* Synthetic recursion prompt (loop guard verification)

---


```
===============================================================================
SECURE AI "CENTRAL BRAIN" ON EKS — MULTI-LAYERED PROTECTIONS (ASCII REFERENCE)
( SPIFFE/SPIRE for workload identity + OAuth2/OIDC for users + mTLS everywhere )
===============================================================================

LEGEND
------
[U]    = User / Operator
[IdP]  = Corporate Identity Provider (OIDC, SSO)
[AS]   = OAuth2 Authorization Server (IdP or internal)
[GW]   = Edge/API Gateway (WAF + authN/Z + rate limits)
[AC]   = AI Agent Controller / "Central Brain"
[TR]   = Tool Router / MCP Gateway
[T*]   = MCP Tools (microservices)
[OBS]  = Observability (logs/traces/metrics) with redaction
[KMS]  = Key mgmt (AWS KMS + Secrets Manager)
[SPIRE]= SPIRE Server (trust domain)
[SP]   = SPIRE Agent (node daemonset)
[SVID] = SPIFFE Verifiable Identity Document (x509-SVID / JWT-SVID)
[mTLS] = mutual TLS using SVIDs
IRSA   = IAM Roles for Service Accounts
NP     = NetworkPolicy (K8s) / SG = Security Group / NACL
-------------------------------------------------------------------------------

                        ┌─────────────────────────────────────
                        │            INTERNET / CORP
                        └─────────────────────────────────────
                                         |
                                         | TLS (HTTPS) + HSTS
                                         v
+----------------------------------------------------------------------------
|                      PERIMETER / EDGE CONTROL PLANE
|
| [U] ---> [IdP/SSO OIDC] ---> (OAuth2/OIDC) ---> [AS] issues:
|           |                                 - ID Token (user identity)
|           |                                 - Access Token (scoped)
|           |                                 - Refresh Token (optional)
|           v
|     MFA / Device posture / Conditional access
|
|                 +----------------------
|                 |   [GW] API GATEWAY    <- WAF (L7), Bot/DoS,
|                 |  + AuthZ + RL            schema validation, caps
|                 +----------+-----------
|                            |  Forwarded to cluster over private link/VPN
+----------------------------|--------------------------------------------
                             |
                             v
===============================================================================
                             E K S   C L U S T E R
===============================================================================

  ┌───────────────────────────────────────────────────────────────
  │                 CLUSTER SECURITY FOUNDATIONS
  │---------------------------------------------------------------
  │ - Private cluster endpoint / restricted API access
  │ - IRSA everywhere (no node IAM creds in pods)
  │ - Pod Security (restricted), PSA/OPA/Gatekeeper
  │ - Image policy: signed + digest-pinned + SBOM + thresholds
  │ - Secrets: Secrets Manager / K8s secrets encrypted with KMS
  │ - Node hardening: IMDSv2, minimal AMI, EDR, CIS baseline
  │
  │ Network segmentation:
  │  * NP (K8s NetworkPolicies) for pod-to-pod
  │  * SG for Pods / SG / NACLs for VPC edges
  │  * Egress gateway / NAT controls + DNS policy
  └───────────────────────────────────────────────────────────────

                     (ALL SERVICE-TO-SERVICE TRAFFIC IS mTLS)
                     (SPIFFE IDs ARE THE SOURCE OF TRUTH IDENTITY)

                         ┌─────────────────────────────────
                         │        WORKLOAD IDENTITY
                         │---------------------------------
                         │ [SPIRE] Server (HA)
                         │ - CA, trust domain
                         │ - workload registration/selectors
                         │ - issues SVIDs
                         └───────────────+─────────────────
                                         |
                                         | SPIRE control channel
                                         v
                         ┌─────────────────────────────────
                         │ [SP] SPIRE Agent (DaemonSet)
                         │ - attests workloads
                         │ - delivers x509-SVID / JWT-SVID
                         └─────────────────────────────────
                                         |
                                         | Workload API
                                         v

  ┌───────────────────────────────      mTLS (SVID)      ┌───────────────────────────────
  │       INGRESS CONTROLLER       <-------------------> │        [AC] CENTRAL BRAIN
  │   (ALB/NLB/Envoy/Istio Ingr)                         │   Agent Controller / Orchestr
  │ - terminates external TLS                            │ - prompt policy enforcement
  │ - forwards internal mTLS                             │ - tool allowlists
  │ - WAF already at edge                                │ - HITL for writes
  └───────────────+───────────────                       └───────────────+───────────────
                  |                                                       |
                  |                                                       | mTLS (SVID)
                  |                                                       v
                  |                                      ┌────────────────────────────────
                  |                                      │        [TR] TOOL ROUTER
                  |                                      │        / MCP GATEWAY
                  |                                      │--------------------------------
                  |                                      │ - Tool registry (signed)
                  |                                      │ - AuthZ: SPIFFE ID -> tool ACL
                  |                                      │ - Validates OAuth2 scopes
                  |                                      │ - Aud/iss binding per tool
                  |                                      │ - Rate limits per tool/action
                  |                                      └───────────────+────────────────
                  |                                                      |
                  |                                                      | mTLS (SVID)
                  |                                                      v
                  |        ┌─────────────────────────────────────────────────────────
                  |        │                 TOOL / MCP EXECUTION ZONE
                  |        │---------------------------------------------------------
                  |        │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌───────────┐
                  |        │  │ [T1]    │  │ [T2]    │  │ [T3]    │  │ [Tn]      │
                  |        │  │ Search  │  │ Slack   │  │ Fetch   │  │ K8s Helper│
                  |        │  │ Tool    │  │ Tool    │  │ URL     │  │ (strict)  │
                  |        │  └────┬────┘  └────┬────┘  └────┬────┘  └─────┬─────┘
                  |        │       |            |            |             |
                  |        │  EGRESS ALLOWLIST  |     FETCH PROXY + SSRF   |  IRSA
                  |        │  + DNS POLICY      |     GUARDS + IP BLOCKS   | +RBAC
                  |        │  (default deny)    |     (block 169.254...)   | least
                  |        │                    |                          | priv
                  |        └─────────────────────────────────────────────────────────

  ┌───────────────────────────────────────────────────────────────
  │                    DATA / SECRETS / AUDIT
  │---------------------------------------------------------------
  │ [KMS] + Secrets Manager: short-lived creds, rotation, enc
  │   ^
  │   | IRSA (pod role)
  │ Tools fetch secrets only when required
  │
  │ [OBS] Logs/Traces/Metrics:
  │ - Structured audit logs (who/what tool/why)
  │ - Token & PII redaction / denylist fields
  │ - Canaries + anomaly detection (exfil/loops/SSRF)
  └───────────────────────────────────────────────────────────────


===============================================================================
MULTI-LAYER PROTECTION STACK (FROM OUTSIDE-IN)
===============================================================================

[LAYER 0: USER / AUTHN]
  - OIDC SSO + MFA + device posture
  - OAuth2 scopes map to agent capabilities (read vs write vs admin)

[LAYER 1: EDGE PROTECTION]
  - WAF, bot control, rate limits, schema validation, payload caps
  - Separate public vs internal endpoints (no direct tool exposure)

[LAYER 2: CLUSTER BASELINE]
  - Private EKS control plane / restricted API
  - PSA "restricted" + OPA/Gatekeeper
  - Image signing + digest pinning + SBOM + vuln thresholds
  - IRSA everywhere (no node creds), secrets encrypted with KMS

[LAYER 3: WORKLOAD IDENTITY (SPIFFE/SPIRE)]
  - Each pod gets a SPIFFE ID (spiffe://trust-domain/ns/.../sa/...)
  - SVID-based mTLS for service-to-service traffic
  - AuthZ keys off SPIFFE ID (strong workload identity)

[LAYER 4: SERVICE MESH / mTLS ENFORCEMENT]
  - STRICT mTLS
  - AuthorizationPolicy: allow only expected callers to each service

[LAYER 5: TOOL ROUTER / GATEWAY POLICY]
  - Verify OAuth2: iss/aud/scope; bind user identity to tool request
  - Verify workload identity (SPIFFE) of caller
  - Per-tool allowlists: actions, destinations, payload caps
  - HITL for destructive operations

[LAYER 6: NETWORK EGRESS CONTROL]
  - Default deny egress; allowlist per tool
  - Block metadata IP: 169.254.169.254
  - Block internal ranges unless required; DNS policy to prevent rebinding
  - Use a fetch proxy for URL tools (SSRF choke point)

[LAYER 7: DATA PROTECTION]
  - Token redaction in logs/traces; DLP gates for Slack/email tools
  - Tenant isolation in vector DB via mandatory filters (tenant_id)
  - Session compartmentalization

[LAYER 8: DETECTION + RESPONSE]
  - Alerts: audience mismatch, SSRF metadata, high-volume exfil, recursion loops
  - Kill switches: disable outbound tools, lock down egress, revoke signing keys
  - Forensics-ready: request_id/session_id + tool execution audit trail

===============================================================================

```
##
##
