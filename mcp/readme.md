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

## 8) Minimal “Blue Team Pack” You Can Drop Into the Repo

If you want to make this GitHub-ready, I’d structure the repo like:

```
/defense/
  /policies/
    gateway-authz.md
    tool-registry-signing.md
    egress-allowlist.md
    rag-tenancy.md
  /detections/
    rules-audience-mismatch.md
    rules-ssrf-metadata.md
    rules-exfil-rate.md
    rules-recursion-dos.md
  /runbooks/
    IR-credential-leak.md
    IR-ssrf-metadata.md
    IR-cross-tenant-memory.md
    IR-tool-poisoning.md
  /tests/
    injection-regression.md
    confused-deputy-regression.md
    ssrf-regression.md
    memory-isolation-regression.md
```

---

## 9) Quick-start: Blue Team Checklist (Actionable)

**Day 0**

* Enforce `aud` + scopes on every tool call
* mTLS between controller ↔ tools
* Default-deny egress; explicitly allow only required destinations
* Redact secrets in logs/traces (drop Authorization headers everywhere)

**Week 1**

* Signed tool registry + approval workflow
* Tenant-bound RAG filters + canary strings per tenant
* Rate limits + payload caps on outbound tools
* Loop detection + cost budgets

**Week 2+**

* Full runbooks, alert tuning, and automated regression suite for all 14 scenarios

##
##
