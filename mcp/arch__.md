# MCP Security Architecture — Revised & Modernized, (..kinda..)

> **Classification:** Internal · Security Sensitive  
> **Last Updated:** 2026-05-30  
> **Owner:** Platform Security Team  
> **Status:** Living Document — PRs welcome via Security Review process

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Layer-by-Layer Reference](#layer-by-layer-reference)
3. [Triple-Lock Model](#triple-lock-model)
4. [Advanced Controls](#advanced-controls)
5. [Modernization Additions](#modernization-additions)
6. [Implementation Roadmap](#implementation-roadmap)
7. [Threat Model](#threat-model)

---

## Architecture Overview

```
╔══════════════════════════════════════════════════════════════════╗
║                  UNTRUSTED ZONE (Public Internet)                ║
╚══════════════════════════════════════════════════════════════════╝
                              │
                              ▼
                        LAYER 0 · EDGE
                              │
                              ▼
                      LAYER 1 · GATEWAY COP
                              │
                              ▼
                     LAYER 2 · IDENTITY COP
                              │
                              ▼
                      LAYER 3 · NETWORK COP
                              │
                              ▼
                     LAYER 4 · WORKLOAD COP
                              │
                              ▼
                     LAYER 5 · CLOUD IAM COP
                              │
                              ▼
                       LAYER 6 · TOOL COP
                              │
                              ▼
                   LAYER 6.5 · BEHAVIORAL COP  ← NEW
                              │
                              ▼
                  LAYER 7 · DATA & MEMORY COP
                              │
                              ▼
                      LAYER 8 · EGRESS COP
                              │
                              ▼
╔══════════════════════════════════════════════════════════════════╗
║        EXTERNAL BACKENDS · GitHub · Slack · AWS Bedrock          ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Layer-by-Layer Reference

### LAYER 0 · Edge Defense

> **Role:** First line — stops unauthenticated and volumetric threats before they enter the system.

| Control | Description |
|---|---|
| OIDC / Okta Authentication | All requests must carry a valid Okta-issued JWT |
| WAF + DDoS Protection | Layer 7 rule-based filtering; volumetric absorption |
| Rate Limiting | Request-level throttle at the CDN / edge proxy |

---

### LAYER 1 · Gateway COP — Protocol Sentry

> **Role:** Authenticates intent, mints scoped tokens, enforces policy, and validates tooling before any dispatch.
> **Modernized:** Static guardrails replaced with OPA + LLM classifier. Delegation chain enforcement added.

| Control | Tag | Description |
|---|---|---|
| Session Control | MCP-18 | ChatID ↔ User binding; session isolation enforced |
| Guardrails — OPA Engine | MCP-01 | Structured policy decisions via Open Policy Agent; replaces static regex filters |
| Guardrails — LLM Classifier | MCP-01 | Secondary small-model intent classifier (e.g., Bedrock Guardrails) evaluates prompt before dispatch; low-confidence = HITL |
| Token Exchange | MCP-02 | Swaps User JWT for a short-lived, scoped Agent Token |
| Token Binding | MCP-09 | Mints claims: `{ sub: user, aud: mcp-tool-x, agent_id: astra }` |
| Tool Registry Verification | MCP-03 | Validates tool exists and is trusted before dispatch |
| Delegation Chain Enforcement | MCP-NEW | RFC 8693 Token Exchange at every agent hop; `delegation_chain` claim appended; max hop depth = 4 |

> **Why delegation chain matters:**
> Modern agentic systems are multi-hop: `User → Orchestrator → Sub-Agent A → Sub-Agent B → Tool`.
> Each hop mints a *narrower* derived token via RFC 8693. Scope never escalates across hops.
> Any layer can audit the full call path from the `delegation_chain` claim.

---

### LAYER 2 · Identity COP — SPIFFE / SPIRE Sentry

> **Role:** Cryptographic workload identity. No valid SVID = no call proceeds.

| Control | Tag | Description |
|---|---|---|
| Mutual TLS | MCP-10 | All peer-to-peer communication encrypted via mTLS |
| SVID Validation | MCP-05 | Rejects any pod without a verified SPIFFE Workload Identity |
| Cross-Team Block | MCP-07 | SRE Agent cert ≠ Security Agent cert; cross-namespace calls are hard-rejected |

---

### LAYER 3 · Network COP — Istio / AuthorizationPolicy

> **Role:** Enforces strict call topology. No lateral movement permitted.

| Control | Tag | Description |
|---|---|---|
| Service-to-Service Policy | MCP-07 | Istio allows ONLY `Gateway → MCP Server`; no lateral movement |
| Namespace Isolation | — | SRE namespace cannot resolve or reach Security namespace |
| Egress Block | — | MCP pods cannot initiate outbound connections back to Agent pods |

---

### LAYER 4 · Workload COP — Kubernetes Sandbox

> **Role:** Hardens the execution environment. Unsigned or unverified workloads never run.
> **Modernized:** SLSA Level 3 provenance and SBOM admission scanning added.

| Control | Tag | Description |
|---|---|---|
| Pod Security Admission | MCP-09 | Non-root, restricted profile, read-only root filesystem |
| Image Provenance | MCP-06 | Signed images only (Cosign / Notary); unsigned = rejected at admission |
| SLSA Level 3 Provenance | MCP-NEW | All MCP connector images must carry SLSA L3 provenance attestation |
| SBOM Admission Scanning | MCP-NEW | SBOM generated at build, stored in registry, cross-referenced against CVE feeds at admission |
| Resource Quotas | MCP-14 | CPU / memory hard limits per pod; prevents resource exhaustion attacks |

---

### LAYER 5 · Cloud IAM COP — IRSA / AWS Sentry

> **Role:** Bridges Kubernetes identity to AWS. No standing credentials anywhere.
> **Modernized:** Vault secretless injection replaces static secrets in env vars or config maps.

| Control | Tag | Description |
|---|---|---|
| OIDC Role Assumption | — | Pod exchanges K8s Service Account Token for a short-lived AWS IAM Token |
| Least-Privilege IAM Role | — | `mcp-github-role`: no S3, no Admin, no wildcard |
| Resource Scope | — | Policy scoped to `org-thousandeyes/*` only |
| Secretless Injection | MCP-NEW | Vault Agent Injector / AWS Secrets Manager + CSI driver; secrets never in env vars or config maps; ephemeral per-pod |
| Zero Standing Secrets | MCP-NEW | All credentials are dynamic, short-lived, rotated on every pod restart minimum |

---

### LAYER 6 · Tool COP — MCP Connector

> **Role:** Enforces tool-level identity, masks sensitive data, and blocks SSRF.
> **Modernized:** JSON Schema output contracts replace ad-hoc sanitization.

| Control | Tag | Description |
|---|---|---|
| Audience Check | MCP-02 | Tool B hard-rejects any token minted for Tool A |
| Identity Scope | MCP-15 | IRSA acts AS the user, not the application service account |
| PII / Secret Masking | MCP-04 | Logging scrubbers mask secrets, tokens, and PII before write |
| SSRF Protection | MCP-08 | Blocks cloud metadata IP (`169.254.169.254`) and unresolvable internal FQDNs |
| Output Schema Contracts | MCP-NEW | Every tool declares a JSON Schema for its response; gateway hard-rejects non-conforming responses; eliminates secondary prompt injection via unexpected fields |

---

### LAYER 6.5 · Behavioral COP — Agent Telemetry ⭐ NEW

> **Role:** Provides real-time detection. Logs without alerting = forensics only. This layer closes that gap.

| Control | Tag | Description |
|---|---|---|
| Baseline Profiling | MCP-NEW | Per `agent_id` normal tool call pattern profiling |
| Anomaly Detection (UEBA) | MCP-NEW | Flags unusual tool sequences, off-hours activity, READ volume spikes before DELETE |
| SIEM Streaming | MCP-NEW | Real-time OpenTelemetry stream to SIEM (Splunk / Panther) |
| Automated Quarantine | MCP-NEW | Anomaly confirmed → `agent_id` suspended, SVID revoked automatically |

```
Detection triggers (examples):
  - agent_id calls github.delete_repo without preceding github.get_repo
  - > 50 READ operations in 60s followed by any WRITE
  - Tool calls originating outside business hours for the user's timezone
  - delegation_chain depth approaching configured maximum
```

---

### LAYER 7 · Data & Memory COP — Vector / Storage Guard

> **Role:** Prevents cross-tenant memory bleed and protects stored context.
> **Modernized:** ABE on vector embeddings, context TTL, and embedding poisoning detection added.

| Control | Tag | Description |
|---|---|---|
| Cross-Tenant Isolation | MCP-11 | Vector DB queries enforce filter: `{ team, session_id }` |
| Attribute-Based Encryption (ABE) | MCP-NEW | Vector embeddings are ABE-encrypted; decrypt keys are team-scoped; cross-tenant similarity search is cryptographically impossible, not just filtered |
| Embedding Poisoning Detection | MCP-NEW | Monitor vector stores for anomalous injection patterns |
| Context TTL | MCP-NEW | Session memory auto-purged after 7 days; no indefinite retention |
| Differential Privacy | — | Session-scoped RAG; noise filtering prevents cross-team memory bleed |
| Encryption at Rest | — | AES-256 for all stored vectors and context blobs |
| Immutable Audit Trail | — | Append-only transaction log (WORM / CloudTrail) |

> **Why ABE over filter-only:**
> A filter of `{ team: "sre" }` is enforced at query time but operates on plaintext embeddings.
> An attacker with DB access or a query bypass sees everything.
> ABE ensures the ciphertext itself is unreadable without the correct team-scoped key — the filter and the encryption are the same control.

---

### LAYER 8 · Egress COP — Cloud Firewall + DLP

> **Role:** Last line. Nothing leaves the system that shouldn't.

| Control | Tag | Description |
|---|---|---|
| FQDN Allow-list | MCP-08 | `*.github.com`, `*.slack.com` only; all other destinations denied |
| Metadata IP Block | MCP-08 | Hard-block `169.254.169.254` at network policy level |
| DLP Inspection | — | Egress payload scanned for PII, secrets, and credential patterns |

---

## Triple-Lock Model

> Why Agent A cannot be used against Agent B.

### 🔒 Lock 1 · The Token (OAuth2 / JWT)

_"I hold the correct scoped key for this specific tool."_

- Short-lived, audience-bound, agent-tagged JWT
- Tool B hard-rejects a token minted for Tool A
- RFC 8693 delegation chain ensures scope narrows at every hop — never escalates

### 🔒 Lock 2 · The Pod (SPIFFE / SPIRE)

_"I am calling from a verified, authorized workload."_

- Each pod carries a cryptographic SPIFFE SVID
- Cross-team pod certificates are mutually exclusive
- Compromising one workload identity does not grant access to any other

### 🔒 Lock 3 · The Network (Istio / mTLS)

_"The physical path is open only for this transaction."_

- AuthorizationPolicies enforce strict `Gateway → MCP` topology
- No lateral movement; no pod-to-pod bypass
- Egress policies block MCP pods from initiating reverse connections

---

### Verdict — Attack Complexity

To fully impersonate an agent, an attacker must **simultaneously**:

1. Steal the user's active Okta session
2. Compromise the Gateway's token-signing private key
3. Forge a valid RFC 8693 delegation chain with correct hop claims
4. Obtain a valid SPIFFE SVID for the target workload
5. Breach EKS node certificate storage
6. Bypass UEBA anomaly detection and avoid quarantine trigger

**That is true defense-in-depth.**

---

## Advanced Controls

### 🛑 Human-in-the-Loop (HITL)

| Property | Value |
|---|---|
| Trigger | Any tool action classified `Write` or `Admin` |
| Examples | `github.delete_repo`, `pagerduty.resolve_incident` |
| Mechanism | Gateway pauses execution; sends Slack / email approval to the user |
| Timeout | No response in 15 minutes = auto-reject |
| Value | Stops prompt injection + token replay attacks at the last mile |

---

### ⏱ Intent-Based Rate Limiting

> Rate limit by **impact per window**, not requests per second.

| Class | Limit |
|---|---|
| `READ` | 100 operations / minute |
| `WRITE` | 10 operations / minute |
| `DELETE` | 1 operation / 10 minutes |
| `ADMIN` | Requires HITL approval regardless of rate |

Limits blast radius if an agent is compromised. Prevents mass exfiltration or infrastructure carpet-bombing.

---

### 🧠 Differential Privacy for Memory (RAG)

Every Vector DB query is scoped with a hard filter:

```json
{
  "team": "sre",
  "session_id": "chat-abc-123"
}
```

Combined with ABE, this prevents **"Ghost of Sprints Past"** — an agent cannot surface secrets from another team's historical session, even via indirect or similarity-based query.

---

## Modernization Additions

### Summary of Changes from v1

| Area | v1 Approach | v2 Approach | Rationale |
|---|---|---|---|
| Guardrails | Static regex / rule filters | OPA + LLM intent classifier | Rules lose the arms race against context-aware prompt injection |
| Multi-agent | Single hop assumed | RFC 8693 delegation chain, max depth 4 | Agentic systems are multi-hop; scope must narrow, never escalate |
| Detection | Immutable logs only | UEBA behavioral layer + SIEM + auto-quarantine | Logs without alerting = forensics only |
| Vector security | Filter-based tenant isolation | ABE encryption + poisoning detection + TTL | Filter bypass exposes plaintext; ABE makes cross-tenant access cryptographically impossible |
| Output contracts | Ad-hoc sanitization | JSON Schema per tool, hard-reject on mismatch | Eliminates secondary prompt injection via unexpected response fields |
| Secrets | IRSA only | IRSA + Vault secretless injection, zero standing secrets | Eliminates credential exposure in env vars and config maps |
| Supply chain | Cosign image signing | Cosign + SLSA L3 + SBOM admission scanning | Modern attacks target the build pipeline, not the image |

---

## Implementation Roadmap

### Priority Matrix

| Priority | Change | Effort | Impact |
|---|---|---|---|
| 🔴 P0 | RFC 8693 delegation chain enforcement | Medium | Closes multi-agent scope escalation |
| 🔴 P0 | Behavioral anomaly layer (UEBA + SIEM) | Medium | Closes detection gap entirely |
| 🟡 P1 | OPA + LLM classifier for guardrails | High | Replaces brittle static rules |
| 🟡 P1 | ABE on vector embeddings + context TTL | High | Closes RAG cross-tenant cryptographic gap |
| 🟢 P2 | JSON Schema output contracts per tool | Low | Quick win; eliminates output injection class |
| 🟢 P2 | Vault secretless injection | Low | Quick win if Vault already deployed |
| 🟢 P2 | SLSA L3 + SBOM admission scanning | Medium | Supply chain hardening |

---

### Phase 1 — Critical (Sprint 1–2)

- [ ] Implement RFC 8693 Token Exchange at Gateway for all agent hops
- [ ] Add `delegation_chain` claim to JWT spec and enforce max depth = 4
- [ ] Deploy OpenTelemetry collector with agent call telemetry
- [ ] Integrate SIEM (Splunk / Panther) with baseline anomaly rules
- [ ] Configure auto-quarantine webhook on SVID revocation

### Phase 2 — Hardening (Sprint 3–4)

- [ ] Replace MCP-01 regex guardrails with OPA policy bundle
- [ ] Deploy Bedrock Guardrails (or equivalent) as LLM intent classifier
- [ ] Define and enforce JSON Schema contracts for all registered tools
- [ ] Enable 7-day TTL on all session memory in vector store
- [ ] Document ABE key management design and begin POC

### Phase 3 — Supply Chain & Secrets (Sprint 5–6)

- [ ] Integrate Vault Agent Injector across all MCP connector pods
- [ ] Enforce zero standing secrets policy; audit and rotate all static creds
- [ ] Add SLSA L3 provenance to MCP connector image build pipeline
- [ ] Generate and store SBOM at build; configure admission webhook CVE check
- [ ] Begin ABE rollout on vector store (team-scoped keys)

---

## Threat Model

### In-Scope Threats

| Threat | Mitigating Layers |
|---|---|
| Prompt injection via user input | L1 (OPA + LLM classifier), L6 (output contracts) |
| Secondary prompt injection via tool response | L6 (JSON Schema contracts), L6 (output sanitization) |
| Agent impersonation | L1 (token binding), L2 (SPIFFE), L3 (Istio) |
| Cross-agent token reuse | L1 (audience binding), L6 (audience check) |
| Multi-hop scope escalation | L1 (RFC 8693 delegation chain) |
| Cross-tenant memory access | L7 (ABE + filter + differential privacy) |
| SSRF to cloud metadata | L6 (SSRF block), L8 (metadata IP block) |
| Supply chain compromise | L4 (SLSA L3 + SBOM) |
| Credential exposure | L5 (Vault secretless) |
| Undetected agent compromise | L6.5 (UEBA + auto-quarantine) |
| Mass exfiltration / carpet bombing | Advanced Controls (impact-based rate limiting) |
| Unauthorized write / delete | Advanced Controls (HITL) |

### Out-of-Scope (Separate Controls Required)

- Physical data center access
- Okta identity provider compromise
- AWS control plane compromise
- Human insider threat at admin level

---

## References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [SPIFFE / SPIRE Documentation](https://spiffe.io/docs/)
- [SLSA Framework](https://slsa.dev/)
- [OPA Documentation](https://www.openpolicyagent.org/docs/)
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AWS IRSA Documentation](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [Istio Authorization Policy](https://istio.io/latest/docs/reference/config/security/authorization-policy/)

---

*This document is maintained by the Platform Security Team.
To propose changes, open a PR and request review from `@security-reviewers`.
For urgent issues, page the on-call via PagerDuty `mcp-security` service.*
