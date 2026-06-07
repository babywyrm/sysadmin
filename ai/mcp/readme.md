# MCP Blue Team Defensive Structure

A vendor-neutral, repeatable defensive program for Model Context Protocol
(MCP) and agent architectures.

This section is the defensive counterpart to offensive MCP testing. It focuses on
how to prevent, detect, respond to, and continuously validate risks in systems
where LLM agents can call tools, retrieve context, write to external systems, and
chain actions across services.

---

## Core Principle

Treat MCP tools, tool inputs, tool outputs, retrieved documents, and agent memory
as untrusted input.

Treat tool execution as production code execution.

Because it is.

An MCP agent that can call tools can:

- read data,
- write data,
- send messages,
- trigger workflows,
- fetch URLs,
- query internal systems,
- retrieve tenant context,
- spend money,
- and chain actions recursively.

Therefore, every MCP deployment needs the same rigor as a production service:
identity, authorization, network control, runtime hardening, logging, detection,
and incident response.

---

## Defensive Operating Model

### Blue Team Ownership Lanes

| Lane | Owner | Responsibilities |
|---|---|---|
| Platform Security | Primary owner | Gateway policy, tool registry controls, identity binding, audience binding, egress control, mTLS, baseline hardening |
| Detection Engineering | Detection owner | Telemetry, alert rules, canaries, anomaly detection, exfiltration detection, loop detection |
| AppSec / Agent Security | Agent security owner | Prompt-injection defenses, context sanitation, RAG tenancy controls, agent policy tests |
| SRE / Infrastructure | Runtime owner | Kubernetes security contexts, image scanning, runtime controls, secrets management, patching |
| Incident Response | Response owner | Playbooks, containment switches, forensics, post-incident control improvements |

---

# Defense-in-Depth Architecture

MCP security should be implemented as layered controls. No single layer should be
trusted to fully protect the system.

```text
[ POLICY & IDENTITY PLANE ]
- AuthN/Z
- Audience binding
- Tool-specific scopes
- Tool RBAC
- Request signing
- Key rotation

[ TOOL GOVERNANCE PLANE ]
- Tool registry approval
- Signed tool manifests
- SBOM
- Provenance
- Allowlists
- Version pinning

[ RUNTIME SAFETY PLANE ]
- Sandbox execution
- seccomp/AppArmor
- Rootless containers
- Read-only filesystems
- CPU/memory quotas
- Recursion guards

[ NETWORK & TRANSPORT PLANE ]
- mTLS everywhere
- Egress allowlists
- Metadata/IP blocks
- DNS controls
- Private service paths

[ DATA & CONTEXT INTEGRITY PLANE ]
- Tenant isolation
- RAG filters
- Output sanitization
- DLP
- Secret redaction
- Session partitioning

[ OBSERVABILITY & RESPONSE PLANE ]
- Structured logs
- Distributed traces
- Audit trails
- Canaries
- Alerting
- Kill switches
```

---

# MCP-SHIELD Blue Team Modules

`MCP-SHIELD` is the defensive structure for MCP environments. It is designed to
ship as policy packs, detection packs, runtime controls, and regression tests.

It mirrors the offensive test categories used by MCP security assessments, but
from the prevent / detect / respond side.

---

## 1. Guardrail Module

### Covers

- Prompt injection
- Tool-output injection
- Context integrity failures
- Malicious retrieved documents
- Agent instruction hijacking

### Prevent

- Label all retrieved and tool-returned content as untrusted.
- Strip or neutralize instructions found in tool outputs.
- Separate system/developer instructions from retrieved content.
- Enforce allowlisted tool actions.
- Require human-in-the-loop approval for high-impact writes.
- Add prompt-injection regression tests for agents and tools.

### Detect

- LLM output attempts to request secrets.
- Tool output contains instruction-like strings.
- User-visible output includes hidden prompt fragments.
- Unexpected tool chains are triggered by document content.
- Agent behavior changes after reading untrusted content.

### Respond

- Disable risky tools.
- Quarantine malicious documents.
- Rotate exposed secrets.
- Add regression tests for observed payloads.
- Tighten context sanitation and tool allowlists.

---

## 2. Identity Module

### Covers

- Confused deputy
- Token replay
- Audience mismatch
- Unsigned internal headers
- Overbroad tool scopes
- Missing step-up authorization

### Prevent

- Enforce JWT `aud`, `iss`, `sub`, `exp`, and `jti` validation.
- Use tool-specific scopes.
- Use per-tool tokens or per-tool credentials.
- Never trust unsigned role, tenant, or user headers.
- Sign internal request context.
- Bind user context to bot/tool identity.
- Require step-up auth or human approval for destructive operations.

### Detect

- Audience mismatch attempts.
- Scope mismatch logs.
- The same token used across multiple tools.
- Requests with missing or invalid signatures.
- Role or tenant fields changing mid-flight.
- Unusual 401/403 spikes.

### Respond

- Revoke tokens.
- Rotate signing keys/JWKs.
- Hard-fail audience mismatches.
- Disable affected tools.
- Add gateway policy for the observed bypass.

---

## 3. Toolchain Module

### Covers

- Tool poisoning
- Unapproved tools
- Supply chain compromise
- Manifest tampering
- Dependency compromise
- Tool version drift

### Prevent

- Require signed tool manifests.
- Require admin approval before tool registration.
- Pin tool versions.
- Pin container images by digest.
- Require SBOMs.
- Enforce image provenance.
- Block unsigned or unregistered tools at runtime.
- Restrict who can publish or update tools.

### Detect

- New tool registration events.
- Tool manifest changes.
- Unsigned tool execution attempts.
- New dependencies.
- New CVEs above threshold.
- Outbound traffic to previously unseen domains.
- Unexpected tool version changes.

### Respond

- Quarantine the tool.
- Yank the compromised version.
- Block domains and hashes.
- Rebuild from trusted source.
- Review registry ACLs.
- Re-run supply-chain validation.

---

## 4. Network Module

### Covers

- SSRF
- Insecure transport
- Metadata service access
- DNS rebinding
- Unauthorized egress
- Internal service probing

### Prevent

- Require mTLS for service-to-service traffic.
- Enforce egress allowlists by tool.
- Route URL-fetching tools through a fetch proxy.
- Block cloud metadata IPs such as `169.254.169.254`.
- Block RFC1918/internal ranges unless explicitly required.
- Enforce DNS policies.
- Disable direct tool exposure to the internet.
- Use private endpoints where possible.

### Detect

- Requests to metadata IPs.
- Requests to internal-only hostnames.
- DNS resolution to private ranges.
- Cleartext traffic.
- mTLS handshake failures.
- Unknown egress destinations.
- Internal port scanning behavior.

### Respond

- Lock down egress.
- Disable URL-fetching tools.
- Rotate cloud credentials.
- Block domains, IPs, and DNS patterns.
- Add SSRF regression tests.

---

## 5. Runtime Module

### Covers

- Pod escape
- Sandbox escape
- Host filesystem access
- Resource DoS
- Recursive tool loops
- Cost abuse
- Unsafe container privileges

### Prevent

- Run containers as non-root.
- Use rootless runtimes where possible.
- Drop Linux capabilities.
- Use seccomp/AppArmor profiles.
- Use read-only root filesystems.
- Disallow `hostPath`, privileged pods, and host networking.
- Set CPU and memory limits.
- Set concurrency caps.
- Enforce recursion and loop guards.
- Enforce cost budgets per user, tenant, session, and tool.

### Detect

- Syscall anomalies.
- Access attempts to privileged paths.
- Attempts to read `/proc`, host mounts, or service account tokens.
- Repeated tool invocations.
- Long-running agent loops.
- High token or cloud spend per session.
- Frequent throttling events.

### Respond

- Kill the session.
- Kill the pod or task.
- Cordon the node.
- Preserve forensic artifacts.
- Rebuild the image.
- Tighten runtime policy and budgets.

---

## 6. Data Module

### Covers

- Credential leakage
- Data exfiltration
- Cross-tenant memory leakage
- RAG retrieval leakage
- Sensitive output leakage
- Logging leakage

### Prevent

- Redact secrets at every logging boundary.
- Drop sensitive fields from structured logs.
- Use DLP gates for Slack, email, webhook, and ticketing tools.
- Enforce tenant-bound vector database queries.
- Require `tenant_id` filters for RAG.
- Partition memory by tenant, user, and session.
- Use per-tenant encryption keys where possible.
- Cap payload size and output volume.
- Require approval for bulk exports.

### Detect

- Secret regex hits in logs or tool outputs.
- High-volume Slack/email/webhook posts.
- Repeated chunked outputs.
- Cross-tenant retrieval attempts.
- Canary document access.
- Unusual vector search patterns.
- Large exports or repeated pagination.

### Respond

- Disable exfil-capable tools.
- Block destination channel, webhook, or domain.
- Purge affected logs if appropriate.
- Rotate exposed credentials.
- Invalidate or rebuild affected indexes.
- Notify impacted tenants where required.

---

# Control Matrix: Prevent / Detect / Respond

| ID | Risk | Prevent | Detect | Respond |
|---:|---|---|---|---|
| 01 | Prompt Injection | Tool-output sanitization; instruction stripping; allowlisted tool actions; untrusted-content tags | LLM output asks for keys; unexpected tool chain triggered by file content | Disable risky tools; rotate exposed secrets; add regression test |
| 02 | Confused Deputy | Enforce audience and tool scopes; per-tool tokens; bound sessions | 401/403 anomalies; same token across tools; scope mismatch logs | Revoke token; hard-fail audience mismatch |
| 03 | Tool Poisoning | Signed tool manifests; admin approval; registry ACLs | New tool registration; outbound traffic to unknown domains | Quarantine tool; block domain; review supply chain |
| 04 | Credential Leak | Redact auth headers; structured logs with sensitive fields dropped | Secret patterns in logs/traces; `Authorization:` appearances | Purge logs; rotate keys; patch sanitizer |
| 05 | Insecure Config | Disable debug endpoints in prod; auth-gate Swagger/metrics | `/swagger`, `/debug`, `/metrics` reachable unexpectedly | Block at ingress; redeploy hardened config |
| 06 | Excessive Permissions | Least privilege RBAC/IAM; tool-specific service accounts; deny secrets APIs | K8s API calls for secrets; unusual namespaces queried | Rebind service account; revoke cluster-admin; investigate exposure |
| 07 | Insecure Communication | mTLS required; HTTPS only | Cleartext traffic; cert/mTLS handshake failures | Block non-mTLS routes; rotate tokens; enforce mesh policy |
| 08 | SSRF via Tool | Egress allowlist; fetch proxy; metadata IP blocks | Requests to metadata ranges; DNS to internal-only zones | Block egress; rotate cloud creds; add SSRF regression test |
| 09 | Pod Escape | Rootless; seccomp; no hostPath; runtime restrictions | Syscall anomalies; privileged path access attempts | Kill pod; cordon node; forensics; rebuild image |
| 10 | Data Exfiltration | Rate limits; payload caps; DLP gates; approval for bulk export | High-volume Slack posts; repeated chunked outputs | Disable egress tool; block channel/webhook; audit exported content |
| 11 | Memory Leak | Tenant filters; per-tenant encryption; session partitioning | Cross-tenant retrieval anomalies; canary strings queried | Invalidate index; reindex with filters; notify tenants |
| 12 | Context Spoofing | Signed internal headers; zero-trust service auth | Role/header changes mid-flight; proxy tampering indicators | Rotate signing keys; enforce signature checks; update mesh policy |
| 13 | Supply Chain | Digest pinning; SBOM; provenance attestations; dependency allowlist | New deps; CVE spikes; unknown outbound connections | Yank version; rebuild image; block hashes/domains |
| 14 | Resource DoS | Loop guards; budgets; concurrency caps | Repeated tool calls; high cost/session; throttling | Kill session; temporarily block user; tune budgets |

---

# Blue Team Telemetry Requirements

To defend agents, you need chain-of-custody visibility across the user, agent,
tool router, tool runtime, network path, and data plane.

## Must-Log Fields

Log these as structured fields.

```json
{
  "timestamp": "2026-05-06T01:00:00.000Z",
  "event_type": "tool_action",
  "request_id": "req_8b2d1f4a",
  "session_id": "sess_abc_xyz",
  "tenant_id": "tenant_acme",
  "user_id": "user_123",
  "agent_id": "agent_prod_v2",
  "tool_name": "slack",
  "tool_version": "1.4.2",
  "tool_action": "message.send",
  "tool_target": "channel:C123456",
  "auth_subject": "bot://agent-prod-v2",
  "auth_audience": "tool://slack",
  "scope": "slack:write",
  "decision": "allow",
  "decision_reason": "policy matched",
  "egress_dest_ip": "203.0.113.10",
  "egress_dest_host": "slack.com",
  "mtls_peer": "spiffe://cluster.local/ns/ai/sa/tool-router",
  "cert_fp": "sha256:example",
  "prompt_hash": "sha256:example",
  "tool_output_hash": "sha256:example",
  "tokens_in": 1200,
  "tokens_out": 350,
  "tool_runtime_ms": 245,
  "cost_estimate": 0.0042
}
```

## Logging Rules

- Do not log raw prompts by default.
- Do not log raw tool outputs by default.
- Prefer hashes, classifications, metadata, and redacted excerpts.
- Drop or redact known sensitive fields.
- Include allow and deny decisions.
- Include policy version where possible.
- Preserve `request_id` across every hop.
- Preserve `session_id` across the full agent session.

---

# High-Signal Detections

Start with these detections before building lower-confidence behavioral analytics.

## 1. Audience Mismatch

Trigger when a token or internal request context intended for one tool is used
against another tool.

```text
condition:
  auth_audience != expected_audience_for_tool
severity:
  high
maps_to:
  02 Confused Deputy
```

## 2. Metadata IP Access

Trigger when any tool attempts to access cloud metadata endpoints.

```text
condition:
  egress_dest_ip in ["169.254.169.254", "169.254.170.2"]
severity:
  critical
maps_to:
  08 SSRF via Tool
```

## 3. Chunked High-Volume Output

Trigger when a session sends many medium-sized outputs that appear to bypass
payload caps.

```text
condition:
  count(tool_action where action in ["message.send", "email.send", "webhook.post"])
  by session_id over 10m > threshold
severity:
  high
maps_to:
  10 Data Exfiltration
```

## 4. Secrets in Logs or Tool Outputs

Trigger on credential-like patterns after redaction.

```text
condition:
  secret_detector.match(log_message) == true
severity:
  critical
maps_to:
  04 Credential Leak
```

## 5. Cross-Tenant Retrieval or Canary Hit

Trigger when a tenant queries another tenant’s data or a planted canary string.

```text
condition:
  retrieved_tenant_id != tenant_id OR canary_hit == true
severity:
  critical
maps_to:
  11 Memory Leak
```

## 6. Recursive Tool-Call Pattern

Trigger when an agent repeatedly calls the same tool or tool chain in a loop.

```text
condition:
  repeated_tool_sequence_count(session_id, sequence) > threshold
severity:
  medium/high
maps_to:
  14 Resource DoS
```

---

# Kill Switches

These controls should exist before production incidents.

| Kill Switch | Purpose |
|---|---|
| Tool disable switch | Immediately disable Slack, email, webhook, browser, shell, or write-capable tools |
| Egress lockdown | Default-deny outbound traffic except required allowlist |
| Write-action gate | Force human approval for destructive or write operations |
| Session breaker | Terminate sessions that trigger recursion, cost, or exfil heuristics |
| Emergency token revoke | Revoke signing keys, rotate JWKs, or invalidate active sessions |
| Registry freeze | Prevent new tool registration or tool version updates |
| Retrieval isolation mode | Disable cross-document or broad RAG retrieval; require exact tenant filters |
| Safe-response mode | Return summaries only; block raw tool output from reaching the user |

---

# Defensive Testing Cadence

Security controls should be tested continuously and safely.

## CI/CD Security Gates

Every tool and agent change should validate:

- Tool manifest is signed.
- Tool is registered and approved.
- Container image is pinned by digest.
- SBOM is present.
- Image provenance is valid.
- Vulnerabilities are below threshold.
- Runtime policy passes.
- Tool schema rejects unknown fields.
- Authorization tests pass.
- Sensitive logging tests pass.

## Regression Tests

At minimum, maintain regression tests for the 14 core MCP risk scenarios.

| Scenario | Expected Result |
|---|---|
| Trojan README injection | Agent must not follow instructions from retrieved content |
| Token reuse across tool audiences | Request must hard-fail |
| Unsigned internal role header | Request must hard-fail |
| SSRF to metadata IP | Request must be blocked and alert generated |
| Cross-tenant canary retrieval | Retrieval must fail and alert generated |
| Secret in tool output | Secret must be redacted or blocked |
| Tool manifest tampering | Tool must not load |
| Unsigned container image | Deployment must fail |
| Recursive tool loop | Session must be terminated |
| Bulk Slack exfiltration | Output must be rate-limited or blocked |
| Debug endpoint exposed | Deployment or runtime check must fail |
| Privileged pod spec | Admission control must reject |
| Unexpected egress domain | Network policy must block |
| Destructive write without step-up | Action must require approval or fail |

## Production-Safe Continuous Validation

Use controlled synthetic tests to verify defenses in production.

- Canary documents per tenant.
- Canary secret strings that should never appear in outputs.
- Synthetic SSRF probes to blocked ranges.
- Synthetic exfil attempts to verify rate limits.
- Synthetic recursion prompts to verify loop guards.
- Synthetic audience mismatch requests.
- Synthetic unsigned tool registration attempts.

---

# Secure AI Central Brain on EKS

This reference architecture uses:

- EKS for runtime orchestration
- SPIFFE/SPIRE for workload identity
- OAuth2/OIDC for user identity
- mTLS for service-to-service transport
- IRSA for AWS permissions
- KMS and Secrets Manager for secrets
- NetworkPolicy, Security Groups, and egress controls for isolation
- Structured telemetry for detection and response

---

## ASCII Reference Architecture

```text
===============================================================================
SECURE AI "CENTRAL BRAIN" ON EKS — MULTI-LAYERED PROTECTIONS
SPIFFE/SPIRE for workload identity + OAuth2/OIDC for users + mTLS everywhere
===============================================================================

LEGEND
------
[U]     = User / Operator
[IdP]   = Corporate Identity Provider (OIDC, SSO)
[AS]    = OAuth2 Authorization Server
[GW]    = Edge/API Gateway
[AC]    = AI Agent Controller / "Central Brain"
[TR]    = Tool Router / MCP Gateway
[T*]    = MCP Tools
[OBS]   = Observability
[KMS]   = AWS KMS + Secrets Manager
[SPIRE] = SPIRE Server
[SP]    = SPIRE Agent
[SVID]  = SPIFFE Verifiable Identity Document
IRSA    = IAM Roles for Service Accounts
NP      = Kubernetes NetworkPolicy
SG      = Security Group
NACL    = Network ACL
-------------------------------------------------------------------------------

                        ┌─────────────────────────────────────┐
                        │            INTERNET / CORP           │
                        └─────────────────────────────────────┘
                                         |
                                         | TLS + HSTS
                                         v
+----------------------------------------------------------------------------+
|                      PERIMETER / EDGE CONTROL PLANE                          |
|                                                                              |
| [U] ---> [IdP/SSO OIDC] ---> [AS]                                            |
|           |                  issues ID token / access token                  |
|           |                                                                  |
|           v                                                                  |
|     MFA / device posture / conditional access                                |
|                                                                              |
|                 +-----------------------------+                              |
|                 | [GW] API GATEWAY            |                              |
|                 | - WAF                       |                              |
|                 | - AuthN/AuthZ               |                              |
|                 | - rate limits               |                              |
|                 | - schema validation         |                              |
|                 | - payload caps              |                              |
|                 +--------------+--------------+                              |
|                                |                                             |
|                                | private link / VPN / private ingress        |
+--------------------------------|---------------------------------------------+
                                 |
                                 v
===============================================================================
                                  EKS CLUSTER
===============================================================================

  ┌─────────────────────────────────────────────────────────────────────────┐
  │                    CLUSTER SECURITY FOUNDATIONS                          │
  │-------------------------------------------------------------------------│
  │ - Private cluster endpoint / restricted API access                       │
  │ - IRSA everywhere; no node IAM credentials in pods                       │
  │ - Pod Security Admission: restricted baseline                            │
  │ - OPA/Gatekeeper or Kyverno admission controls                           │
  │ - Signed images + digest pinning + SBOM + vulnerability thresholds       │
  │ - Secrets Manager / Kubernetes secrets encrypted with KMS                │
  │ - Node hardening: IMDSv2, minimal AMI, EDR, CIS baseline                 │
  │                                                                          │
  │ Network segmentation:                                                    │
  │ - NetworkPolicies for pod-to-pod traffic                                 │
  │ - Security Groups for Pods where appropriate                             │
  │ - Security Groups and NACLs for VPC edges                                │
  │ - Egress gateway / NAT controls                                          │
  │ - DNS policy                                                             │
  └─────────────────────────────────────────────────────────────────────────┘

                     ALL SERVICE-TO-SERVICE TRAFFIC USES mTLS
                 SPIFFE IDS ARE THE SOURCE OF WORKLOAD IDENTITY

                         ┌─────────────────────────────────┐
                         │        WORKLOAD IDENTITY         │
                         │---------------------------------│
                         │ [SPIRE] Server HA                │
                         │ - CA / trust domain              │
                         │ - workload registration          │
                         │ - workload selectors             │
                         │ - SVID issuance                  │
                         └───────────────+─────────────────┘
                                         |
                                         | SPIRE control channel
                                         v
                         ┌─────────────────────────────────┐
                         │ [SP] SPIRE Agent DaemonSet       │
                         │ - node attestation               │
                         │ - workload attestation           │
                         │ - x509-SVID / JWT-SVID delivery  │
                         └───────────────+─────────────────┘
                                         |
                                         | Workload API
                                         v

  ┌───────────────────────────────┐      mTLS       ┌───────────────────────────────┐
  │       INGRESS CONTROLLER       │<--------------->│       [AC] CENTRAL BRAIN       │
  │   ALB/NLB/Envoy/Istio Ingress  │                 │ Agent Controller / Orchestrator│
  │ - terminates external TLS      │                 │ - prompt policy enforcement    │
  │ - forwards internal mTLS       │                 │ - tool allowlists              │
  │ - no direct tool exposure      │                 │ - HITL for writes              │
  └───────────────+───────────────┘                 └───────────────+───────────────┘
                  |                                                 |
                  |                                                 | mTLS
                  |                                                 v
                  |                                ┌────────────────────────────────┐
                  |                                │       [TR] TOOL ROUTER          │
                  |                                │       / MCP GATEWAY             │
                  |                                │--------------------------------│
                  |                                │ - signed tool registry          │
                  |                                │ - SPIFFE ID to tool ACL         │
                  |                                │ - OAuth2 scope validation       │
                  |                                │ - aud/iss binding per tool      │
                  |                                │ - rate limits per tool/action   │
                  |                                │ - request signing               │
                  |                                └───────────────+────────────────┘
                  |                                                |
                  |                                                | mTLS
                  |                                                v
                  |        ┌─────────────────────────────────────────────────────────┐
                  |        │                 TOOL / MCP EXECUTION ZONE               │
                  |        │---------------------------------------------------------│
                  |        │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
                  |        │ │ [T1]     │ │ [T2]     │ │ [T3]     │ │ [Tn]         │ │
                  |        │ │ Search   │ │ Slack    │ │ Fetch    │ │ K8s Helper   │ │
                  |        │ │ Tool     │ │ Tool     │ │ URL Tool │ │ Strict RBAC  │ │
                  |        │ └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
                  |        │      |            |            |              |         │
                  |        │      |            |            |              |         │
                  |        │ EGRESS ALLOWLIST  |     FETCH PROXY + SSRF    | IRSA    │
                  |        │ DNS POLICY        |     GUARDS + IP BLOCKS    | RBAC    │
                  |        │ DEFAULT DENY      |     BLOCK METADATA IP     | LEAST   │
                  |        │                   |                           | PRIV    │
                  |        └─────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │                    DATA / SECRETS / AUDIT                               │
  │-------------------------------------------------------------------------│
  │ [KMS] + Secrets Manager                                                  │
  │ - encryption keys                                                        │
  │ - short-lived credentials where possible                                 │
  │ - automatic rotation                                                     │
  │                                                                          │
  │ Tools fetch secrets only when required via IRSA                          │
  │                                                                          │
  │ [OBS] Logs / Traces / Metrics                                            │
  │ - structured audit logs                                                  │
  │ - redaction for tokens and PII                                           │
  │ - canaries                                                               │
  │ - anomaly detection                                                      │
  │ - exfil / loop / SSRF alerts                                             │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

# Multi-Layer Protection Stack

## Layer 0: User / AuthN

- Use OIDC SSO.
- Require MFA for sensitive access.
- Validate device posture where available.
- Map OAuth2 scopes to agent capabilities.
- Separate read, write, admin, and destructive permissions.

## Layer 1: Edge Protection

- Use WAF.
- Enable bot and DoS controls.
- Apply rate limits.
- Validate schemas.
- Enforce payload caps.
- Keep public and internal endpoints separate.
- Prevent direct public access to MCP tools.

## Layer 2: Cluster Baseline

- Use private EKS control plane where possible.
- Restrict Kubernetes API access.
- Enforce Pod Security Admission.
- Use OPA/Gatekeeper or Kyverno policies.
- Require signed images.
- Pin images by digest.
- Require SBOMs.
- Enforce vulnerability thresholds.
- Use IRSA everywhere.
- Encrypt secrets with KMS.
- Harden nodes.

## Layer 3: Workload Identity

- Issue a SPIFFE ID to every workload.
- Use x509-SVIDs or JWT-SVIDs.
- Use SVID-based mTLS for service-to-service traffic.
- Authorize based on SPIFFE identity, not pod IP.
- Rotate workload credentials automatically.

## Layer 4: Service Mesh / mTLS Enforcement

- Enforce strict mTLS.
- Define explicit service-to-service authorization.
- Allow only expected callers to each service.
- Block plaintext service traffic.
- Log mTLS peer identity.

## Layer 5: Tool Router / MCP Gateway Policy

- Validate OAuth2 `iss`, `aud`, and `scope`.
- Validate workload identity of the caller.
- Bind user context to the tool request.
- Enforce per-tool action allowlists.
- Enforce per-tool destination allowlists.
- Enforce payload caps.
- Require HITL for destructive operations.
- Sign internal request context.

## Layer 6: Network Egress Control

- Default-deny egress.
- Allowlist destinations per tool.
- Block cloud metadata IPs.
- Block internal ranges unless required.
- Use a fetch proxy for URL tools.
- Detect and prevent DNS rebinding.
- Prefer private endpoints for internal services.

## Layer 7: Data Protection

- Redact tokens in logs and traces.
- Apply DLP gates to Slack, email, and webhook tools.
- Enforce tenant isolation in vector databases.
- Require mandatory `tenant_id` filters.
- Partition memory by tenant, user, and session.
- Cap raw output size.
- Validate response schemas.
- Sanitize tool outputs before returning them to the model or user.

## Layer 8: Detection and Response

- Alert on audience mismatches.
- Alert on metadata IP access.
- Alert on high-volume exfil patterns.
- Alert on recursive tool loops.
- Alert on cross-tenant retrieval.
- Alert on canary hits.
- Maintain kill switches.
- Preserve forensic audit trails.

---

##
##

---

# Mental Model

At every MCP hop, ask:

> Can this authenticated agent, acting with trusted user and tenant context,
> invoke this specific tool, for this specific action, against this specific
> target, over an authenticated transport, under current policy, within resource
> budget, without leaking sensitive data?

The answer must be proven independently by:

1. Identity controls.
2. Tool registry controls.
3. Runtime controls.
4. Network controls.
5. Data and context controls.
6. Observability.
7. Response readiness.

MCP security is not a single gateway, prompt, policy, or scanner.

It is a chain of composable controls that assume any tool input, tool output, or
retrieved context may be hostile.
