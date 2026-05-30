# MCP Security Architecture v2

> **Owner:** Platform Security · **Updated:** 2026-05-30 · **Status:** Living Doc

---

## Full Request Flow (ASCII)

```text
╔══════════════════════════════════════════════════════════════════════════════════╗
║                         UNTRUSTED ZONE · Public Internet                        ║
╚══════════════════════════════════════════════════════════════════════════════════╝
                                        │ ① User JWT (Okta/OIDC)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L0 · EDGE                                                                        │
│  [Okta OIDC Auth] ──► [WAF + DDoS] ──► [Edge Rate Limiting]                     │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L1 · GATEWAY COP                                              ┌───────────────┐  │
│                                                               │  🛑 HITL      │  │
│  [MCP-18 Session Control]                                     │  Slack/Email  │  │
│       │                                                       │  15min timeout│  │
│       ▼                                                       └───────┬───────┘  │
│  [MCP-01 OPA Policy Engine]──────────────────────────────────── low   │          │
│       │              [LLM Intent Classifier]      confidence ──► conf  │          │
│       ▼                                                               │          │
│  [MCP-02 Token Exchange · User JWT → Scoped Agent Token]             │          │
│       │                                                               │          │
│       ▼                                                               │          │
│  [MCP-NEW · RFC 8693 Delegation Chain]◄──────────────────────────────┘          │
│       │   scope narrows per hop · max depth = 4                                  │
│       │   delegation_chain claim appended at each hop                            │
│       │                                                                           │
│       ▼                                                                           │
│  [MCP-03 Tool Registry Verification]──► UNKNOWN TOOL? ──► ✗ REJECT              │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ② Scoped Agent Token + SPIFFE SVID
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L2 · IDENTITY COP · SPIFFE/SPIRE                                                 │
│                                                                                  │
│  [MCP-10 mTLS Tunnel]                                                            │
│       │                                                                           │
│       ▼                                                                           │
│  [MCP-05 SVID Validation]──► NO VALID SVID? ──► ✗ HARD REJECT                  │
│       │                                                                           │
│       ▼                                                                           │
│  [MCP-07 Cross-Team Block]──► SRE cert = Security cert? ──► ✗ HARD REJECT       │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ③ Verified Identity + Scoped Token
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L3 · NETWORK COP · Istio / AuthorizationPolicy                                   │
│                                                                                  │
│  [Gateway → MCP Server ONLY]──► any other path? ──► ✗ REJECT                   │
│       │                                                                           │
│  [Namespace Isolation · SRE ╳ Security]                                          │
│       │                                                                           │
│  [Egress Block · MCP pods cannot call back to agent pods]                        │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ④ Authorized Execution Command
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L4 · WORKLOAD COP · Kubernetes Sandbox                                           │
│                                                                                  │
│  [MCP-09 Pod Security Admission · non-root · read-only FS]                       │
│       │                                                                           │
│  [MCP-06 Image Signing · Cosign/Notary]──► unsigned? ──► ✗ REJECT AT ADMISSION  │
│       │                                                                           │
│  [MCP-NEW SLSA L3 Provenance + SBOM CVE Scan]──► fail? ──► ✗ REJECT            │
│       │                                                                           │
│  [MCP-14 Resource Quotas · CPU/mem hard limits]                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ⑤ IRSA Handshake
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L5 · CLOUD IAM COP · IRSA / AWS                                                  │
│                                                                                  │
│  [OIDC Role Assumption · K8s SA Token → short-lived IAM Token]                   │
│       │                                                                           │
│  [Least-Privilege IAM · mcp-github-role · no wildcard · org-thousandeyes/* only] │
│       │                                                                           │
│  [MCP-NEW Vault Secretless · ephemeral injection · no env vars · rotated]        │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ⑥ Tool Execution
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L6 · TOOL COP · MCP Connector                                                    │
│                                                                                  │
│  [MCP-02 Audience Check]──► token.aud ≠ this tool? ──► ✗ HARD REJECT           │
│       │                                                                           │
│  [MCP-15 Identity Scope · IRSA acts as user not app SA]                          │
│       │                                                                           │
│  [MCP-04 PII/Secret Masking · scrubbed before log write]                         │
│       │                                                                           │
│  [MCP-08 SSRF Block · 169.254.169.254 + internal FQDNs]                          │
│       │                                                                           │
│  [MCP-NEW JSON Schema Contracts]──► response mismatch? ──► ✗ REJECT             │
│       │                                                                           │
│  WRITE or ADMIN action? ──────────────────────────────────► 🛑 HITL REQUIRED    │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ⑦ Telemetry Stream
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L6.5 · BEHAVIORAL COP · Agent Telemetry  ⭐ NEW                                  │
│                                                                                  │
│  [UEBA Baseline · per agent_id · tool call pattern profiling]                    │
│       │                                                                           │
│       ├──► unusual sequence?  ──┐                                                │
│       ├──► off-hours activity? ─┼──► ⚠ ANOMALY ──► 🚫 SUSPEND agent_id         │
│       ├──► READ spike + DELETE? ─┘              ──► 🚫 REVOKE SVID              │
│       │                                                                           │
│  [OpenTelemetry ──► SIEM · Splunk / Panther · real-time]                         │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ⑧ Verified Output
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L7 · DATA & MEMORY COP · Vector / Storage Guard                                  │
│                                                                                  │
│  [MCP-11 Cross-Tenant Filter · { team, session_id } enforced on all queries]     │
│       │                                                                           │
│  [MCP-NEW ABE · team-scoped decrypt keys · cross-tenant = cryptographically ✗]   │
│       │                                                                           │
│  [MCP-NEW Embedding Poisoning Detection]                                          │
│       │                                                                           │
│  [MCP-NEW Context TTL · 7-day auto-purge]                                        │
│       │                                                                           │
│  [AES-256 Encryption at Rest · WORM Audit Trail / CloudTrail]                    │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │ ⑨ Approved Egress Only
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ L8 · EGRESS COP · Cloud Firewall + DLP                                           │
│                                                                                  │
│  [MCP-08 FQDN Allow-list · *.github.com · *.slack.com · all else ✗ DENIED]      │
│       │                                                                           │
│  [MCP-08 Metadata IP Block · 169.254.169.254 hard-blocked at network policy]     │
│       │                                                                           │
│  [DLP Inspection · PII · secrets · credential patterns scanned on egress]        │
└──────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║              ✅ EXTERNAL BACKENDS · GitHub · Slack · AWS Bedrock                 ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## Control Reference

| Layer | Control | Tag | What It Does | What It Blocks |
|---|---|---|---|---|
| L0 | Okta OIDC Auth | — | Validates user identity at the edge | Unauthenticated requests |
| L0 | WAF + DDoS | — | L7 rule filtering + volumetric absorption | Malformed requests, flood attacks |
| L0 | Edge Rate Limiting | — | Request-level throttle at CDN | Brute force, credential stuffing |
| L1 | Session Control | MCP-18 | Binds ChatID to authenticated user | Session hijacking, chat spoofing |
| L1 | OPA Policy Engine | MCP-01 | Structured policy evaluation on every request | Policy violations, unauthorized tool dispatch |
| L1 | LLM Intent Classifier | MCP-01 | Secondary model scores prompt intent; low confidence → HITL | Context-aware prompt injection that bypasses regex |
| L1 | Token Exchange | MCP-02 | Swaps User JWT for short-lived scoped Agent Token | Overprivileged or reused tokens |
| L1 | RFC 8693 Delegation Chain | MCP-NEW | Scope narrows at each agent hop; max depth = 4 | Multi-hop scope escalation, infinite agent recursion |
| L1 | Tool Registry Verification | MCP-03 | Tool must exist and be trusted before dispatch | Unknown or spoofed tool invocation |
| L2 | mTLS Tunnel | MCP-10 | Encrypts all peer-to-peer communication | Eavesdropping, MITM |
| L2 | SVID Validation | MCP-05 | Cryptographic workload identity; no SVID = hard reject | Unverified pod calls, identity spoofing |
| L2 | Cross-Team Block | MCP-07 | Namespace certs are mutually exclusive | SRE agent calling Security tooling and vice versa |
| L3 | Service Topology Policy | MCP-07 | Istio enforces `Gateway → MCP` only | Lateral movement between services |
| L3 | Namespace Isolation | — | SRE namespace cannot resolve Security namespace | Cross-team network reachability |
| L3 | Egress Block | — | MCP pods cannot initiate calls back to agent pods | Reverse shell, C2 callbacks from compromised tools |
| L4 | Pod Security Admission | MCP-09 | Non-root, restricted profile, read-only FS | Container escape, FS tampering |
| L4 | Image Signing | MCP-06 | Cosign/Notary; unsigned images rejected at admission | Tampered or supply-chain-compromised images |
| L4 | SLSA L3 + SBOM | MCP-NEW | Provenance attestation + CVE scan at admission | Build pipeline compromise, known vulnerable dependencies |
| L4 | Resource Quotas | MCP-14 | Hard CPU/mem limits per pod | Resource exhaustion, noisy-neighbor DoS |
| L5 | OIDC Role Assumption | — | K8s SA Token exchanged for short-lived IAM Token | Long-lived credential exposure |
| L5 | Least-Privilege IAM | — | `mcp-github-role`; no S3, no admin, scoped to `org-thousandeyes/*` | Privilege escalation, unauthorized AWS resource access |
| L5 | Vault Secretless Injection | MCP-NEW | Secrets injected ephemerally; never in env vars; rotated each pod restart | Credential leakage via env var inspection or config dump |
| L6 | Audience Check | MCP-02 | Tool B hard-rejects tokens minted for Tool A | Cross-tool token reuse |
| L6 | Identity Scope | MCP-15 | IRSA acts as user, not app service account | Privilege bleed from app SA to user-scoped actions |
| L6 | PII/Secret Masking | MCP-04 | Scrubs secrets, tokens, PII from logs before write | Sensitive data in audit logs |
| L6 | SSRF Block | MCP-08 | Blocks `169.254.169.254` + unresolvable internal FQDNs | SSRF attacks targeting cloud metadata or internal services |
| L6 | JSON Schema Contracts | MCP-NEW | Tool response validated against declared schema; mismatch = reject | Secondary prompt injection via unexpected response fields |
| L6 | HITL on Write/Admin | — | Gateway pauses; Slack/email approval required; 15min timeout = reject | Prompt injection executing destructive actions, token replay |
| L6.5 | UEBA Baseline | MCP-NEW | Per `agent_id` normal pattern profiling | Establishes detection baseline |
| L6.5 | Anomaly Detection | MCP-NEW | Flags unusual sequences, off-hours activity, READ spike before DELETE | Compromised agent exfiltration patterns |
| L6.5 | SIEM Streaming | MCP-NEW | OpenTelemetry → Splunk/Panther in real time | Delayed detection; forensics-only posture |
| L6.5 | Auto-Quarantine | MCP-NEW | Anomaly confirmed → `agent_id` suspended + SVID revoked | Continued damage from a confirmed compromised agent |
| L7 | Cross-Tenant Filter | MCP-11 | Hard filter `{ team, session_id }` on all vector queries | Accidental cross-team data surfacing |
| L7 | ABE on Vectors | MCP-NEW | Embeddings encrypted with team-scoped keys; cross-tenant decrypt = impossible | DB breach exposing other teams' embeddings; filter bypass |
| L7 | Embedding Poisoning Detection | MCP-NEW | Anomalous vector injection patterns flagged | Adversarial data injected into the vector store |
| L7 | Context TTL | MCP-NEW | Session memory auto-purged at 7 days | Indefinite retention of sensitive session context |
| L7 | Encryption at Rest | — | AES-256 on all vectors and context blobs | Data exposure from storage breach |
| L7 | Immutable Audit Trail | — | Append-only WORM / CloudTrail | Log tampering, audit evasion |
| L8 | FQDN Allow-list | MCP-08 | `*.github.com`, `*.slack.com` only; all else denied | Data exfiltration to arbitrary external destinations |
| L8 | Metadata IP Block | MCP-08 | `169.254.169.254` hard-blocked at network policy | SSRF reaching cloud metadata from egress path |
| L8 | DLP Inspection | — | Egress payload scanned for PII, secrets, credential patterns | Exfiltration of sensitive data to allowed destinations |

##
##

## Full Request Flow

```mermaid
flowchart TD
    Internet(["🌐 Public Internet"])

    subgraph L0["L0 · Edge"]
        Okta["Okta OIDC Auth"]
        WAF["WAF + DDoS"]
        RL["Rate Limiting"]
    end

    subgraph L1["L1 · Gateway COP"]
        SC["MCP-18 Session Control\nChatID ↔ User binding"]
        OPA["MCP-01 OPA Policy Engine\n+ LLM Intent Classifier"]
        TX["MCP-02 Token Exchange\nUser JWT → Scoped Agent Token"]
        DC["MCP-NEW Delegation Chain\nRFC 8693 · max depth 4\nscope narrows per hop"]
        TR["MCP-03 Tool Registry\nVerification"]
    end

    subgraph L2["L2 · Identity COP · SPIFFE/SPIRE"]
        mTLS["MCP-10 mTLS Tunnel"]
        SVID["MCP-05 SVID Validation\nNo SVID = hard reject"]
        CTB["MCP-07 Cross-Team Block\nSRE cert ≠ Security cert"]
    end

    subgraph L3["L3 · Network COP · Istio"]
        S2S["MCP-07 Gateway → MCP only\nNo lateral movement"]
        NS["Namespace Isolation"]
        EB["Egress Block\nMCP pods cannot call back to agents"]
    end

    subgraph L4["L4 · Workload COP · K8s"]
        PSA["MCP-09 Pod Security Admission\nnon-root · read-only FS"]
        IMG["MCP-06 Signed Images\nCosign / Notary"]
        SLSA["MCP-NEW SLSA L3 Provenance\n+ SBOM CVE scan at admission"]
        RQ["MCP-14 Resource Quotas\nCPU/mem hard limits"]
    end

    subgraph L5["L5 · Cloud IAM · IRSA"]
        IRSA["OIDC Role Assumption\nK8s SA Token → short-lived IAM Token"]
        IAM["Least-Privilege IAM\nmcp-github-role · no wildcard"]
        VAULT["MCP-NEW Vault Secretless\nno env vars · ephemeral · rotated"]
    end

    subgraph L6["L6 · Tool COP · MCP Connector"]
        AUD["MCP-02 Audience Check\nToken for Tool A rejected by Tool B"]
        IS["MCP-15 Identity Scope\nIRSA acts as user not app SA"]
        PII["MCP-04 PII/Secret Masking\nLogs scrubbed before write"]
        SSRF["MCP-08 SSRF Block\n169.254.169.254 + internal FQDN"]
        SC2["MCP-NEW JSON Schema Contracts\nTool response validated · mismatch = reject"]
    end

    subgraph L65["L6.5 · Behavioral COP · NEW ⭐"]
        UEBA["UEBA Baseline per agent_id\nUnusual sequences · off-hours · volume spikes"]
        SIEM["OpenTelemetry → SIEM\nSplunk / Panther"]
        AQ["Auto-Quarantine\nAnomaly → suspend agent_id + revoke SVID"]
    end

    subgraph L7["L7 · Data & Memory COP"]
        CT["MCP-11 Cross-Tenant Isolation\nfilter: { team, session_id }"]
        ABE["MCP-NEW Attribute-Based Encryption\nVectors encrypted · team-scoped keys\ncross-tenant = cryptographically impossible"]
        EPD["MCP-NEW Embedding Poisoning Detection"]
        TTL["MCP-NEW Context TTL · 7-day auto-purge"]
        EAR["AES-256 Encryption at Rest"]
        WORM["Immutable Audit Trail\nWORM / CloudTrail"]
    end

    subgraph L8["L8 · Egress COP"]
        FQDN["MCP-08 FQDN Allow-list\n*.github.com · *.slack.com only"]
        MIB["MCP-08 Metadata IP Block\n169.254.169.254 hard-blocked"]
        DLP["DLP Inspection\nPII · secrets · credential patterns"]
    end

    Backends(["✅ GitHub · Slack · AWS Bedrock"])

    %% Happy path flow
    Internet --> L0
    L0 --> |"① User JWT"| L1
    L1 --> |"② Scoped Agent Token\n+ SPIFFE SVID"| L2
    L2 --> |"③ Verified Identity\n+ Scoped Token"| L3
    L3 --> |"④ Authorized Exec Command"| L4
    L4 --> |"⑤ IRSA Handshake"| L5
    L5 --> |"⑥ Tool Execution"| L6
    L6 --> |"⑦ Telemetry"| L65
    L65 --> |"⑧ Verified Output"| L7
    L7 --> |"⑨ Approved Egress"| L8
    L8 --> Backends

    %% Rejection paths
    OPA -->|"Low confidence\nIntent unclear"| HITL(["🛑 HITL Approval\nSlack / Email\n15 min timeout"])
    L6 -->|"Write or Admin action"| HITL
    AQ -->|"Anomaly confirmed"| REVOKE(["🚫 SVID Revoked\nAgent Suspended"])

    %% Multi-agent delegation
    DC -->|"Sub-agent call\nnarrower token minted"| DC

    %% Styling
    classDef newControl fill:#1a472a,stroke:#2d6a4f,color:#fff
    classDef rejectNode fill:#7f1d1d,stroke:#991b1b,color:#fff
    classDef backend fill:#1e3a5f,stroke:#2563eb,color:#fff
    classDef internet fill:#3b1f00,stroke:#92400e,color:#fff

    class VAULT,DC,SLSA,SC2,UEBA,SIEM,AQ,ABE,EPD,TTL newControl
    class HITL,REVOKE rejectNode
    class Backends backend
    class Internet internet
```

---

## Layer Reference

### L0 · Edge
| Control | Detail |
|---|---|
| Okta OIDC | All requests require valid Okta JWT |
| WAF + DDoS | L7 rule filtering + volumetric absorption |
| Rate Limiting | Edge-level request throttle |

---

### L1 · Gateway COP
| Control | Tag | Detail |
|---|---|---|
| Session Control | MCP-18 | ChatID ↔ User binding |
| Guardrails | MCP-01 | OPA policy engine + LLM intent classifier; low confidence → HITL |
| Token Exchange | MCP-02 | User JWT → short-lived scoped Agent Token |
| Delegation Chain | MCP-NEW | RFC 8693; `delegation_chain` claim; scope narrows per hop; max depth = 4 |
| Tool Registry | MCP-03 | Tool must exist and be trusted before dispatch |

> **Delegation model:** `User → Orchestrator → Sub-Agent → Tool`
> Each hop calls RFC 8693 exchange. Resulting token has equal or lesser scope. Depth > 4 = hard reject.

---

### L2 · Identity COP — SPIFFE/SPIRE
| Control | Tag | Detail |
|---|---|---|
| mTLS | MCP-10 | All peer comms encrypted |
| SVID Validation | MCP-05 | No valid SPIFFE SVID = rejected |
| Cross-Team Block | MCP-07 | Certs are namespace-exclusive; SRE ≠ Security |

---

### L3 · Network COP — Istio
| Control | Detail |
|---|---|
| Service Topology | `Gateway → MCP Server` only; no lateral movement |
| Namespace Isolation | SRE namespace cannot reach Security namespace |
| Egress Block | MCP pods cannot initiate connections back to agent pods |

---

### L4 · Workload COP — Kubernetes
| Control | Tag | Detail |
|---|---|---|
| Pod Security | MCP-09 | Non-root, restricted, read-only FS |
| Image Signing | MCP-06 | Cosign / Notary; unsigned = rejected at admission |
| SLSA L3 + SBOM | MCP-NEW | Provenance attestation required; SBOM scanned against CVE feeds at admission |
| Resource Quotas | MCP-14 | Hard CPU/mem limits per pod |

---

### L5 · Cloud IAM — IRSA
| Control | Detail |
|---|---|
| OIDC Role Assumption | K8s SA Token → short-lived AWS IAM Token |
| Least-Privilege IAM | `mcp-github-role`; no S3, no admin, no wildcard; scoped to `org-thousandeyes/*` |
| Vault Secretless | Secrets injected ephemerally via Vault Agent / CSI driver; never in env vars; rotated each pod restart |

---

### L6 · Tool COP — MCP Connector
| Control | Tag | Detail |
|---|---|---|
| Audience Check | MCP-02 | Tool B rejects tokens minted for Tool A |
| Identity Scope | MCP-15 | IRSA acts as user, not app service account |
| PII Masking | MCP-04 | Secrets, tokens, PII scrubbed from logs before write |
| SSRF Block | MCP-08 | `169.254.169.254` + unresolvable internal FQDNs blocked |
| Output Contracts | MCP-NEW | JSON Schema per tool; non-conforming response = hard reject; kills secondary prompt injection via unexpected fields |

---

### L6.5 · Behavioral COP ⭐ NEW
| Control | Detail |
|---|---|
| UEBA Baseline | Per `agent_id` normal pattern profiling |
| Anomaly Triggers | Unusual tool sequences · off-hours · READ spike before DELETE · delegation depth approaching max |
| SIEM Stream | OpenTelemetry → Splunk / Panther in real time |
| Auto-Quarantine | Anomaly confirmed → `agent_id` suspended + SVID revoked |

---

### L7 · Data & Memory COP
| Control | Tag | Detail |
|---|---|---|
| Cross-Tenant Isolation | MCP-11 | Hard filter `{ team, session_id }` on all vector queries |
| ABE on Vectors | MCP-NEW | Embeddings encrypted with team-scoped keys; cross-tenant access cryptographically impossible regardless of query |
| Poisoning Detection | MCP-NEW | Anomalous vector injection patterns flagged |
| Context TTL | MCP-NEW | Session memory auto-purged at 7 days |
| Encryption at Rest | — | AES-256 on all vectors and context blobs |
| Audit Trail | — | Append-only WORM / CloudTrail |

> **Why ABE over filter-only:** A query-time filter on plaintext embeddings fails if the DB is breached or the filter is bypassed. ABE makes the ciphertext itself unreadable without the correct team key. The encryption *is* the access control.

---

### L8 · Egress COP
| Control | Tag | Detail |
|---|---|---|
| FQDN Allow-list | MCP-08 | `*.github.com`, `*.slack.com` only; all else denied |
| Metadata IP Block | MCP-08 | `169.254.169.254` hard-blocked at network policy |
| DLP Inspection | — | Egress scanned for PII, secrets, credential patterns |

---

## Triple-Lock Model

```
┌─────────────────────────────────────────────────────────────┐
│  To impersonate an agent, an attacker must simultaneously:  │
│                                                             │
│  🔒 LOCK 1 · TOKEN    Steal active Okta session             │
│                    +  Compromise Gateway signing key        │
│                    +  Forge valid RFC 8693 delegation chain │
│                                                             │
│  🔒 LOCK 2 · POD      Obtain valid SPIFFE SVID              │
│                    +  Breach EKS node cert storage          │
│                                                             │
│  🔒 LOCK 3 · NETWORK  Bypass Istio AuthorizationPolicy      │
│                    +  Evade UEBA anomaly detection          │
└─────────────────────────────────────────────────────────────┘
```

---

## Advanced Controls

### 🛑 Human-in-the-Loop (HITL)
- **Triggers:** Any `Write` or `Admin` tool action (e.g. `github.delete_repo`)
- **Flow:** Gateway pauses → Slack/email approval sent → no click in 15 min = auto-reject
- **Value:** Stops prompt injection and token replay at the last mile

### ⏱ Impact-Based Rate Limiting
| Class | Limit |
|---|---|
| `READ` | 100 ops / min |
| `WRITE` | 10 ops / min |
| `DELETE` | 1 op / 10 min |
| `ADMIN` | HITL required regardless |

### 🧠 RAG Memory Isolation
Every vector query: `{ "team": "sre", "session_id": "chat-abc-123" }` + ABE team-key required to decrypt.
Prevents cross-team memory bleed even via indirect similarity queries.

---

## Implementation Roadmap

### 🔴 P0 — Sprint 1–2
- [ ] RFC 8693 Token Exchange at Gateway; `delegation_chain` claim; max depth = 4
- [ ] OpenTelemetry collector + SIEM baseline anomaly rules
- [ ] Auto-quarantine webhook on SVID revocation

### 🟡 P1 — Sprint 3–4
- [ ] Replace MCP-01 regex with OPA policy bundle + LLM intent classifier
- [ ] JSON Schema contracts for all registered tools
- [ ] 7-day TTL on session memory; ABE POC design doc

### 🟢 P2 — Sprint 5–6
- [ ] Vault Agent Injector across all MCP connector pods; zero standing secrets audit
- [ ] SLSA L3 provenance in image build pipeline; SBOM admission webhook
- [ ] ABE rollout on vector store

---

## Threat Coverage

| Threat | Mitigating Layers |
|---|---|
| Prompt injection | L1 OPA + LLM classifier, L6 output contracts |
| Secondary prompt injection | L6 JSON Schema contracts |
| Agent impersonation | L1 token binding, L2 SPIFFE, L3 Istio |
| Multi-hop scope escalation | L1 RFC 8693 delegation chain |
| Cross-tenant memory access | L7 ABE + filter + differential privacy |
| SSRF | L6 SSRF block, L8 metadata IP block |
| Supply chain compromise | L4 SLSA L3 + SBOM |
| Credential exposure | L5 Vault secretless |
| Undetected compromise | L6.5 UEBA + auto-quarantine |
| Mass exfiltration | Impact-based rate limiting |
| Unauthorized write/delete | HITL |

---

## References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [SPIFFE / SPIRE](https://spiffe.io/docs/)
- [SLSA Framework](https://slsa.dev/)
- [OPA](https://www.openpolicyagent.org/docs/)
- [NIST SP 800-207 — Zero Trust](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

*Maintained by Platform Security · PRs require `@security-reviewers` approval · Urgent issues → PagerDuty `mcp-security`*
