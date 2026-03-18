╔══════════════════════════════════════════════════════════════════╗
║                     UNTRUSTED ZONE (Public Internet)             ║
╚══════════════════════════════════════════════════════════════════╝
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 0 │ EDGE DEFENSE                                          │
│                                                                  │
│  ◆ OIDC / Okta Authentication                                    │
│  ◆ WAF + DDoS Protection                                         │
│  ◆ Rate Limiting (Request-level)                                 │
└──────────────────────────────────────────────────────────────────┘
                              │
                   (1) User JWT (Okta / OIDC)
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 1 │ GATEWAY COP  ·  Protocol Sentry                       │
│                                                                  │
│  ◆ [MCP-18] Session Control    — ChatID ↔ User binding           │
│  ◆ [MCP-01] Guardrails         — Prompt injection / impersonation│
│             filtering                                            │
│  ◆ [MCP-02] Token Exchange     — Swaps User JWT for a short-lived│
│             Scoped Agent Token                                   │
│  ◆ [MCP-09] Token Binding      — Mints claims:                   │
│             { sub: user, aud: mcp-tool-x, agent_id: astra }      │
│  ◆ [MCP-03] Tool Registry      — Validates tool exists & is      │
│             Verification         trusted before dispatch         │
└──────────────────────────────────────────────────────────────────┘
                              │
              (2) Scoped Agent Token  +  SPIFFE SVID
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 2 │ IDENTITY COP  ·  SPIFFE / SPIRE Sentry                │
│                                                                  │
│  ◆ [MCP-10] mTLS               — Peer-to-peer encrypted tunnel   │
│  ◆ [MCP-05] SVID Validation    — Rejects any pod without a       │
│             verified SPIFFE Workload Identity                    │
│  ◆ [MCP-07] Cross-Team Block   — SRE Agent cert ≠ Security Agent │
│             cert; cross-namespace calls are hard-rejected        │
└──────────────────────────────────────────────────────────────────┘
                              │
                 (3) Verified Identity  +  Scoped Token
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 3 │ NETWORK COP  ·  Istio / AuthorizationPolicy           │
│                                                                  │
│  ◆ [MCP-07] Service-to-Service — Istio allows ONLY               │
│             Gateway → MCP Server; no lateral movement            │
│  ◆ Namespace Isolation        — SRE namespace cannot resolve or  │
│             reach Security namespace                             │
│  ◆ Egress Block                — MCP pods cannot initiate        │
│             outbound connections back to Agent pods              │
└──────────────────────────────────────────────────────────────────┘
                              │
                    (4) Authorized Execution Command
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 4 │ WORKLOAD COP  ·  Kubernetes Sandbox                   │
│                                                                  │
│  ◆ [MCP-09] Pod Security       — Non-root, restricted profile,   │
│             Admission            read-only root filesystem       │
│  ◆ [MCP-06] Image Provenance   — Signed images only (Cosign /    │
│             Notary); unsigned = rejected at admission            │
│  ◆ [MCP-14] Resource Quotas    — CPU / memory hard limits per    │
│             pod; prevents resource exhaustion attacks            │
└──────────────────────────────────────────────────────────────────┘
                              │
                    (5) Cloud Handshake  ·  IRSA
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 5 │ CLOUD IAM COP  ·  IRSA / AWS Sentry                   │
│                                                                  │
│  ◆ OIDC Role Assumption        — Pod exchanges K8s Service       │
│             Account Token for a short-lived AWS IAM Token        │
│  ◆ Least-Privilege IAM Role    — "mcp-github-role": no S3,       │
│             no Admin, no wildcard                                │
│  ◆ Resource Scope              — Policy scoped to                │
│             org-thousandeyes/* only                              │
└──────────────────────────────────────────────────────────────────┘
                              │
                    (6) Tool Execution
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 6 │ TOOL COP  ·  MCP Connector                            │
│                                                                  │
│  ◆ [MCP-02] Audience Check     — Tool B hard-rejects any token   │
│             minted for Tool A                                    │
│  ◆ [MCP-15] Identity Scope     — IRSA acts AS the user, not      │
│             the application service account                      │
│  ◆ [MCP-04] PII / Secret       — Logging scrubbers mask secrets, │
│             Masking              tokens, and PII before write    │
│  ◆ [MCP-08] SSRF Protection    — Blocks cloud metadata IP        │
│             (169.254.169.254) and unresolvable internal FQDNs    │
│  ◆ [MCP-13] Output             — Sanitizes tool responses to     │
│             Sanitization         prevent secondary prompt inject │
└──────────────────────────────────────────────────────────────────┘
                              │
                    (7) Verified Output / Storage
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 7 │ DATA & MEMORY COP  ·  Vector / Storage Guard          │
│                                                                  │
│  ◆ [MCP-11] Cross-Tenant       — Vector DB queries enforce       │
│             Isolation            filter: { team, session_id }    │
│  ◆ Differential Privacy        — Session-scoped RAG; noise       │
│             filtering prevents cross-team memory bleed           │
│  ◆ Encryption at Rest          — AES-256 for all stored vectors  │
│             and context blobs                                    │
│  ◆ Immutable Audit Trail       — Append-only transaction log     │
│             (WORM / CloudTrail)                                  │
└──────────────────────────────────────────────────────────────────┘
                              │
                    (8) Approved Egress Only
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 8 │ EGRESS COP  ·  Cloud Firewall + DLP                   │
│                                                                  │
│  ◆ [MCP-08] FQDN Allow-list    — e.g. *.github.com, *.slack.com  │
│             only; all other destinations denied                  │
│  ◆ [MCP-08] Metadata IP Block  — Hard-block 169.254.169.254 at   │
│             the network policy level                             │
│  ◆ DLP Inspection              — Egress payload scanned for PII, │
│             secrets, and credential patterns                     │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
╔══════════════════════════════════════════════════════════════════╗
║         EXTERNAL BACKENDS  ·  GitHub · Slack · AWS Bedrock       ║
╚══════════════════════════════════════════════════════════════════╝


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TRIPLE-LOCK SUMMARY  ·  Why Agent A Cannot Be Used Against Agent B
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔒 LOCK 1 · THE TOKEN (OAuth2 / JWT)
     "I hold the correct scoped key for this specific tool."
     → Short-lived, audience-bound, agent-tagged JWT.
     → Tool B hard-rejects a token minted for Tool A.

  🔒 LOCK 2 · THE POD (SPIFFE / SPIRE)
     "I am calling from a verified, authorized workload."
     → Each pod carries a cryptographic SPIFFE SVID.
     → Cross-team pod certificates are mutually exclusive.

  🔒 LOCK 3 · THE NETWORK (Istio / mTLS)
     "The physical path is open only for this transaction."
     → AuthorizationPolicies enforce a strict Gateway → MCP topology.
     → No lateral movement; no pod-to-pod bypass.

  ─────────────────────────────────────────────────────────────────
  VERDICT: To impersonate an agent, an attacker must simultaneously:
    1. Steal the user's active Okta session
    2. Compromise the Gateway's token-signing private key
    3. Obtain a valid SPIFFE SVID for the target workload
    4. Breach EKS node certificate storage

  That is true defense-in-depth.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ADVANCED CONTROLS  ·  The Final Shield
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🛑 HUMAN-IN-THE-LOOP (HITL)
     Trigger  : Any tool action classified Write or Admin
                (e.g. github.delete_repo, pagerduty.resolve_incident)
     Mechanism: Gateway pauses execution; sends Slack / email
                approval request to the user
     Value    : Stops prompt injection + token replay attacks dead
                at the last mile — no "Approve" click, no action

  ⏱  INTENT-BASED RATE LIMITING
     Instead of: requests / second
     Use       : impact / window

     Example policy:
       READ   → 100 operations / minute
       WRITE  → 10  operations / minute
       DELETE → 1   operation  / 10 minutes

     Value    : Limits blast radius if an agent is compromised;
                prevents mass exfiltration or infrastructure
                "carpet-bombing"

  🧠 DIFFERENTIAL PRIVACY FOR MEMORY (RAG)
     Mechanism: Every Vector DB query is scoped with a hard filter:
                { "team": "sre", "session_id": "chat-abc-123" }
     Value    : Prevents "Ghost of Sprints Past" — an agent
                cannot surface secrets from another team's
                historical session, even via indirect query
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
