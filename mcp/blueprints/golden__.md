# MCP @ Scale — Golden Path v2

> **Purpose:** This is the single reference document that governs how every MCP integration in our EKS cluster is built, secured, and operated.
> All proposals beneath it are implementation detail. This is the law.

---

## What "Golden Path" Means Here

A golden path is an **opinionated, pre-approved route** that any team can follow to ship an MCP integration without reinventing security decisions. If you follow this path, you are considered compliant. If you deviate, you need a security review.

Four rules that never bend:

```text
RULE 1: Every request carries a user identity. No anonymous tool execution.
RULE 2: Every tool is registered, signed, and scoped. No ad-hoc tools.
RULE 3: Every secret lives in Secrets Manager. No exceptions.
RULE 4: The AI advises. The gates decide. No LLM output is trusted as authorization.
```

---

## What This Document Does NOT Cover

- LLM model selection, fine-tuning, or prompt engineering practices
- Data residency and cross-region compliance
- Multi-region failover architecture
- End-user privacy (GDPR/CCPA) — handled by separate data governance policy
- Pricing or cost allocation models for LLM usage

These are important but governed by separate policies. This document covers the **security architecture** of MCP tool execution.

---

## The Master Session Flow (Left → Right)

This covers a complete user-initiated MCP session from browser/client to tool execution and back. Read left to right across each layer.

```text
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
  LAYER          USER DEVICE          OKTA              INTERNET EDGE          EKS CLUSTER (INTERNAL)
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 0                                                                                                         │
  │ BOOTSTRAP    [MCP Client]                                                                                       │
  │ (one-time    Cursor / Claude                                                                                    │
  │  per client  Code / Internal                                                                                    │
  │  install)    Agent                                                                                              │
  │              │                                                                                                  │
  │              │  1. Client starts cold. No token.                                                                │
  │              │     Attempts unauthenticated connect                                                             │
  │              │─────────────────────────────────────────────────────────────────────────────────────────────►   │
  │              │                                                          [ALB + WAF]──►[MCP Gateway]            │
  │              │                                                                         │                       │
  │              │                                                                         │ Returns:              │
  │              │                                                                         │ HTTP 401              │
  │              │                                                                         │ WWW-Authenticate:     │
  │              │  2. Client reads protected resource metadata                            │ Bearer                │
  │              │◄────────────────────────────────────────────────────────────────────────│ resource_metadata=    │
  │              │    /.well-known/oauth-protected-resource                                │ "https://mcp.co/      │
  │              │    { authorization_servers: ["https://your-org.okta.com"] }            │  .well-known/opr"       │
  │              │                                                                                                  │
  │              │  3. Client fetches Okta auth server metadata                                                     │
  │              │─────────────────────────────────────────────────────────►[OKTA]                                  │
  │              │    /.well-known/oauth-authorization-server                │                                      │
  │              │◄─────────────────────────────────────────────────────────│                                       │
  │              │    { authorization_endpoint, token_endpoint,              │                                      │
  │              │      registration_endpoint, scopes_supported... }         │                                      │
  │              │                                                           │                                      │
  │              │  4. Client is pre-registered in Okta (golden path)       │                                       │
  │              │     client_id already exists. Skip DCR.                  │                                       │
  │              │     (New teams: pre-registration request to Platform Sec) │                                      │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 1                                                                                                        │
  │ USER         [MCP Client]──────────────────────────────────────────────►[OKTA]                                 │
  │ AUTHN &      │                                                           │                                     │
  │ CONSENT      │  5. Authorization Code Grant begins (PKCE + resource)    │                                      │
  │              │     Browser opens:                                        │                                     │
  │              │     /authorize?                                           │                                     │
  │              │       response_type=code                                  │  User sees:                         │
  │              │       client_id=<pre-registered>                          │  ┌────────────────┐                 │
  │              │       redirect_uri=https://client.co/cb                  │  │  Okta Login    │                  │
  │              │       scope=mcp:read mcp:write                           │  │  + MFA         │                  │
  │              │       code_challenge=<S256>                               │  │  + Consent     │                 │
  │              │       resource=https://mcp.internal.co                   │  │    screen      │                  │
  │              │                                                           │  └────────────────┘                 │
  │              │  6. User authenticates (SSO + MFA)                       │                                      │
  │              │     User consents to scopes                               │                                     │
  │              │     Okta checks group membership                          │                                     │
  │              │     (only eng-sre can consent to mcp:admin)              │                                      │
  │              │                                                           │                                     │
  │              │  7. Okta redirects with auth code                        │                                      │
  │              │◄──────────────────────────────────────────────────────── │                                      │
  │              │     https://client.co/cb?code=AUTH_CODE&state=xyz        │                                      │
  │              │                                                           │                                     │
  │              │  8. Client exchanges code for tokens (PKCE verifier)     │                                      │
  │              │─────────────────────────────────────────────────────────►│                                      │
  │              │     POST /token                                           │                                     │
  │              │     { grant_type=authorization_code,                      │                                     │
  │              │       code=AUTH_CODE, code_verifier=<pkce>,              │  Okta mints:                         │
  │              │       resource=https://mcp.internal.co }                 │  ┌──────────────────────────────┐    │
  │              │◄─────────────────────────────────────────────────────────│  │ access_token (JWT, 15 min)   │    │
  │              │                                                           │  │  iss: okta.com/oauth2/...    │   │
  │              │                                                           │  │  aud: https://mcp.internal   │   │
  │              │  Client stores:                                           │  │  sub: user@company.com       │   │
  │              │  - access_token  (memory only, never disk)               │  │  scp: [mcp:read, mcp:write]   │   │
  │              │  - refresh_token (encrypted, secure storage)             │  │  exp: now + 900s              │   │
  │              │                                                           │  │ refresh_token (encrypted)    │  │
  │              │                                                           │  └──────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 2                                                                                                         │
  │ MCP          [MCP Client]                                                            [EKS CLUSTER]              │
  │ SESSION                                                                                                         │
  │ INIT         │  9. Client connects to MCP Gateway (authenticated)                                               │
  │              │─────────────────────────────────────────────────────────────────────────────────────────────►    │
  │              │     POST /mcp                                            [ALB+WAF]──►[MCP Gateway]               │
  │              │     Authorization: Bearer <access_token>                              │                          │
  │              │     MCP: initialize { capabilities, clientInfo }                     │ A. WAF checks:            │
  │              │                                                                       │    payload size         │
  │              │                                                                       │    schema valid         │
  │              │                                                                       │    rate limit ok        │
  │              │                                                                       │                         │
  │              │                                                                       │ B. JWT validation:      │
  │              │                                                                       │    iss == okta.com ✓    │
  │              │                                                                       │    aud == mcp.internal ✓│
  │              │                                                                       │    exp not passed ✓     │
  │              │                                                                       │    sig valid ✓          │
  │              │                                                                       │                         │
  │              │                                                                       │ C. Build session ctx:   │
  │              │                                                                       │    session_id = uuid    │
  │              │                                                                       │    user_sub = from JWT  │
  │              │                                                                       │    scopes = from JWT    │
  │              │                                                                       │    client_id = from JWT │
  │              │                                                                       │    call_count = 0       │
  │              │                                                                       │    cost_usd = 0.00      │
  │              │                                                                       │                         │
  │              │◄────────────────────────────────────────────────────────────────────── │                        │
  │              │     MCP: initialized { serverInfo, capabilities }                    │                          │
  │              │     session_id bound to token for duration                            │                         │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 3                                                                                                         │
  │ TOOL         [MCP Client]                [MCP Gateway]   [Tool Router]   [Tool Pod]   [AI Brain]                │
  │ INVOCATION                                                                                                      │
  │              │  10. User prompt triggers tool call                                                              │
  │              │─────────────────────────────────────────────────────────────────────────────────────────────►    │
  │              │     MCP: tools/call                                      │                                      │
  │              │     { name: "slack-post",                                │                                      │
  │              │       arguments: { channel: "#alerts",                   │                                      │
  │              │                   message: "Deploy complete" } }         │                                      │
  │              │                                                          │                                      │
  │              │                                              D. Tool registry lookup:                           │
  │              │                                                 slack-post v1.2.3 ✓                             │
  │              │                                                 image digest match ✓                           │
  │              │                                                 required_scope: mcp:write                      │
  │              │                                                 token scope includes mcp:write ✓               │
  │              │                                                 hitl_required: false ✓                         │
  │              │                                                 payload <= 4096 bytes ✓                        │
  │              │                                                 delegation_depth < MAX (3) ✓                   │
  │              │                                                          │                                     │
  │              │                                              D'. Session rate check:                           │
  │              │                                                 session call_count < 200 ✓                     │
  │              │                                                 per-tool rate < 20/min ✓                       │
  │              │                                                 session cost_usd < $5.00 ✓                     │
  │              │                                                          │                                     │
  │              │                                              E. AI policy evaluation:                          │
  │              │                                                 ┌────────┴──────────────────────┐              │
  │              │                                                 │ LLM evaluates request against │              │
  │              │                                                 │ system prompt + context.       │             │
  │              │                                                 │                                │             │
  │              │                                                 │ ai_verdict: allow | deny       │             │
  │              │                                                 │ ai_analysis: "reason text"     │             │
  │              │                                                 │                                │             │
  │              │                                                 │ IF ai_verdict == deny:         │             │
  │              │                                                 │   Log divergence event         │             │
  │              │                                                 │   (signal_tier: HIGH)          │             │
  │              │                                                 │   Block OR flag depending      │             │
  │              │                                                 │   on enforcement_mode config   │             │
  │              │                                                 └────────┬──────────────────────┘              │
  │              │                                                          │                                     │
  │              │                                              F. Token exchange (RFC 8693):                     │
  │              │                                                 Gateway calls Okta:                            │
  │              │                                                 subject_token = user JWT                       │
  │              │                                                 resource = https://slack-tool.internal         │
  │              │                                                 Okta returns tool-scoped JWT                   │
  │              │                                                 (Okta client secret via Secrets Manager,       │
  │              │                                                  same IRSA path as tool secrets)               │
  │              │                                                          │                                     │
  │              │                                              G. mTLS call to Tool Pod:                         │
  │              │                                                 ┌────────┴───────────────────────┐             │
  │              │                                                 │  SPIFFE ID verified:           │             │
  │              │                                                 │  caller = agent-gateway ✓      │             │
  │              │                                                 │  → AuthorizationPolicy allows  │             │
  │              │                                                 └────────┬───────────────────────┘             │
  │              │                                                          │──────────────────────►[slack-tool]  │
  │              │                                                          │  tool-scoped JWT                    │
  │              │                                                          │  + tool arguments                  │
  │              │                                                                          │                    │
  │              │                                                          H. Tool executes:                    │
  │              │                                                             fetch Slack creds                 │
  │              │                                                             from Secrets Manager (IRSA)       │
  │              │                                                             POST to hooks.slack.com           │
  │              │                                                             (via egress allowlist only)       │
  │              │                                                                          │                    │
  │              │                                                          I. Output sanitization:              │
  │              │                                                             ┌────────────────────────────┐    │
  │              │                                                             │ Strip secrets/canary tokens│    │
  │              │                                                             │ Scan for embedded instruct.│    │
  │              │                                                             │ Truncate to response cap   │    │
  │              │                                                             │ Log raw (redacted) to OBS  │    │
  │              │                                                             └────────────────────────────┘    │
  │              │                                                                          │                    │
  │              │                                                          J. Structured audit log emitted:     │
  │              │                                                             { request_id, session_id,         │
  │              │                                                               user_sub, tool, action,         │
  │              │                                                               ai_verdict, ai_analysis,        │
  │              │                                                               decision: allow,                │
  │              │                                                               signal_tier, reason_code,       │
  │              │                                                               egress_dest, duration_ms,       │
  │              │                                                               cost_usd }                      │
  │              │                                                                          │                    │
  │              │◄─────────────────────────────────────────────────────────────────────── │                     │
  │              │     MCP: tools/call result { content: "Message posted" }                │                     │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 3b     [MCP Client]                               [MCP Gateway]   [HITL Gate]   [Approver]              │
  │ WRITE /                                                                                                       │
  │ ADMIN TOOL   │  10b. Prompt triggers destructive/admin tool                                                   │
  │ (HITL PATH)  │─────────────────────────────────────────────────────────────────────────────────────────────►  │
  │              │     MCP: tools/call { name: "k8s-helper",                │                                     │
  │              │       arguments: { action: "delete_pod", ... } }         │                                     │
  │              │                                                           │                                    │
  │              │                                               D'. scope mcp:admin ✓                            │
  │              │                                                  hitl_required: TRUE                           │
  │              │                                                           │                                    │
  │              │◄────────────────────────────────────────────────────────── │                                   │
  │              │     MCP: pending { approval_id: "xyz",                   │────────────────────►[Slack/PagerDuty│
  │              │             message: "Waiting for approval" }            │   Approval request:  Approver UI]   │
  │              │                                                           │   { who, what, why }               │
  │              │                                                                          │                     │
  │              │                                                          Approver clicks APPROVE               │
  │              │                                                                          │                     │
  │              │                                                           │◄─────────────│                     │
  │              │                                                           │  approval_id confirmed             │
  │              │                                                           │                                    │
  │              │                                                           │  continues to steps E → J          │
  │              │◄─────────────────────────────────────────────────────────│                                     │
  │              │     MCP: tools/call result (post-approval)               │                                     │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 3c     [MCP Client]                               [MCP Gateway]   [OKTA]                                │
  │ STEP-UP                                                                                                       │
  │ AUTH         │  10c. Client requests tool beyond current scope                                                │
  │              │─────────────────────────────────────────────────────────────────────────────────────────────►  │
  │              │     MCP: tools/call { name: "data-exporter" }           │                                      │
  │              │     scope in token: mcp:read                            │                                      │
  │              │     required scope: mcp:export (not present)            │                                      │
  │              │                                                          │                                     │
  │              │◄─────────────────────────────────────────────────────── │                                      │
  │              │     HTTP 403                                             │                                     │
  │              │     WWW-Authenticate: Bearer                             │                                     │
  │              │       error="insufficient_scope"                         │                                     │
  │              │       scope="mcp:export"                                 │                                     │
  │              │                                                          │                                     │
  │              │  Client re-runs Phase 1 auth with scope=mcp:export      │                                      │
  │              │─────────────────────────────────────────────────────────────────────────────────────────────►  │
  │              │                                             [OKTA] checks: user group allows mcp:export?       │
  │              │                                                    YES → new token issued with mcp:export      │
  │              │                                                    NO  → 403 back to user, hard stop           │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 4      [MCP Client]                                               [MCP Gateway]   [OKTA]                │
  │ TOKEN        │  11. access_token nearing expiry (gateway pre-checks)                                          │
  │ REFRESH      │      OR client detects 401 on next call                                                        │
  │              │                                                                                                │
  │              │  Client silently refreshes (no user interaction):                                               │
  │              │─────────────────────────────────────────────────────────────────────────────────────────────►   │
  │              │     POST /token                                                           │                     │
  │              │     { grant_type=refresh_token,                                           │                     │
  │              │       refresh_token=<stored>,                                             │                     │
  │              │       resource=https://mcp.internal.co }                                  │                     │
  │              │◄──────────────────────────────────────────────────────────────────────── │                      │
  │              │     { new access_token, new refresh_token }                               │                     │
  │              │       (rotate both; invalidate old refresh token)                         │                     │
  │              │       (any cached tool-exchange tokens also invalidated)                  │                     │
  │              │                                                                                                 │
  │              │  Session continues transparently ───────────────────────────────────────────────────────────►   │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ PHASE 5      [MCP Client]                     [OBS / SIEM]         [Detection Engine]   [On-Call / SOC]         │
  │ DETECTION    │                                                                                                  │
  │ & RESPONSE   │  Every tool call in Phases 3/3b/3c emits structured log (step J)                                 │
  │              │────────────────────────────────────────────────────►│                                            │
  │              │                                                       │                                          │
  │              │                                        HIGH SIGNAL (P0, immediate):                              │
  │              │                                          AI verdict deny + tool granted (confused deputy)        │
  │              │                                          Canary string in tool response                          │
  │              │                                          Audience mismatch on JWT                                │
  │              │                                          SSRF probe to 169.254.x.x                               │
  │              │                                          Pod escape syscall anomaly                              │
  │              │                                                       │                                          │
  │              │                                        MEDIUM SIGNAL (P1, 1h SLA):                               │
  │              │                                          Unreviewed grant (no AI evaluation)                     │
  │              │                                          >50 outbound msgs/min from one session                  │
  │              │                                          Same tool called >20x in session                        │
  │              │                                          Token refresh >3x normal frequency                      │
  │              │                                          Session cost > 80% of ceiling                           │
  │              │                                                       │                                          │
  │              │                                        LOW SIGNAL (log, weekly review):                          │
  │              │                                          Policy denied as expected                               │
  │              │                                          Step-up auth triggered                                  │
  │              │                                          New tool onboarded (informational)                      │
  │              │                                                       │                                          │
  │              │                                                       │  HIGH signal ──────────────────────►    │
  │              │                                                                        [PagerDuty / Slack SOC] │
  │              │                                                                         │                      │
  │              │                                                                         │  Responder triggers: │
  │              │                                                                         │  - Kill switch:      │
  │              │                                                                         │    disable tool      │
  │              │                                                                         │  - Revoke token      │
  │              │                                                                         │    in Okta           │
  │              │                                                                         │  - Lock egress       │
  │              │                                                                         │  - Lockdown mode     │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
```

---

## Diagram 2: Component Trust Map

Who trusts whom, and on what basis. Print this and put it on the wall.

```text
                         TRUST BOUNDARIES
  ═══════════════════════════════════════════════════════════

  [USER]
    │  trusts: Okta login page (SSO/MFA)
    │  is trusted by: Okta (after MFA), MCP Client
    ▼

  [MCP CLIENT]  (Cursor, Claude Code, internal agent)
    │  trusts: Okta-issued JWT (validated via OIDC discovery)
    │  presents: JWT to MCP Gateway
    │  is trusted by: MCP Gateway (only after JWT validation)
    ▼

  [ALB + WAF]
    │  trusts: nothing — validates schema, size, rate
    │  is trusted by: nobody downstream (just passes valid traffic)
    ▼

  [MCP GATEWAY]
    │  trusts: Okta JWTs (iss + aud + sig + exp + scope)
    │  trusts: SPIFFE SVIDs from SPIRE (for inbound from mesh)
    │  trusts: Tool Registry (signed manifests only)
    │  trusts: AI Brain (for analysis ONLY, never for authorization)
    │  does NOT trust: tool output (sanitized before returning to LLM/user)
    │  does NOT trust: anything claiming identity without a JWT or SVID
    │  does NOT trust: AI verdicts as authorization decisions (gates decide)
    ▼

  [AI BRAIN / LLM]
    │  trusts: MCP Gateway (for prompt + context delivery)
    │  is trusted by: Gateway (for advisory analysis ONLY)
    │  does NOT make: authorization decisions (Gates 2/3 do that)
    │  does NOT see: raw secrets (redacted before prompt construction)
    │  does NOT see: raw tool output from previous calls (sanitized first)
    │  WARNING: AI may say "deny" while tool logic says "allow" — this is
    │           the confused deputy. Detection, not prevention, at this layer.
    ▼

  [TOOL ROUTER / REGISTRY]
    │  trusts: MCP Gateway (SPIFFE ID only)
    │  trusts: Okta (via token exchange JWT for downstream)
    │  does NOT trust: direct calls from any other pod
    ▼

  [TOOL PODS]
    │  trusts: Tool Router (SPIFFE ID, verified by mesh)
    │  trusts: AWS Secrets Manager (IRSA, scoped per pod)
    │  trusts: Downstream APIs (per tool allowlist)
    │  does NOT trust: environment variables for secrets
    │  does NOT trust: calls from non-gateway SPIFFE IDs
    │  does NOT invoke: other tools directly (no tool-to-tool calls;
    │                   delegation goes back through gateway with depth check)
    ▼

  [DOWNSTREAM SERVICES]  (Slack, DBs, internal APIs)
    │  trusts: Tool Pod (via tool-scoped token exchange JWT)
    │  does NOT trust: original MCP access token (passthrough blocked)
```

---

## Diagram 3: The Six Decision Gates

Every tool call passes through exactly six gates in sequence. If any gate fails, the request stops there.

```text
  TOOL CALL REQUEST
        │
        ▼
  ┌─────────────────────────────────────────────────────┐
  │  GATE 1: TRANSPORT SECURITY                         │
  │                                                     │
  │  ✓ TLS/HTTPS valid cert                             │
  │  ✓ WAF: payload size within cap                     │
  │  ✓ WAF: schema matches MCP spec                     │
  │  ✓ WAF: rate limit not exceeded                     │
  │                                                     │
  │  FAIL → 400 / 429 / 502                             │
  └─────────────────────────┬───────────────────────────┘
                            │ PASS
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  GATE 2: IDENTITY & AUTHORIZATION                   │
  │                                                     │
  │  ✓ JWT present in Authorization header              │
  │  ✓ iss == https://your-org.okta.com/oauth2/...      │
  │  ✓ aud == https://mcp.internal.yourdomain.com       │
  │  ✓ exp not exceeded                                 │
  │  ✓ sig valid (Okta JWKS)                            │
  │  ✓ scope contains required tier for this tool       │
  │  ✓ Okta client_id is pre-registered                 │
  │                                                     │
  │  FAIL aud/iss/sig  → 401  (alert P0)                │
  │  FAIL scope        → 403  (trigger step-up)         │
  └─────────────────────────┬───────────────────────────┘
                            │ PASS
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  GATE 3: TOOL GOVERNANCE                            │
  │                                                     │
  │  ✓ Tool name exists in signed registry              │
  │  ✓ Tool version digest matches pinned hash          │
  │  ✓ Requested action is in tool's allowed_actions    │
  │  ✓ Payload within tool's cap                        │
  │  ✓ HITL not required (or approval already granted)  │
  │  ✓ Delegation depth < MAX_DEPTH (default: 3)        │
  │                                                     │
  │  FAIL unknown tool     → 404  (alert P1)            │
  │  FAIL digest mismatch  → 500  (alert P0 + halt)     │
  │  FAIL needs HITL       → 202  (pending approval)    │
  │  FAIL depth exceeded   → 403  (alert P1 + log chain)│
  └─────────────────────────┬───────────────────────────┘
                            │ PASS
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  GATE 4: SESSION RATE & COST LIMITS                 │
  │                                                     │
  │  ✓ Session call_count < MAX_CALLS (default: 200)    │
  │  ✓ Per-tool rate < MAX_PER_TOOL (default: 20/min)   │
  │  ✓ Session cost_usd < COST_CEILING (default: $5)    │
  │  ✓ Recursion depth < MAX_RECURSION (default: 5)     │
  │                                                     │
  │  FAIL rate    → 429  (alert P2)                     │
  │  FAIL cost    → 402  (alert P1 + notify user)       │
  │  FAIL recurse → 403  (alert P1 + kill session)      │
  └─────────────────────────┬───────────────────────────┘
                            │ PASS
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  GATE 5: AI POLICY EVALUATION                       │
  │                                                     │
  │  ✓ LLM evaluates request against system prompt      │
  │  ✓ ai_verdict recorded (allow / deny / uncertain)   │
  │  ✓ ai_analysis text captured for audit              │
  │                                                     │
  │  enforcement_mode = "advisory":                     │
  │    Log verdict + continue (default during rollout)  │
  │  enforcement_mode = "enforce":                      │
  │    ai_verdict deny → BLOCK tool execution           │
  │                                                     │
  │  ALWAYS: if ai_verdict==deny AND tool would grant:  │
  │    emit HIGH signal confused_deputy alert            │
  │                                                     │
  │  FAIL (enforce mode) → 403  (reason: ai_policy)     │
  └─────────────────────────┬───────────────────────────┘
                            │ PASS (or advisory mode)
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  GATE 6: WORKLOAD IDENTITY (mTLS / SPIFFE)          │
  │                                                     │
  │  ✓ mTLS handshake valid                             │
  │  ✓ Caller SPIFFE ID ==                              │
  │    spiffe://.../ns/mcp-core/sa/agent-gateway        │
  │  ✓ Istio AuthorizationPolicy allows this caller     │
  │  ✓ SPIRE SVID not expired                           │
  │                                                     │
  │  FAIL → 403  (alert P0, possible lateral movement)  │
  └─────────────────────────┬───────────────────────────┘
                            │ ALL SIX GATES PASSED
                            ▼
                ┌──────────────────────┐
                │    TOOL EXECUTES     │
                │                      │
                │  → Output sanitized  │
                │  → Audit log emitted │
                │  → Response returned │
                └──────────────────────┘
```

---

## Diagram 4: Secrets Flow (No Env Vars, Ever)

```text
  AT POD STARTUP                    DURING TOOL EXECUTION
  ══════════════                    ═════════════════════

  [Pod starts]                      [Tool needs Slack token]
       │                                      │
       │  IRSA: pod SA                        │  Request to
       │  has IAM role                        │  Secrets Manager
       │  bound to it                         │  (same IRSA role)
       ▼                                      ▼
  [AWS STS]                         [Secrets Manager]
       │                                      │
       │  Temporary credentials              │  Returns secret value
       │  (never in env vars)                │  (short TTL, in memory)
       ▼                                      ▼
  [IRSA creds in pod]               [Tool holds secret in memory]
  [auto-rotated by SDK]             [NOT logged, NOT forwarded]
                                    [Redacted at OBS boundary]

  TOKEN EXCHANGE SECRETS
  ══════════════════════
  The Okta client secret used for token exchange (Phase 3 step F)
  follows the SAME path: Secrets Manager via IRSA. Never in env vars,
  never in ConfigMaps, never in gateway code.

  WHAT NEVER HAPPENS:
  ✗  secret in Dockerfile ENV
  ✗  secret in K8s secret mounted as env var (use CSI driver instead)
  ✗  secret in MCP tool arguments
  ✗  secret in structured logs
  ✗  secret passed from gateway to tool in request body
  ✗  secret visible in AI prompt or LLM context window
```

---

## Diagram 5: Output Sanitization Pipeline

Tool output is untrusted. Before it reaches the LLM or the user, it passes through sanitization.

```text
  TOOL RESPONSE (raw)
        │
        ▼
  ┌─────────────────────────────────────────────────────┐
  │  STEP 1: SECRET STRIPPING                           │
  │                                                     │
  │  Scan for patterns:                                 │
  │    Bearer tokens, API keys, JWTs                    │
  │    AWS access keys (AKIA...)                        │
  │    Canary strings (CZTZ{...} or custom)             │
  │    Secrets Manager ARNs                             │
  │                                                     │
  │  Action: replace with [REDACTED]                    │
  │  Alert: if canary found → P0 alert                  │
  └─────────────────────────┬───────────────────────────┘
                            │
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  STEP 2: INJECTION SCAN                             │
  │                                                     │
  │  Scan for embedded instructions:                    │
  │    "ignore previous instructions"                   │
  │    "system: you are now..."                         │
  │    base64-encoded instruction blocks                │
  │    markdown/HTML that could alter rendering         │
  │                                                     │
  │  Action: flag in audit log, strip if enforce mode   │
  │  Alert: P1 if detected (indirect injection attempt) │
  └─────────────────────────┬───────────────────────────┘
                            │
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  STEP 3: SIZE & STRUCTURE                           │
  │                                                     │
  │  Truncate to MAX_RESPONSE_SIZE (default: 16KB)      │
  │  Validate JSON structure (no malformed payloads)    │
  │  Strip internal fields (_flags, _debug, _internal)  │
  │                                                     │
  │  Action: truncate + log full response to OBS        │
  └─────────────────────────┬───────────────────────────┘
                            │
                            ▼
                   SANITIZED RESPONSE
              (safe for LLM context + user)
```

---

## Diagram 6: The Kill Switch Panel

When something goes wrong, your team needs to know exactly what lever to pull. Define these before you go live.

```text
  INCIDENT SEVERITY MAP + KILL SWITCHES
  ══════════════════════════════════════════════════════════════════

  SEVERITY   TRIGGER CONDITION                  KILL SWITCH               OWNER
  ─────────────────────────────────────────────────────────────────────────────
  SEV-0      Audience mismatch alert (P0)       Revoke Okta token         SecOps
             SSRF hit on 169.254.169.254         immediately via API
             Pod escape syscall anomaly          Cordon node, kill pod     SRE
             Confused deputy: AI denied,         Kill session + revoke     SecOps
               tool granted sensitive access     token + disable tool

  SEV-1      Exfil: >50 Slack msgs/min          Disable slack-tool        Platform Sec
             Canary string retrieved            globally (registry flag)
             Cross-tenant RAG hit              Invalidate vector index    AppSec
             Session cost > ceiling            Kill session               Platform Sec
             Indirect injection detected        Quarantine tool output     AppSec

  SEV-2      Recursion: tool called >20x        Kill user session          Platform Sec
             in same session                   (session_id revoke)
             Scope escalation probe pattern     Temporary block            SecOps
                                               client_id in gateway
             Delegation depth exceeded          Block delegation chain     Platform Sec

  SEV-3      New unregistered tool attempt      Reject + alert             Platform Sec
             CVE in tool image                  Block image digest         SRE
                                               Force redeploy

  ──────────────────────────────────────────────────────────────────────────────
  MASTER KILL SWITCH: "MCP LOCKDOWN MODE"
  ──────────────────────────────────────────────────────────────────────────────
  Action: Gateway rejects all tool calls at Gate 2 regardless of token validity
  How:    Feature flag in gateway config (ConfigMap hot-reload, <30 sec)
  Who:    Any SecOps, SRE, or Platform Sec lead
  When:   Unknown active compromise, suspected supply chain attack,
          confused deputy pattern detected across multiple sessions
  ──────────────────────────────────────────────────────────────────────────────
```

---

## Diagram 7: New Tool Onboarding Path

Every team that wants to add an MCP tool must follow this path. No exceptions.

```text
  TEAM WANTS TO ADD NEW MCP TOOL
             │
             ▼
  ┌──────────────────────────────┐
  │  1. DESIGN REVIEW            │
  │  Submit tool proposal with:  │
  │  - what the tool does        │
  │  - what scope tier needed    │
  │  - egress destinations       │
  │  - secrets required          │
  │  - HITL requirement?         │
  │  - delegation: does it call  │
  │    other tools? (depth)      │
  │  - AI evaluation needed?     │
  │  Owner: Platform Security    │
  └──────────────┬───────────────┘
                 │ approved
                 ▼
  ┌──────────────────────────────┐
  │  2. BUILD REQUIREMENTS       │
  │  - Rootless container        │
  │  - Seccomp + AppArmor        │
  │  - No shell in prod image    │
  │  - SBOM generated            │
  │  - Image signed (Cosign)     │
  │  - Digest pinned in registry │
  │  - Output sanitization hooks │
  │  Owner: Tool Team + AppSec   │
  └──────────────┬───────────────┘
                 │ build done
                 ▼
  ┌──────────────────────────────┐
  │  3. SECURITY SCAN            │
  │  - Vuln scan (Trivy/Grype)   │
  │  - No critical/high CVEs     │
  │  - Secrets scan (Trufflehog) │
  │  - SAST on tool code         │
  │  - MCP security scan         │
  │    (mcpnuke against staging) │
  │  Owner: AppSec (CI gate)     │
  └──────────────┬───────────────┘
                 │ scan clean
                 ▼
  ┌──────────────────────────────┐
  │  4. REGISTRY REGISTRATION    │
  │  - Add entry to tool-        │
  │    registry.yaml             │
  │  - Pin image digest          │
  │  - Define allowed_actions    │
  │  - Define egress_allowlist   │
  │  - Set hitl_required flag    │
  │  - Set max_delegation_depth  │
  │  - Set ai_evaluation_mode    │
  │  - PR review by Platform Sec │
  │  Owner: Platform Security    │
  └──────────────┬───────────────┘
                 │ merged
                 ▼
  ┌──────────────────────────────┐
  │  5. STAGING VALIDATION       │
  │  - Deploy to staging cluster │
  │  - Run MCP inspector tests   │
  │  - Run SSRF regression test  │
  │  - Run scope enforcement test│
  │  - Run exfil rate limit test │
  │  - Run confused deputy test  │
  │    (verify AI deny → block)  │
  │  - Run output injection test │
  │  Owner: Tool Team + SRE      │
  └──────────────┬───────────────┘
                 │ tests pass
                 ▼
  ┌──────────────────────────────┐
  │  6. PROD ROLLOUT             │
  │  - Deploy with canary (10%)  │
  │  - OBS dashboard confirmed   │
  │  - Detection rules active    │
  │  - Kill switch tested        │
  │  - Runbook written + linked  │
  │  Owner: SRE                  │
  └──────────────┬───────────────┘
                 │
                 ▼
           TOOL IS LIVE
```

---

## Golden Path Summary Card

Cut this down to a single-page reference for every team:

```text
  ╔══════════════════════════════════════════════════════════════════╗
  ║         MCP GOLDEN PATH — ONE PAGE REFERENCE                     ║
  ╠══════════════════════════════════════════════════════════════════╣
  ║                                                                  ║
  ║  IDENTITY    Every request carries an Okta JWT.                  ║
  ║              aud MUST be the MCP server URL.                     ║
  ║              Tokens live 15 min. Refresh tokens rotate.          ║
  ║                                                                  ║
  ║  TOOLS       Every tool is registered, signed, digest-pinned.    ║
  ║              Every tool has an explicit egress allowlist.        ║
  ║              Write/delete tools require HITL approval.           ║
  ║              Delegation depth is bounded (default: 3).           ║
  ║                                                                  ║
  ║  AI LAYER    The AI advises. The gates decide.                   ║
  ║              AI verdicts are logged, not trusted for authz.      ║
  ║              AI-deny + tool-grant = confused deputy = P0 alert.  ║
  ║              Tool output is sanitized before reaching the LLM.  ║
  ║                                                                  ║
  ║  NETWORK     Default-deny egress. mTLS everywhere internal.      ║
  ║              SPIFFE IDs are the only intra-cluster identity.     ║
  ║              No direct pod-to-pod. Everything through gateway.   ║
  ║                                                                  ║
  ║  SECRETS     AWS Secrets Manager + IRSA. No env vars.            ║
  ║              Secrets never logged, never forwarded, never in     ║
  ║              LLM context. Token exchange secrets same path.      ║
  ║                                                                  ║
  ║  LIMITS      Per-session call cap, per-tool rate limit,          ║
  ║              cost ceiling per session, recursion depth cap.      ║
  ║              All configurable per tool in registry.              ║
  ║                                                                  ║
  ║  OBSERVE     Every tool call = one structured audit log line     ║
  ║              with ai_verdict, signal_tier, and reason_code.      ║
  ║              Tokens + secrets redacted before shipping.          ║
  ║              Canaries in every tenant's data store.              ║
  ║              Signal tiers: HIGH (P0) / MEDIUM (P1) / LOW.       ║
  ║                                                                  ║
  ║  RESPOND     Kill switches defined and tested before go-live.    ║
  ║              Runbook per tool. Runbook per alert.                ║
  ║              Incident postmortem = new regression test.          ║
  ║              Master lockdown mode: <30 sec to full stop.        ║
  ║                                                                  ║
  ╠══════════════════════════════════════════════════════════════════╣
  ║  DEVIATION FROM THIS PATH REQUIRES SECURITY REVIEW             ║
  ╚══════════════════════════════════════════════════════════════════╝
```

---

## Implementation Timeline

```text
WEEK 1  → Stand up MCP Gateway in staging. Wire to Okta.
          Validate JWT gate (Gate 2) works end-to-end.
          One read-only tool only. No write tools yet.

WEEK 2  → Deploy SPIRE. Enable mTLS between gateway and that one tool.
          Add structured logging with signal_tier field.
          Ship logs to OBS stack.
          Write first three detection rules:
            1. audience mismatch (P0)
            2. SSRF probe (P0)
            3. confused deputy (P0)

WEEK 3  → Tool registry v1. Sign your first tool image with Cosign.
          Add second tool (a write tool). Enable HITL gate.
          Implement Gate 4 (session rate + cost limits).
          Test kill switches in staging. Document the runbook.

WEEK 4  → Prod deploy of the two tools. Canary 10% traffic.
          OBS dashboard live. On-call knows the kill switches.
          Implement output sanitization pipeline (Gate 5 output side).
          Postmortem template ready before anything breaks.

WEEK 5  → Run mcpnuke scan against staging. Map findings to gates.
          Fix any confused-deputy or output-injection findings.
          Implement AI policy evaluation gate (Gate 5, advisory mode).

WEEK 6  → Red team exercise: internal team tries to bypass all 6 gates.
          Update kill switch runbook with findings.
          Enable Gate 5 enforcement mode for high-risk tools.

WEEK 8  → First tool registry rotation. Re-sign all images.
          First quarterly review of detection rule efficacy.
          Onboard third tool using the full onboarding path.

WEEK 10+→ Onboard additional tools using the new tool onboarding path.
          Add step-up auth. Add token exchange for downstream APIs.
          Promote Gate 5 to enforcement mode for all tools.
          Grow from there.
```

The diagrams above are living documents. As you add tools, update the trust map and the kill switch panel first — those are the two most operationally critical artifacts you own.

---

## Testing Your Implementation

For hands-on validation of the attack patterns this golden path defends against:

- **[Camazotz](https://github.com/babywyrm/camazotz)** — MCP security playground with 25 labs covering confused deputy, SSRF, token replay, delegation chain abuse, output injection, and more. Run the labs against your staging gateway to validate gate enforcement.
- **[mcpnuke](https://github.com/babywyrm/mcpnuke)** — automated MCP security scanner. Run against your staging deployment as part of the tool onboarding path (Step 3) and as a recurring regression check.
- **[MCP Security Assessment Framework](https://github.com/babywyrm/mcpnuke/docs/mcp-security-assessment-framework.md)** — vendor-neutral assessment matrix mapping 25 risks to pentest checks with MCP JSON-RPC examples.

---

*Golden Path version: 2.0 — 2026-04-10*
*Mapped to OWASP MCP Top 10 (2025) and MCP Red Team Playbook*
