# MCP @ Scale — Golden Path v3

> **Purpose:** This is the single reference document that governs how every MCP integration in our EKS cluster is built, secured, and operated.
> All proposals beneath it are implementation detail. This is the law.

---

## What "Golden Path" Means Here

A golden path is an **opinionated, pre-approved route** that any team can follow to ship an MCP integration without reinventing security decisions. If you follow this path, you are considered compliant. If you deviate, you need a security review.

Four rules that never bend:

```text
RULE 1  Every request carries a user identity. No anonymous tool execution.
RULE 2  Every tool is registered, signed, and scoped. No ad-hoc tools.
RULE 3  Every secret lives in Secrets Manager. No exceptions.
RULE 4  The AI advises. The gates decide. No LLM output is trusted as authorization.
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

## The Master Session Flow

This covers a complete user-initiated MCP session from browser/client to tool execution and back. Read each phase top to bottom.

```text
LAYER        USER DEVICE            OKTA               INTERNET EDGE            EKS CLUSTER
=============================================================================================================

PHASE 0 — BOOTSTRAP (one-time per client install)
-------------------------------------------------------------------------------------------------------------

  [MCP Client]
  Cursor / Claude Code
  / Internal Agent
       |
       |  1. Client starts cold. No token.
       |     Attempts unauthenticated connect.
       |
       |---------------------------------------------------------------------->  [ALB + WAF] --> [MCP Gateway]
       |                                                                                              |
       |                                                                              Returns HTTP 401
       |                                                                              WWW-Authenticate:
       |  2. Client reads protected resource metadata.                                Bearer
       |<---------------------------------------------------------------------  resource_metadata=
       |     /.well-known/oauth-protected-resource                                "/.well-known/opr"
       |     { authorization_servers: ["https://your-org.okta.com"] }
       |
       |  3. Client fetches Okta auth server metadata.
       |-------------------------------------------->  [OKTA]
       |     /.well-known/oauth-authorization-server      |
       |<--------------------------------------------     |
       |     { authorization_endpoint,                    |
       |       token_endpoint,                            |
       |       scopes_supported ... }                     |
       |                                                  |
       |  4. Client is pre-registered (golden path).      |
       |     client_id already exists. Skip DCR.          |
       |     New teams: request to Platform Security.     |


PHASE 1 — USER AUTHENTICATION & CONSENT
-------------------------------------------------------------------------------------------------------------

  [MCP Client] ---------------------------------->  [OKTA]
       |                                              |
       |  5. Authorization Code Grant (PKCE)          |     User sees:
       |     /authorize?                              |     +------------------+
       |       response_type=code                     |     | Okta Login       |
       |       client_id=<pre-registered>             |     | + MFA            |
       |       redirect_uri=https://client.co/cb      |     | + Consent screen |
       |       scope=mcp:read mcp:write               |     +------------------+
       |       code_challenge=<S256>                  |
       |       resource=https://mcp.internal.co       |     RFC 8707 Resource Indicator
       |                                              |     binds token to specific MCP server
       |  6. User authenticates (SSO + MFA).          |
       |     User consents to scopes.                 |
       |     Okta checks group membership.            |
       |     (only eng-sre can consent mcp:admin)     |
       |                                              |
       |  7. Okta redirects with auth code.           |
       |<------------------------------------------   |
       |     /cb?code=AUTH_CODE&state=xyz             |
       |                                              |
       |  8. Client exchanges code for tokens.        |
       |-------------------------------------------->  
       |     POST /token                              |     Okta mints:
       |     { grant_type=authorization_code,         |     +------------------------------+
       |       code=AUTH_CODE,                        |     | access_token (JWT, 15 min)   |
       |       code_verifier=<pkce>,                  |     |   iss: okta.com/oauth2/...    |
       |       resource=https://mcp.internal.co }     |     |   aud: https://mcp.internal   |
       |<------------------------------------------   |     |   sub: user@company.com       |
       |                                              |     |   scp: [mcp:read, mcp:write]  |
       |  Client stores:                              |     |   exp: now + 900s             |
       |  - access_token  (memory only, never disk)  |     | refresh_token (encrypted)     |
       |  - refresh_token (encrypted secure storage) |     +------------------------------+


PHASE 2 — MCP SESSION INITIALIZATION
-------------------------------------------------------------------------------------------------------------

  [MCP Client]                                                             [EKS CLUSTER]
       |
       |  9. Client connects to MCP Gateway (authenticated).
       |---------------------------------------------------------------------->  [ALB+WAF] --> [MCP Gateway]
       |     POST /mcp                                                                              |
       |     Authorization: Bearer <access_token>                                    A. WAF checks:
       |     { method: "initialize",                                                    payload size
       |       params: { capabilities, clientInfo } }                                   schema valid
       |                                                                                rate limit ok
       |                                                                                            |
       |                                                                             B. JWT validation:
       |                                                                                iss == okta ✓
       |                                                                                aud == mcp  ✓
       |                                                                                exp valid   ✓
       |                                                                                sig valid   ✓
       |                                                                                            |
       |                                                                             C. Build session:
       |                                                                                session_id = uuid
       |                                                                                user_sub = JWT.sub
       |                                                                                scopes = JWT.scp
       |                                                                                call_count = 0
       |                                                                                cost_usd = 0.00
       |<----------------------------------------------------------------------                     |
       |     { result: { serverInfo, capabilities } }                                               |
       |     Mcp-Session-Id: <session_id>                                                           |


PHASE 3 — TOOL INVOCATION (the critical path)
-------------------------------------------------------------------------------------------------------------

  [MCP Client]             [MCP Gateway]    [Tool Router]    [Tool Pod]    [AI Brain]
       |                        |                |               |             |
       |  10. User prompt       |                |               |             |
       |      triggers call.    |                |               |             |
       |----------------------->|                |               |             |
       |  tools/call            |                |               |             |
       |  { name: "slack-post", |                |               |             |
       |    arguments: {        | D. Registry    |               |             |
       |      channel: "#ops",  |    lookup:     |               |             |
       |      message: "done" } |    name ✓      |               |             |
       |  }                     |    digest ✓    |               |             |
       |                        |    scope ✓     |               |             |
       |                        |    hitl ✓      |               |             |
       |                        |    depth ✓     |               |             |
       |                        |                |               |             |
       |                        | D'. Session    |               |             |
       |                        |     limits:    |               |             |
       |                        |     calls ✓    |               |             |
       |                        |     rate ✓     |               |             |
       |                        |     cost ✓     |               |             |
       |                        |                |               |             |
       |                        | E. AI policy --+----------------------------->|
       |                        |    evaluation  |               |    LLM evaluates
       |                        |                |               |    request against
       |                        |    ai_verdict: |               |    system prompt.
       |                        |    allow|deny  |               |             |
       |                        |<---------------+-----------------------------+
       |                        |                |               |             |
       |                        | F. Token       |               |             |
       |                        |    exchange    |               |             |
       |                        |    (RFC 8693): |               |             |
       |                        |    user JWT -->|-> Okta        |             |
       |                        |    tool JWT <--|<- Okta        |             |
       |                        |                |               |             |
       |                        | G. mTLS call --|-------------->|             |
       |                        |    SPIFFE ID   |  tool JWT     |             |
       |                        |    verified    |  + arguments  |             |
       |                        |                |               |             |
       |                        |                |    H. Execute:|             |
       |                        |                |       secrets |             |
       |                        |                |       via IRSA|             |
       |                        |                |       call API|             |
       |                        |                |       (egress |             |
       |                        |                |       allowed)|             |
       |                        |                |               |             |
       |                        |                |    I. Output  |             |
       |                        |                |       sanitize|             |
       |                        |                |       secrets |             |
       |                        |                |       strip   |             |
       |                        |                |<--------------|             |
       |                        |                |               |             |
       |                        | J. Audit log:  |               |             |
       |                        |    request_id  |               |             |
       |                        |    session_id  |               |             |
       |                        |    user_sub    |               |             |
       |                        |    tool, action|               |             |
       |                        |    ai_verdict  |               |             |
       |                        |    signal_tier |               |             |
       |                        |    cost_usd    |               |             |
       |<-----------------------|                |               |             |
       |  tools/call result     |                |               |             |
       |  { content: "Posted" } |                |               |             |


PHASE 3b — HITL PATH (write/admin tools)
-------------------------------------------------------------------------------------------------------------

  [MCP Client]                    [MCP Gateway]    [HITL Gate]    [Approver]
       |                               |               |              |
       |  tools/call                   |               |              |
       |  { name: "k8s-helper",        |               |              |
       |    arguments: {               |               |              |
       |      action: "delete_pod" } } |               |              |
       |------------------------------>|               |              |
       |                               | scope ✓       |              |
       |                               | hitl: TRUE    |              |
       |<------------------------------|               |              |
       |  pending: approval_id="xyz"   |----------------------------->|
       |                               |  who, what, why              |
       |                               |               |   APPROVE    |
       |                               |<-----------------------------|
       |                               |  continues E->J              |
       |<------------------------------|               |              |
       |  tools/call result            |               |              |


PHASE 3c — STEP-UP AUTHENTICATION
-------------------------------------------------------------------------------------------------------------

  [MCP Client]                    [MCP Gateway]    [OKTA]
       |                               |              |
       |  tools/call                   |              |
       |  { name: "data-exporter" }    |              |
       |  scope in token: mcp:read     |              |
       |  required: mcp:export         |              |
       |------------------------------>|              |
       |                               |              |
       |<------------------------------|              |
       |  HTTP 403                     |              |
       |  WWW-Authenticate: Bearer     |              |
       |    error="insufficient_scope" |              |
       |    scope="mcp:export"         |              |
       |                               |              |
       |  Client re-runs Phase 1       |              |
       |  with scope=mcp:export -------|------------->|
       |                               |   group ok?  |
       |                               |   YES: token |
       |                               |   NO:  403   |


PHASE 4 — TOKEN REFRESH & REVOCATION
-------------------------------------------------------------------------------------------------------------

  [MCP Client]                                         [MCP Gateway]    [OKTA]
       |                                                    |             |
       |  11. access_token nearing expiry                   |             |
       |      OR client receives 401.                       |             |
       |                                                    |             |
       |  Client silently refreshes:                        |             |
       |-------------------------------------------------------->         |
       |     POST /token                                     |            |
       |     { grant_type=refresh_token,                     |            |
       |       refresh_token=<stored>,                       |            |
       |       resource=https://mcp.internal.co }            |            |
       |<--------------------------------------------------------         |
       |     { new access_token, new refresh_token }         |            |
       |     (rotate both; old refresh invalidated)          |            |
       |     (cached tool-exchange tokens also expire)       |            |
       |                                                     |            |
       |  12. REVOCATION (offboarding / compromise):         |            |
       |      Okta admin revokes user or client.             |            |
       |      Gateway calls introspection on next request.   |            |
       |      Stale JWT rejected even if sig valid.          |            |
       |      Session killed; all tool-exchange tokens void. |            |
       |                                                     |            |
       |  Revocation propagation time:                       |            |
       |    JWT expiry-based: up to 15 min (token TTL)       |            |
       |    Introspection-based: near-instant (<1s)          |            |
       |    Recommendation: introspect on every tool call    |            |
       |    for high-risk tools (mcp:admin, mcp:write).      |            |


PHASE 5 — DETECTION & RESPONSE
-------------------------------------------------------------------------------------------------------------

  [MCP Client]                  [OBS / SIEM]          [Detection]       [SOC]
       |                             |                     |               |
       |  Every tool call emits      |                     |               |
       |  structured log (step J).   |                     |               |
       |                             |                     |               |
       |                        HIGH SIGNAL (P0):          |               |
       |                          AI deny + tool grant     |               |
       |                          (confused deputy)        |               |
       |                          Canary in response       |               |
       |                          Audience mismatch        |               |
       |                          SSRF to 169.254.x.x      |               |
       |                          Pod escape syscall       |               |
       |                          Revoked token used       |               |
       |                                                   |               |
       |                        MEDIUM SIGNAL (P1):        |               |
       |                          Unreviewed grant         |               |
       |                          >50 msgs/min/session     |               |
       |                          Tool called >20x         |               |
       |                          Refresh >3x normal       |               |
       |                          Cost >80% ceiling        |               |
       |                                                   |               |
       |                        LOW SIGNAL:                |               |
       |                          Policy denied (expected) |               |
       |                          Step-up triggered        |               |
       |                          New tool onboarded       |               |
       |                                                   |               |
       |                          HIGH ----------------------->  [PagerDuty]
       |                                                   |      Kill switch
       |                                                   |      Revoke token
       |                                                   |      Lock egress
       |                                                   |      Lockdown mode

=============================================================================================================
```

---

## Diagram 2: Component Trust Map

Who trusts whom, and on what basis. Print this and put it on the wall.

```text
                        TRUST BOUNDARIES
=============================================

[USER]
  |  trusts: Okta login page (SSO/MFA)
  |  is trusted by: Okta (after MFA), MCP Client
  v

[MCP CLIENT]  (Cursor, Claude Code, internal agent)
  |  trusts: Okta-issued JWT (validated via OIDC discovery)
  |  presents: JWT to MCP Gateway
  |  is trusted by: MCP Gateway (only after JWT validation)
  v

[ALB + WAF]
  |  trusts: nothing -- validates schema, size, rate
  |  is trusted by: nobody (just passes valid traffic)
  v

[MCP GATEWAY]
  |  trusts: Okta JWTs (iss + aud + sig + exp + scope)
  |  trusts: SPIFFE SVIDs from SPIRE (mesh identity)
  |  trusts: Tool Registry (signed manifests only)
  |  trusts: AI Brain (for analysis ONLY, never authorization)
  |  does NOT trust: tool output (sanitized before return)
  |  does NOT trust: identity without JWT or SVID
  |  does NOT trust: AI verdicts as authorization
  v

[AI BRAIN / LLM]
  |  trusts: MCP Gateway (prompt + context delivery)
  |  is trusted by: Gateway (advisory analysis ONLY)
  |  does NOT make: authorization decisions (Gates 2/3)
  |  does NOT see: raw secrets (redacted first)
  |  does NOT see: raw tool output (sanitized first)
  |  WARNING: AI may say "deny" while tool says "allow"
  |           -- this IS the confused deputy. Detect it.
  v

[TOOL ROUTER / REGISTRY]
  |  trusts: MCP Gateway (SPIFFE ID only)
  |  trusts: Okta (via token exchange JWT)
  |  does NOT trust: direct calls from any other pod
  v

[TOOL PODS]
  |  trusts: Tool Router (SPIFFE ID, mesh-verified)
  |  trusts: AWS Secrets Manager (IRSA, scoped per pod)
  |  trusts: Downstream APIs (per tool allowlist)
  |  does NOT trust: env vars for secrets
  |  does NOT trust: non-gateway SPIFFE IDs
  |  does NOT invoke: other tools directly
  |     (delegation goes back through gateway with depth check)
  v

[DOWNSTREAM SERVICES]  (Slack, DBs, internal APIs)
  |  trusts: Tool Pod (via tool-scoped exchange JWT)
  |  does NOT trust: original MCP access token (blocked)
```

---

## Diagram 3: The Six Decision Gates

Every tool call passes through exactly six gates in sequence. If any gate fails, the request stops there.

```text
TOOL CALL REQUEST
      |
      v
+---------------------------------------------------+
|  GATE 1: TRANSPORT SECURITY                        |
|                                                    |
|  * TLS/HTTPS valid cert                            |
|  * WAF: payload size within cap                    |
|  * WAF: schema matches MCP spec                    |
|  * WAF: rate limit not exceeded                    |
|                                                    |
|  FAIL --> 400 / 429 / 502                          |
+------------------------+--------------------------+
                         | PASS
                         v
+---------------------------------------------------+
|  GATE 2: IDENTITY & AUTHORIZATION                  |
|                                                    |
|  * JWT in Authorization header                     |
|  * iss == https://your-org.okta.com/oauth2/...     |
|  * aud == https://mcp.internal.yourdomain.com      |
|  * exp not exceeded                                |
|  * sig valid (Okta JWKS, cached + rotated)         |
|  * scope contains required tier for tool           |
|  * client_id is pre-registered                     |
|  * (optional) introspect for high-risk tools       |
|                                                    |
|  FAIL aud/iss/sig --> 401  (alert P0)              |
|  FAIL scope       --> 403  (trigger step-up)       |
|  FAIL revoked     --> 401  (alert P0, kill session)|
+------------------------+--------------------------+
                         | PASS
                         v
+---------------------------------------------------+
|  GATE 3: TOOL GOVERNANCE                           |
|                                                    |
|  * Tool name exists in signed registry             |
|  * Tool version digest matches pinned hash         |
|  * Requested action in tool's allowed_actions      |
|  * Payload within tool's cap                       |
|  * HITL not required (or approval granted)         |
|  * Delegation depth < MAX_DEPTH (default: 3)       |
|                                                    |
|  FAIL unknown tool    --> 404  (alert P1)          |
|  FAIL digest mismatch --> 500  (alert P0 + halt)   |
|  FAIL needs HITL      --> 202  (pending approval)  |
|  FAIL depth exceeded  --> 403  (alert P1 + log)    |
+------------------------+--------------------------+
                         | PASS
                         v
+---------------------------------------------------+
|  GATE 4: SESSION RATE & COST LIMITS                |
|                                                    |
|  * Session call_count < MAX_CALLS (200)            |
|  * Per-tool rate < MAX_PER_TOOL (20/min)           |
|  * Session cost_usd < COST_CEILING ($5)            |
|  * Recursion depth < MAX_RECURSION (5)             |
|                                                    |
|  FAIL rate    --> 429  (alert P2)                  |
|  FAIL cost    --> 402  (alert P1 + notify user)    |
|  FAIL recurse --> 403  (alert P1 + kill session)   |
+------------------------+--------------------------+
                         | PASS
                         v
+---------------------------------------------------+
|  GATE 5: AI POLICY EVALUATION                      |
|                                                    |
|  * LLM evaluates request against system prompt     |
|  * ai_verdict recorded (allow / deny / uncertain)  |
|  * ai_analysis text captured for audit             |
|                                                    |
|  enforcement_mode = "advisory":                    |
|    Log verdict + continue (default during rollout) |
|  enforcement_mode = "enforce":                     |
|    ai_verdict deny --> BLOCK tool execution        |
|                                                    |
|  ALWAYS: ai_deny + tool_grant =                    |
|    emit HIGH signal confused_deputy alert          |
|                                                    |
|  FAIL (enforce) --> 403  (reason: ai_policy)       |
+------------------------+--------------------------+
                         | PASS (or advisory)
                         v
+---------------------------------------------------+
|  GATE 6: WORKLOAD IDENTITY (mTLS / SPIFFE)         |
|                                                    |
|  * mTLS handshake valid                            |
|  * Caller SPIFFE ID ==                             |
|    spiffe://.../ns/mcp-core/sa/agent-gateway       |
|  * Istio AuthorizationPolicy allows caller         |
|  * SPIRE SVID not expired                          |
|                                                    |
|  FAIL --> 403  (alert P0, lateral movement)        |
+------------------------+--------------------------+
                         | ALL SIX GATES PASSED
                         v
              +------------------------+
              |    TOOL EXECUTES       |
              |                        |
              |  -> Output sanitized   |
              |  -> Audit log emitted  |
              |  -> Response returned  |
              +------------------------+
```

---

## Diagram 4: Secrets Flow (No Env Vars, Ever)

```text
AT POD STARTUP                      DURING TOOL EXECUTION
==============                      =====================

[Pod starts]                        [Tool needs Slack token]
     |                                        |
     |  IRSA: pod SA has                     |  Request to
     |  IAM role bound                       |  Secrets Manager
     |  to it                                |  (same IRSA role)
     v                                        v
[AWS STS]                           [Secrets Manager]
     |                                        |
     |  Temporary credentials                |  Returns secret
     |  (never in env vars)                  |  (short TTL, in memory)
     v                                        v
[IRSA creds in pod]                 [Tool holds secret in memory]
[auto-rotated by SDK]               [NOT logged, NOT forwarded]
                                    [Redacted at OBS boundary]

TOKEN EXCHANGE SECRETS
======================
The Okta client secret used for token exchange (Phase 3 step F)
follows the SAME path: Secrets Manager via IRSA. Never in env vars,
never in ConfigMaps, never in gateway code.

WHAT NEVER HAPPENS:
  x  secret in Dockerfile ENV
  x  secret in K8s secret mounted as env var (use CSI driver)
  x  secret in MCP tool arguments
  x  secret in structured logs
  x  secret passed from gateway to tool in request body
  x  secret visible in AI prompt or LLM context window
```

---

## Diagram 5: Output Sanitization Pipeline

Tool output is untrusted. Before it reaches the LLM or the user, it passes through sanitization.

```text
TOOL RESPONSE (raw)
      |
      v
+---------------------------------------------------+
|  STEP 1: SECRET STRIPPING                          |
|                                                    |
|  Scan for patterns:                                |
|    Bearer tokens, API keys, JWTs                   |
|    AWS access keys (AKIA...)                       |
|    Canary strings (CZTZ{...} or custom)            |
|    Secrets Manager ARNs                            |
|                                                    |
|  Action: replace with [REDACTED]                   |
|  Alert: if canary found --> P0 alert               |
+------------------------+--------------------------+
                         |
                         v
+---------------------------------------------------+
|  STEP 2: INJECTION SCAN                            |
|                                                    |
|  Scan for embedded instructions:                   |
|    "ignore previous instructions"                  |
|    "system: you are now..."                        |
|    base64-encoded instruction blocks               |
|    markdown/HTML that could alter rendering        |
|                                                    |
|  Action: flag in audit log, strip if enforce mode  |
|  Alert: P1 if detected (indirect injection)        |
+------------------------+--------------------------+
                         |
                         v
+---------------------------------------------------+
|  STEP 3: SIZE & STRUCTURE                          |
|                                                    |
|  Truncate to MAX_RESPONSE_SIZE (default: 16KB)     |
|  Validate JSON structure (no malformed payloads)   |
|  Strip internal fields (_flags, _debug, _internal) |
|                                                    |
|  Action: truncate + log full response to OBS       |
+------------------------+--------------------------+
                         |
                         v
                SANITIZED RESPONSE
           (safe for LLM context + user)
```

---

## Diagram 6: The Kill Switch Panel

When something goes wrong, your team needs to know exactly what lever to pull. Define these before you go live.

```text
INCIDENT SEVERITY MAP + KILL SWITCHES
======================================================================

SEVERITY  TRIGGER                         KILL SWITCH             OWNER
----------------------------------------------------------------------
SEV-0     Audience mismatch (P0)          Revoke Okta token       SecOps
          SSRF to 169.254.169.254         immediately via API
          Pod escape syscall              Cordon node, kill pod   SRE
          Confused deputy: AI denied,     Kill session + revoke   SecOps
            tool granted sensitive access token + disable tool
          Revoked token still in use      Force introspect +      SecOps
            (revocation gap detected)     kill all user sessions

SEV-1     Exfil: >50 msgs/min            Disable tool globally   PlatSec
          Canary string retrieved         (registry flag)
          Cross-tenant RAG hit            Invalidate vector idx   AppSec
          Session cost > ceiling          Kill session             PlatSec
          Indirect injection detected     Quarantine tool output  AppSec

SEV-2     Tool called >20x in session    Kill user session        PlatSec
          Scope escalation probe          Block client_id         SecOps
          Delegation depth exceeded       Block delegation chain  PlatSec

SEV-3     Unregistered tool attempt       Reject + alert          PlatSec
          CVE in tool image               Block digest, redeploy  SRE

----------------------------------------------------------------------
MASTER KILL SWITCH: "MCP LOCKDOWN MODE"
----------------------------------------------------------------------
Action:  Gateway rejects ALL tool calls at Gate 2 regardless of JWT
How:     Feature flag in ConfigMap (hot-reload, <30 sec)
Who:     Any SecOps, SRE, or Platform Security lead
When:    Unknown active compromise, suspected supply chain attack,
         confused deputy across multiple sessions
----------------------------------------------------------------------
```

---

## Diagram 7: New Tool Onboarding Path

Every team that wants to add an MCP tool must follow this path. No exceptions.

```text
TEAM WANTS TO ADD NEW MCP TOOL
           |
           v
+------------------------------+
|  1. DESIGN REVIEW            |
|                              |
|  Submit proposal with:       |
|  - what the tool does        |
|  - scope tier needed         |
|  - egress destinations       |
|  - secrets required          |
|  - HITL requirement?         |
|  - delegation depth?         |
|  - AI evaluation needed?     |
|                              |
|  Owner: Platform Security    |
+--------------+---------------+
               | approved
               v
+------------------------------+
|  2. BUILD REQUIREMENTS       |
|                              |
|  - Rootless container        |
|  - Seccomp + AppArmor        |
|  - No shell in prod image    |
|  - SBOM generated            |
|  - Image signed (Cosign)     |
|  - Digest pinned in registry |
|  - Output sanitization hooks |
|                              |
|  Owner: Tool Team + AppSec   |
+--------------+---------------+
               | build done
               v
+------------------------------+
|  3. SECURITY SCAN            |
|                              |
|  - Vuln scan (Trivy/Grype)   |
|  - No critical/high CVEs     |
|  - Secrets scan (Trufflehog) |
|  - SAST on tool code         |
|  - MCP security scan         |
|    (mcpnuke against staging) |
|                              |
|  Owner: AppSec (CI gate)     |
+--------------+---------------+
               | scan clean
               v
+------------------------------+
|  4. REGISTRY REGISTRATION    |
|                              |
|  - Add to tool-registry.yaml |
|  - Pin image digest          |
|  - Define allowed_actions    |
|  - Define egress_allowlist   |
|  - Set hitl_required flag    |
|  - Set max_delegation_depth  |
|  - Set ai_evaluation_mode    |
|  - PR review by Platform Sec |
|                              |
|  Owner: Platform Security    |
+--------------+---------------+
               | merged
               v
+------------------------------+
|  5. STAGING VALIDATION       |
|                              |
|  - Deploy to staging cluster |
|  - Run MCP inspector tests   |
|  - Run SSRF regression test  |
|  - Run scope enforcement     |
|  - Run exfil rate limit test |
|  - Run confused deputy test  |
|  - Run output injection test |
|                              |
|  Owner: Tool Team + SRE      |
+--------------+---------------+
               | tests pass
               v
+------------------------------+
|  6. PROD ROLLOUT             |
|                              |
|  - Deploy with canary (10%)  |
|  - OBS dashboard confirmed   |
|  - Detection rules active    |
|  - Kill switch tested        |
|  - Runbook written + linked  |
|                              |
|  Owner: SRE                  |
+--------------+---------------+
               |
               v
         TOOL IS LIVE
```

---

## IDP Degradation & Fallback Strategy

What happens when Okta (or your IdP) is unreachable?

```text
DEGRADATION DECISION TREE
==========================

IdP reachable?
  |
  +-- YES --> Normal operation (all 6 gates active)
  |
  +-- NO  --> FAIL CLOSED (recommended default)
              |
              +-- All tool calls rejected at Gate 2
              +-- /config reports: idp_degraded: true
              +-- Existing sessions with valid cached JWTs:
              |     Option A: Honor until exp (up to 15 min gap)
              |     Option B: Reject immediately (stricter)
              |     Recommendation: Option B for mcp:admin/write
              |                     Option A for mcp:read only
              |
              +-- Alert: P1 "IdP unreachable" to on-call
              +-- Recovery: automatic when IdP returns
              +-- Health check: probe IdP every 10s (TTL cache)

WHY NOT FAIL-OPEN:
  Fail-open means any request without a valid JWT proceeds.
  This violates Rule 1 ("every request carries a user identity").
  The only exception: pre-approved read-only tools can optionally
  operate in "degraded read" mode if explicitly configured per-tool
  in the registry with: degraded_mode: "allow_read".
```

---

## Token Binding: DPoP (Future Hardening)

The current flow uses **bearer tokens** — anyone with the JWT can use it. **DPoP (Demonstrating Proof of Possession)** binds the token to the client's key pair.

```text
WITHOUT DPoP (current):
  Attacker steals JWT --> Attacker can use it from any device

WITH DPoP (hardened):
  Attacker steals JWT --> Useless without client's private key
  Each request includes a DPoP proof signed by client key
  Server validates: JWT + DPoP proof + key binding

IMPLEMENTATION:
  1. Client generates ephemeral key pair at session start
  2. Token request includes DPoP proof header
  3. Okta binds token to key thumbprint (cnf claim)
  4. Every MCP request includes fresh DPoP proof
  5. Gateway validates proof before accepting JWT

STATUS: Not yet required on the golden path.
        Add when: MCP clients support DPoP natively,
        OR when operating in high-risk environments
        where token theft is a demonstrated threat.
```

---

## OWASP MCP Top 10 Mapping

How each golden path gate defends against the [OWASP MCP Top 10 (2025)](https://genai.owasp.org/resource/owasp-model-context-protocol-top-10/):

| OWASP Risk | Description | Gate(s) | Defense |
|------------|-------------|---------|---------|
| MCP-01 | Tool Poisoning | Gate 3 | Signed registry, digest pinning, SBOM |
| MCP-02 | Rug Pull | Gate 3 | Runtime digest verification, manifest pinning |
| MCP-03 | Excessive Permissions | Gates 2, 3 | Scope tiers, per-tool allowed_actions |
| MCP-04 | Server Spoofing | Gates 1, 6 | TLS + mTLS, SPIFFE identity |
| MCP-05 | Unauthorized Access | Gate 2 | JWT validation, scope enforcement, step-up |
| MCP-06 | Data Exfiltration | Gates 4, 5 | Rate limits, egress allowlists, AI eval |
| MCP-07 | Prompt Injection | Gate 5 + Output | AI policy eval + output sanitization |
| MCP-08 | Audit & Telemetry | Phase 5 | Structured logging, signal tiers, OBS |
| MCP-09 | Resource Exhaustion | Gate 4 | Call caps, cost ceilings, recursion limits |
| MCP-10 | Third-Party Risk | Gate 3, Onboarding | Security scan, staging validation |

---

## Camazotz Lab Validation Mapping

Each golden path gate maps to specific [Camazotz](https://github.com/babywyrm/camazotz) labs that demonstrate the vulnerability it defends against:

| Gate / Control | Camazotz Lab | Threat ID | What It Proves |
|----------------|-------------|-----------|----------------|
| Gate 2: Identity | `auth_lab` | MCP-T04 | Token issuance without identity verification |
| Gate 2: Audience | `auth_lab` | MCP-T04 | Token replay across service boundaries |
| Gate 2: Revocation | `revocation_lab` | MCP-T26 | Gap between revoke intent and effect |
| Gate 3: Registry | `tool_lab` | MCP-T03 | Tool mutation after initial vetting |
| Gate 3: HITL | `hallucination_lab` | MCP-T10 | Destructive ops without confirmation |
| Gate 3: Delegation | `delegation_chain_lab` | MCP-T25 | Unbounded delegation depth |
| Gate 4: Rate limits | `cost_exhaustion_lab` | MCP-T27 | Cost misattribution and exhaustion |
| Gate 5: AI policy | `config_lab` | MCP-T09 | System prompt tampering |
| Gate 5: Confused deputy | `context_lab` | MCP-T01 | Injected directives treated as instructions |
| Gate 6: Network | `egress_lab` | MCP-T06 | SSRF to metadata and internal services |
| Output sanitization | `secrets_lab` | MCP-T07 | Credentials in tool responses |
| Output sanitization | `indirect_lab` | MCP-T02 | Injected payloads from external content |
| Audit logging | `audit_lab` | MCP-T13 | Service account masking real actor |
| Secrets flow | `credential_broker_lab` | MCP-T23 | Cross-team credential theft |
| Token exchange | `oauth_delegation_lab` | MCP-T21 | Stolen refresh token replay |
| RBAC | `rbac_lab` | MCP-T20 | Group prefix injection bypass |
| Trust boundaries | `tenant_lab` | MCP-T11 | Cross-tenant memory access |
| Exfiltration | `comms_lab` | MCP-T12 | Multi-step data exfiltration chain |
| Pattern downgrade | `pattern_downgrade_lab` | MCP-T24 | Auth downgrade via capability override |
| Temporal drift | `temporal_lab` | MCP-T16 | Config values changing mid-session |
| Attribution | `attribution_lab` | MCP-T22 | Forged execution context |
| Notifications | `notification_lab` | MCP-T17 | Malicious server-initiated payloads |
| Error disclosure | `error_lab` | MCP-T15 | Secrets in tracebacks and debug info |
| Webhooks | `shadow_lab` | MCP-T14 | Persistent exfiltration via webhooks |

Run `mcpnuke` against your staging gateway to validate that your gate implementations actually block these attack patterns.

---

## Golden Path Summary Card

Cut this down to a single-page reference for every team:

```text
+==================================================================+
|         MCP GOLDEN PATH -- ONE PAGE REFERENCE                    |
+==================================================================+
|                                                                  |
|  IDENTITY   Every request carries an Okta JWT.                   |
|             aud MUST be the MCP server URL.                      |
|             Tokens live 15 min. Refresh tokens rotate.           |
|             Revoked tokens caught via introspection.             |
|                                                                  |
|  TOOLS      Every tool: registered, signed, digest-pinned.       |
|             Every tool has an explicit egress allowlist.         |
|             Write/delete tools require HITL approval.            |
|             Delegation depth bounded (default: 3).               |
|                                                                  |
|  AI LAYER   The AI advises. The gates decide.                    |
|             AI verdicts logged, not trusted for authz.           |
|             AI-deny + tool-grant = confused deputy = P0.         |
|             Tool output sanitized before reaching LLM.           |
|                                                                  |
|  NETWORK    Default-deny egress. mTLS everywhere internal.       |
|             SPIFFE IDs are the only intra-cluster identity.      |
|             No direct pod-to-pod. Everything through gateway.    |
|                                                                  |
|  SECRETS    AWS Secrets Manager + IRSA. No env vars.             |
|             Secrets never logged, forwarded, or in LLM context.  |
|             Token exchange secrets follow the same path.         |
|                                                                  |
|  LIMITS     Per-session call cap, per-tool rate limit,           |
|             cost ceiling, recursion depth cap.                   |
|             All configurable per tool in registry.               |
|                                                                  |
|  OBSERVE    Every tool call = one structured audit log line      |
|             with ai_verdict, signal_tier, reason_code.           |
|             Tokens + secrets redacted before shipping.           |
|             Canaries in every tenant data store.                 |
|             Signal tiers: HIGH (P0) / MEDIUM (P1) / LOW.         |
|                                                                  |
|  RESPOND    Kill switches defined and tested before go-live.     |
|             Runbook per tool. Runbook per alert.                 |
|             Incident postmortem = new regression test.           |
|             Master lockdown mode: <30 sec to full stop.          |
|                                                                  |
|  DEGRADE    IdP down = fail closed (default).                    |
|             Read-only degraded mode: opt-in per tool.            |
|             DPoP token binding: future hardening path.           |
|                                                                  |
+==================================================================+
|  DEVIATION FROM THIS PATH REQUIRES SECURITY REVIEW               |
+==================================================================+
```

---

## Implementation Timeline

```text
WEEK 1    Stand up MCP Gateway in staging. Wire to Okta.
          Validate JWT gate (Gate 2) end-to-end.
          One read-only tool only. No write tools yet.

WEEK 2    Deploy SPIRE. Enable mTLS gateway <-> tool.
          Structured logging with signal_tier field.
          Ship logs to OBS stack.
          Write first three detection rules:
            1. audience mismatch (P0)
            2. SSRF probe (P0)
            3. confused deputy (P0)

WEEK 3    Tool registry v1. Sign first image with Cosign.
          Add second tool (write). Enable HITL gate.
          Implement Gate 4 (session rate + cost limits).
          Test kill switches in staging. Document runbook.

WEEK 4    Prod deploy (two tools). Canary 10% traffic.
          OBS dashboard live. On-call knows kill switches.
          Output sanitization pipeline (Gate 5 output).
          Postmortem template ready.

WEEK 5    mcpnuke scan against staging. Map findings to gates.
          Fix confused-deputy and output-injection findings.
          AI policy evaluation gate (Gate 5, advisory mode).
          Add introspection for mcp:admin tools (revocation).

WEEK 6    Red team exercise: bypass all 6 gates.
          Update kill switch runbook with findings.
          Gate 5 enforcement mode for high-risk tools.

WEEK 8    First tool registry rotation. Re-sign all images.
          Quarterly detection rule efficacy review.
          Onboard third tool using full onboarding path.

WEEK 10+  Add step-up auth. Token exchange for downstream.
          Evaluate DPoP for high-risk tool paths.
          Gate 5 enforcement mode for all tools.
          Grow from there.
```

The diagrams above are living documents. As you add tools, update the trust map and the kill switch panel first — those are the two most operationally critical artifacts you own.

---

## Standards Referenced

| Standard | Where Used |
|----------|-----------|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 Authorization Framework (Phase 1) |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE (Phase 1, step 5) |
| [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) | Token Exchange (Phase 3, step F) |
| [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) | Resource Indicators (Phase 1, step 5) |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | DPoP (future hardening) |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token Introspection (Phase 4, revocation) |
| [SPIFFE](https://spiffe.io/) | Workload identity (Gate 6) |
| [MCP Spec 2025-03-26](https://modelcontextprotocol.io/) | Streamable HTTP transport, session management |

---

## Testing Your Implementation

For hands-on validation of the attack patterns this golden path defends against:

- **[Camazotz](https://github.com/babywyrm/camazotz)** — MCP security playground with 25 labs covering every threat in the mapping table above. The `/identity` dashboard shows live ZITADEL integration status. Run the labs against your staging gateway to validate gate enforcement.
- **[mcpnuke](https://github.com/babywyrm/mcpnuke)** — automated MCP security scanner. Run against your staging deployment as part of the tool onboarding path (Step 3) and as a recurring regression check.
- **[MCP Security Assessment Framework](https://github.com/babywyrm/mcpnuke/docs/mcp-security-assessment-framework.md)** — vendor-neutral assessment matrix mapping 25 risks to pentest checks with MCP JSON-RPC examples.

---

*Golden Path version: 3.0 — 2026-04-12*
*Mapped to OWASP MCP Top 10 (2025) and MCP Red Team Playbook*
