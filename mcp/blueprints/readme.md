## Proposal 1: Identity & Auth Architecture (Okta-Centric)

### Okta as the Authorization Server

The MCP spec's OAuth 2.1 requirements map cleanly onto Okta. Here's the binding:

| MCP OAuth Role | Okta Component |
|---|---|
| Authorization Server | Okta Custom Auth Server |
| Resource Server | Your MCP Gateway |
| Dynamic Client Reg | Okta API + DCR or pre-registration |
| JWKS / token validation | Okta's `/keys` endpoint |
| Scopes | Okta Custom Scopes per tool group |

### Scope Design for Dozens of Tools

Don't create one scope per tool. Group by impact tier:

```text
mcp:read          → query/search tools (safe, low blast radius)
mcp:write         → Slack post, DB write, file create
mcp:delete        → destructive ops
mcp:admin         → K8s helper, IAM tools, config changes
mcp:internal      → cross-service agent-to-agent calls
```

Then Okta policies enforce which users/groups can consent to which scopes. Map your Okta groups (e.g., `eng-platform`, `sre`, `readonly`) to scope allowlists via Okta authorization policies.

### Client Registration Strategy

Given you control the environment (internal EKS, known clients):

- **Pre-register** MCP clients in Okta (avoid DCR complexity in prod)
- Each MCP client (e.g., Cursor, Claude Code, internal agent) gets its **own OAuth client ID** — never share
- For agent-to-agent (server-to-server) flows, use **Okta Client Credentials** with a machine-to-machine app and scoped down service accounts
- Pin `redirect_uris` to known values; reject wildcards at Okta policy level

### Token Binding

Okta-issued tokens must be validated at the MCP Gateway for:

```text
iss   → your Okta org URL
aud   → your MCP server URL (use RFC 8707 resource param)
scope → must include required tier for the tool being called
exp   → enforce short TTL (15–60 min), use refresh tokens
```

Reject anything that doesn't have the MCP server URL as audience. This is your confused deputy defense.

---

## Proposal 2: EKS Architecture — Components & Responsibilities

```text
┌─────────────────────────────────────────────────────┐
│                   OKTA (Identity Plane)             │
│  Auth Server → issues JWT access tokens + refresh  │
│  Groups → scope policies → client registrations    │
└─────────────────────┬───────────────────────────────┘
                      │ HTTPS / OIDC discovery
                      ▼
┌─────────────────────────────────────────────────────┐
│            EKS CLUSTER                              │
│                                                     │
│  [ALB + WAF]                                        │
│    → TLS termination, rate limits, geo blocks       │
│    → Route to MCP Gateway only                      │
│                                                     │
│  [MCP Agent Gateway] (your "Tool Router")           │
│    → Validates Okta JWT (iss/aud/scope/exp)         │
│    → SPIFFE/SVID mTLS to all downstream tools       │
│    → Tool registry + allowlist enforcement          │
│    → HITL gate for write/delete scopes              │
│    → Per-tool rate limits + payload caps            │
│    → Structured audit logging to OBS stack          │
│                                                     │
│  [Tool Pods] (one deployment per tool or group)     │
│    → Rootless, seccomp, read-only FS                │
│    → IRSA with least-privilege IAM role             │
│    → Egress via allowlist only                      │
│    → Fetch proxy for any URL-fetching tools         │
│    → Secrets via AWS Secrets Manager (not env vars) │
│                                                     │
│  [SPIRE Server + Agent DaemonSet]                   │
│    → Workload identity for all pod-to-pod mTLS      │
│                                                     │
│  [OBS Stack] (Fluent Bit → S3/CloudWatch/SIEM)      │
│    → Redact tokens/secrets before shipping          │
└─────────────────────────────────────────────────────┘
```

---

## Proposal 3: MCP Gateway — The Critical Component

This is your enforcement chokepoint. It needs to do all of the following:

### Token Validation (per request)

```python
# Pseudocode — validate every inbound MCP request
def validate_request(token, tool_name, action):
    claims = verify_jwt(
        token,
        jwks_uri="https://your-org.okta.com/keys",
        expected_iss="https://your-org.okta.com",
        expected_aud="https://mcp.internal.yourdomain.com"
    )
    
    required_scope = TOOL_SCOPE_MAP[tool_name][action]
    if required_scope not in claims["scp"]:
        raise HTTP403(
            error="insufficient_scope",
            scope=required_scope  # triggers step-up auth
        )
    
    return claims  # pass user context downstream
```

### Tool Registry (enforced at gateway)

```yaml
# tool-registry.yaml — every tool must be registered + signed
tools:
  - name: slack-post
    version: "1.2.3"
    image_digest: "sha256:abc123..."
    required_scope: mcp:write
    allowed_actions: [post_message, list_channels]
    egress_allowlist: ["hooks.slack.com"]
    hitl_required: false
    payload_cap_bytes: 4096

  - name: k8s-helper
    version: "0.9.1"
    image_digest: "sha256:def456..."
    required_scope: mcp:admin
    allowed_actions: [get_pods, get_logs]  # no apply/delete without HITL
    egress_allowlist: ["kubernetes.default.svc"]
    hitl_required: true  # any write op
    payload_cap_bytes: 16384
```

### Downstream Token Propagation (Token Exchange)

For tools that call other OAuth-protected internal APIs, use **RFC 8693 Token Exchange**:

```text
MCP Gateway receives Okta access token
  → calls Okta token endpoint with:
      grant_type=urn:ietf:params:oauth:grant-type:token-exchange
      subject_token=<original Okta token>
      resource=https://internal-api.yourdomain.com
  → Okta issues new token scoped to that resource
  → Tool uses the exchanged token for downstream API calls

This preserves user identity end-to-end without token passthrough.
```

**Do not pass the original MCP token directly to downstream services.** The spec prohibits it, and it creates confused deputy vulnerabilities.

---

## Proposal 4: SPIFFE/SPIRE for Internal mTLS

With dozens of tools, managing per-service certs manually is unscalable. SPIRE solves this.

### SPIFFE ID scheme

```text
spiffe://yourdomain.internal/ns/mcp-tools/sa/slack-tool
spiffe://yourdomain.internal/ns/mcp-tools/sa/k8s-helper
spiffe://yourdomain.internal/ns/mcp-core/sa/agent-gateway
```

### Istio AuthorizationPolicy (enforce at mesh layer)

```yaml
# Only the MCP gateway can call tools — nothing else
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: tool-access-policy
  namespace: mcp-tools
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
          - "cluster.local/ns/mcp-core/sa/agent-gateway"
```

This means even if something else in your cluster is compromised, it cannot call MCP tools directly — the mesh rejects it.

---

## Proposal 5: Egress Hardening (SSRF + Exfil Defense)

With dozens of tools, uncontrolled egress is your biggest risk.

### Network Policy — default deny, allowlist per tool

```yaml
# Default deny all egress for tool namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: mcp-tools
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress: []
---
# Slack tool — only hooks.slack.com:443
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: slack-tool-egress
  namespace: mcp-tools
spec:
  podSelector:
    matchLabels:
      app: slack-tool
  policyTypes: [Egress]
  egress:
  - ports: [{port: 443, protocol: TCP}]
    to: [{ipBlock: {cidr: "<resolved slack IP>/32"}}]
```

### URL-Fetching Tools — Mandatory Proxy

Any tool that fetches arbitrary URLs (browser tool, fetch tool) **must** go through a hardening proxy:

```text
Tool → [Squid/custom SSRF proxy] → external
                 ↓ blocks:
          169.254.169.254 (IMDS)
          10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
          internal EKS service endpoints
          DNS rebinding attempts
```

---

## Proposal 6: Secrets Management

Never put secrets in environment variables for MCP servers. With Okta + AWS:

```text
Pattern:
  1. Tool pod has IRSA role with minimal Secrets Manager permissions
  2. At startup, fetches secret by ARN (not by name — pin the ARN)
  3. Short-lived: cache in memory, refresh before expiry
  4. Gateway redacts Authorization headers from all logs

Okta API tokens for the MCP gateway:
  → Store in Secrets Manager
  → Rotate via Lambda + Secrets Manager rotation
  → IRSA policy scoped to that one secret ARN only
```

---

## Proposal 7: Observability & Detection

### Must-log fields on every MCP tool execution

```json
{
  "request_id": "uuid",
  "session_id": "uuid",
  "user_sub": "okta|abc123",
  "okta_client_id": "0oa...",
  "tool_name": "slack-post",
  "tool_version": "1.2.3",
  "action": "post_message",
  "scopes_presented": ["mcp:write"],
  "auth_decision": "allow",
  "egress_dest": "hooks.slack.com",
  "payload_bytes": 312,
  "duration_ms": 145,
  "spiffe_caller": "spiffe://yourdomain.internal/ns/mcp-core/sa/agent-gateway"
}
```

### Top detection rules to implement first

| Priority | Detection | Signal |
|---|---|---|
| P0 | SSRF to IMDS | Any request to `169.254.169.254` |
| P0 | Audience mismatch | JWT `aud` != MCP server URL |
| P1 | Token in logs | Regex: `Bearer [A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+` |
| P1 | Recursion/loop | Same session calling same tool >N times in <60s |
| P1 | Exfil via Slack | Slack tool posting >X messages/min |
| P2 | Cross-tenant RAG | Vector DB query returning records with wrong tenant_id |
| P2 | Scope escalation probe | Repeated 403s with different scope values |

---

## Proposal 8: Phased Rollout Plan

Given the scope of this, don't try to ship everything at once:

### Phase 1 — Foundation (Weeks 1–4)
- [ ] Pre-register all MCP clients in Okta with correct scopes
- [ ] Deploy MCP Gateway with JWT validation (iss/aud/scope/exp)
- [ ] Default-deny egress NetworkPolicies, allowlist per tool
- [ ] Secrets Manager for all tool credentials (no env vars)
- [ ] Structured audit logging with token redaction

### Phase 2 — Hardening (Weeks 5–8)
- [ ] SPIRE deployment + mTLS between gateway and tools
- [ ] Tool registry with signed manifests + digest pinning
- [ ] SSRF proxy for URL-fetching tools
- [ ] HITL gate for `mcp:write` and `mcp:admin` scopes
- [ ] Detection rules live in SIEM

### Phase 3 — Advanced (Weeks 9–12)
- [ ] RFC 8693 Token Exchange for downstream APIs
- [ ] Step-up auth (403 + scope negotiation) for sensitive tools
- [ ] Client credentials flow for agent-to-agent tools
- [ ] Canary docs/strings per tenant in vector DB
- [ ] Kill-switch runbooks tested in staging

---

## Key Risks to Resolve Before Going Live

1. **Do you have one Okta auth server or multiple?** — Matters for audience binding across tools
2. **Are any tools multi-tenant?** — RAG/vector isolation needs tenant_id filters from day one, not retroactively
3. **What's your HITL mechanism?** — Slack approval bot? Manual review queue? Define it before enabling write tools
4. **Who owns tool registry approvals?** — Needs a clear owner or it becomes a rubber stamp

