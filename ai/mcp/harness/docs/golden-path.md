# MCP Security Golden Path

> The minimum-viable security posture for shipping MCP integrations.
> Follow this path and you'll have controls for the OWASP MCP Top 10
> without over-engineering.

## Who This Is For

Teams that are:
- Deploying MCP servers in production (internal or SaaS-facing)
- Building agents that consume MCP tools
- Operating infrastructure where MCP servers have sensitive access

## The Path

### Phase 0: Inventory (Day 1)

```yaml
# mcp-inventory.yaml — track every MCP server in your environment
servers:
  - name: github-mcp
    owner: platform-team
    access_level: write
    data_sensitivity: high
    auth_method: oauth2
    deployed_in: eks-prod
    last_scanned: null

  - name: docs-reader
    owner: ml-team
    access_level: read-only
    data_sensitivity: low
    auth_method: bearer_token
    deployed_in: gke-staging
    last_scanned: null
```

**Action**: Catalog every MCP server. Tag with owner, access level, data sensitivity.

### Phase 1: Static Scan Gate (Week 1)

Add to CI — nothing merges without a clean scan:

```yaml
# .github/workflows/mcp-gate.yml
- uses: your-org/mcp-slayer-action@v1
  with:
    config: .security/slayer-config.yaml
    modules: "token-validation,tool-poisoning,prompt-injection-canary"
    fail-on-critical: "true"
```

**Minimum modules for Phase 1:**
- `token-validation` — catches broken auth before deployment
- `tool-poisoning` — catches hidden instructions in schemas
- `prompt-injection-canary` — catches injectable tool outputs

### Phase 2: Runtime Enforcement (Month 1)

Deploy per-tool auth and basic policy:

```yaml
# opa-policy.rego — deny by default, allow explicitly
package mcp.authz

default allow = false

allow {
    input.caller_identity in data.tool_grants[input.tool_name]
    input.action in data.allowed_actions[input.tool_name]
}
```

**Controls:**
- Per-tool audience binding (no token replay)
- OPA/Cedar policy for tool-call authorization
- Rate limiting on tool invocations (prevent loop abuse)
- Audit logging with `session_id` correlation

### Phase 3: Detection & Response (Month 2)

Wire findings to alerting:

```yaml
# SIEM integration in slayer-config.yaml
siem:
  enabled: true
  type: "splunk"  # or elastic, datadog
  endpoint: "${SIEM_HEC_URL}"
  api_key: "${SIEM_TOKEN}"
  index_name: "mcp_security"
```

**Minimum alert set:**
| Alert | Condition |
|---|---|
| Injection attempt | Prompt Guard quarantine event |
| Auth failure spike | >5 token denials in 60s per agent |
| Tool definition drift | Hash mismatch on scheduled check |
| Exfiltration pattern | Bulk read + external write in same session |

### Phase 4: Purple Team Validation (Quarterly)

Run campaign chains to validate defense-in-depth:

```bash
mcp-slayer campaign --config prod-config.yaml --chain all
```

**Track over time:**
- Detection rate per OWASP category
- MTTD trend (should decrease over time)
- Regressions (previously-caught attacks slipping through)

## Architecture Reference

```
Developer workstation
    │
    ▼ (PR opened)
┌───────────────┐
│  CI Pipeline  │ ← mcp-slayer static scan (fail on CRITICAL)
└───────┬───────┘
        │ (merge)
        ▼
┌───────────────┐
│   Staging     │ ← full module scan + campaign chains
└───────┬───────┘
        │ (promote)
        ▼
┌───────────────────────────────────────────────────┐
│              Production Runtime                     │
│                                                    │
│  Agent → Policy (OPA) → MCP Server → Audit Log   │
│            ↑                ↑            ↓        │
│         Token Auth      Rate Limit     SIEM       │
│                                          ↓        │
│                                       Alerting    │
└───────────────────────────────────────────────────┘
```

## Maturity Levels

| Level | What you have | Risk posture |
|---|---|---|
| 0 | Nothing — MCP servers deployed ad-hoc | Exposed to all OWASP MCP Top 10 |
| 1 | Static scan in CI | Catches tool poisoning and broken auth pre-deploy |
| 2 | Runtime policy + rate limiting | Blocks confused deputy and loop abuse |
| 3 | SIEM + alerting | Detects injection attempts and exfil patterns |
| 4 | Purple team + regression | Validates controls continuously, prevents drift |

## Common Mistakes

- **Trusting AI reasoning as enforcement** — the model's refusal is not a security control
- **Shared tokens across tools** — one compromise = full lateral movement
- **No audit correlation** — individual logs exist but can't trace a chain
- **Static scans without runtime** — you catch the bug but can't stop the exploit
- **Runtime without regression** — you fix once but it comes back next sprint
