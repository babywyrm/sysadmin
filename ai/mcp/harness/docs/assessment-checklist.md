# MCP Security Assessment Checklist

> Structured checklist for conducting MCP security assessments.
> Use as a pre-deployment gate, periodic review, or incident-driven audit.

## Instructions

1. Complete each section relevant to your deployment
2. Mark items as PASS / FAIL / N/A / DEFERRED
3. Any FAIL in a CRITICAL row blocks deployment
4. DEFERRED items require a tracking ticket with remediation timeline

---

## 1. Identity & Access Control

| # | Check | Severity | Status |
|---|---|---|---|
| 1.1 | Each MCP tool has a distinct service identity (not shared credentials) | CRITICAL | |
| 1.2 | Tokens include `aud` claim bound to specific tool/service | CRITICAL | |
| 1.3 | Token expiry is ≤ 1 hour for privileged tools | HIGH | |
| 1.4 | Token replay detection implemented (JTI store or equivalent) | HIGH | |
| 1.5 | Scope is minimally granted per tool (principle of least privilege) | HIGH | |
| 1.6 | Service-to-service auth uses mTLS or equivalent workload identity | MEDIUM | |
| 1.7 | Human-to-agent delegation uses scoped, time-limited grants | MEDIUM | |

## 2. Tool Schema Integrity

| # | Check | Severity | Status |
|---|---|---|---|
| 2.1 | Tool descriptions scanned for hidden instructions (tool poisoning) | CRITICAL | |
| 2.2 | Tool schemas pinned by hash at onboarding | HIGH | |
| 2.3 | Schema drift detected and gates re-deployment | HIGH | |
| 2.4 | Tool parameter names validated against injection patterns | MEDIUM | |
| 2.5 | Hidden fields (x-agent-hint, default values) reviewed for instructions | MEDIUM | |

## 3. Prompt Injection Defense

| # | Check | Severity | Status |
|---|---|---|---|
| 3.1 | Tool outputs labeled as untrusted before entering agent context | CRITICAL | |
| 3.2 | Output classifiers (Prompt Guard or equivalent) active on tool responses | HIGH | |
| 3.3 | RAG-retrieved content tagged with provenance and trust level | HIGH | |
| 3.4 | User content vs. system instructions clearly delineated in context | MEDIUM | |
| 3.5 | Canary tokens planted in sensitive content surfaces for leak detection | MEDIUM | |

## 4. Command Execution & Data Access

| # | Check | Severity | Status |
|---|---|---|---|
| 4.1 | File system access restricted to explicit allowlisted paths | CRITICAL | |
| 4.2 | Command execution uses allowlist, not blocklist | CRITICAL | |
| 4.3 | Network egress restricted (no unrestricted outbound from MCP servers) | HIGH | |
| 4.4 | Database queries parameterized (no agent-constructed raw SQL) | HIGH | |
| 4.5 | Secrets are never returned in tool output plaintext | HIGH | |
| 4.6 | SSRF protections prevent internal metadata/service access | HIGH | |

## 5. Rate Limiting & Abuse Prevention

| # | Check | Severity | Status |
|---|---|---|---|
| 5.1 | Per-agent rate limits on tool invocations | HIGH | |
| 5.2 | Recursive/nested tool call depth capped | HIGH | |
| 5.3 | Fan-out limits on multi-tool composition | MEDIUM | |
| 5.4 | Token budget limits per session/user | MEDIUM | |
| 5.5 | Alert on anomalous tool invocation patterns | MEDIUM | |

## 6. Audit & Observability

| # | Check | Severity | Status |
|---|---|---|---|
| 6.1 | Every tool invocation logged (caller, tool, action, params hash, result status) | CRITICAL | |
| 6.2 | Logs include session_id for end-to-end correlation | HIGH | |
| 6.3 | Audit logs are immutable (attacker cannot suppress/modify) | HIGH | |
| 6.4 | Log pipeline handles load without dropping security events | HIGH | |
| 6.5 | SIEM alerts configured for injection, replay, denial spikes, drift | MEDIUM | |
| 6.6 | Purple team exercises validate detection coverage quarterly | MEDIUM | |

## 7. Supply Chain & Deployment

| # | Check | Severity | Status |
|---|---|---|---|
| 7.1 | MCP server images built from pinned, verified dependencies | HIGH | |
| 7.2 | No ambient credentials in build environment | HIGH | |
| 7.3 | Container images scanned before deployment | MEDIUM | |
| 7.4 | Deployment manifests reviewed for capability escalation | MEDIUM | |
| 7.5 | Shadow/unauthorized MCP servers detected via service discovery | MEDIUM | |

## 8. Multi-Agent & Delegation

| # | Check | Severity | Status |
|---|---|---|---|
| 8.1 | Agent-to-agent delegation uses scoped, per-hop tokens (OBO) | HIGH | |
| 8.2 | Delegation chain depth is bounded | MEDIUM | |
| 8.3 | Cross-agent message integrity verified (signed payloads) | MEDIUM | |
| 8.4 | Sub-agents cannot escalate beyond parent's scope | HIGH | |

---

## Scoring

| Total CRITICAL passes | Readiness |
|---|---|
| All (8/8) | Deploy-ready |
| 6-7 / 8 | Deploy with compensating controls + tracking tickets |
| < 6 / 8 | Block deployment — remediate first |

---

## Automation

Run the automated portion via MCP-SLAYER:

```bash
# Covers checks: 1.1-1.4, 2.1, 3.1, 4.4-4.6, 5.1-5.2, 6.1
mcp-slayer --config assessment-config.yaml --authorized \
    --modules all --output-formats json,sarif
```

Manual review required for: 2.2-2.5, 3.4, 4.1-4.3, 6.3-6.4, 7.x, 8.x.
