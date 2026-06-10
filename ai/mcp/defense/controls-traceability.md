# Controls Traceability Matrix

Maps every red team threat (MCP-T01–T14) to specific defensive controls,
detection rules, IR playbooks, responsible owners, and validation methods.

This is the central reference for answering: "If the red team exploits X, does
the blue team have coverage for X?"

---

## Full Matrix

| Threat ID | Threat | Shield Module | Key Controls | Detection | IR Playbook | Validation |
|---|---|---|---|---|---|---|
| MCP-T01 | Prompt Injection via Tool Output | Guardrail | Output sanitization; untrusted-content labels; allowlisted actions | D07 | IR-01 | Inject known payloads via tool output; verify agent ignores them |
| MCP-T02 | Indirect Prompt Injection (Content) | Guardrail | Separate system/user/retrieved content planes; instruction stripping | D07 | IR-01 | Plant instruction in document; verify no tool execution |
| MCP-T03 | Context Poisoning / Rug-Pull | Guardrail | Session integrity checks; context hash validation; replay detection | D07, D10 | IR-01 | Modify context mid-session; verify session terminates |
| MCP-T04 | Confused Deputy / Token Replay | Identity | Audience binding; per-tool tokens; JTI validation | D01, D09 | IR-02 | Replay token to wrong tool; verify 403 |
| MCP-T05 | Privilege Escalation via Scope | Identity | Least-privilege scopes; step-up auth; HITL for destructive ops | D01, D11 | IR-02 | Request action outside granted scope; verify rejection |
| MCP-T06 | SSRF via Tool | Network | Fetch proxy; egress allowlist; metadata IP blocks; resolved-IP check | D02, D12 | IR-05 | Request metadata IP via various encodings; verify block |
| MCP-T07 | Credential Leakage | Data | Redaction at every boundary; DLP gates; secret scanning | D04 | IR-03 | Inject credential into tool output; verify redaction |
| MCP-T08 | Supply Chain via Content | Toolchain | Signed manifests; digest pinning; SBOM; provenance | D08, D14 | — | Register unsigned tool; verify rejection |
| MCP-T09 | Agent Config Tampering | Toolchain | Read-only config; branch protection; drift detection | D10 | IR-04 | Attempt config write; verify deny |
| MCP-T10 | Resource DoS / Loop Abuse | Runtime | Loop guards; concurrency caps; cost budgets; recursion limits | D06, D11 | — | Trigger infinite loop; verify session kill |
| MCP-T11 | Cross-Tenant Data Leakage | Data | Mandatory tenant filters; canary documents; session partitioning | D05 | IR-03 | Query with wrong tenant_id; verify empty result + alert |
| MCP-T12 | Data Exfiltration (Slow Drip) | Data | Rate limits; payload caps; DLP; per-session volume caps | D03, D05 | IR-03 | Send N messages in window; verify rate-limit trigger |
| MCP-T13 | Audit Evasion | Identity | Mandatory attribution fields; structured logging; completeness checks | D13 | — | Drop user_id from request; verify log flag |
| MCP-T14 | Persistent Callback / Backdoor | Toolchain | Callback allowlists; registration approval; webhook audit | D14 | IR-04 | Register unapproved webhook; verify block |

---

## Coverage Analysis

### Controls by Shield Module

```text
Guardrail  → T01, T02, T03
Identity   → T04, T05, T13
Toolchain  → T08, T09, T14
Network    → T06
Runtime    → T10
Data       → T07, T11, T12
```

### Gaps and Open Items

| Gap | Status | Priority |
|---|---|---|
| MCP-T08: No automated provenance verification in CI | Open | P1 |
| MCP-T13: Log completeness monitoring not implemented | Open | P2 |
| MCP-T14: Callback allowlist not centrally managed | Open | P2 |
| IR playbook for supply chain compromise (MCP-T08) | Not started | P2 |
| IR playbook for resource DoS (MCP-T10) | Not started | P3 |
| Automated purple team regression for all 14 threats | In progress (harness) | P1 |

---

## Ownership

| Shield Module | Control Owner | Detection Owner | IR Owner |
|---|---|---|---|
| Guardrail | AppSec / Agent Security | Detection Engineering | IR + AppSec |
| Identity | Platform Security | Detection Engineering | IR + Platform |
| Toolchain | Platform Security | Detection Engineering | IR + Platform |
| Network | SRE / Infrastructure | Detection Engineering | IR + SRE |
| Runtime | SRE / Infrastructure | Detection Engineering | IR + SRE |
| Data | AppSec / Agent Security | Detection Engineering | IR + AppSec |

---

## Validation Cadence

| Activity | Frequency | Owner |
|---|---|---|
| Regression tests (14 scenarios) | Every deploy (CI) | AppSec |
| Purple team exercise (selected threats) | Monthly | Red + Blue |
| Full MCP-SLAYER assessment | Quarterly | Red Team |
| Canary verification | Continuous | Detection Engineering |
| IR playbook tabletop | Quarterly | IR |
| Kill switch drill | Monthly | Platform Security |
| Detection rule review | After each incident | Detection Engineering |
