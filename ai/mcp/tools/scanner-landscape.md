# MCP Security Scanning Tools

> A practitioner-first index of security scanners, guardrails, and research
> tools for the [Model Context Protocol](https://modelcontextprotocol.io/)
> ecosystem — maintained for Red, Blue, and Purple Team use.
>
> *v2.0 — aligned with Zero-Trust AI Mesh architecture (v0.3)*

MCP servers expand an agent's attack surface dramatically: filesystem access,
code execution, SaaS APIs, cloud infra. New attack classes like **tool
poisoning** and **indirect prompt injection** are no longer theoretical —
they've shown up in real-world MCP server disclosures.

This repo tracks the tools that actually help — and how they map to a
hardened agent architecture.

---

## Threat Model

| Threat | Description | Mesh Layer |
|---|---|---|
| **Tool / metadata poisoning** | Malicious instructions hidden in tool descriptions, parameter names, or examples — executed by the agent without user awareness | Layer 5 — Prompt Guard |
| **Indirect prompt injection** | Untrusted external content (docs, emails, web pages) becomes agent instructions via MCP tool responses | Layer 5 — Prompt Guard |
| **Tool shadowing / cross-origin escalation** | A malicious tool overrides or mimics a trusted one; unsafe tool composition across origins | Layer 1 — Token Isolation (`aud` binding) |
| **Rug pulls / definition drift** | Tool definitions change after trust is established — hash pinning and drift detection are your main controls | Layer 0 — Ingress + external drift monitoring |
| **Classic AppSec inside MCP servers** | Path traversal, command injection, SSRF, hardcoded secrets — same bugs, new attack surface | Layer 3 — OPA + Layer 4 — IAM |
| **Zombie / zero-click agent takeover** | Injected payloads that silently persist across sessions or trigger on specific conversation states | Layer 5 — Prompt Guard + Layer 0 rate limits |
| **Token replay / cross-tool escalation** | Stolen or replayed bot tokens used to reach unintended tools | Layer 1 — JTI store + `aud` binding |
| **Agent loop abuse / fan-out DoS** | Prompt-driven recursive tool calls exhaust resources or amplify blast radius | Layer 0 — Rate limits + loop depth cap |

**Key reading:**
- [Tool Poisoning Attacks — Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCP Attack Vectors — Unit 42 / Palo Alto](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Classic Vulns Meet AI Infra — Endor Labs](https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec)
- [Securing the AI Agent Revolution — Coalition for Secure AI](https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/)

---

## How These Tools Map to the Mesh Architecture

The Zero-Trust AI Mesh (v0.3) provides runtime enforcement. MCP scanning tools
operate **before and alongside** that enforcement layer:

```text
┌─────────────────────────────────────────────────────────────┐
│                     BEFORE ONBOARDING                       │
│  mcp-scan (static) · mcp-scanner · ramparts · aws-sample    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                ZERO-TRUST AI MESH (runtime)                 │
│  Layer 0: Ingress + rate limits                             │
│  Layer 1: Token isolation + JTI store                       │
│  Layer 2: SPIFFE/SPIRE workload identity                    │
│  Layer 3: OPA policy enforcement                            │
│  Layer 4: IRSA / scoped cloud credentials                   │
│  Layer 5: Prompt Guard (injection interception)             │
│  Layer 6: Response sanitization                             │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    RUNTIME ALONGSIDE                        │
│  mcp-scan (proxy mode) · drift monitoring · SIEM alerts     │
└─────────────────────────────────────────────────────────────┘
```

Static scanners are a **pre-onboarding gate**, not a runtime substitute.
Proxy-mode tools complement — but don't replace — the mesh enforcement layers.

---

## Tool Landscape

> Only actively maintained projects are listed. Badges are live.

### mcp-scan — Invariant Labs

[![Stars](https://img.shields.io/github/stars/invariantlabs-ai/mcp-scan?style=flat-square&logo=github)](https://github.com/invariantlabs-ai/mcp-scan)
[![Last Commit](https://img.shields.io/github/last-commit/invariantlabs-ai/mcp-scan?style=flat-square)](https://github.com/invariantlabs-ai/mcp-scan)
[![License](https://img.shields.io/github/license/invariantlabs-ai/mcp-scan?style=flat-square)](https://github.com/invariantlabs-ai/mcp-scan/blob/main/LICENSE)

The most mature MCP-native scanner. Does static analysis of installed MCP
configs (Claude Desktop, Cursor, Windsurf, VS Code) and can run as a
**runtime proxy** to enforce policies, log tool calls, and detect drift.

**Mesh alignment:** Primary tooling for drift detection (Layer 0 complement)
and pre-onboarding static gate. Proxy mode feeds the same audit trail as the
mesh SIEM integration — correlate by `session_id`.

**Best for:** Pre-onboarding static scans + runtime guardrails + drift
detection in one tool.

```bash
# auto-discover and scan all known MCP client configs
uvx mcp-scan@latest

# scan a specific config
uvx mcp-scan@latest ~/.vscode/mcp.json

# proxy mode — runtime monitoring and policy enforcement
uvx mcp-scan@latest proxy
```

---

### MCP Scanner — Cisco AI Defense

[![Stars](https://img.shields.io/github/stars/cisco-ai-defense/mcp-scanner?style=flat-square&logo=github)](https://github.com/cisco-ai-defense/mcp-scanner)
[![Last Commit](https://img.shields.io/github/last-commit/cisco-ai-defense/mcp-scanner?style=flat-square)](https://github.com/cisco-ai-defense/mcp-scanner)
[![License](https://img.shields.io/github/license/cisco-ai-defense/mcp-scanner?style=flat-square)](https://github.com/cisco-ai-defense/mcp-scanner/blob/main/LICENSE)

Multi-engine scanner: YARA rules + LLM-based judgment + vendor inspection API.
Covers tools, prompts, resources, and instructions. Also targets behavioral
analysis of MCP server source code.

**Mesh alignment:** YARA signatures complement the Prompt Guard pattern library
(Layer 5). Export matched patterns into `PromptGuardConfig.scanPatterns` to
unify detection across static and runtime layers.

**Best for:** Orgs wanting multi-signal detection (signature + semantic) and
API-driven integration into CI pipelines.

```bash
pip install mcp-scanner

# scan a local MCP server directory
mcp-scanner scan ./my-mcp-server

# scan a remote MCP server endpoint
mcp-scanner scan --url http://localhost:8080
```

---

### Ramparts — Javelin AI

[![Stars](https://img.shields.io/github/stars/getjavelin/ramparts?style=flat-square&logo=github)](https://github.com/getjavelin/ramparts)
[![Last Commit](https://img.shields.io/github/last-commit/getjavelin/ramparts?style=flat-square)](https://github.com/getjavelin/ramparts)
[![License](https://img.shields.io/github/license/getjavelin/ramparts?style=flat-square)](https://github.com/getjavelin/ramparts/blob/main/LICENSE)

Focused on **indirect attack vectors** and configuration vulnerabilities in MCP
servers. Good complement to mcp-scan for a second-opinion pass before
onboarding.

**Mesh alignment:** Surfaces indirect injection vectors that feed directly into
Prompt Guard (Layer 5) tuning. Ramparts findings → injection pattern library
updates → Prompt Guard `scanPatterns`.

**Best for:** Indirect prompt injection surface mapping + config hardening
checks.

```bash
pip install ramparts

# scan an MCP server for indirect attack vectors
ramparts scan --url http://localhost:8080
```

---

### sample-mcp-security-scanner — AWS Samples

[![Stars](https://img.shields.io/github/stars/aws-samples/sample-mcp-security-scanner?style=flat-square&logo=github)](https://github.com/aws-samples/sample-mcp-security-scanner)
[![Last Commit](https://img.shields.io/github/last-commit/aws-samples/sample-mcp-security-scanner?style=flat-square)](https://github.com/aws-samples/sample-mcp-security-scanner)
[![License](https://img.shields.io/github/license/aws-samples/sample-mcp-security-scanner?style=flat-square)](https://github.com/aws-samples/sample-mcp-security-scanner/blob/main/LICENSE)

A reference implementation that wraps **Checkov + Semgrep + Bandit** as an MCP
server — so AI coding assistants (Amazon Q, Kiro, etc.) can invoke AppSec
scanners natively. More of a pattern than a ready-made product, but an
excellent base for embedding security scanning into agent workflows.

**Mesh alignment:** IaC findings from Checkov feed directly into OPA policy
authoring (Layer 3). If Checkov flags a misconfiguration in your cloud
resources, that's an input to a new Rego rule — close the loop.

**Best for:** Purple Teams building agent-native security toolchains; embedding
IaC + SAST scanning into AI-assisted dev workflows.

---

### mcp-for-security — Cyprox

[![Stars](https://img.shields.io/github/stars/cyproxio/mcp-for-security?style=flat-square&logo=github)](https://github.com/cyproxio/mcp-for-security)
[![Last Commit](https://img.shields.io/github/last-commit/cyproxio/mcp-for-security?style=flat-square)](https://github.com/cyproxio/mcp-for-security)
[![License](https://img.shields.io/github/license/cyproxio/mcp-for-security?style=flat-square)](https://github.com/cyproxio/mcp-for-security/blob/main/LICENSE)

A collection of MCP servers wrapping classic security tools: nmap, ffuf,
sqlmap, and more. **Not a scanner of MCP** — it's a toolkit for building
controlled Purple Team and pentest toolchains on top of MCP.

**Mesh alignment:** Ideal for validating Layer 3 OPA policies and Layer 0 rate
limits under adversarial conditions. Run it in a sandbox mesh and confirm your
`allowed_actions` restrictions and loop depth caps hold against agent-driven
offensive tooling.

**Best for:** Red/Purple Teams building agent-driven pentest workflows in a
controlled lab environment.

> ⚠️ Use only in authorized, isolated environments. These are live offensive
> tools exposed over MCP.

---

### awesome-mcp-security — Puliczek

[![Stars](https://img.shields.io/github/stars/Puliczek/awesome-mcp-security?style=flat-square&logo=github)](https://github.com/Puliczek/awesome-mcp-security)
[![Last Commit](https://img.shields.io/github/last-commit/Puliczek/awesome-mcp-security?style=flat-square)](https://github.com/Puliczek/awesome-mcp-security)

Curated index of MCP security research, tools, writeups, and CVEs. Good
starting point for threat intel and keeping up with the research stream.

**Best for:** Staying current. Bookmark it.

---

## Practical Applications by Team

### 🔴 Red Team

The goal is **proving what can go wrong** before real attackers do — and
specifically stress-testing mesh enforcement layers.

- **Supply chain triage:** static scan every third-party MCP server repo/config
  before connecting it to a privileged agent. Treat it like reviewing a new npm
  dependency. Fail it if mcp-scan or mcp-scanner returns high-severity findings.
- **Drift / rug-pull simulation:** hash-pin a known-good tool definition, mutate
  it, and confirm the alert fires. Then verify that a drifted definition causes
  a token minting failure at Layer 1 — not just a monitoring alert.
- **Composition risk mapping:** test toxic tool combinations (code execution +
  filesystem + outbound HTTP) in a sandbox mesh. Verify that OPA `allowed_actions`
  and `aud` binding actually prevent cross-tool escalation — don't assume it.
- **Prompt injection end-to-end:** craft a payload that a real MCP server
  response could plausibly contain. Confirm Layer 5 Prompt Guard quarantines
  it before it reaches the agent context window. Log the `contentHash` and
  verify it lands in the SIEM.
- **Loop depth abuse:** write a prompt that drives an agent into recursive tool
  calls. Confirm gateway rate limits and OPA `loop_depth_acceptable` both fire
  independently — belt and suspenders.

**Deliverable:** a go/no-go gate checklist for MCP server onboarding + a
regression suite of injection/drift/loop-abuse test cases that prove mesh
enforcement survives updates.

---

### 🔵 Blue Team

Shift left, enforce at runtime, and make sure you can reconstruct what happened.

- **Pre-merge gating:** treat MCP servers as third-party dependencies. Run
  mcp-scan + mcp-scanner in CI. Block merges on high-severity findings.
- **Runtime enforcement:** deploy mcp-scan proxy mode in front of
  high-risk MCP servers (filesystem, git, cloud admin, SaaS write). Its
  logs should feed the same SIEM pipeline as mesh audit events — correlate
  on `session_id` and `request_id`.
- **Drift monitoring:** hash-pin tool definitions at onboarding using mcp-scan
  baselines. Any change triggers a re-scan gate before the server is trusted
  again. This is your primary control against rug pulls.
- **SIEM alert set (minimum viable):**

  | Alert | Signal |
  |---|---|
  | Prompt injection attempt | `prompt_guard.result == "quarantine"` |
  | Token replay | `event: "replay_attempt"` in JTI store logs |
  | OPA denial spike | `opa_decision == "deny"` rate > baseline |
  | Risk score spike | `user_context.risk_score > 0.7` |
  | Loop depth breach | `loop_depth > 8` (warn before hard cap) |
  | Tool definition drift | Hash mismatch on scheduled baseline check |

- **Incident response:** when you suspect injection-driven exfil, you need
  (1) mesh audit logs correlated by `request_id`, (2) tool definition
  baselines from mcp-scan, (3) Prompt Guard `contentHash` of quarantined
  payloads, (4) OPA decision log with `opa_policy_version`. All four exist
  in the v0.3 audit schema.

**Operational pattern:** `MCP allowlist → static scan gate → baseline → proxy
+ mesh enforcement → egress controls → SIEM correlation`. No single layer.

---

### 🟣 Purple Team

Build repeatable exercises and close the loop between detection and engineering.

- **MCP threat lab:** pick 2–3 MCP servers your org actually uses. Run them
  through static scans, then deploy them behind a full mesh (all six layers).
  Fire test injection payloads and verify the complete chain: Prompt Guard
  quarantine → SIEM alert → OPA policy update → regression test added.
- **Pattern pipeline:** Cisco mcp-scanner YARA findings → Ramparts injection
  surface report → Prompt Guard `scanPatterns` update → regression test proving
  the new pattern fires. Ship it as a versioned config change, not a hotfix.
- **OPA policy validation:** use mcp-for-security in an isolated mesh to verify
  that `allowed_actions`, tenant isolation, and `loop_depth_acceptable` rules
  hold against agent-driven offensive tooling. If a rule can be bypassed in the
  lab, it will be bypassed in prod.
- **Detection engineering inputs:** use published MCP injection research
  (Unit 42, Invariant Labs, ZombieAgent writeup) to design safe training
  scenarios. Published vectors are enough to build detection rules — no live
  exploit payloads needed.

---

## Rollout Path

```text
1. Inventory    — catalog every MCP server + client config in dev, CI, and prod
2. Baseline     — static scan (mcp-scan + mcp-scanner) before onboarding
                  anything new; fail-open only with explicit sign-off
3. Mesh         — deploy Zero-Trust AI Mesh (v0.3) for highest-risk agents:
                  filesystem, repo, cloud admin, SaaS write
4. Proxy        — mcp-scan proxy mode for MCP servers not yet behind the mesh;
                  logs fed to the same SIEM pipeline
5. Drift        — hash-pin tool definitions; re-scan gate on any mutation
6. Regression   — Purple Team suite: injection payloads + loop abuse + drift
                  simulation; runs on every mesh or MCP server update
```

---

## Recent Incidents

| Date | Summary | Affected Mesh Layer | Source |
|---|---|---|---|
| 2026-01 | Three vulnerabilities in Anthropic's official MCP Git server enabled file exfiltration and RCE-class issues | Layer 4 (credential scope) + Layer 6 (response sanitization) | [The Hacker News](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html) · [TechRadar](https://www.techradar.com/pro/security/anthropics-official-git-mcp-server-had-some-worrying-security-flaws-this-is-what-happened-next) |
| 2026-01 | ZombieAgent: zero-click silent account takeover via MCP prompt injection | Layer 5 (Prompt Guard) + Layer 0 (session persistence controls) | [TechRadar](https://www.techradar.com/pro/security/this-zombieagent-zero-click-vulnerability-allows-for-silent-account-takeover-heres-what-we-know) |

---

## What "Good" Looks Like

- ✅ Every MCP server statically scanned **before** it's reachable by a privileged agent
- ✅ Zero-Trust AI Mesh (v0.3) enforced for all agents with sensitive tool access
- ✅ Prompt Guard active on every tool response before it reaches the agent context window
- ✅ Tool definition drift alerts (hash/pin at onboarding, re-scan gate on mutation)
- ✅ Runtime proxy enforcement for MCP servers not yet behind the full mesh
- ✅ SIEM alerts on: injection quarantines, token replays, OPA denials, risk spikes, loop depth breaches
- ✅ A repeatable Purple Team regression suite covering injection, drift, loop abuse, and cross-tool escalation — runs on every update

---

*v2.0 changes: threat model expanded with token replay and loop abuse rows + mesh layer mapping; tool entries annotated with mesh alignment; Red/Blue/Purple sections updated with mesh-specific TTPs; SIEM alert table added; incident table annotated with affected layers; rollout path updated to include mesh deployment step.*
