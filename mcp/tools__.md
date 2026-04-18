# MCP Security Scanning Tools

> A practitioner-first index of security scanners, guardrails, and research
> tools for the [Model Context Protocol](https://modelcontextprotocol.io/)
> ecosystem — maintained for Red, Blue, and Purple Team use.

MCP servers expand an agent's attack surface dramatically: filesystem access,
code execution, SaaS APIs, cloud infra. New attack classes like **tool
poisoning** and **indirect prompt injection** are no longer theoretical —
they've shown up in real-world MCP server disclosures.

This repo tracks the tools that actually help.

---

## Threat Model

| Threat | Description |
|---|---|
| **Tool / metadata poisoning** | Malicious instructions hidden in tool descriptions, parameter names, or examples — executed by the agent without user awareness |
| **Indirect prompt injection** | Untrusted external content (docs, emails, web pages) becomes agent instructions via MCP tool responses |
| **Tool shadowing / cross-origin escalation** | A malicious tool overrides or mimics a trusted one; unsafe tool composition across origins |
| **Rug pulls / definition drift** | Tool definitions change after trust is established — hash pinning and drift detection are your main controls |
| **Classic AppSec inside MCP servers** | Path traversal, command injection, SSRF, hardcoded secrets — same bugs, new attack surface |
| **Zombie / zero-click agent takeover** | Injected payloads that silently persist across sessions or trigger on specific conversation states |

**Key reading:**
- [Tool Poisoning Attacks — Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCP Attack Vectors — Unit 42 / Palo Alto](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Classic Vulns Meet AI Infra — Endor Labs](https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec)
- [Securing the AI Agent Revolution — Coalition for Secure AI](https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/)

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

The goal here is **proving what can go wrong** before real attackers do.

- **Supply chain triage**: run static scans on every third-party MCP server
  repo/config before connecting it to a privileged agent. Treat it like
  reviewing a new npm dependency.
- **Drift / rug-pull simulation**: verify your org actually detects when a
  "trusted" tool definition changes. Hash-pin a known-good state, mutate it,
  confirm the alert fires.
- **Composition risk mapping**: test toxic tool combinations (e.g. code
  execution + filesystem + outbound HTTP) in a sandbox. Document the blast
  radius and the guardrail requirements to contain it.
- **Control validation**: confirm proxy policies actually block restricted tool
  calls, catch secrets/PII in responses, and flag suspicious patterns — not
  just in theory but against real test cases.

**Deliverable:** a go/no-go gate checklist for MCP server onboarding + a
regression suite of benign test cases that prove enforcement stays on after
updates.

---

### 🔵 Blue Team

Shift left, enforce at runtime, and make sure you can reconstruct what happened.

- **Pre-merge gating**: treat MCP servers as third-party dependencies. Scan
  repos in CI and block merges/releases on high-severity findings (poisoned
  metadata, unsafe configs, hardcoded secrets).
- **Runtime enforcement**: proxy-based policy enforcement between agents and MCP
  servers — log everything, block the high-risk stuff.
- **Drift monitoring**: hash-pin tool definitions at onboarding. Alert on any
  change. This is your primary control against rug pulls.
- **Incident response**: when you suspect injection-driven exfil, you need
  (1) MCP traffic logs, (2) tool definition baselines, (3) a diff of what
  changed and when. Proxy mode is built for this.

**Operational pattern:** `MCP allowlist → baseline → proxy enforcement → egress
controls`. Don't rely on any single layer.

---

### 🟣 Purple Team

Build repeatable exercises and close the loop between detection and engineering.

- **MCP threat lab**: pick 2–3 MCP servers your org actually uses. Run them
  through static scans, then stand up a runtime proxy with enforced policies
  and verify telemetry + alerting fires correctly end-to-end.
- **Agent-native AppSec**: use the AWS sample scanner pattern to embed
  Semgrep/Checkov/Bandit into agent workflows — then verify policies prevent
  risky tool usage even when the agent is instructed to bypass them.
- **Detection engineering inputs**: use published MCP injection research
  (Unit 42, Invariant Labs) to design safe training scenarios. No live exploit
  payloads needed — the published vectors are enough to build detection rules
  against.

---

## Rollout Path

A pragmatic sequence that works for most teams:

```text
1. Inventory   — catalog every MCP server + client config in dev, CI, and prod
2. Baseline    — static scan before onboarding anything new; fail-open only
                 with explicit sign-off
3. Proxy       — runtime enforcement for highest-risk agents (filesystem, repo,
                 cloud admin, SaaS with write access)
4. Drift       — hash-pin tool definitions; alert on any mutation
5. Regression  — Purple Team suite that proves controls survive updates and
                 config changes
```

---

## Recent Incidents

| Date | Summary | Source |
|---|---|---|
| 2026-01 | Three vulnerabilities in Anthropic's official MCP Git server enabled file exfiltration and RCE-class issues | [The Hacker News](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html) · [TechRadar](https://www.techradar.com/pro/security/anthropics-official-git-mcp-server-had-some-worrying-security-flaws-this-is-what-happened-next) |
| 2026-01 | ZombieAgent: zero-click silent account takeover via MCP prompt injection | [TechRadar](https://www.techradar.com/pro/security/this-zombieagent-zero-click-vulnerability-allows-for-silent-account-takeover-heres-what-we-know) |

---

## What "Good" Looks Like

- ✅ Every MCP server scanned **before** it's reachable by a privileged agent
- ✅ Runtime proxy enforcement for sensitive tool categories (files, git, cloud,
  SaaS write)
- ✅ Tool definition drift alerts (hash/pin at onboarding)
- ✅ Egress controls + secret/PII detection in the guardrail layer
- ✅ A repeatable Purple Team regression suite that runs on every update

---

##
##
