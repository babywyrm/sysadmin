# MCP Security Scanning Tools — README (Red/Blue/Purple Team)

This README is a **living index** of security scanners and guardrail tools built for (or commonly used with) the **Model Context Protocol (MCP)** ecosystem—plus **practical ways to apply each** from a Red/Blue/Purple Team perspective.

Why it matters: MCP servers expand an agent’s power surface (filesystem, code, SaaS, infra) and introduce new attack patterns like **tool poisoning** and **indirect prompt injection**. Recent disclosures around real-world MCP servers show these risks are not theoretical. ([The Hacker News][1])

---

## Threats these tools typically cover

* **Tool poisoning / metadata poisoning** (malicious instructions hidden in tool descriptions, params, examples) ([invariantlabs.ai][2])
* **Indirect prompt injection** (untrusted content becomes “instructions” to the agent) ([Unit 42][3])
* **Cross-tool / cross-origin escalation** (tool shadowing, unsafe composition) ([GitHub][4])
* **Rug pulls / drift** (tool definitions change after you trust them; hash/pin/monitor) ([GitHub][4])
* **Classic AppSec bugs inside MCP servers** (path traversal, command/arg injection, SSRF) ([endorlabs.com][5])

---

## Tool landscape: MCP-first scanners & guardrails

| Tool                                | Type                 | What it’s best at                                                                           | Notes                                                                                                                                               |
| ----------------------------------- | -------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **mcp-scan** (Invariant)            | CLI + proxy          | Static scanning + **runtime proxy guardrails** (monitor/log/enforce policies)               | Scans installed MCP configs (Claude/Cursor/Windsurf, etc.) and can proxy traffic to enforce guardrails, detect drift, and log safely. ([GitHub][4]) |
| **MCP Scanner** (Cisco)             | CLI / SDK / API      | Multi-engine scanning (YARA + LLM-judge + vendor inspection API) + behavioral code scanning | Designed to scan tools/prompts/resources/instructions; also aims at source/behavioral analysis of MCP server code. ([GitHub][6])                    |
| **Ramparts** (Javelin / Highflame)  | Scanner              | “Indirect attack vector” + config vuln scanning                                             | Positioned as scanning MCP servers for indirect vectors and config/security issues. ([GitHub][7])                                                   |
| **MCPScan.ai**                      | Web service          | Repo/config scanning + “tool metadata scanner”                                              | Web UI flow for scanning MCP server repos and tool definitions (LLM classifier approach described). ([mcpscan.ai][8])                               |
| **Secure-Hulk**                     | Scanner + reporting  | Config scanning + HTML report                                                               | Focus on prompt injection, tool poisoning, cross-origin escalation, exfil, toxic flows; generates HTML report. ([GitHub][9])                        |
| **mcp-watch**                       | Scanner              | Research-driven detection ideas (e.g., parameter injection, steganographic tricks)          | Aims to detect novel MCP attack vectors (including “conversation exfiltration trigger phrases”). ([GitHub][10])                                     |
| **AWS sample MCP security scanner** | MCP server (pattern) | Turn existing scanners into MCP tools for AI assistants                                     | Implements an MCP server that wraps **Checkov + Semgrep + Bandit** for code/IaC scanning in AI workflows. ([GitHub][11])                            |

**Extra (useful adjacent project):**

* **mcp-for-security** is not a “scanner of MCP” so much as a **collection of MCP servers for security tools** (nmap/ffuf/sqlmap/etc.)—useful for building controlled Purple Team toolchains, but you’ll still want “scanner/guardrail” layers above it. ([GitHub][12])

---

## Practical applications by team

### Red Team uses (authorized testing / adversarial validation)

Use these tools to **prove what can go wrong** before real attackers do—without turning this into exploit instructions.

* **Supply chain triage of third-party MCP servers**: run static scans on any MCP server repo/config before connecting it to a privileged agent. (mcp-scan, Cisco MCP Scanner, MCPScan.ai) ([GitHub][4])
* **Drift/rug-pull simulation**: validate that your org detects when a “trusted” tool definition changes (hash pinning / change alerts). (mcp-scan proxy) ([GitHub][4])
* **Composition risk mapping**: test “toxic combinations” (e.g., a code tool + filesystem tool) in a sandbox and document guardrail requirements. Real-world reports highlight how chaining can create serious outcomes. ([The Hacker News][1])
* **Control validation**: confirm that proxy policies actually block restricted tool calls, secrets/PII leakage paths, or suspicious response patterns. (mcp-scan proxy guardrails) ([GitHub][4])

**Deliverable:** a “go/no-go” gate checklist for MCP onboarding + a regression suite of *benign* test cases that ensure policy enforcement stays on.

---

### Blue Team uses (prevention, monitoring, response)

* **Pre-merge gating**: treat MCP servers as third-party dependencies—scan repos and block merges/releases on high-risk findings (poisoned tool metadata, unsafe configs). ([GitHub][4])
* **Runtime enforcement**: put a policy layer between agents and MCP servers (proxy-based monitoring/logging + enforcement). ([GitHub][4])
* **Continuous drift monitoring**: alert if tool definitions change unexpectedly (hashing/pinning) to catch “rug pulls.” ([GitHub][4])
* **Incident response for agents**: when you suspect prompt-injection-driven exfil, you want (1) MCP traffic logs, (2) tool definition baselines, (3) diff of tool changes. Proxy modes are built for this style of visibility. ([GitHub][4])

**Operational pattern:** “MCP allowlist + baseline + proxy + egress controls” (don’t rely on just one layer). ([Coalition for Secure AI][13])

---

### Purple Team uses (repeatable exercises + detection engineering)

* **Build an MCP threat lab**: pick 2–3 MCP servers you rely on, run them through static scans, then run runtime proxy with enforced policies and confirm telemetry + alerting triggers. ([GitHub][4])
* **Turn classical AppSec into agent security**: use the AWS sample MCP server approach to embed Semgrep/Checkov/Bandit feedback into agent workflows—then verify policies prevent risky tool usage even when the agent “wants to.” ([GitHub][11])
* **Exercise design inputs**: leverage public research on MCP prompt-injection vectors to create safe training scenarios and validations (no exploit payloads needed). ([Unit 42][3])

---

## Suggested rollout path (pragmatic)

1. **Inventory** every MCP server and client config in use (dev + CI + prod agents).
2. **Baseline & scan** (static) before onboarding anything new.
3. **Proxy & enforce** at runtime for the highest-risk agents (filesystem / repo access / SaaS admin).
4. **Drift detection** (hash pinning) + alerting.
5. **Purple Team regression suite** that proves controls keep working after updates.

This matches the direction many vendors/researchers recommend: treat MCP servers like real software supply chain and AppSec targets, not “just plugins.” ([endorlabs.com][5])

---

## Quickstart snippets (defender-oriented)

### mcp-scan (static scan + proxy)

From the project README: a quick run can discover and scan common MCP configs; proxy mode adds continuous monitoring/guardrails. ([GitHub][4])

```bash
# one-shot scan (auto-discovers common MCP client configs)
uvx mcp-scan@latest

# scan a specific MCP config file
mcp-scan ~/.vscode/mcp.json

# proxy mode (runtime monitoring/guardrails)
mcp-scan proxy
```

### AWS sample MCP security scanner (MCP server wrapping scanners)

This project demonstrates an MCP server that exposes **Checkov + Semgrep + Bandit** scanning through a single interface so AI assistants can request scans in a standardized way. ([GitHub][11])

---

## What “good” looks like (minimum bar)

* ✅ All MCP servers/toolsets scanned **before** they’re reachable by privileged agents
* ✅ Runtime enforcement for sensitive tools (files, git, cloud admin, ticketing)
* ✅ Tool definition drift alerts (hash/pin)
* ✅ Egress controls + secret/PII detection in the guardrail layer
* ✅ A repeatable Purple Team regression suite

---

## Appendix: research & ecosystem indexes

* **awesome-mcp-security** (curated links) ([GitHub][14])
* **mcpverified security tools list** ([mcpverified.com][15])

---

### Recent incidents & why you should care

* [TechRadar](https://www.techradar.com/pro/security/anthropics-official-git-mcp-server-had-some-worrying-security-flaws-this-is-what-happened-next?utm_source=chatgpt.com)
* [TechRadar](https://www.techradar.com/pro/security/this-zombieagent-zero-click-vulnerability-allows-for-silent-account-takeover-heres-what-we-know?utm_source=chatgpt.com)

---

##
##

[1]: https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html?utm_source=chatgpt.com "Three Flaws in Anthropic MCP Git Server Enable File ..."
[2]: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks?utm_source=chatgpt.com "MCP Security Notification: Tool Poisoning Attacks"
[3]: https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/?utm_source=chatgpt.com "New Prompt Injection Attack Vectors Through MCP Sampling"
[4]: https://github.com/invariantlabs-ai/mcp-scan "GitHub - invariantlabs-ai/mcp-scan: Constrain, log and scan your MCP connections for security vulnerabilities."
[5]: https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec?utm_source=chatgpt.com "Classic Vulnerabilities Meet AI Infrastructure: Why MCP ..."
[6]: https://github.com/cisco-ai-defense/mcp-scanner "GitHub - cisco-ai-defense/mcp-scanner: Scan MCP servers for potential threats & security findings."
[7]: https://github.com/getjavelin/ramparts "GitHub - highflame-ai/ramparts: mcp scan that scans any mcp server for indirect attack vectors and security or configuration vulnerabilities"
[8]: https://mcpscan.ai/?utm_source=chatgpt.com "mcpscan.ai - MCP Security Scanner"
[9]: https://github.com/AppiumTestDistribution/secure-hulk "GitHub - AppiumTestDistribution/secure-hulk: Secure-Hulk is a security scanner for Model Context Protocol (MCP) servers and tools. It helps identify potential security vulnerabilities in MCP configurations, such as prompt injection, tool poisoning, cross-origin escalation, data exfiltration, and toxic agent flows."
[10]: https://github.com/kapilduraphe/mcp-watch "GitHub - kapilduraphe/mcp-watch: A comprehensive security scanner for Model Context Protocol (MCP) servers that detects vulnerabilities and security issues in your MCP server implementations."
[11]: https://github.com/aws-samples/sample-mcp-security-scanner "GitHub - aws-samples/sample-mcp-security-scanner: This pattern describes how to implement a Model Context Protocol (MCP) server that integrates three industry-standard security scanning tools (Checkov, Semgrep, and Bandit) to provide comprehensive code security analysis. The server enables AI coding assistants like Kiro and Amazon Q Developer to automatically scan code snippets."
[12]: https://github.com/cyproxio/mcp-for-security?utm_source=chatgpt.com "cyproxio/mcp-for-security"
[13]: https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/?utm_source=chatgpt.com "Securing the AI Agent Revolution: A Practical Guide to ..."
[14]: https://github.com/Puliczek/awesome-mcp-security?utm_source=chatgpt.com "Puliczek/awesome-mcp-security"
[15]: https://mcpverified.com/security/tools?utm_source=chatgpt.com "MCP Security Tools"
