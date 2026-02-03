# MCP Security Runbook — Red vs Blue Primer (..beta..)

> **Purpose:** A fast, practical primer for running **authorized** Red/Blue validation cycles on **MCP servers + agent toolchains** (Model Context Protocol).
> **Scope:** discovery → testing → detection/response → hardening → regression.
> **Non-goals:** exploit development, bypass payloads, or instructions that enable real-world abuse.

---

## 1) What each team is trying to prove

### Red Team goals (authorized validation)

* Can untrusted MCP tools/resources **change agent behavior** (tool poisoning, instruction smuggling)?
* Can agent actions be **tricked into exfiltration** (secrets, tokens, sensitive text) or unsafe actions?
* Can tool composition create **confused deputy** outcomes (agent uses a privileged tool due to untrusted input)?
* Can a “trusted” tool change silently (**drift/rug pull**) without detection?
* Can a compromised MCP server or dependency cause **unexpected side effects**?

### Blue Team goals (control assurance)

* Do we have **inventory** and **ownership** for every MCP server and tool?
* Are we enforcing **allowlists** and **least privilege** per agent?
* Do we have **runtime visibility** into tool calls and responses?
* Can we **detect and stop** malicious or anomalous tool usage reliably?
* Can we respond quickly: **who, what, when, which tool, what data**?

---

## 2) Common MCP attack patterns to test (at a safe, non-exploit level)

### A. Tool poisoning

**Idea:** Malicious content in tool metadata (descriptions, examples, param docs) nudges the model into unsafe behavior.
**Red:** Validate if tools with “helpful” but unsafe instructions change outputs/behavior.
**Blue:** Detect metadata changes + enforce policy that tool metadata is not treated as instructions.

### B. Indirect prompt injection

**Idea:** Agent reads untrusted content (repo, ticket, doc) that contains instructions.
**Red:** Confirm the agent can be influenced by untrusted data sources.
**Blue:** Ensure content is labeled untrusted + guardrails prevent it from becoming policy.

### C. Confused deputy / tool chaining

**Idea:** Low-trust input causes high-trust tools to execute actions.
**Red:** Attempt to cause privileged tool use from untrusted sources (without harmful payloads).
**Blue:** Require justification gates, confirmations, and policy checks on sensitive actions.

### D. Drift / rug pull

**Idea:** Tool definitions or servers change after approval.
**Red:** Simulate a “benign” change to tool metadata and verify alerting.
**Blue:** Detect diffs, block unknown versions, require re-approval.

### E. Classic AppSec in MCP servers

**Idea:** MCP servers are still software: authn/authz bugs, path issues, SSRF, injection.
**Red:** Do standard AppSec review + testing in a sandbox.
**Blue:** Apply standard SDLC + SAST/DAST, container hardening, least privilege, logging.

---

## 3) Engagement rules (must-have)

### Safety guardrails for Red Team

* Test **only** in approved environments / sandboxes.
* Use **synthetic secrets** (fake API keys) and **canary tokens** where possible.
* Do not target real production data or real customer environments.
* Maintain a written **stop condition** list (e.g., unexpected privilege escalation, unapproved egress).

### Evidence expectations (for both teams)

* Tool inventory + versions + hashes
* Agent policies in effect (allowlist, deny rules, sensitive actions)
* Full logs of tool calls (request/response metadata; redact sensitive values)
* Clear reproduction steps (safe), timestamps, and outcomes

---

## 4) Pre-flight checklist (Blue leads, Red participates)

### Inventory & baselines

* [ ] List all MCP servers in use (name, repo, owner, environment, purpose)
* [ ] List all tools exposed per server (tool names + input/output schemas)
* [ ] Record versions/commits/images + **hash** tool definitions/configs
* [ ] Define allowed destinations (egress allowlist) for networked tools

### Least privilege

* [ ] Split agents into tiers (low-risk vs privileged)
* [ ] For each agent: allow only the minimal tools required
* [ ] Ensure each MCP server runs with minimal OS/container permissions

### Visibility

* [ ] Central logging for tool calls (structured)
* [ ] Alerts for: unusual tool frequency, denied actions, drift, policy violations
* [ ] “Break glass” kill switch (disable a tool/server quickly)

---

## 5) Execution flow (Red ↔ Blue)

### Phase 1 — Discovery & mapping

**Red does:**

* Document trust boundaries: what is untrusted input vs trusted tools?
* Identify “high-impact” tool categories: filesystem, shell/exec, cloud admin, git, ticketing, email.

**Blue does:**

* Confirm monitoring coverage (do we see every tool call?)
* Confirm enforcement points (can we block actions in-line?)

**Outputs**

* Data flow diagram (agent ↔ MCP servers ↔ resources)
* Tool risk tier list (High / Medium / Low)

---

### Phase 2 — Controlled adversarial testing (safe)

**Red does (examples of safe tests):**

* Confirm whether untrusted content changes agent decisions.
* Try to trigger high-risk tool usage without explicit human approval.
* Attempt to cause “tool chaining” (e.g., read → decide → write) against a sandbox target.

**Blue does:**

* Tune policy rules and confirm blocks/alerts
* Validate logs show the **why** (which input influenced which action)

**Outputs**

* Findings with severity, evidence, and recommended controls
* Updated policies and allowlists

---

### Phase 3 — Detection engineering & response drills

**Red does:**

* Replay test cases to ensure consistent detection
* Provide “expected telemetry” list for each scenario

**Blue does:**

* Create alert rules and dashboards
* Run an IR tabletop: identify → contain → eradicate → recover

**Outputs**

* Detection rules + runbooks
* “Known-good” baseline patterns for normal tool usage

---

### Phase 4 — Hardening & regression

**Both do:**

* Convert findings into controls
* Build a regression suite for every control (tests must stay safe and reproducible)

**Outputs**

* CI gates (scan before deploy)
* Runtime guardrails (proxy/policy)
* Monthly/quarterly re-validation schedule

---

## 6) Recommended controls mapped to common failures

### If you saw: tool poisoning / metadata injection

* Enforce **tool definition pinning** (hash/commit) and alert on diffs
* Treat tool metadata as **untrusted**; do not allow it to override policy
* Require code review for tool schema/description changes

### If you saw: indirect prompt injection from docs/repos/tickets

* Add an “untrusted content” label and strip/ignore instructions
* Require human confirmation on sensitive actions
* Add response filters for secrets/PII

### If you saw: confused deputy / risky chaining

* Require “intent + justification” gates before sensitive tools
* Separate read-only tools from write/exec tools by agent tier
* Enforce explicit allowlist of target resources (paths, repos, APIs)

### If you saw: drift/rug pull

* Automated diffs + approval workflow
* Block unknown tool versions by default
* Runtime “deny by default” until approved

---

## 7) Minimal artifacts to check in (repo structure)

```
/runbooks/
  mcp-red-v-blue-primer.md
  incident-response-mcp.md
/policies/
  allowlists/
  deny-rules/
  tool-risk-tiers.yml
/tests/
  regression/
    safe-scenarios.md
    expected-telemetry.yml
/inventory/
  mcp-servers.md
  tool-baselines/
```

---

## 8) Quick kickoff template (copy/paste)

### Engagement header

* **Environment:** (dev / staging / sandbox)
* **Time window:** (dates)
* **Owners:** (Red lead / Blue lead / platform owner)
* **Stop conditions:** (list)
* **Logging locations:** (links)
* **Kill switch procedure:** (how to disable tool/server)

### Test matrix (starter)

| Scenario                           | Tools involved | Expected Blue signal              | Expected enforcement      |
| ---------------------------------- | -------------- | --------------------------------- | ------------------------- |
| Untrusted content influences agent | (list)         | Alert on policy violation attempt | Block sensitive tool call |
| Tool metadata changes              | (tool)         | Diff alert + approval required    | Block unknown version     |
| Suspicious tool chaining           | (read→write)   | Correlated event trail            | Require confirmation gate |

---

##
##
