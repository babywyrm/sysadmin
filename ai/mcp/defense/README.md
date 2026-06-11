# MCP Blue Team Defense

The defensive counterpart to the red team playbook and MCP-SLAYER harness.
Covers prevention, detection, response, and continuous validation for MCP and
agent architectures.

---

## Layout

| File | Purpose |
|---|---|
| `blue-team-structure.md` | Full defensive operating model, MCP-SHIELD modules, control matrix, reference architecture |
| `detection-catalog.md` | High-signal detection rules with pseudo-logic, severity, and taxonomy mapping |
| `detection-templates.md` | Production-ready Splunk SPL + Elastic KQL queries for all 14 detections |
| `incident-response.md` | IR playbooks for MCP-specific incidents (injection, exfil, config tamper, SSRF) |
| `kill-switch-automation.md` | Executable triggers, scripts, webhook specs, and drill schedule for all 8 kill switches |
| `controls-traceability.md` | Maps MCP-T01–T14 to controls, detections, IR, owners — with CVSS prioritization |

---

## How This Connects

```text
RED TEAM PLAYBOOK              TAXONOMY BRIDGE              BLUE TEAM DEFENSE
(redteam/readme.md)            (harness/taxonomy.py)        (defense/)
                                                            
MCP-T01 Prompt Injection ──────── MCP06 ─────────────────► Guardrail Module
MCP-T03 Confused Deputy  ──────── MCP02 ─────────────────► Identity Module
MCP-T06 SSRF via Tool    ──────── MCP05 ─────────────────► Network Module
MCP-T08 Supply Chain     ──────── MCP04 ─────────────────► Toolchain Module
MCP-T12 Exfiltration     ──────── MCP10 ─────────────────► Data Module
...                                                         ...

Every red team finding should map to a defensive control.
Every defensive control should be testable via the harness.
```

---

## Maturity Targets

| Capability | Current | Next Milestone |
|---|---|---|
| Operating model defined | Done | — |
| Control matrix (14 risks) | Done | — |
| CVSS risk prioritization | Done (P0–P3 bands) | — |
| Telemetry requirements | Done | — |
| High-signal detections | 14 rules (full catalog) | — |
| Detection templates (SPL + KQL) | Done (all 14) | Add saved searches / alert configs |
| Kill switches defined | Done | — |
| Kill switch automation | Done (8 scripts + webhook) | Wire to SIEM alert actions |
| Regression test catalog | 14 scenarios | Wire into MCP-SLAYER harness |
| IR playbooks | 5 full playbooks | Add supply chain + DoS playbooks |
| Controls traceability | Done (full matrix) | — |

---

## Quick Reference

### Core Principle

> Treat MCP tools, tool inputs, tool outputs, retrieved documents, and agent
> memory as untrusted input. Treat tool execution as production code execution.

### MCP-SHIELD Modules

1. **Guardrail** — Prompt injection, context integrity, instruction hijacking
2. **Identity** — Confused deputy, token replay, audience binding
3. **Toolchain** — Tool poisoning, supply chain, manifest integrity
4. **Network** — SSRF, egress control, metadata blocking, DNS
5. **Runtime** — Pod security, resource DoS, loop guards, sandboxing
6. **Data** — Exfiltration, tenant isolation, DLP, secret redaction
