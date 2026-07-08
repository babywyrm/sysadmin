# Campaign Runner — Multi-Stage Attack Chain Orchestration

> Single-module tests find individual vulnerabilities.
> Campaigns validate defense-in-depth by chaining vulnerabilities the way a real attacker would.

## Overview

The campaign runner orchestrates **multi-stage attack chains** by sequencing
existing MCP-SLAYER modules into realistic attack workflows. Each stage gates
on the previous — if a defense blocks one stage, the campaign can halt (proving
defense-in-depth) or continue (measuring detection coverage across the full chain).

This mirrors how real adversaries operate: initial access leads to lateral
movement, which enables privilege escalation, which enables exfiltration.
Testing individual modules in isolation misses the compounding risk.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Campaign Definition (YAML)                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │ Stage 1 │→ │ Stage 2 │→ │ Stage 3 │→ │ Stage N │       │
│  │ module  │  │ module  │  │ module  │  │ module  │       │
│  │ gate    │  │ gate    │  │ gate    │  │ gate    │       │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │
└─────────────────────────────────────────────────────────────┘
         │              │              │
         ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Campaign Runner Engine                     │
│  • Sequential stage execution                                │
│  • Gate logic (stop_on_block / continue_always / stop_on_vuln)│
│  • Dependency resolution                                     │
│  • Finding propagation between stages                        │
│  • ABRS blast radius scoring                                 │
│  • Kill switch integration                                   │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Campaign Result                            │
│  • Per-stage outcomes + findings                             │
│  • Detection rate across chain                               │
│  • ABRS score + risk level                                   │
│  • Halt point (which defense stopped the chain)              │
└─────────────────────────────────────────────────────────────┘
```

## Usage

### List available campaigns

```bash
mcp-slayer campaign --list
```

### Run a specific chain

```bash
mcp-slayer campaign --config slayer-config.yaml --chain chain-1-semantic-drift-exfil
```

### Run all built-in chains

```bash
mcp-slayer campaign --config slayer-config.yaml --chain all
```

### Run a custom campaign file

```bash
mcp-slayer campaign --config slayer-config.yaml --chain-file ./my-campaign.yaml
```

## Built-in Campaigns

| Chain | Name | Stages | Domain | Kill Chain |
|---|---|---|---|---|
| 1 | Semantic Drift → DNS Exfil | 5 | A+B+E | initial_access → execution → lateral → exfil |
| 2 | RAG Poisoning → Persistence | 4 | B+C+F | initial_access → persistence → privesc → impact |
| 3 | Supply Chain → Token Replay | 4 | D | supply_chain → execution → privesc → exfil |
| 4 | Alert Fatigue → Exfil | 4 | E | defense_evasion → collection → exfil |
| 5 | Agentic Ransomware | 5 | B+C | privesc → collection → impact → persistence |

## Campaign Definition Format

Campaigns are defined in YAML:

```yaml
id: my-campaign
name: "Human-Readable Name"
description: "What this campaign validates"

# ABRS parameters
abrs_reachable_agents: 3
abrs_avg_tool_scope: 2.5
abrs_memory_persistence_days: 7
abrs_isolation_boundaries: 2

success_conditions:
  - "Condition 1 for campaign success"
  - "Condition 2"

blue_team_gates:
  - "What defenses should catch this"

stages:
  - id: stage-1
    module: prompt-injection-canary  # Must exist in MODULE_REGISTRY
    action: "What this stage does"
    taxonomy_ids: ["MCP-T01", "MCP-T02"]
    gate: stop_on_block  # or: continue_always, stop_on_vuln

  - id: stage-2
    module: exfiltration-routing
    action: "Leverages stage-1 foothold"
    depends_on: [stage-1]       # Only runs if stage-1 was VULNERABLE
    inject_from_prior: true     # Receives stage-1 findings as context
    gate: continue_always
```

## Gate Logic

| Gate | Behavior |
|---|---|
| `stop_on_block` | Halt campaign if this stage's attack is blocked (validates defense-in-depth) |
| `continue_always` | Always proceed regardless of outcome (measures full-chain detection coverage) |
| `stop_on_vuln` | Halt if this stage succeeds (useful for "should not be possible" assertions) |

## Dependency Resolution

Stages can declare `depends_on: [stage-id-1, stage-id-2]`. A stage only runs if
**all** its dependencies resulted in `VULNERABLE` or `PARTIALLY_VULNERABLE`. If
a dependency was blocked, errored, or skipped, the dependent stage is skipped.

This models realistic attacker behavior: you can't exfiltrate via DNS if you
never gained injection access.

## Finding Propagation

When `inject_from_prior: true`, findings from earlier stages are passed to the
current stage's module as `injected_context`. This enables realistic chaining
where output from stage N feeds stage N+1 — credentials discovered in stage 1
become the authentication material for stage 2's confused deputy attack.

## ABRS — Agentic Blast Radius Score

Traditional CVSS fails to capture agentic propagation. ABRS measures compound
risk when a campaign succeeds:

$$
\text{ABRS} = \frac{R_a \times \bar{S}_t \times D_m}{I_b}
$$

| Variable | Description |
|---|---|
| R_a | Reachable agents from initial compromise |
| S_t | Average tool scope breadth (1=read-only, 5=admin+write+external) |
| D_m | Memory persistence in days (min 1.0 for stateless) |
| I_b | Isolation boundary count (segments, trust zones, approval gates) |

| ABRS Score | Risk Level |
|---|---|
| < 5 | Contained |
| 5–20 | Elevated |
| 20–100 | Critical |
| > 100 | Systemic |

## Writing Custom Campaigns

1. Identify the attack chain you want to validate
2. Map each stage to an existing MCP-SLAYER module
3. Define dependency relationships (which stages require prior success)
4. Set gate logic based on your validation goal
5. Add ABRS parameters based on your target architecture

See the built-in chains in `mcp_slayer/campaign/chains/` for reference
implementations based on the Red Team Playbook v3.1.

## Integration with Purple Team

Campaign results include detection metrics:
- **Detection rate**: What percentage of stages fired alerts
- **Halt point**: Which defense-in-depth layer stopped the chain
- **Per-stage timing**: How long each attack took (correlates with MTTD)

These feed directly into the Phase 3 purple team automation pipeline for
continuous validation of defense effectiveness.
