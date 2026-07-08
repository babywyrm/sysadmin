# MCP Security Research Roadmap

> **Status:** Active | **Last updated:** 2026-06-12 | **Owner:** Security Research

---

## Vision

Build the most complete open research archive for securing Model Context
Protocol deployments — covering architecture, offensive testing, defensive
operations, and reusable tooling — so that any team shipping MCP integrations
can adopt proven patterns instead of learning through incidents.

---

## Current Maturity

| Area | Docs | Tooling | Tests | Status |
|---|---|---|---|---|
| Architecture | 3 reference designs (generic, AWS, EKS) | — | — | Strong |
| Red Team Playbook | v2.1 stable + v3.1 RC | MCP-SLAYER v3.1 packaged | 48 passing | Strong |
| Scenarios | 7 field scenarios + mermaid diagrams | — | — | Strong |
| Assessment Framework | v1 + v3 matrices | — | — | Medium |
| Defense / Blue Team | Operating model, detections (14+SPL/KQL), IR (5), kill switch automation (8), CVSS scoring | — | — | Strong |
| Scanner Landscape | v2 index with mesh alignment | — | — | Medium |
| Golden Path | v3 full session flow | — | — | Strong |
| Taxonomy Bridge | MCP-T01–T14 ↔ OWASP MCP01–10 | `mcp_slayer.taxonomy` | 8 tests | Strong |
| Harness (MCP-SLAYER) | Engine + campaign + property testing | 17 modules, campaign runner (5 chains), property-based payloads, SARIF/JSON/YAML/MD | 127 tests | Phase 2 complete |
| Keycloak/IdP | SPEC + client | — | — | Thin |
| Llama/Local Models | Config examples | — | — | Thin |
| RFC/Proposals | EKS hardening standard | — | — | Thin |
| Runbooks | v2.0 red-vs-blue (1260 lines) | — | — | Medium |

---

## Progress at a Glance

```mermaid
flowchart LR
    P1["Phase 1<br/>Foundation Hardening<br/>✓ complete"]:::done
    P2["Phase 2<br/>Harness Expansion<br/>✓ complete"]:::done
    P3["Phase 3<br/> Purple Team Automation<br/>✓ complete"]:::done
    P4["Phase 4<br/>Ecosystem Integration<br/>◐ next"]:::active
    P1 --> P2 --> P3 --> P4

    classDef done fill:#1f7a1f,stroke:#0d3d0d,color:#ffffff
    classDef active fill:#b58900,stroke:#5c4500,color:#ffffff
    classDef todo fill:#444444,stroke:#222222,color:#dddddd
```

**Phase 2 internals** — complete. All modules, campaign runner, and
property-based testing are shipped:

```mermaid
flowchart TB
    subgraph shipped["Shipped — 17 modules + campaign runner"]
        direction TB
        M1["token-validation · MCP01"]:::done
        M2["confused-deputy · MCP02"]:::done
        M3["tool-poisoning · MCP03"]:::done
        M4["ssrf-metadata · MCP05"]:::done
        M5["dos-recursion · MCP-T10"]:::done
        M6["prompt-injection-canary · MCP06"]:::done
        M7["audit-evasion · MCP08"]:::done
        M8["shadow-server · MCP09"]:::done
        M9["context-leakage · MCP10"]:::done
        M10["exfiltration-routing · MCP10"]:::done
        M11["secrets-in-tool-output · MCP-T07"]:::done
        M12["agent-config-tampering · MCP-T09"]:::done
        M13["hallucination-destruction · MCP-T10"]:::done
        M14["blocklist-bypass · MCP-T44"]:::done
        M15["rag-pipeline-injection · MCP-T39"]:::done
        M16["governance-gate-bypass · MCP-T41"]:::done
        M17["transport-identity · MCP-T45–T49"]:::done
        CR["campaign runner<br/>5 built-in chains · ABRS scoring"]:::done
    end
    classDef done fill:#1f7a1f,stroke:#0d3d0d,color:#ffffff
```

---

## Roadmap Phases

### Phase 1 — Foundation Hardening (current)

**Goal:** Make the existing research usable without tribal knowledge.

- [x] Package MCP-SLAYER as installable `uv` project
- [x] Unify config schemas (v1 + v3 → canonical v3.1)
- [x] Build taxonomy bridge (playbook ↔ OWASP ↔ harness)
- [x] Expand defense/ with detection rule templates (14 rules in detection-catalog.md)
- [x] Add IR playbooks for MCP incidents (5 playbooks in incident-response.md)
- [x] Create controls-to-findings traceability matrix (controls-traceability.md)
- [x] Clean up thin subdirs (keycloak, llama, inference) with proper READMEs

### Phase 2 — Harness Expansion

**Goal:** Cover the full OWASP MCP Top 10 with runnable modules.

- [x] Module: prompt-injection-canary (MCP06, MCP-T01/T02)
- [x] Module: context-leakage (MCP10, MCP-T05/T11)
- [x] Module: tool-poisoning (MCP03, MCP-T08)
- [x] Module: token-validation (MCP01, MCP-T04)
- [x] Module: audit-evasion (MCP08, MCP-T13)
- [x] Module: exfiltration-routing (MCP10, MCP-T12)
- [x] Module: dos-recursion (MCP-T10, loop depth)
- [x] Campaign runner (multi-stage chain orchestration — 5 built-in chains, ABRS scoring)
- [x] Property-based testing for payload generation (5 generators, 16 mutation operators, shrinking engine)

### Phase 2b — Extended Taxonomy & Gap Modules ✓

**Goal:** Fill T01–T14 gaps and add extended T37–T49 attack classes.

- [x] Module: secrets-in-tool-output (MCP-T07) — credential pattern scan on tool responses
- [x] Module: agent-config-tampering (MCP-T09) — config-write surface + behavioral canary
- [x] Module: hallucination-destruction (MCP-T10) — ambiguous-instruction gate probe
- [x] Taxonomy: extend PlaybookThreatID to T37–T49 (23 total threat IDs)
- [x] Module: blocklist-bypass (MCP-T44) — perl/ruby/lua/awk/node/php canary
- [x] Module: rag-pipeline-injection (MCP-T39) — authority injection + corpus propagation
- [x] Module: governance-gate-bypass (MCP-T41) — redirect-chain allowlist bypass
- [x] Module: transport-identity (MCP-T45–T49) — OBO/act-chain across Transport B/C/D/E

Total: 17 registered modules. 23 taxonomy IDs. Campaign runner (5 chains).
Property-based payload generation (5 generators, 16 mutations). 127 tests.

**Phase 2 is complete.** All orchestration and testing items shipped.

### Phase 3 — Purple Team Automation

**Goal:** Close the loop between red findings and blue detection.

- [x] SIEM integration (Splunk HEC, Elastic, Datadog) — batched event streaming with backpressure
- [x] Detection validation framework (attack → alert correlation, MTTD/MTTR, coverage by category)
- [x] Canary deployment tooling (plant + monitor + alert) — 6 surface types, pluggable check functions
- [x] GitHub Actions workflow for scheduled purple team drills (configurable campaigns + SARIF upload)
- [x] MTTD/MTTR tracking dashboard (historical trending, regression detection, coverage heatmap)
- [x] Regression test suite from confirmed findings (auto-generate, persist, verify)

### Phase 4 — Ecosystem Integration

**Goal:** Make the research consumable outside this repo.

- [ ] Publish scanner landscape as standalone living doc
- [ ] Extract golden path as team-adoptable template
- [ ] Package assessment framework as structured checklist tool
- [ ] CI integration: `mcp-slayer` as GitHub Action
- [ ] Contribution guide for external scenario submissions
- [ ] Training material: MCP security workshop outline

---

## Threat Landscape Watch

Track emerging risks that may require new taxonomy entries or modules:

| Signal | Source | Impact if confirmed |
|---|---|---|
| MCP server rug-pull in production | Invariant Labs, community reports | New module: drift-detection |
| Multi-agent delegation chain attacks | v3.1 playbook Domain F | New module: delegation-abuse |
| Agentic ransomware patterns | v3.1 playbook Chain 5 | New campaign: ransom-chain |
| Tool schema smuggling in production | Community CVEs | New module: schema-validation |
| Cross-session memory poisoning | Academic research | New module: memory-persistence |
| OAuth token scope creep in MCP auth | MCP RFC evolution | Update: token-validation module |

---

## Principles

1. **Research first, tooling second.** Understand the risk before automating
   the test. A well-documented threat model is more valuable than a broken
   scanner.

2. **Preserve attribution.** Copied research stays attributed. Moved files use
   `git mv`. Delete only confirmed junk.

3. **Vendor-neutral by default.** Architecture designs work on any cloud.
   AWS-specific variants are explicitly labeled.

4. **Living documents.** Every successful attack improves the playbook. Every
   remediation becomes a regression test.

5. **Practical over theoretical.** If it hasn't been demonstrated in a
   scenario or a harness module, it's a hypothesis, not a finding.
