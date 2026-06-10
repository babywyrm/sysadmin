# Model Context Protocol Security

MCP security research, architecture, offensive testing, defensive operations,
and reusable tooling. This is an active research archive — see `ROADMAP.md` for
current priorities and maturity levels.

---

## Quick Start

```bash
# Run the MCP-SLAYER security assessment harness
cd harness && uv sync && uv run mcp-slayer --help

# Print the taxonomy bridge (playbook threats ↔ OWASP categories)
uv run mcp-slayer --taxonomy

# Run harness tests
make test
```

---

## Layout

| Directory | Purpose | Maturity |
|---|---|---|
| `architecture/` | Zero-trust mesh designs, layered security models, AWS-native variant | Strong |
| `redteam/` | Red team playbooks (v2.1 stable, v3.1 RC), threat taxonomy, attack modules | Strong |
| `redteam/scenarios/` | Field-tested multi-MCP attack scenarios with mermaid diagrams | Strong |
| `assessments/` | MCP pentest methodology, risk cards, assessment matrices | Medium |
| `defense/` | Blue-team ops: operating model, detection catalog, IR playbooks, controls traceability | Strong |
| `blueprints/` | Golden path v3, production design playbooks | Strong |
| `harness/` | **MCP-SLAYER v3.1** — packaged `uv` project, async harness, 3 modules | Active dev |
| `tools/` | Scanner and guardrail landscape index (mcp-scan, ramparts, etc.) | Medium |
| `runbooks/` | Operational red-vs-blue runbook (v2.0, 1200+ lines) | Medium |
| `rfc/` | RFC-style proposals and EKS hardening standard | Thin |
| `keycloak/` | Identity-provider and auth-flow experiments | Thin |
| `llama/` | MCP server configuration examples for local model work | Thin |
| `arbiter/` | Larger prototype code retained for review | Thin |
| `inference/` | Inference-specific MCP notes | Thin |

---

## Key Documents

| Document | What it is |
|---|---|
| `ROADMAP.md` | Phased roadmap, maturity table, threat landscape watch |
| `architecture/zero-trust-tool-execution.md` | 6-layer defense model with OPA, SPIFFE, IRSA |
| `architecture/security-architecture-v2.md` | Full request flow (L0–L7) with ASCII diagrams |
| `architecture/aws-agentic-mesh.md` | AWS-native variant using Bedrock, AVP, STS |
| `redteam/readme.md` | Red team playbook v2.1 — taxonomy, modules, campaigns, reporting |
| `redteam/v3__.md` | v3.1 RC — agentic reasoning, multi-agent, temporal attacks |
| `redteam/scenarios/readme.md` | 7 field scenarios (poisoned wiki, self-modifying agent, etc.) |
| `blueprints/golden__.md` | Golden path v3 — full MCP session flow from OAuth to tool execution |
| `defense/README.md` | Blue team index, maturity targets, cross-reference to red team |
| `defense/blue-team-structure.md` | Full operating model, MCP-SHIELD modules, control matrix, EKS reference arch |
| `defense/detection-catalog.md` | 14 detection rules with pseudo-logic, severity, data sources, response actions |
| `defense/incident-response.md` | IR playbooks for top 5 MCP incident types with SLAs |
| `defense/controls-traceability.md` | Maps MCP-T01–T14 → controls → detections → IR → owners |
| `tools/scanner-landscape.md` | Practitioner index of MCP security scanners |
| `runbooks/beta__.md` | Red-vs-blue operational runbook v2.0 |

---

## MCP-SLAYER Harness

The runnable security assessment framework lives in `harness/`. It's a proper
Python package managed with `uv`:

```
harness/
├── pyproject.toml          # uv-managed, installable
├── Makefile                # sync, test, lint, verify
├── mcp_slayer/
│   ├── cli.py              # CLI entry point
│   ├── config.py           # Unified config (loads v1 + v3 formats)
│   ├── engine.py           # Async execution context
│   ├── models.py           # Finding, Evidence, Severity, enums
│   ├── taxonomy.py         # MCP-T01–T14 ↔ OWASP MCP01–10 bridge
│   ├── reporting.py        # JSON, YAML, Markdown, SARIF output
│   ├── modules/
│   │   ├── base.py         # Attack module ABC
│   │   ├── confused_deputy.py   # MCP02: token replay, scope inflation
│   │   ├── ssrf_metadata.py     # MCP05: cloud IMDS SSRF
│   │   └── shadow_server.py     # MCP09: unauth access, default creds
│   └── utils.py            # Redaction, sanitization
├── tests/                  # 19 tests (taxonomy, config, models)
└── configs/                # Reference config examples (v1 + v3)
```

---

## Threat Taxonomy

Two taxonomies exist and are explicitly bridged:

**Playbook Taxonomy** (MCP-T01 through MCP-T14): Defined in the red team
playbook. Describes concrete threat classes specific to MCP architectures.

**OWASP MCP Top 10** (MCP01 through MCP10): Industry-standard risk categories
used by the harness for finding classification.

The bridge lives in `harness/mcp_slayer/taxonomy.py` and maps every playbook
threat to one or more OWASP categories (and vice versa). Run
`mcp-slayer --taxonomy` to print the full table.

---

## Handling Notes

- Prefer adding indexes and preserving attribution over deleting copied research.
- Move files with `git mv` so history remains easy to follow.
- Keep concrete target notes out unless sanitized and intentionally general.
- Cloud provider infra belongs under `cloud/` unless tightly coupled to agent
  runtime architecture.
- Kubernetes deployment material belongs under a platform area unless tightly
  coupled to an agent gateway design.
