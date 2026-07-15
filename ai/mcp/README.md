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

# Run campaign chains
uv run mcp-slayer campaign --list

# Run all tests
uv run pytest
```

---

## Repository Map

```text
ai/mcp/
├── ROADMAP.md              # Phases 1–4 complete; threat landscape watch
├── README.md               # This file
│
├── harness/                # MCP-SLAYER v3.1 — the core assessment framework
│   ├── mcp_slayer/
│   │   ├── engine.py       # Execution engine + context manager
│   │   ├── config.py       # Unified v1/v3.1 config schema
│   │   ├── models.py       # Finding, Evidence, Severity, enums
│   │   ├── taxonomy.py     # MCP-T01–T49 ↔ OWASP MCP01–10 bridge (23 IDs)
│   │   ├── cli.py          # CLI: module scan + campaign subcommand
│   │   ├── reporting.py    # JSON, YAML, Markdown, SARIF output
│   │   ├── modules/        # 17 attack modules (full OWASP MCP Top 10)
│   │   ├── campaign/       # Multi-stage chain orchestration (5 built-in)
│   │   ├── payloads/       # Property-based generation (5 generators, 16 mutations)
│   │   └── purple/         # SIEM, detection, canary, dashboard, regression
│   ├── action/             # Reusable GitHub Action for CI gates
│   ├── .github/workflows/  # Purple team drill workflow
│   ├── tests/              # 168 tests
│   ├── configs/            # Reference config examples (v1 + v3)
│   ├── docs/               # Campaign runner, payloads, golden path, workshop
│   └── CONTRIBUTING.md     # How to add scenarios, modules, campaigns
│
├── redteam/                # Red team playbook (v3.1) + attack chains
│   ├── v3__.md             # Full playbook: Domains A–F, Chains 1–5, ABRS
│   ├── chains__.md         # Visual attack chain diagrams
│   ├── owasp__.md          # OWASP MCP Top 10 detailed analysis
│   ├── agentic__.md        # Agentic-specific attack patterns
│   └── scenarios/          # Field scenarios with mermaid diagrams
│
├── defense/                # Blue team operations
│   ├── detection-catalog.md     # 14+ detection rules (SPL/KQL)
│   ├── incident-response.md     # 5 IR playbooks
│   ├── kill-switch-automation.md # 8 kill switch patterns
│   ├── controls-traceability.md # Controls → findings matrix
│   └── blue-team-structure.md   # Operating model
│
├── architecture/           # Reference security architectures
│   ├── zero-trust-tool-execution.md  # Vendor-neutral zero-trust design
│   ├── aws-agentic-mesh.md           # AWS-specific variant
│   └── security-architecture-v2.md   # Generic mesh architecture
│
├── assessments/            # Assessment frameworks
│   ├── security-assessment-framework-v3.md  # Full matrix (current)
│   └── security-assessment-framework.md     # v1 (historical)
│
├── tools/                  # Scanner landscape + tooling notes
│   └── scanner-landscape.md  # v3.0: all MCP scanners + internal tools
│
├── arbiter/                # Legacy policy engine prototypes (reference)
├── blueprints/             # Early architecture proposals (superseded by harness/docs)
├── keycloak/               # Keycloak/IdP integration research
├── llama/                  # Local model config examples
├── inference/              # Inference-layer security notes
├── rfc/                    # EKS hardening RFC + proposals
└── runbooks/               # Operational runbook drafts
```

---

## Threat Taxonomy

Two taxonomies bridged in `harness/mcp_slayer/taxonomy.py`:

| Taxonomy | IDs | Purpose |
|---|---|---|
| **Playbook** | MCP-T01–T14 (core) + MCP-T37–T49 (extended) | Concrete MCP threat classes |
| **OWASP MCP Top 10** | MCP01–MCP10 | Industry-standard risk categories |

Run `mcp-slayer --taxonomy` to print the full bridge table.

---

## Harness Capabilities

| Capability | Description |
|---|---|
| 17 attack modules | Full OWASP MCP Top 10 + extended taxonomy coverage |
| Campaign runner | 5 multi-stage chains from playbook v3.1 (gate logic, ABRS) |
| Property-based payloads | 5 generators, 16 mutation operators, shrinking engine |
| SIEM streaming | Splunk HEC, Elasticsearch, Datadog |
| Detection validation | MTTD/MTTR measurement, coverage-by-category |
| Canary deployment | 6 surface types, pluggable monitoring |
| Dashboard trending | Historical drill results, regression detection |
| Regression suite | Auto-generate CI tests from confirmed findings |
| GitHub Action | Reusable composite action with SARIF upload |
| 168 tests | Full coverage, 0.24s execution |

---

## Related Tools (agentic-sec ecosystem)

| Tool | Role |
|---|---|
| [mcpnuke](https://github.com/babywyrm/mcpnuke) | External MCP scanner with AI-assisted behavioral probes |
| [skillseraph](https://github.com/babywyrm/skillseraph) | Agent config static analysis (skills, rules, hooks) |
| [stoneburner](https://github.com/babywyrm/stoneburner) | Architecture review + adversarial benchmarks |
| [nullfield](https://github.com/babywyrm/nullfield) | MCP-aware policy enforcement point (PEP) |

---

## Handling Notes

- Prefer adding indexes and preserving attribution over deleting copied research.
- Move files with `git mv` so history remains easy to follow.
- Keep concrete target notes out unless sanitized and intentionally general.
- Cloud provider infra belongs under `cloud/` unless tightly coupled to agent
  runtime architecture.
