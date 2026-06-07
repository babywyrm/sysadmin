# Model Context Protocol Security

MCP research, agent security architecture, assessment methodology, and tooling
notes live here. This area is active research and should be organized before it
is pruned.

## Layout

- `architecture/`: Zero-trust agent mesh designs, AWS-native variants, and
  request/session flow models.
- `assessments/`: MCP pentest methodology, risk cards, and assessment matrices.
- `defense/`: Blue-team operating model, control families, detection, response,
  and hardening notes.
- `tools/`: Scanner and guardrail landscape notes.
- `redteam/`: Red-team playbooks, agentic attack chains, scenarios, and OWASP
  MCP mapping material.
- `blueprints/`: Longer-form design blueprints and playbooks.
- `harness/`: Runnable or semi-runnable trust-chain and validation harnesses.
- `inference/`: Inference-specific MCP notes.
- `keycloak/`: Identity-provider and auth-flow experiments.
- `llama/`: MCP server configuration examples for local model/runtime work.
- `rfc/`: RFC-style proposals and structured interface sketches.
- `runbooks/`: Operational runbooks and longer working drafts.
- `arbiter/`: Larger prototype code retained for review before further sorting.

## Handling Notes

Prefer adding indexes and preserving attribution over deleting copied research.
Move files with `git mv` so history remains easy to follow.
