# AI And Agent Security

AI, LLM, MCP, agent gateway, provider, and agent red-team research lives here.

## Layout

- `mcp/`: Model Context Protocol security research, blue-team controls,
  red-team playbooks, harnesses, auth, inference notes, and RFC-style proposals.
- `llms/`: General LLM notes, provider experiments, Bedrock snippets, and agent
  gateway deployment material.
- `providers/openai/`: OpenAI, Claude, prompt testing, and provider-specific
  experiments.

## Boundaries

- Cloud provider infrastructure belongs under `cloud/` unless it is specific to
  agent or LLM runtime architecture.
- Kubernetes deployment material belongs under the future `kubernetes/` area
  unless it is tightly coupled to an AI/agent gateway design.
- Broad architecture modeling remains in `modeling/` until it is reviewed and
  moved deliberately.

## MCP Notes

The MCP material is valuable active research. Preserve methodology, taxonomy,
defensive controls, and red-team harness ideas. Prefer reorganizing it into
clear subareas rather than pruning it.
