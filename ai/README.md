# AI And Agent Security

AI, LLM, MCP, agent gateway, provider, and agent red-team research lives here.
This area is a research archive, not a single deployable project.

## Layout

- `mcp/`: Model Context Protocol security research, blue-team controls,
  red-team playbooks, harnesses, auth, inference notes, and RFC-style proposals.
- `agent-safety/`: Defensive scanners and hook examples for agent control files,
  Cursor skills, rules, hooks, and tool-call safety.
- `llms/`: General LLM security notes, model comparison notes, Bedrock snippets,
  agent gateway deployment material, and literature/reference archives.
- `providers/`: Provider-specific experiments and examples. These may use older
  APIs and should be treated as historical samples unless a local README says
  otherwise.

## Boundaries

- Cloud provider infrastructure belongs under `cloud/` unless it is specific to
  agent or LLM runtime architecture.
- Kubernetes deployment material belongs under a Kubernetes/platform area unless
  it is tightly coupled to an AI or agent gateway design.
- Broad architecture modeling remains in `modeling/` until it is reviewed and
  moved deliberately.
- Copied public references should be preserved with attribution when useful, but
  should not be mistaken for maintained local code.

## Cleanup Policy

Preserve useful research. Prefer moving, indexing, and labeling material before
pruning it. Delete only reproducible junk or confirmed unsafe material after a
separate review.
