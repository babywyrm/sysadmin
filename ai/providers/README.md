# AI Provider Experiments

Provider-specific AI experiments live here. Keep vendor-neutral architecture,
MCP, and LLM security notes in `ai/mcp/` or `ai/llms/`.

## Layout

- `openai/`: OpenAI-era API examples, prompt testing notes, Claude comparison
  snippets, MCP/provider integration sketches, and small Flask demos.

## Handling Notes

Provider examples are often time-sensitive. Preserve them as historical samples
unless they are being actively refreshed, and label outdated code rather than
silently modernizing it.
