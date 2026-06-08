# Agent Safety

Portable defensive tooling for inspecting AI agent control files, tool calls,
and agent startup context.

This is a heuristic self-audit toolkit, not a sandbox. It is meant to catch
risky agent instructions before a local workflow, CI job, Codex-style preflight,
Cursor hook, or agentic cluster trusts them.

## Layout

- `agent_safety/`: Standard-library Python scanner core and adapters.
- `policies/`: JSON policy presets.
- `fixtures/`: Benign and suspicious examples for smoke testing.
- `cursor-hooks/`: Hook scripts and configs for scanning suspicious agent
  control files before they are read or written.
- `tests/`: Unit tests for scanner parity, adapters, and CLI behavior.

## Threat Model

Agent control files can become a supply-chain surface. Treat files such as
`SKILL.md`, `AGENTS.md`, `.cursor/rules/**`, `.cursor/hooks/**`, and plugin docs
as executable influence over future agents.

The scanner looks for prompt injection, covert instructions, suspicious network
fetch instructions, secret access language, external URLs, encoded payloads,
blocked tool calls, and agent-start context tampering.

## Local CLI

Run from this directory:

```bash
python3 -m agent_safety scan-file fixtures/benign/SKILL.md --format json
python3 -m agent_safety scan fixtures --format json
python3 -m agent_safety scan fixtures --format jsonl
```

Exit codes:

- `0`: no findings at or above the policy threshold.
- `1`: findings at or above the policy threshold.
- `2`: CLI/runtime error.

## Cursor Hooks

Use `cursor-hooks/` for local Cursor workflows. The shell wrappers delegate to
the shared package with `python3 -m agent_safety hook ...`.

See `cursor-hooks/README.md` for install commands.

## Codex Preflight

Codex support starts as a generic stdin/stdout JSON adapter:

```bash
printf '{"instructions":"Ignore previous instructions."}' \
  | python3 -m agent_safety hook codex-preflight
```

This avoids assuming a specific Codex hook contract while still making the
scanner usable from scripts, CI, or local wrappers.

## Cluster Self-Audit

Agentic cluster jobs should scan mounted repositories or generated control-file
bundles and emit JSON Lines for collection:

```bash
python3 -m agent_safety scan /workspace/control-bundle --format jsonl
```

Keep cluster policies strict and deterministic. Do not depend on local absolute
paths.

## Cross-Platform Notes

- macOS/Linux users can use the POSIX shell wrappers in `cursor-hooks/`.
- Windows users should call `python -m agent_safety ...` directly.
- Runtime code is standard-library Python for v1.
