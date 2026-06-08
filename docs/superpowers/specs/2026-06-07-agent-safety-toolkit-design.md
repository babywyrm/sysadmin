# Agent Safety Toolkit Design

## Goal

Mature `ai/agent-safety/` from Cursor hook examples into a portable self-audit
toolkit for agent control files, tool-call review, and agent startup context
validation.

The toolkit must preserve the current scanner behavior while making it usable
from local developer workflows, CI/pre-commit checks, Codex-style adapters,
Cursor hooks, and agentic-cluster self-audit jobs.

## Non-Goals

- Do not replace Cursor, Codex, or other agent platform permission systems.
- Do not claim sandboxing. This is heuristic scanning and policy enforcement.
- Do not add heavy runtime dependencies in v1.
- Do not discard the existing scanner rules or hook response formats.

## Current State

Existing scanner scripts live under `ai/agent-safety/cursor-hooks/`:

- `scan_skill.py` scans agent control files such as `SKILL.md`, `AGENTS.md`,
  `.cursor/rules/**`, `.cursor/hooks/**`, plugins, and related docs.
- `scan_tool.py` scans proposed tool calls for blocked tools, shell injection,
  sensitive paths, exfiltration URLs, and encoded payloads.
- `validate_agent.py` scans startup context for prompt-injection and
  system-prompt-tampering language.
- Hook wrappers and Cursor hook config examples support the current local
  install workflow.

These scripts are useful but tightly coupled to hook usage, duplicate scanner
models, and do not yet provide repo scanning, policy files, baselines, or
Codex/cluster adapters.

## Architecture

Create a small Python package under `ai/agent-safety/agent_safety/`.

```text
ai/agent-safety/
  agent_safety/
    __init__.py
    cli.py
    models.py
    policies.py
    scanners/
      __init__.py
      control_files.py
      tool_calls.py
      agent_context.py
    adapters/
      __init__.py
      cursor.py
      codex.py
  policies/
    default.json
    strict.json
  fixtures/
    benign/
    suspicious/
  tests/
  cursor-hooks/
    existing compatibility wrappers and hook configs
```

The scanner core owns detection logic and returns structured findings. Adapters
translate platform-specific input/output shapes into the shared model.

## Shared Finding Model

Every scanner emits findings with this shape:

```json
{
  "scanner": "control_files",
  "rule_id": "PROMPT_IGNORE_INSTRUCTIONS",
  "severity": "high",
  "label": "prompt injection: ignore previous instructions",
  "path": "skills/example/SKILL.md",
  "line": 12,
  "snippet": "Ignore previous instructions"
}
```

Severity order is:

1. `critical`
2. `high`
3. `medium`
4. `low`

## CLI Contract

The CLI must be runnable without installation from the directory:

```bash
python -m agent_safety scan path/to/repo
python -m agent_safety scan-file path/to/SKILL.md
python -m agent_safety hook cursor-before-read
python -m agent_safety hook cursor-before-tool
python -m agent_safety hook cursor-before-agent
python -m agent_safety hook codex-preflight
```

Output formats:

- Human-readable text by default.
- JSON with `--format json`.
- JSON Lines with `--format jsonl` for cluster jobs.

Exit codes:

- `0`: no findings at or above the configured threshold.
- `1`: findings at or above the configured threshold.
- `2`: scanner, policy, or runtime error.

## Policy Contract

Policies are JSON files for v1 to avoid adding YAML dependencies. A policy can
define:

- File include/exclude patterns.
- Trusted URL regexes.
- Maximum file size.
- Maximum findings.
- Severity threshold.
- Blocked tool names.
- Sensitive argument regexes.
- Suppressions by rule/path/snippet.

`default.json` should preserve current scanner behavior. `strict.json` should
raise sensitivity for cluster and CI use.

## Adapter Contracts

### Cursor

Cursor adapters must preserve current hook response shapes:

```json
{"permission": "allow"}
```

```json
{
  "permission": "ask",
  "user_message": "...",
  "agent_message": "...",
  "metadata": {
    "scanner": "agent-safety",
    "finding_count": 1,
    "findings": []
  }
}
```

Existing wrapper scripts under `cursor-hooks/` should become thin calls into the
new CLI while retaining current filenames.

### Codex

Codex support should start as a generic preflight JSON/stdin adapter because
local Codex installations may vary. The adapter should support:

- Scanning instruction files and repository agent-control files before use.
- Emitting plain JSON results with findings and exit codes.
- Avoiding platform-specific assumptions until a concrete Codex hook contract is
  available.

### Cluster

Cluster jobs should call the CLI against mounted repositories or generated agent
control bundles and write JSONL output. The scanner must avoid absolute local
paths and should be deterministic for repeatable audits.

## Behavior To Preserve

- `scan_skill.py` rule coverage must move into `scanners/control_files.py`.
- `scan_tool.py` rule coverage must move into `scanners/tool_calls.py`.
- `validate_agent.py` rule coverage must move into `scanners/agent_context.py`.
- Code block stripping for prose scanning must remain.
- Raw obfuscation scanning must remain.
- Trusted URL behavior must remain configurable.
- Current smoke-test cases must become automated tests.

## Test Strategy

Use Python `unittest` or simple `pytest`-compatible tests that rely only on the
standard library unless the repo later adopts a Python project file for this
toolkit.

Minimum tests:

- Benign non-control file is ignored.
- Benign skill file passes.
- Prompt-injection skill file emits a high finding.
- External untrusted URL emits a medium finding.
- Long base64 payload emits a medium finding.
- Suspicious shell tool call emits critical findings.
- Benign local tool call passes.
- Suspicious agent context emits critical findings.
- Cursor adapter returns `allow` for clean input.
- Cursor adapter returns `ask` for suspicious input.
- CLI exits `1` when findings meet threshold.
- CLI exits `0` when findings are below threshold.

## Cross-Platform Requirements

- Use Python 3 standard-library APIs.
- Use `pathlib` for filesystem paths.
- Avoid hardcoded absolute paths.
- Keep POSIX shell wrappers for macOS/Linux users.
- Support Windows users through `python -m agent_safety ...`.
- Keep all scanner I/O available through stdin/stdout JSON.

## Rollout

1. Add tests that encode current scanner behavior.
2. Extract shared models and scanner modules.
3. Add policy loading with default behavior parity.
4. Add CLI scan and scan-file modes.
5. Convert Cursor wrappers to call the CLI.
6. Add Codex preflight and cluster scan documentation.
7. Run smoke tests, secret scan, and commit in focused batches.
