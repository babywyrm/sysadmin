# Cursor Operations Notes

This directory contains Cursor repair and cleanup scripts.

Agent-control-file scanners and hook examples moved to:

```text
ai/agent-safety/cursor-hooks/
```

## Files

- `clean__.sh`: Linux Cursor cleanup utility.
- `respawn___.sh`: macOS Cursor repair/reset utility.
- `migrate__OSx__.py`: Zero-dep SSH transfer of Cursor state between machines.

Review each script before running. Both shell scripts can remove local Cursor
state when invoked with stronger flags.

## Agent rules

Shared ponytail (craft) and caveman (voice) rules live in
[`../.cursor/rules/`](../.cursor/rules/) — the only path Cursor loads rules
from. Read, use, or suggest improvements there:

- [`ponytail.mdc`](../.cursor/rules/ponytail.mdc)
- [`caveman.mdc`](../.cursor/rules/caveman.mdc)
- [`README.md`](../.cursor/rules/README.md)
