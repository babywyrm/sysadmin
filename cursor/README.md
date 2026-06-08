# Cursor Operations Notes

This directory contains Cursor repair and cleanup scripts.

Agent-control-file scanners and hook examples moved to:

```text
ai/agent-safety/cursor-hooks/
```

## Files

- `clean__.sh`: Linux Cursor cleanup utility.
- `respawn___.sh`: macOS Cursor repair/reset utility.

Review each script before running. Both scripts can remove local Cursor state
when invoked with stronger flags.
