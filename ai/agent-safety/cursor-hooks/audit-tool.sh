#!/usr/bin/env bash
set -Eeuo pipefail

LOG_PATH="${CURSOR_TOOL_AUDIT_LOG:-$HOME/.cursor/tool-audit.jsonl}"
mkdir -p "$(dirname "$LOG_PATH")"

python3 - "$LOG_PATH" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

log_path = sys.argv[1]

try:
    payload = json.load(sys.stdin)
except Exception:
    payload = {}

record = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "event": "tool_call",
    "tool": payload.get("tool_name") or payload.get("tool") or payload.get("name"),
}

with open(log_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, sort_keys=True) + "\n")

print(json.dumps({"permission": "allow"}))
PY
