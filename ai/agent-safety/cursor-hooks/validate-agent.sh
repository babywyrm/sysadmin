#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SAFETY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export PYTHONPATH="${PYTHONPATH:-}:$AGENT_SAFETY_ROOT"
exec python3 -m agent_safety hook cursor-before-agent
