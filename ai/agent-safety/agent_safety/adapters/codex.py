from __future__ import annotations

from typing import Any

from agent_safety.scanners.agent_context import scan_agent_context


def codex_preflight(data: dict[str, object]) -> dict[str, Any]:
    result = scan_agent_context(data)
    return {
        "adapter": "codex-preflight",
        "finding_count": len(result.findings),
        "findings": [finding.to_dict() for finding in result.findings],
        "errors": list(result.errors),
    }
