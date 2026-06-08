from __future__ import annotations

from typing import Any

from agent_safety.models import ScanResult
from agent_safety.scanners.agent_context import scan_agent_context
from agent_safety.scanners.control_files import is_control_file, scan_control_file
from agent_safety.scanners.tool_calls import scan_tool_call

PATH_KEYS: tuple[str, ...] = (
    "path",
    "file_path",
    "filePath",
    "filename",
    "absolutePath",
    "absolute_path",
)


def _extract_path(data: dict[str, object]) -> str:
    for key in PATH_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    file_obj = data.get("file")
    if isinstance(file_obj, dict):
        for key in PATH_KEYS:
            value = file_obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _allow_or_ask(result: ScanResult, title: str, agent_message: str) -> dict[str, Any]:
    if not result.has_findings:
        return {"permission": "allow"}
    finding_text = "\n".join(
        f"- [{finding.severity.upper()}] {finding.rule_id}: "
        f"{finding.label}; matched: {finding.snippet!r}"
        for finding in result.findings
    )
    return {
        "permission": "ask",
        "user_message": (
            f"{title}\n\nFindings: {len(result.findings)}\n\n"
            f"{finding_text}\n\nReview before allowing this operation."
        ),
        "agent_message": agent_message,
        "metadata": {
            "scanner": "agent-safety",
            "finding_count": len(result.findings),
            "findings": [finding.to_dict() for finding in result.findings],
        },
    }


def cursor_before_read(data: dict[str, object]) -> dict[str, Any]:
    path = _extract_path(data)
    if not is_control_file(path):
        return {"permission": "allow"}
    result = scan_control_file(path)
    return _allow_or_ask(
        result,
        f"Security scan flagged `{path}` before the agent reads it.",
        f"agent-safety flagged {path} with {len(result.findings)} finding(s).",
    )


def cursor_before_tool(data: dict[str, object]) -> dict[str, Any]:
    result = scan_tool_call(data)
    tool_name = data.get("tool_name") or data.get("tool") or data.get("name") or ""
    return _allow_or_ask(
        result,
        f"Tool call intercepted: `{tool_name}`",
        f"agent-safety flagged tool call {tool_name!r} with {len(result.findings)} finding(s).",
    )


def cursor_before_agent(data: dict[str, object]) -> dict[str, Any]:
    result = scan_agent_context(data)
    return _allow_or_ask(
        result,
        "Agent start blocked: suspicious patterns detected in agent context.",
        f"agent-safety detected {len(result.findings)} suspicious pattern(s) in agent context.",
    )
