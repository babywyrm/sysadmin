#!/usr/bin/env python3
"""
scan-tool.py

Defensive beforeToolCall hook. Validates tool calls before execution.
Blocks shell injection, network exfiltration, and dangerous file operations.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

SCANNER_NAME = "scan-tool.py"

logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger(SCANNER_NAME)

MAX_FINDINGS = int(os.environ.get("SCAN_TOOL_MAX_FINDINGS", "25"))
MAX_SNIPPET_CHARS = int(os.environ.get("SCAN_TOOL_MAX_SNIPPET_CHARS", "180"))

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

# ---------------------------------------------------------------------------
# Blocked tool names
# ---------------------------------------------------------------------------

BLOCKED_TOOLS: frozenset[str] = frozenset(
    {
        # Direct shell access
        "run_terminal_command",
        "execute_command",
        "shell",
        "bash",
        "terminal",
        # Dangerous file ops
        "delete_file",
        "remove_file",
        "overwrite_file",
        # Network
        "http_request",
        "fetch_url",
        "web_request",
    }
)

SENSITIVE_ARG_PATTERNS: tuple[tuple[str, str, str], ...] = (
    # (rule_id, severity, pattern)
    (
        "ARG_SHELL_INJECTION",
        "critical",
        r"[;&|`$]|\$\(|\beval\b|\bexec\b",
    ),
    (
        "ARG_PATH_TRAVERSAL",
        "high",
        r"\.\./|\.\.\\",
    ),
    (
        "ARG_SENSITIVE_PATH",
        "high",
        r"(~|/root|/etc/passwd|/etc/shadow|\.ssh|\.aws|\.env|/proc/self)",
    ),
    (
        "ARG_EXFIL_DESTINATION",
        "critical",
        r"https?://(?!localhost|127\.0\.0\.1)[^\s]+",
    ),
    (
        "ARG_BASE64_ENCODED",
        "medium",
        r"[A-Za-z0-9+/]{80,}={0,2}",
    ),
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    label: str
    severity: str
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "label": self.label,
            "snippet": self.snippet,
        }

    def format(self) -> str:
        return (
            f"- [{self.severity.upper()}] {self.rule_id}: "
            f"{self.label}; matched: {self.snippet!r}"
        )


@dataclass
class ScanResult:
    tool_name: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def truncated(self) -> bool:
        return len(self.findings) >= MAX_FINDINGS


def _compact_snippet(value: str) -> str:
    value = re.sub(r"\s+", " ", str(value)).strip()
    if len(value) > MAX_SNIPPET_CHARS:
        return value[: MAX_SNIPPET_CHARS - 3] + "..."
    return value


def _scan_args(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    for arg_name, arg_value in args.items():
        value_str = str(arg_value)

        for rule_id, severity, pattern in SENSITIVE_ARG_PATTERNS:
            try:
                if re.search(pattern, value_str, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            label=f"suspicious pattern in arg '{arg_name}'",
                            snippet=_compact_snippet(value_str),
                        )
                    )
            except re.error as exc:
                log.warning("Pattern error in %s: %s", rule_id, exc)

            if len(findings) >= MAX_FINDINGS:
                return findings

    return findings


def scan_tool_call(data: dict[str, Any]) -> ScanResult:
    tool_name = data.get("tool_name") or data.get("tool") or data.get("name") or ""
    args = data.get("args") or data.get("arguments") or data.get("params") or {}

    if not isinstance(args, dict):
        args = {}

    result = ScanResult(tool_name=str(tool_name))

    if tool_name in BLOCKED_TOOLS:
        result.findings.append(
            Finding(
                rule_id="BLOCKED_TOOL",
                severity="critical",
                label=f"tool '{tool_name}' is on the blocked list",
                snippet=tool_name,
            )
        )

    result.findings.extend(_scan_args(args))
    result.findings.sort(
        key=lambda f: SEVERITY_RANK.get(f.severity.lower(), 9)
    )
    return result


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _load_input() -> dict[str, Any]:
    try:
        data = json.load(sys.stdin)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError as exc:
        log.warning("Failed to parse stdin: %s", exc)
        return {}


def main() -> int:
    data = _load_input()
    result = scan_tool_call(data)

    if not result.has_findings:
        _emit({"permission": "allow"})
        return 0

    finding_text = "\n".join(f.format() for f in result.findings)
    if result.truncated:
        finding_text += f"\n- Output truncated at {MAX_FINDINGS} findings."

    user_msg = (
        f"Tool call intercepted: `{result.tool_name}`\n\n"
        f"Findings: {len(result.findings)}\n\n"
        f"{finding_text}\n\n"
        "Review before allowing this tool call to proceed."
    )

    agent_msg = (
        f"{SCANNER_NAME} flagged tool call '{result.tool_name}' "
        f"with {len(result.findings)} finding(s). Paused for user review."
    )

    _emit(
        {
            "permission": "ask",
            "user_message": user_msg,
            "agent_message": agent_msg,
            "metadata": {
                "scanner": SCANNER_NAME,
                "tool_name": result.tool_name,
                "finding_count": len(result.findings),
                "truncated": result.truncated,
                "findings": [f.to_dict() for f in result.findings],
            },
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
