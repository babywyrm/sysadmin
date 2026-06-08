from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from agent_safety.models import Finding, SEVERITY_RANK, ScanResult

SCANNER = "tool_calls"
MAX_FINDINGS = int(os.environ.get("SCAN_TOOL_MAX_FINDINGS", "25"))
MAX_SNIPPET_CHARS = int(os.environ.get("SCAN_TOOL_MAX_SNIPPET_CHARS", "180"))

BLOCKED_TOOLS: frozenset[str] = frozenset(
    {
        "run_terminal_command",
        "execute_command",
        "shell",
        "bash",
        "terminal",
        "delete_file",
        "remove_file",
        "overwrite_file",
        "http_request",
        "fetch_url",
        "web_request",
    }
)


@dataclass(frozen=True)
class ArgPattern:
    rule_id: str
    severity: str
    pattern: str


SENSITIVE_ARG_PATTERNS: tuple[ArgPattern, ...] = (
    ArgPattern(
        rule_id="ARG_SHELL_INJECTION",
        severity="critical",
        pattern=r"[;&|`$]|\$\(|\beval\b|\bexec\b",
    ),
    ArgPattern(
        rule_id="ARG_PATH_TRAVERSAL",
        severity="high",
        pattern=r"\.\./|\.\.\\",
    ),
    ArgPattern(
        rule_id="ARG_SENSITIVE_PATH",
        severity="high",
        pattern=r"(~|/root|/etc/passwd|/etc/shadow|\.ssh|\.aws|\.env|/proc/self)",
    ),
    ArgPattern(
        rule_id="ARG_EXFIL_DESTINATION",
        severity="critical",
        pattern=r"https?://(?!localhost|127\.0\.0\.1)[^\s]+",
    ),
    ArgPattern(
        rule_id="ARG_BASE64_ENCODED",
        severity="medium",
        pattern=r"[A-Za-z0-9+/]{80,}={0,2}",
    ),
)


def _compact_snippet(value: object) -> str:
    snippet = re.sub(r"\s+", " ", str(value)).strip()
    if len(snippet) > MAX_SNIPPET_CHARS:
        return snippet[: MAX_SNIPPET_CHARS - 3] + "..."
    return snippet


def _finding(rule_id: str, severity: str, label: str, snippet: object) -> Finding:
    return Finding(
        scanner=SCANNER,
        rule_id=rule_id,
        severity=severity,
        label=label,
        path=None,
        line=None,
        snippet=_compact_snippet(snippet),
    )


def _extract_tool_name(data: dict[str, object]) -> str:
    value = data.get("tool_name") or data.get("tool") or data.get("name") or ""
    return str(value)


def _extract_args(data: dict[str, object]) -> dict[str, object]:
    args = data.get("args") or data.get("arguments") or data.get("params") or {}
    return args if isinstance(args, dict) else {}


def _scan_args(args: dict[str, object]) -> list[Finding]:
    findings: list[Finding] = []
    for arg_name, arg_value in args.items():
        value = str(arg_value)
        for pattern in SENSITIVE_ARG_PATTERNS:
            if re.search(pattern.pattern, value, re.IGNORECASE):
                findings.append(
                    _finding(
                        rule_id=pattern.rule_id,
                        severity=pattern.severity,
                        label=f"suspicious pattern in arg '{arg_name}'",
                        snippet=value,
                    )
                )
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


def scan_tool_call(data: dict[str, Any]) -> ScanResult:
    tool_name = _extract_tool_name(data)
    findings: list[Finding] = []
    if tool_name in BLOCKED_TOOLS:
        findings.append(
            _finding(
                rule_id="BLOCKED_TOOL",
                severity="critical",
                label=f"tool '{tool_name}' is on the blocked list",
                snippet=tool_name,
            )
        )
    findings.extend(_scan_args(_extract_args(data)))
    findings.sort(key=lambda finding: SEVERITY_RANK.get(finding.severity.lower(), 9))
    return ScanResult(findings=findings[:MAX_FINDINGS])
