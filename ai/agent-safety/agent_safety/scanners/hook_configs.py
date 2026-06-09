from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_safety.models import SEVERITY_RANK, Finding, ScanResult

SCANNER = "hook_configs"

SECURITY_CRITICAL_EVENTS: frozenset[str] = frozenset(
    {
        "beforeReadFile",
        "beforeWriteFile",
        "beforeToolCall",
        "beforeAgentStart",
        "beforeSubmitPrompt",
        "beforeShellExecution",
        "beforeMCPExecution",
        "preToolUse",
        "UserPromptSubmit",
        "PreToolUse",
    }
)

COMMAND_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    (
        "HOOK_NETWORK_BOOTSTRAP",
        "critical",
        "hook command fetches remote content",
        r"\b(curl|wget|fetch)\b.{0,120}https?://",
    ),
    (
        "HOOK_SHELL_PIPE",
        "critical",
        "hook command pipes content to shell",
        r"\|\s*(sh|bash|zsh|python|python3|perl|ruby)\b",
    ),
    (
        "HOOK_RAW_ARGUMENT_LOGGING",
        "high",
        "hook appears to log raw tool arguments",
        r"\b(log[-_ ]?raw|raw[-_ ]?arguments|raw[-_ ]?args|dump[-_ ]?args)\b",
    ),
    (
        "HOOK_DANGEROUS_DELETE",
        "high",
        "hook command contains broad delete operation",
        r"\brm\s+-rf\b|\bRemove-Item\b.{0,80}\b-Recurse\b",
    ),
)


def _finding(
    rule_id: str,
    severity: str,
    label: str,
    path: str | None,
    snippet: str,
) -> Finding:
    return Finding(
        scanner=SCANNER,
        rule_id=rule_id,
        severity=severity,
        label=label,
        path=path,
        line=1,
        snippet=snippet,
    )


def _iter_hook_entries(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return []

    entries: list[tuple[str, dict[str, Any]]] = []
    for event_name, configured in hooks.items():
        if isinstance(configured, list):
            for item in configured:
                if isinstance(item, dict):
                    entries.append((str(event_name), item))
        elif isinstance(configured, dict):
            entries.append((str(event_name), configured))
    return entries


def scan_hook_config(data: dict[str, Any], path: str | None = None) -> ScanResult:
    findings: list[Finding] = []
    for event_name, hook in _iter_hook_entries(data):
        command = hook.get("command")
        command_text = command if isinstance(command, str) else ""

        if event_name in SECURITY_CRITICAL_EVENTS and hook.get("failClosed") is not True:
            findings.append(
                _finding(
                    "HOOK_MISSING_FAIL_CLOSED",
                    "high",
                    "security-critical hook does not set failClosed true",
                    path,
                    event_name,
                )
            )

        for rule_id, severity, label, pattern in COMMAND_PATTERNS:
            if command_text and re.search(pattern, command_text, re.IGNORECASE):
                findings.append(_finding(rule_id, severity, label, path, command_text))

    findings.sort(key=lambda finding: SEVERITY_RANK.get(finding.severity.lower(), 9))
    return ScanResult(findings=findings)


def scan_hook_config_file(path: str | Path) -> ScanResult:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ScanResult(
            findings=[
                _finding(
                    "HOOK_CONFIG_READ_ERROR",
                    "high",
                    "could not read hook config",
                    str(path),
                    str(exc),
                )
            ],
            errors=[str(exc)],
        )
    if not isinstance(payload, dict):
        return ScanResult(
            findings=[
                _finding(
                    "HOOK_CONFIG_INVALID_SHAPE",
                    "high",
                    "hook config must be a JSON object",
                    str(path),
                    type(payload).__name__,
                )
            ],
            errors=["hook config must be a JSON object"],
        )
    return scan_hook_config(payload, str(path))
