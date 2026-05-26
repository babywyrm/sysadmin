#!/usr/bin/env python3
"""
validate-agent.py

beforeAgentStart hook.
Validates agent context and checks for system prompt tampering before
any agent session begins.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

SCANNER_NAME = "validate-agent.py"

logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger(SCANNER_NAME)

MAX_SNIPPET_CHARS = int(os.environ.get("SCAN_SKILL_MAX_SNIPPET_CHARS", "180"))

SYSTEM_PROMPT_INJECTION_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (
        "INJECT_IGNORE_INSTRUCTIONS",
        "high",
        r"\bignore\s+(previous|prior|above|all|earlier)\s+(instructions|rules|messages|directives)\b",
    ),
    (
        "INJECT_PERSONA_OVERRIDE",
        "high",
        r"\byou\s+are\s+now\s+(?!a\s+(?:skill|hook|rule|tool|scanner|validator)\b)",
    ),
    (
        "INJECT_SYSTEM_CLAIM",
        "critical",
        r"\b(system\s*:\s*(you\s+are|override|act\s+as|ignore|developer|assistant))\b",
    ),
    (
        "INJECT_JAILBREAK",
        "critical",
        r"\b(DAN|jailbreak|do\s+anything\s+now|unrestricted\s+mode|developer\s+mode)\b",
    ),
    (
        "INJECT_COVERT",
        "high",
        r"\b(silently|covertly|secretly|without\s+telling\s+(the\s+)?user)\b",
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
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


def _compact_snippet(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > MAX_SNIPPET_CHARS:
        return value[: MAX_SNIPPET_CHARS - 3] + "..."
    return value


def _scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for rule_id, severity, pattern in SYSTEM_PROMPT_INJECTION_PATTERNS:
        try:
            for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        label="suspicious pattern in agent context",
                        snippet=_compact_snippet(match.group(0)),
                    )
                )
        except re.error as exc:
            log.warning("Pattern error in %s: %s", rule_id, exc)

    return findings


def validate_agent(data: dict[str, Any]) -> ScanResult:
    result = ScanResult()

    # Check system prompt, context, and any injected rules
    fields_to_check = (
        "system_prompt",
        "systemPrompt",
        "context",
        "instructions",
        "rules",
        "prompt",
    )

    for field_name in fields_to_check:
        value = data.get(field_name)
        if isinstance(value, str) and value.strip():
            result.findings.extend(_scan_text(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    result.findings.extend(_scan_text(item))

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
    result = validate_agent(data)

    if not result.has_findings:
        _emit({"permission": "allow"})
        return 0

    finding_text = "\n".join(f.format() for f in result.findings)

    user_msg = (
        f"Agent start blocked — suspicious patterns detected in agent context.\n\n"
        f"Findings: {len(result.findings)}\n\n"
        f"{finding_text}\n\n"
        "Review the agent configuration before proceeding."
    )

    agent_msg = (
        f"{SCANNER_NAME} detected {len(result.findings)} suspicious pattern(s) "
        "in agent context. Paused for user review."
    )

    _emit(
        {
            "permission": "ask",
            "user_message": user_msg,
            "agent_message": agent_msg,
            "metadata": {
                "scanner": SCANNER_NAME,
                "finding_count": len(result.findings),
                "findings": [f.to_dict() for f in result.findings],
            },
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
  
