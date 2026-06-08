from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from agent_safety.models import Finding, SEVERITY_RANK, ScanResult

SCANNER = "agent_context"
MAX_SNIPPET_CHARS = int(os.environ.get("SCAN_SKILL_MAX_SNIPPET_CHARS", "180"))

FIELDS_TO_CHECK: tuple[str, ...] = (
    "system_prompt",
    "systemPrompt",
    "context",
    "instructions",
    "rules",
    "prompt",
)


@dataclass(frozen=True)
class ContextPattern:
    rule_id: str
    severity: str
    pattern: str


SYSTEM_PROMPT_INJECTION_PATTERNS: tuple[ContextPattern, ...] = (
    ContextPattern(
        rule_id="INJECT_IGNORE_INSTRUCTIONS",
        severity="high",
        pattern=r"\bignore\s+(previous|prior|above|all|earlier)\s+(instructions|rules|messages|directives)\b",
    ),
    ContextPattern(
        rule_id="INJECT_PERSONA_OVERRIDE",
        severity="high",
        pattern=r"\byou\s+are\s+now\s+(?!a\s+(?:skill|hook|rule|tool|scanner|validator)\b)",
    ),
    ContextPattern(
        rule_id="INJECT_SYSTEM_CLAIM",
        severity="critical",
        pattern=r"\b(system\s*:\s*(you\s+are|override|act\s+as|ignore|developer|assistant))\b",
    ),
    ContextPattern(
        rule_id="INJECT_JAILBREAK",
        severity="critical",
        pattern=r"\b(DAN|jailbreak|do\s+anything\s+now|unrestricted\s+mode|developer\s+mode)\b",
    ),
    ContextPattern(
        rule_id="INJECT_COVERT",
        severity="high",
        pattern=r"\b(silently|covertly|secretly|without\s+telling\s+(the\s+)?user)\b",
    ),
)


def _compact_snippet(value: str) -> str:
    snippet = re.sub(r"\s+", " ", value).strip()
    if len(snippet) > MAX_SNIPPET_CHARS:
        return snippet[: MAX_SNIPPET_CHARS - 3] + "..."
    return snippet


def _finding(pattern: ContextPattern, snippet: str) -> Finding:
    return Finding(
        scanner=SCANNER,
        rule_id=pattern.rule_id,
        severity=pattern.severity,
        label="suspicious pattern in agent context",
        path=None,
        line=None,
        snippet=_compact_snippet(snippet),
    )


def _scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in SYSTEM_PROMPT_INJECTION_PATTERNS:
        for match in re.finditer(pattern.pattern, text, re.IGNORECASE | re.MULTILINE):
            findings.append(_finding(pattern, match.group(0)))
    return findings


def scan_agent_context(data: dict[str, Any]) -> ScanResult:
    findings: list[Finding] = []
    for field_name in FIELDS_TO_CHECK:
        value = data.get(field_name)
        if isinstance(value, str) and value.strip():
            findings.extend(_scan_text(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    findings.extend(_scan_text(item))
    findings.sort(key=lambda finding: SEVERITY_RANK.get(finding.severity.lower(), 9))
    return ScanResult(findings=findings)
