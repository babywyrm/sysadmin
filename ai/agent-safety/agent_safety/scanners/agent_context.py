from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from agent_safety.models import SEVERITY_RANK, Finding, ScanResult

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


def _iter_strings(value: Any) -> Iterator[str]:
    """Yield every string leaf, recursing through lists and dicts.

    Agent context often nests the real text inside message objects
    (``[{"role": ..., "content": ...}]``) or sub-dicts; a flat scan misses it.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def scan_agent_context(data: dict[str, Any]) -> ScanResult:
    findings: list[Finding] = []
    for field_name in FIELDS_TO_CHECK:
        for text in _iter_strings(data.get(field_name)):
            if text.strip():
                findings.extend(_scan_text(text))
    findings.sort(key=lambda finding: SEVERITY_RANK.get(finding.severity.lower(), 9))
    return ScanResult(findings=findings)
