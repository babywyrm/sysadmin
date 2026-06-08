#!/usr/bin/env python3
"""
scan-skill.py

Defensive pre-read scanner for Cursor/agent skill, rule, hook, and plugin
markdown files.

Purpose:
    Scan SKILL.md, RULE.md, AGENTS.md, and files under known Cursor
    skill/plugin paths before an agent reads them.

Hook:
    Designed for a beforeReadFile-style hook.

Returns:
    {"permission": "allow"}
        if the file is outside scope or no red flags are found.

    {"permission": "ask", "user_message": "...", "agent_message": "..."}
        if suspicious patterns are found.

Notes:
    - Heuristic scanner, not a parser or sandbox.
    - Strips fenced/inline code before prose scanning to reduce false positives.
    - Obfuscation checks scan the raw file.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = int(os.environ.get("SCAN_SKILL_MAX_BYTES", "1048576"))  # 1 MiB
MAX_FINDINGS = int(os.environ.get("SCAN_SKILL_MAX_FINDINGS", "25"))
MAX_SNIPPET_CHARS = int(os.environ.get("SCAN_SKILL_MAX_SNIPPET_CHARS", "180"))

SCANNER_NAME = "scan-skill.py"

logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger(SCANNER_NAME)

# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------

SKILL_PATH_MARKERS: tuple[str, ...] = (
    "/.cursor/skills/",
    "/.cursor/plugins/",
    "/.cursor/hooks/",
    "/.cursor/rules/",
)

SKILL_BASENAMES: frozenset[str] = frozenset(
    {
        "SKILL.MD",
        "RULE.MD",
        "AGENTS.MD",
        "AGENT.MD",
        "PLUGIN.MD",
        "HOOK.MD",
    }
)

# ---------------------------------------------------------------------------
# Trusted URL allowlist
# ---------------------------------------------------------------------------

DEFAULT_TRUSTED_URL_PATTERNS: tuple[str, ...] = (
    r"^https?://modelcontextprotocol\.io(?:/|$)",
    r"^https?://spec\.modelcontextprotocol\.io(?:/|$)",
    r"^https?://github\.com/babywyrm(?:/|$)",
    r"^https?://(?:www\.)?github\.com/modelcontextprotocol(?:/|$)",
    r"^https?://shields\.io(?:/|$)",
    r"^https?://img\.shields\.io(?:/|$)",
    r"^https?://localhost(?::\d+)?(?:/|$)",
    r"^https?://127\.0\.0\.1(?::\d+)?(?:/|$)",
)

# Matches placeholder URLs used in documentation examples
_PLACEHOLDER_URL_RE = re.compile(
    r"^https?://(TARGET|<[^>]+>|example\.com|your[-_]?domain)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    rule_id: str
    label: str
    severity: str
    pattern: str
    target: str = "prose"  # "prose" | "raw"
    flags: int = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class Finding:
    rule_id: str
    label: str
    severity: str
    line: int
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "label": self.label,
            "line": self.line,
            "snippet": self.snippet,
        }

    def format(self) -> str:
        return (
            f"- [{self.severity.upper()}] {self.rule_id} "
            f"line {self.line}: {self.label}; matched: {self.snippet!r}"
        )


@dataclass
class ScanResult:
    path: str
    findings: list[Finding] = field(default_factory=list)
    read_error: str | None = None

    @property
    def display_path(self) -> str:
        return _short_path(self.path)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def truncated(self) -> bool:
        return len(self.findings) >= MAX_FINDINGS


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

PROSE_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="NET_FETCH_INSTRUCTION",
        severity="medium",
        label="instruction to run a network fetch",
        pattern=(
            r"\b(run|execute|call|invoke|perform)\b.{0,80}"
            r"\b(curl|wget|fetch|requests\.get|httpx\.get|urllib\.request)\b"
        ),
    ),
    Rule(
        rule_id="SHELL_EXEC_INSTRUCTION",
        severity="medium",
        label="instruction to execute shell commands",
        pattern=(
            r"\b(run|execute|spawn|invoke)\b.{0,80}"
            r"\b(bash|sh|zsh|python\s+-c|perl\s+-e|ruby\s+-e"
            r"|osascript|powershell|pwsh)\b"
        ),
    ),
    Rule(
        rule_id="HIDE_FROM_USER",
        severity="high",
        label="instruction to hide behavior from the user",
        pattern=(
            r"don['\u2019]?t\s+(tell|inform|mention|show|reveal|disclose)"
            r"\s+(the\s+)?user"
        ),
    ),
    Rule(
        rule_id="COVERT_BEHAVIOR",
        severity="high",
        label="instruction to act covertly",
        pattern=(
            r"\b(silently|covertly|secretly|stealthily"
            r"|without\s+notif\w+"
            r"|without\s+telling\s+(the\s+)?user"
            r"|without\s+user\s+consent)\b"
        ),
    ),
    Rule(
        rule_id="EXFILTRATION",
        severity="critical",
        label="possible exfiltration instruction",
        pattern=(
            r"\b(exfiltrat\w+"
            r"|steal\s+\w+"
            r"|harvest\s+(token|tokens|cred|creds|credential|credentials"
            r"|secret|secrets|key|keys|password|passwords))\b"
        ),
    ),
    Rule(
        rule_id="PROMPT_IGNORE_INSTRUCTIONS",
        severity="high",
        label="prompt injection: ignore previous instructions",
        pattern=(
            r"\bignore\s+(previous|prior|above|all|earlier)"
            r"\s+(instructions|rules|messages|directives)\b"
        ),
    ),
    Rule(
        rule_id="PROMPT_PERSONA_OVERRIDE",
        severity="medium",
        label="prompt injection: persona override",
        pattern=r"\byou\s+are\s+now\s+(?!a\s+(?:skill|hook|rule|tool|scanner|validator)\b)",
    ),
    Rule(
        rule_id="PROMPT_SYSTEM_CLAIM",
        severity="high",
        label="prompt injection: system role claim",
        pattern=(
            r"\b(system\s*:\s*"
            r"(you\s+are|override|act\s+as|ignore|developer|assistant))\b"
        ),
    ),
    Rule(
        rule_id="PROMPT_NEW_SYSTEM_INSTRUCTION",
        severity="high",
        label="prompt injection: new system instruction directive",
        pattern=(
            r"\bnew\s+(system\s+)?instruction\b"
            r"(?!\s+(example|format|set|type|section|template))"
        ),
    ),
    Rule(
        rule_id="TOOL_PERMISSION_OVERRIDE",
        severity="high",
        label="instruction to override tool permissions",
        pattern=(
            r"\b(always|automatically|silently)\s+(allow|approve|grant|bypass)\b"
            r".{0,80}\b(tool|command|permission|approval|sandbox|policy)\b"
        ),
    ),
    Rule(
        rule_id="SECRET_ACCESS",
        severity="high",
        label="instruction to access secrets or credentials",
        pattern=(
            r"\b(read|open|dump|print|extract|collect)\b.{0,80}"
            r"\b(\.env|secret|secrets|token|tokens|credential|credentials"
            r"|password|passwords|ssh\s+key|api\s+key)\b"
        ),
    ),
)

RAW_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="BASE64_BLOB",
        severity="medium",
        label="long base64-like blob",
        pattern=r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])",
        target="raw",
    ),
    Rule(
        rule_id="HEX_BLOB",
        severity="low",
        label="long hex-like blob",
        pattern=r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{160,}(?![A-Fa-f0-9])",
        target="raw",
    ),
    Rule(
        rule_id="DATA_URI_PAYLOAD",
        severity="medium",
        label="embedded data URI payload",
        pattern=r"data:[a-zA-Z0-9.+/-]+;base64,[A-Za-z0-9+/=]{80,}",
        target="raw",
    ),
)

_URL_RE = re.compile(r"https?://[^\s<>)\"']+", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def _short_path(path: str) -> str:
    parts = [p for p in _normalize_path(path).split("/") if p]
    return "/".join(parts[-3:]) if len(parts) >= 3 else "/".join(parts)


def is_skill_file(path: str) -> bool:
    """Return True if the path looks like an agent skill/rule/plugin file."""
    if not path:
        return False
    normalized = _normalize_path(path)
    basename = os.path.basename(normalized).upper()
    if basename in SKILL_BASENAMES:
        return True
    lowered = normalized.lower()
    return any(marker in lowered for marker in SKILL_PATH_MARKERS)


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def _read_file(path: str) -> tuple[str | None, str | None]:
    """
    Read a file and return (content, error).
    On success, error is None. On failure, content is None.
    """
    try:
        p = Path(path).expanduser()
        if not p.exists():
            return None, "file does not exist"
        if not p.is_file():
            return None, "path is not a regular file"
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            return None, (
                f"file too large to scan safely: {size} bytes > {MAX_FILE_BYTES} bytes"
            )
        return p.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"could not read file: {exc}"


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


def _strip_code_blocks(content: str) -> str:
    """
    Replace fenced and inline code with placeholders.
    Reduces false positives from examples shown inside skill docs.
    """
    content = re.sub(r"```[\s\S]*?```", "\n[CODE_BLOCK]\n", content)
    content = re.sub(r"`[^`\n]+`", "[INLINE_CODE]", content)
    return content


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _compact_snippet(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > MAX_SNIPPET_CHARS:
        return value[: MAX_SNIPPET_CHARS - 3] + "..."
    return value


# ---------------------------------------------------------------------------
# URL trust
# ---------------------------------------------------------------------------


def _build_trusted_url_patterns() -> list[re.Pattern[str]]:
    patterns = list(DEFAULT_TRUSTED_URL_PATTERNS)
    extra = os.environ.get("SCAN_SKILL_TRUSTED_URL_REGEX", "").strip()
    if extra:
        patterns.extend(p.strip() for p in extra.split(",") if p.strip())

    compiled: list[re.Pattern[str]] = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error as exc:
            log.warning("Invalid trusted URL pattern %r: %s", pat, exc)
    return compiled


_TRUSTED_URL_PATTERNS: list[re.Pattern[str]] = _build_trusted_url_patterns()


def _is_trusted_url(url: str) -> bool:
    if _PLACEHOLDER_URL_RE.match(url):
        return True
    return any(p.search(url) for p in _TRUSTED_URL_PATTERNS)


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------


def _scan_rules(text: str, rules: Iterable[Rule]) -> list[Finding]:
    findings: list[Finding] = []

    for rule in rules:
        try:
            regex = re.compile(rule.pattern, rule.flags)
        except re.error as exc:
            log.warning("Rule %s failed to compile: %s", rule.rule_id, exc)
            findings.append(
                Finding(
                    rule_id="SCANNER_RULE_ERROR",
                    severity="low",
                    label=f"scanner rule failed to compile: {rule.rule_id}",
                    line=1,
                    snippet=str(exc),
                )
            )
            continue

        for match in regex.finditer(text):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    label=rule.label,
                    line=_line_for_offset(text, match.start()),
                    snippet=_compact_snippet(match.group(0)),
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return findings

    return findings


def _scan_urls(prose: str) -> list[Finding]:
    findings: list[Finding] = []

    for match in _URL_RE.finditer(prose):
        url = match.group(0).rstrip(".,;:")
        if _is_trusted_url(url):
            continue
        findings.append(
            Finding(
                rule_id="EXTERNAL_URL",
                severity="medium",
                label="external URL outside trusted allowlist",
                line=_line_for_offset(prose, match.start()),
                snippet=_compact_snippet(url),
            )
        )
        if len(findings) >= MAX_FINDINGS:
            break

    return findings


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    result: list[Finding] = []

    for f in findings:
        key = (f.rule_id, f.line, f.snippet)
        if key in seen:
            continue
        seen.add(key)
        result.append(f)

    result.sort(key=lambda f: (SEVERITY_RANK.get(f.severity.lower(), 9), f.line))
    return result[:MAX_FINDINGS]


def scan_file(path: str) -> ScanResult:
    """Scan a skill/rule/plugin file and return a ScanResult."""
    result = ScanResult(path=path)
    raw, error = _read_file(path)

    if error:
        log.warning("Read error for %r: %s", path, error)
        result.read_error = error
        result.findings.append(
            Finding(
                rule_id="READ_ERROR",
                severity="high",
                label="could not read file",
                line=1,
                snippet=error,
            )
        )
        return result

    assert raw is not None
    prose = _strip_code_blocks(raw)

    all_findings: list[Finding] = []
    all_findings.extend(_scan_rules(prose, PROSE_RULES))
    all_findings.extend(_scan_urls(prose))
    all_findings.extend(_scan_rules(raw, RAW_RULES))

    result.findings = _dedupe_findings(all_findings)
    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _format_findings_text(result: ScanResult) -> str:
    lines = [f.format() for f in result.findings]
    if result.truncated:
        lines.append(f"- Output truncated at {MAX_FINDINGS} findings.")
    return "\n".join(lines)


def _build_ask_response(result: ScanResult) -> dict[str, Any]:
    finding_text = _format_findings_text(result)
    dp = result.display_path

    user_msg = (
        f"Security scan flagged `{dp}` before the agent reads it.\n\n"
        f"Findings: {len(result.findings)}\n\n"
        f"{finding_text}\n\n"
        "Review the raw file before proceeding. Allow only if you trust the "
        "source and have verified these are examples or benign documentation."
    )

    agent_msg = (
        f"{SCANNER_NAME} flagged {dp} with {len(result.findings)} finding(s). "
        "Paused for user review."
    )

    return {
        "permission": "ask",
        "user_message": user_msg,
        "agent_message": agent_msg,
        "metadata": {
            "scanner": SCANNER_NAME,
            "path": dp,
            "finding_count": len(result.findings),
            "max_findings": MAX_FINDINGS,
            "truncated": result.truncated,
            "findings": [f.to_dict() for f in result.findings],
        },
    }


# ---------------------------------------------------------------------------
# Input / output
# ---------------------------------------------------------------------------


def _load_input() -> dict[str, Any]:
    try:
        data = json.load(sys.stdin)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError as exc:
        log.warning("Failed to parse stdin as JSON: %s", exc)
        return {}


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _extract_path(data: dict[str, Any]) -> str:
    candidates = (
        "path",
        "file_path",
        "filePath",
        "filename",
        "absolutePath",
        "absolute_path",
    )
    for key in candidates:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    file_obj = data.get("file")
    if isinstance(file_obj, dict):
        for key in candidates:
            value = file_obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    return ""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    data = _load_input()
    path = _extract_path(data)

    if not is_skill_file(path):
        _emit({"permission": "allow"})
        return 0

    result = scan_file(path)

    if not result.has_findings:
        _emit({"permission": "allow"})
        return 0

    _emit(_build_ask_response(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
