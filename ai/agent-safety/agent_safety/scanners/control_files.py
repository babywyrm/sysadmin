from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from agent_safety.models import Finding, SEVERITY_RANK, ScanResult

SCANNER = "control_files"

MAX_FILE_BYTES = int(os.environ.get("SCAN_SKILL_MAX_BYTES", "1048576"))
MAX_FINDINGS = int(os.environ.get("SCAN_SKILL_MAX_FINDINGS", "25"))
MAX_SNIPPET_CHARS = int(os.environ.get("SCAN_SKILL_MAX_SNIPPET_CHARS", "180"))

CONTROL_PATH_MARKERS: tuple[str, ...] = (
    "/.cursor/skills/",
    "/.cursor/plugins/",
    "/.cursor/hooks/",
    "/.cursor/rules/",
)

CONTROL_BASENAMES: frozenset[str] = frozenset(
    {
        "SKILL.MD",
        "RULE.MD",
        "AGENTS.MD",
        "AGENT.MD",
        "PLUGIN.MD",
        "HOOK.MD",
    }
)

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

_PLACEHOLDER_URL_RE = re.compile(
    r"^https?://(TARGET|<[^>]+>|example\.com|your[-_]?domain)",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s<>)\"']+", re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    label: str
    severity: str
    pattern: str
    flags: int = re.IGNORECASE | re.MULTILINE


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
            r"don['\u2019]?\s+(tell|inform|mention|show|reveal|disclose)"
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
    ),
    Rule(
        rule_id="HEX_BLOB",
        severity="low",
        label="long hex-like blob",
        pattern=r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{160,}(?![A-Fa-f0-9])",
    ),
    Rule(
        rule_id="DATA_URI_PAYLOAD",
        severity="medium",
        label="embedded data URI payload",
        pattern=r"data:[a-zA-Z0-9.+/-]+;base64,[A-Za-z0-9+/=]{80,}",
    ),
)


def _normalize_path(path: str | Path) -> str:
    return str(path).replace("\\", "/")


def is_control_file(path: str | Path) -> bool:
    normalized = _normalize_path(path)
    if not normalized:
        return False
    if Path(normalized).name.upper() in CONTROL_BASENAMES:
        return True
    lowered = normalized.lower()
    return any(marker in lowered for marker in CONTROL_PATH_MARKERS)


def _strip_code_blocks(content: str) -> str:
    content = re.sub(r"```[\s\S]*?```", "\n[CODE_BLOCK]\n", content)
    return re.sub(r"`[^`\n]+`", "[INLINE_CODE]", content)


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _compact_snippet(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > MAX_SNIPPET_CHARS:
        return value[: MAX_SNIPPET_CHARS - 3] + "..."
    return value


def _trusted_url_patterns() -> list[re.Pattern[str]]:
    patterns = list(DEFAULT_TRUSTED_URL_PATTERNS)
    extra = os.environ.get("SCAN_SKILL_TRUSTED_URL_REGEX", "").strip()
    if extra:
        patterns.extend(p.strip() for p in extra.split(",") if p.strip())
    return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]


def _is_trusted_url(url: str) -> bool:
    if _PLACEHOLDER_URL_RE.match(url):
        return True
    return any(pattern.search(url) for pattern in _trusted_url_patterns())


def _finding(
    *,
    rule_id: str,
    severity: str,
    label: str,
    path: str | None,
    line: int | None,
    snippet: str,
) -> Finding:
    return Finding(
        scanner=SCANNER,
        rule_id=rule_id,
        severity=severity,
        label=label,
        path=path,
        line=line,
        snippet=snippet,
    )


def _scan_rules(text: str, rules: Iterable[Rule], path: str | None) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        regex = re.compile(rule.pattern, rule.flags)
        for match in regex.finditer(text):
            findings.append(
                _finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    label=rule.label,
                    path=path,
                    line=_line_for_offset(text, match.start()),
                    snippet=_compact_snippet(match.group(0)),
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


def _scan_urls(prose: str, path: str | None) -> list[Finding]:
    findings: list[Finding] = []
    for match in _URL_RE.finditer(prose):
        url = match.group(0).rstrip(".,;:")
        if _is_trusted_url(url):
            continue
        findings.append(
            _finding(
                rule_id="EXTERNAL_URL",
                severity="medium",
                label="external URL outside trusted allowlist",
                path=path,
                line=_line_for_offset(prose, match.start()),
                snippet=_compact_snippet(url),
            )
        )
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, int | None, str, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.line, finding.snippet, finding.path)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    result.sort(
        key=lambda finding: (
            SEVERITY_RANK.get(finding.severity.lower(), 9),
            finding.path or "",
            finding.line or 0,
        )
    )
    return result[:MAX_FINDINGS]


def scan_control_text(text: str, path: str | None = None) -> ScanResult:
    prose = _strip_code_blocks(text)
    findings: list[Finding] = []
    findings.extend(_scan_rules(prose, PROSE_RULES, path))
    findings.extend(_scan_urls(prose, path))
    findings.extend(_scan_rules(text, RAW_RULES, path))
    return ScanResult(findings=_dedupe_findings(findings))


def scan_control_file(path: str | Path) -> ScanResult:
    target = Path(path).expanduser()
    display_path = str(path)
    try:
        if not target.exists():
            return ScanResult(
                findings=[
                    _finding(
                        rule_id="READ_ERROR",
                        severity="high",
                        label="could not read file",
                        path=display_path,
                        line=1,
                        snippet="file does not exist",
                    )
                ],
                errors=["file does not exist"],
            )
        if not target.is_file():
            return ScanResult(
                findings=[
                    _finding(
                        rule_id="READ_ERROR",
                        severity="high",
                        label="could not read file",
                        path=display_path,
                        line=1,
                        snippet="path is not a regular file",
                    )
                ],
                errors=["path is not a regular file"],
            )
        size = target.stat().st_size
        if size > MAX_FILE_BYTES:
            error = f"file too large to scan safely: {size} bytes > {MAX_FILE_BYTES} bytes"
            return ScanResult(
                findings=[
                    _finding(
                        rule_id="READ_ERROR",
                        severity="high",
                        label="could not read file",
                        path=display_path,
                        line=1,
                        snippet=error,
                    )
                ],
                errors=[error],
            )
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        error = f"could not read file: {exc}"
        return ScanResult(
            findings=[
                _finding(
                    rule_id="READ_ERROR",
                    severity="high",
                    label="could not read file",
                    path=display_path,
                    line=1,
                    snippet=error,
                )
            ],
            errors=[error],
        )
    return scan_control_text(text, display_path)
