#!/usr/bin/env python3
"""
scan-skill.py

Defensive pre-read scanner for Cursor/agent skill, rule, hook, and plugin
markdown files.

Purpose:
    Scan SKILL.md, RULE.md, AGENTS.md, and files under known Cursor skill/plugin
    paths before an agent reads them.

Hook:
    Designed for a beforeReadFile-style hook.

Returns:
    {"permission": "allow"}
        if the file is outside scope or no red flags are found.

    {"permission": "ask", "user_message": "...", "agent_message": "..."}
        if suspicious patterns are found.

Notes:
    - This is a heuristic scanner, not a parser or sandbox.
    - It intentionally strips fenced and inline code before scanning prose-heavy
      instruction patterns to reduce false positives from examples.
    - Obfuscation checks scan the raw file.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MAX_FILE_BYTES = int(os.environ.get("SCAN_SKILL_MAX_BYTES", "1048576"))  # 1 MiB
MAX_FINDINGS = int(os.environ.get("SCAN_SKILL_MAX_FINDINGS", "25"))
MAX_SNIPPET_CHARS = int(os.environ.get("SCAN_SKILL_MAX_SNIPPET_CHARS", "180"))

DEFAULT_TRUSTED_URL_PATTERNS = (
    r"^https?://modelcontextprotocol\.io(?:/|$)",
    r"^https?://spec\.modelcontextprotocol\.io(?:/|$)",
    r"^https?://github\.com/babywyrm(?:/|$)",
    r"^https?://(?:www\.)?github\.com/modelcontextprotocol(?:/|$)",
    r"^https?://shields\.io(?:/|$)",
    r"^https?://img\.shields\.io(?:/|$)",
    r"^https?://localhost(?::\d+)?(?:/|$)",
    r"^https?://127\.0\.0\.1(?::\d+)?(?:/|$)",
)

SKILL_PATH_MARKERS = (
    "/.cursor/skills/",
    "/.cursor/plugins/",
    "/.cursor/hooks/",
    "/.cursor/rules/",
)

SKILL_BASENAMES = {
    "SKILL.MD",
    "RULE.MD",
    "AGENTS.MD",
    "AGENT.MD",
    "PLUGIN.MD",
    "HOOK.MD",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    label: str
    severity: str
    pattern: str
    target: str = "prose"
    flags: int = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class Finding:
    rule_id: str
    label: str
    severity: str
    line: int
    snippet: str


PROSE_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="NET_FETCH_INSTRUCTION",
        severity="medium",
        label="instruction to run a network fetch",
        pattern=r"\b(run|execute|call|invoke|perform)\b.{0,80}\b(curl|wget|fetch|requests\.get|httpx\.get|urllib\.request)\b",
    ),
    Rule(
        rule_id="SHELL_EXEC_INSTRUCTION",
        severity="medium",
        label="instruction to execute shell commands",
        pattern=r"\b(run|execute|spawn|invoke)\b.{0,80}\b(bash|sh|zsh|python\s+-c|perl\s+-e|ruby\s+-e|osascript|powershell|pwsh)\b",
    ),
    Rule(
        rule_id="HIDE_FROM_USER",
        severity="high",
        label="instruction to hide behavior from the user",
        pattern=r"don['\u2019]?t\s+(tell|inform|mention|show|reveal|disclose)\s+(the\s+)?user",
    ),
    Rule(
        rule_id="COVERT_BEHAVIOR",
        severity="high",
        label="instruction to act covertly",
        pattern=r"\b(silently|covertly|secretly|stealthily|without\s+notif\w+|without\s+telling\s+(the\s+)?user|without\s+user\s+consent)\b",
    ),
    Rule(
        rule_id="EXFILTRATION",
        severity="critical",
        label="possible exfiltration instruction",
        pattern=r"\b(exfiltrat\w+|steal\s+\w+|harvest\s+(token|tokens|cred|creds|credential|credentials|secret|secrets|key|keys|password|passwords))\b",
    ),
    Rule(
        rule_id="PROMPT_IGNORE_INSTRUCTIONS",
        severity="high",
        label="prompt injection: ignore previous instructions",
        pattern=r"\bignore\s+(previous|prior|above|all|earlier)\s+(instructions|rules|messages|directives)\b",
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
        pattern=r"\b(system\s*:\s*(you\s+are|override|act\s+as|ignore|developer|assistant))\b",
    ),
    Rule(
        rule_id="PROMPT_NEW_SYSTEM_INSTRUCTION",
        severity="high",
        label="prompt injection: new system instruction directive",
        pattern=r"\bnew\s+(system\s+)?instruction\b(?!\s+(example|format|set|type|section|template))",
    ),
    Rule(
        rule_id="TOOL_PERMISSION_OVERRIDE",
        severity="high",
        label="instruction to override tool permissions",
        pattern=r"\b(always|automatically|silently)\s+(allow|approve|grant|bypass)\b.{0,80}\b(tool|command|permission|approval|sandbox|policy)\b",
    ),
    Rule(
        rule_id="SECRET_ACCESS",
        severity="high",
        label="instruction to access secrets or credentials",
        pattern=r"\b(read|open|dump|print|extract|collect)\b.{0,80}\b(\.env|secret|secrets|token|tokens|credential|credentials|password|passwords|ssh\s+key|api\s+key)\b",
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

URL_RE = re.compile(r"https?://[^\s<>)\"']+", re.IGNORECASE)


def load_input() -> dict[str, Any]:
    try:
        data = json.load(sys.stdin)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def is_skill_file(path: str) -> bool:
    if not path:
        return False

    normalized = normalize_path(path)
    lowered = normalized.lower()
    basename = os.path.basename(normalized).upper()

    if basename in SKILL_BASENAMES:
        return True

    return any(marker in lowered for marker in SKILL_PATH_MARKERS)


def short_path(path: str) -> str:
    normalized = normalize_path(path)
    parts = [p for p in normalized.split("/") if p]
    if len(parts) >= 3:
        return "/".join(parts[-3:])
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return normalized


def read_file(path: str) -> tuple[str | None, str | None]:
    try:
        p = Path(path).expanduser()

        if not p.exists():
            return None, "file does not exist"

        if not p.is_file():
            return None, "path is not a regular file"

        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            return None, f"file is too large to scan safely: {size} bytes > {MAX_FILE_BYTES} bytes"

        return p.read_text(encoding="utf-8", errors="replace"), None

    except Exception as exc:
        return None, f"could not read file: {exc}"


def strip_code_blocks(content: str) -> str:
    """
    Remove fenced and inline code before prose scanning.

    This reduces false positives where a skill document shows bad examples
    inside code fences.
    """
    content = re.sub(r"```[\s\S]*?```", "\n[CODE_BLOCK]\n", content)
    content = re.sub(r"`[^`\n]+`", "[INLINE_CODE]", content)
    return content


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def compact_snippet(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > MAX_SNIPPET_CHARS:
        return value[: MAX_SNIPPET_CHARS - 3] + "..."
    return value


def trusted_url_patterns() -> list[re.Pattern[str]]:
    extra = os.environ.get("SCAN_SKILL_TRUSTED_URL_REGEX", "").strip()
    patterns = list(DEFAULT_TRUSTED_URL_PATTERNS)

    if extra:
        patterns.extend(part.strip() for part in extra.split(",") if part.strip())

    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            continue

    return compiled


def is_trusted_url(url: str) -> bool:
    if url.startswith(("http://TARGET", "https://TARGET")):
        return True

    if url.startswith(("http://<", "https://<")):
        return True

    return any(pattern.search(url) for pattern in trusted_url_patterns())


def scan_urls(prose: str) -> list[Finding]:
    findings: list[Finding] = []

    for match in URL_RE.finditer(prose):
        url = match.group(0).rstrip(".,;:")
        if is_trusted_url(url):
            continue

        findings.append(
            Finding(
                rule_id="EXTERNAL_URL",
                severity="medium",
                label="external URL in prose outside trusted allowlist",
                line=line_number_for_offset(prose, match.start()),
                snippet=compact_snippet(url),
            )
        )

        if len(findings) >= MAX_FINDINGS:
            break

    return findings


def scan_rules(text: str, rules: Iterable[Rule]) -> list[Finding]:
    findings: list[Finding] = []

    for rule in rules:
        try:
            regex = re.compile(rule.pattern, rule.flags)
        except re.error as exc:
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
                    line=line_number_for_offset(text, match.start()),
                    snippet=compact_snippet(match.group(0)),
                )
            )

            if len(findings) >= MAX_FINDINGS:
                return findings

    return findings


def severity_rank(severity: str) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }
    return order.get(severity.lower(), 9)


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    result: list[Finding] = []

    for finding in findings:
        key = (finding.rule_id, finding.line, finding.snippet)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)

    result.sort(key=lambda f: (severity_rank(f.severity), f.line, f.rule_id))
    return result[:MAX_FINDINGS]


def scan_file(path: str) -> tuple[list[Finding], str | None]:
    raw, error = read_file(path)
    if error:
        return [
            Finding(
                rule_id="READ_ERROR",
                severity="high",
                label="could not read file",
                line=1,
                snippet=error,
            )
        ], error

    assert raw is not None

    prose = strip_code_blocks(raw)

    findings: list[Finding] = []
    findings.extend(scan_rules(prose, PROSE_RULES))
    findings.extend(scan_urls(prose))
    findings.extend(scan_rules(raw, RAW_RULES))

    return dedupe_findings(findings), None


def format_findings(findings: list[Finding]) -> str:
    lines: list[str] = []

    for finding in findings:
        lines.append(
            f"- [{finding.severity.upper()}] {finding.rule_id} "
            f"line {finding.line}: {finding.label}; matched: {finding.snippet!r}"
        )

    if len(findings) >= MAX_FINDINGS:
        lines.append(f"- Output truncated at {MAX_FINDINGS} findings.")

    return "\n".join(lines)


def extract_path(data: dict[str, Any]) -> str:
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


def main() -> int:
    data = load_input()
    path = extract_path(data)

    if not is_skill_file(path):
        emit({"permission": "allow"})
        return 0

    findings, _ = scan_file(path)

    if not findings:
        emit({"permission": "allow"})
        return 0

    display_path = short_path(path)
    finding_text = format_findings(findings)

    user_msg = (
        f"Security scan flagged `{display_path}` before the agent reads it.\n\n"
        f"Findings: {len(findings)}\n\n"
        f"{finding_text}\n\n"
        "Review the raw file before proceeding. Allow only if you trust the "
        "source and have checked that these are examples or benign documentation."
    )

    agent_msg = (
        f"scan-skill hook flagged {display_path} with {len(findings)} finding(s). "
        "Paused for user review."
    )

    emit(
        {
            "permission": "ask",
            "user_message": user_msg,
            "agent_message": agent_msg,
            "metadata": {
                "scanner": "scan-skill.py",
                "path": display_path,
                "finding_count": len(findings),
                "max_findings": MAX_FINDINGS,
            },
        }
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
