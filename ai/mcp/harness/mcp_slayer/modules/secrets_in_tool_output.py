"""MCP-T07: Secrets in Tool Output.

Tools that return credentials, tokens, connection strings, or key material in
their plaintext response expose secrets to every layer that logs or forwards
that output — the agent context window, downstream LLMs, observability pipelines,
and any human who inspects a transcript. Even a single unfiltered credential
in a response is immediately actionable by an attacker.

Maps to playbook threat MCP-T07 (Secrets in Tool Output) / OWASP MCP07
(Insufficient Authentication — weak output filtering).
"""

from __future__ import annotations

import json
import re
from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

_TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _call(tool_name: str, args: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args or {}},
    }


# Credential patterns ordered by specificity / severity.
_PATTERNS: list[tuple[str, str, Severity]] = [
    # Cloud provider keys
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", Severity.CRITICAL),
    (r"(?i)aws.{0,30}secret.{0,10}['\"]?([A-Za-z0-9+/]{40})", "AWS secret", Severity.CRITICAL),
    # Tokens and signed strings
    (r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}", "JWT", Severity.HIGH),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token", Severity.CRITICAL),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub Actions token", Severity.CRITICAL),
    (r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}", "Bearer token in output", Severity.HIGH),
    # Private keys
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key block", Severity.CRITICAL),
    # Connection strings
    (r"(?i)(postgresql|mysql|mongodb|redis|amqp)://[^@\s]{3,}@[^\s\"']+", "Database/broker URL with credentials", Severity.CRITICAL),
    # Generic secret-like KV
    (r"(?i)(?:password|passwd|secret|api[-_]?key|token)\s*[=:]\s*['\"]?([^\s'\"]{8,})", "Credential key-value pair", Severity.HIGH),
]

_COMPILED: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(p), label, sev) for p, label, sev in _PATTERNS
]


class SecretsInToolOutputModule(AttackModule):
    """Invokes tools and scans their plaintext responses for credential material.

    Iterates available tools, calls each with minimal or empty arguments, and
    checks the raw response text against a pattern catalogue. Findings are
    per-tool, with the matched pattern as evidence.
    """

    id: ClassVar[str] = "secrets-in-tool-output"
    name: ClassVar[str] = "Secrets in Tool Output"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.INSUFFICIENT_AUTH
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.SECRETS_IN_TOOL_OUTPUT,
    ]
    description: ClassVar[str] = (
        "Calls available tools and scans responses for credentials, tokens, "
        "and key material that should never appear in plaintext output."
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.HIGH,
        Severity.CRITICAL,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.ctx.config.tools:
            tool_findings = await self._execute_with_safeguards(
                self._probe_tool, tool
            )
            findings.extend(tool_findings)
        return findings

    async def _probe_tool(self, tool) -> list[Finding]:
        # Enumerate tools on this server.
        base = str(tool.base_url).rstrip("/")
        for ep in tool.schema_endpoints:
            url = f"{base}{ep}"
            async with self.ctx.http_client.post(
                url,
                json=_TOOLS_LIST,
                headers=self.ctx.get_auth_headers(tool.auth_profile),
            ) as r:
                if r.status != 200:
                    continue
                body = await r.json(content_type=None)
            tool_list = _extract_tool_names(body)
            findings: list[Finding] = []
            for tool_name in tool_list:
                f = await self._invoke_and_scan(tool, url, tool_name)
                if f:
                    findings.append(f)
            return findings
        return []

    async def _invoke_and_scan(self, tool, endpoint: str, tool_name: str) -> Finding | None:
        async with self.ctx.http_client.post(
            endpoint,
            json=_call(tool_name),
            headers=self.ctx.get_auth_headers(tool.auth_profile),
        ) as r:
            raw = await r.text()

        matches = _scan_for_secrets(raw)
        if not matches:
            return None

        worst = max(matches, key=lambda m: list(Severity).index(m[1]))
        label, severity, snippet = worst
        return self._create_finding(
            title=f"Credential exposure: '{label}' in output of tool '{tool_name}'",
            severity=severity,
            target_url=endpoint,
            outcome=AttackOutcome.VULNERABLE,
            target_tool=tool_name,
            description=(
                f"Tool '{tool_name}' on server '{tool.name}' returned content "
                f"matching the pattern for '{label}'. Credentials in plaintext "
                f"responses are captured by the agent context window, logged by "
                f"observability pipelines, and visible in any transcript replay."
            ),
            impact=(
                "Exposed credentials can be extracted from logs, context dumps, "
                "or LLM memory and used for lateral movement or persistent access."
            ),
            recommendation=(
                "Apply output filtering at the MCP gateway: redact credential "
                "patterns before returning tool results. Never return raw secret "
                "values — return masked representations or confirm-only receipts. "
                "Audit tool schemas for `password`, `secret`, `key`, `token` fields."
            ),
            evidence={
                "tool_server": tool.name,
                "tool_name": tool_name,
                "pattern": label,
                "snippet": snippet[:60] + "…" if len(snippet) > 60 else snippet,
                "all_matches": [m[0] for m in matches],
            },
            blue_team_signal="D10: credential pattern in tool response",
        )


def _extract_tool_names(body: dict) -> list[str]:
    result = body.get("result", body)
    tools = result.get("tools", []) if isinstance(result, dict) else []
    return [t.get("name", "") for t in tools if isinstance(t, dict) and t.get("name")]


def _scan_for_secrets(text: str) -> list[tuple[str, Severity, str]]:
    hits: list[tuple[str, Severity, str]] = []
    for pattern, label, sev in _COMPILED:
        m = pattern.search(text)
        if m:
            hits.append((label, sev, m.group(0)))
    return hits
