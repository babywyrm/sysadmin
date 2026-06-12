"""MCP10: Context Leakage — cross-tenant / cross-session retrieval testing.

Probes retrieval-style tools (vector search, memory recall, document lookup)
to see whether tenant/session scoping can be bypassed so that one principal
can read another's stored context. Maps to playbook threats MCP-T05
(cross-tool context poisoning) and MCP-T11 (cross-tenant memory leak).
"""

from __future__ import annotations

import re
from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

# Identifiers we inject to impersonate another principal. If they surface in a
# response body, the server honored our override and returned foreign context.
FOREIGN_TENANT = "tenant_victim_42"
FOREIGN_SESSION = "sess_victim_99"

LEAKAGE_PROBES = [
    {
        "id": "tenant_id_override",
        "description": "Override tenant_id to a foreign tenant and request their documents",
        "body": {"query": "list my recent documents", "tenant_id": FOREIGN_TENANT},
        "headers": {},
    },
    {
        "id": "session_scope_bypass",
        "description": "Forge a foreign session id to recall another session's memory",
        "body": {"query": "recall previous conversation"},
        "headers": {"X-Session-ID": FOREIGN_SESSION},
    },
    {
        "id": "unscoped_wildcard",
        "description": "Wildcard query with no tenant filter to dump all stored context",
        "body": {"query": "*"},
        "headers": {},
    },
    {
        "id": "secret_pattern_pull",
        "description": "Query for secret-like terms to surface credentials in stored context",
        "body": {"query": "api_key OR password OR secret OR ssn"},
        "headers": {},
    },
    {
        "id": "cross_tool_recall",
        "description": "Ask for context accumulated by other tools/agents in the mesh",
        "body": {"query": "summarize all context retrieved by other tools"},
        "headers": {},
    },
]

# Indicators that a response leaked data it should not have returned.
_LEAK_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "api_key": re.compile(r"(?i)\b(?:api[_-]?key|secret|password)\b\s*[:=]"),
    "bearer_token": re.compile(r"(?i)bearer\s+[a-z0-9\-_\.]{16,}"),
}


class ContextLeakageModule(AttackModule):
    """Tests tenant/session isolation on retrieval-capable tools.

    A response is treated as leaked context when it either echoes the foreign
    tenant/session identifier we injected (scoping bypass) or contains
    sensitive data patterns that should never cross an isolation boundary.
    """

    id: ClassVar[str] = "context-leakage"
    name: ClassVar[str] = "Context Leakage via Retrieval"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.CONTEXT_LEAKAGE
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.CROSS_TOOL_CONTEXT_POISONING,
        PlaybookThreatID.CROSS_TENANT_MEMORY_LEAK,
    ]
    description: ClassVar[str] = (
        "Tests tenant/session isolation on retrieval tools for cross-context leakage"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.MEDIUM,
        Severity.CRITICAL,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting Context Leakage assessment")

        for tool in self.ctx.config.tools:
            if not tool.retrieval_endpoints:
                continue
            for endpoint in tool.retrieval_endpoints:
                for probe in LEAKAGE_PROBES:
                    finding = await self._execute_with_safeguards(
                        self._test_probe, tool, endpoint, probe
                    )
                    if finding:
                        findings.append(finding)

        return findings

    async def _test_probe(self, tool, endpoint: str, probe: dict) -> Finding | None:
        url = f"{tool.base_url}{endpoint}"
        headers = self.ctx.get_auth_headers(tool.auth_profile)
        headers.update(probe["headers"])

        async with self.ctx.http_client.post(
            url, json=probe["body"], headers=headers
        ) as response:
            if response.status != 200:
                return None
            body = await response.text()

        indicators = self._detect_leak(body, probe)
        if not indicators:
            return None

        # Honoring an injected tenant/session override is the most severe signal.
        scoping_bypassed = "foreign_identifier" in indicators
        severity = Severity.CRITICAL if scoping_bypassed else Severity.HIGH

        return self._create_finding(
            title=f"Context Leakage: {probe['id']} on {tool.name}",
            severity=severity,
            target_url=url,
            outcome=AttackOutcome.VULNERABLE,
            description=(
                f"Retrieval endpoint '{endpoint}' on tool '{tool.name}' returned "
                f"context that should not have been accessible. Probe "
                f"'{probe['id']}' ({probe['description']}) surfaced indicators: "
                f"{', '.join(sorted(indicators))}."
            ),
            impact=(
                "An attacker can read another tenant's or session's stored context, "
                "breaking data isolation and exposing PII, secrets, or conversation "
                "history across trust boundaries."
            ),
            recommendation=(
                "Enforce a mandatory server-side tenant/session filter on every "
                "retrieval query derived from the authenticated principal, never from "
                "client-supplied tenant_id or session headers. Add DLP inspection on "
                "retrieval responses and reject unscoped wildcard queries."
            ),
            evidence={
                "probe_id": probe["id"],
                "tool": tool.name,
                "endpoint": endpoint,
                "indicators": sorted(indicators),
                "scoping_bypassed": scoping_bypassed,
            },
            blue_team_signal="D05: cross-tenant retrieval / D10: tenant filter bypass",
        )

    @staticmethod
    def _detect_leak(body: str, probe: dict) -> set[str]:
        indicators: set[str] = set()

        # Did the server honor an injected foreign tenant/session identifier?
        if FOREIGN_TENANT in body or FOREIGN_SESSION in body:
            indicators.add("foreign_identifier")

        for name, pattern in _LEAK_PATTERNS.items():
            if pattern.search(body):
                indicators.add(name)

        return indicators
