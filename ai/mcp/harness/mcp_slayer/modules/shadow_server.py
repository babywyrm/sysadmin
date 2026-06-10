"""MCP09: Shadow MCP Server Discovery."""

from __future__ import annotations

import base64
from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID


class ShadowServerModule(AttackModule):
    """Identifies unauthorized or misconfigured MCP instances.

    Attack scenarios:
        1. Unauthenticated tool endpoints
        2. Default credentials
        3. Outdated versions with known CVEs
    """

    id: ClassVar[str] = "shadow-server"
    name: ClassVar[str] = "Shadow MCP Server Discovery"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.SHADOW_SERVERS
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.PERSISTENCE_VIA_CALLBACK,
    ]
    description: ClassVar[str] = (
        "Identifies unauthorized or misconfigured MCP instances"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.MEDIUM,
        Severity.HIGH,
    )

    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "user"),
        ("mcp", "mcp"),
    ]

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting shadow server discovery")

        for tool in self.ctx.config.tools:
            finding = await self._test_unauthenticated_access(tool)
            if finding:
                findings.append(finding)

            finding = await self._test_default_credentials(tool)
            if finding:
                findings.append(finding)

            finding = await self._test_outdated_version(tool)
            if finding:
                findings.append(finding)

        return findings

    async def _test_unauthenticated_access(self, tool) -> Finding | None:
        url = f"{tool.base_url}{tool.health_path}"

        async with self.ctx.http_client.get(url) as response:
            status = response.status
            body = await response.text()

        if status == 200:
            return self._create_finding(
                title=f"Unauthenticated Access to {tool.name}",
                severity=Severity.HIGH,
                target_url=url,
                outcome=AttackOutcome.VULNERABLE,
                target_tool=tool.name,
                description=(
                    f"Tool '{tool.name}' health endpoint is accessible without "
                    f"authentication, indicating a shadow or misconfigured deployment."
                ),
                impact=(
                    "Internal MCP infrastructure enumeration, "
                    "potential direct tool invocation."
                ),
                recommendation=(
                    "Enforce mTLS for all tool-to-gateway communication. "
                    "Deploy namespace-level NetworkPolicies with default deny."
                ),
                evidence={"status": status, "response_snippet": body[:200]},
                blue_team_signal="HTTP 200 to /health from unexpected source IP",
            )
        return None

    async def _test_default_credentials(self, tool) -> Finding | None:
        url = f"{tool.base_url}{tool.execute_path}"

        for username, password in self.DEFAULT_CREDS:
            auth_header = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()

            async with self.ctx.http_client.post(
                url,
                json={"action": "health"},
                headers={"Authorization": f"Basic {auth_header}"},
            ) as response:
                if response.status == 200:
                    return self._create_finding(
                        title=f"Default Credentials on {tool.name}",
                        severity=Severity.CRITICAL,
                        target_url=url,
                        outcome=AttackOutcome.VULNERABLE,
                        target_tool=tool.name,
                        cvss_score=9.8,
                        description=(
                            f"Tool '{tool.name}' accepts default credentials "
                            f"({username}/***), exposing it to trivial compromise."
                        ),
                        impact="Full tool control, potential lateral movement.",
                        recommendation=(
                            "Generate strong random credentials via secret manager. "
                            "Rotate immediately. Use certificate-based auth."
                        ),
                        evidence={"username": username},
                        blue_team_signal="Successful auth with known default usernames",
                    )
        return None

    async def _test_outdated_version(self, tool) -> Finding | None:
        url = f"{tool.base_url}{tool.health_path}"

        async with self.ctx.http_client.get(url) as response:
            version_header = response.headers.get("X-MCP-Version")

        if not version_header:
            return None

        try:
            parts = version_header.split(".")
            major, minor = int(parts[0]), int(parts[1])
        except (IndexError, ValueError):
            return None

        if major < 1 or (major == 1 and minor < 5):
            return self._create_finding(
                title=f"Outdated MCP Version on {tool.name}",
                severity=Severity.MEDIUM,
                target_url=url,
                outcome=AttackOutcome.VULNERABLE,
                target_tool=tool.name,
                description=(
                    f"Tool '{tool.name}' runs MCP {version_header}, below "
                    f"minimum supported 1.5.0. May contain known vulnerabilities."
                ),
                impact="Exposure to known CVEs, potential RCE or data exfiltration.",
                recommendation=(
                    "Upgrade to latest MCP version. "
                    "Enforce version policy in admission webhooks."
                ),
                evidence={"version": version_header},
                blue_team_signal="version < 1.5.0 in service registry",
            )
        return None
