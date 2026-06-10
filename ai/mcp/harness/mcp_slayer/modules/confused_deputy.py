"""MCP02: Privilege Escalation via Confused Deputy / Token Replay."""

from __future__ import annotations

import base64
import json
from typing import Any, ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID


class ConfusedDeputyModule(AttackModule):
    """Tests for missing JWT audience binding and scope validation.

    Attack scenarios:
        1. Cross-tool token acceptance (missing audience validation)
        2. Scope inflation (read token used for write operations)
    """

    id: ClassVar[str] = "confused-deputy"
    name: ClassVar[str] = "Confused Deputy Attack"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.PRIVILEGE_ESCALATION
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.CONFUSED_DEPUTY,
        PlaybookThreatID.TOKEN_AUDIENCE_BYPASS,
        PlaybookThreatID.AUDIT_LOG_EVASION,
    ]
    description: ClassVar[str] = (
        "Tests for missing JWT audience binding and scope validation"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.HIGH,
        Severity.CRITICAL,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting Confused Deputy assessment")

        tools = self.ctx.config.tools
        if len(tools) < 2:
            self.logger.warning("Need at least 2 tools for cross-tool replay test")
            return findings

        source_tool = tools[0]
        token = await self._obtain_token(source_tool)
        if not token:
            self.logger.warning(f"Could not obtain token for {source_tool.name}")
            return findings

        claims = self._decode_jwt_unsafe(token)

        for target_tool in tools[1:]:
            finding = await self._test_token_replay(
                source_tool, target_tool, token, claims
            )
            if finding:
                findings.append(finding)

        findings.extend(await self._test_scope_inflation())
        return findings

    async def _obtain_token(self, tool) -> str | None:
        auth_profile = self.ctx.get_auth_profile(tool.auth_profile)
        if auth_profile.type == "bearer" and auth_profile.token:
            return auth_profile.token.get_secret_value()
        return None

    async def _test_token_replay(
        self, source_tool, target_tool, token: str, claims: dict[str, Any]
    ) -> Finding | None:
        url = f"{target_tool.base_url}{target_tool.execute_path}"

        async with self.ctx.http_client.post(
            url,
            json={"action": "health"},
            headers={"Authorization": f"Bearer {token}"},
        ) as response:
            status = response.status

        if status == 200:
            return self._create_finding(
                title=f"Cross-Tool Token Acceptance: {source_tool.name} -> {target_tool.name}",
                severity=Severity.HIGH,
                target_url=url,
                outcome=AttackOutcome.VULNERABLE,
                target_tool=target_tool.name,
                description=(
                    f"Tool '{target_tool.name}' accepted a JWT issued for "
                    f"'{source_tool.name}', indicating missing audience validation."
                ),
                impact=(
                    "Attacker with access to any low-privilege tool can replay tokens "
                    "against high-privilege tools, bypassing RBAC."
                ),
                recommendation=(
                    "Enforce JWT audience (aud) claim at every tool boundary. "
                    "Use tool-specific signing keys and log cross-tool attempts."
                ),
                evidence={
                    "source_tool": source_tool.name,
                    "target_tool": target_tool.name,
                    "token_claims": claims,
                    "response_status": status,
                },
                blue_team_signal="jwt.aud != expected_tool_id in access logs",
            )
        return None

    async def _test_scope_inflation(self) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.ctx.config.tools:
            if not tool.deny_actions:
                continue
            url = f"{tool.base_url}{tool.execute_path}"
            for action in tool.deny_actions:
                async with self.ctx.http_client.post(
                    url,
                    json={"action": action, "resource": "__slayer_test__"},
                    headers=self.ctx.get_auth_headers(tool.auth_profile),
                ) as response:
                    if response.status in (200, 201, 202):
                        findings.append(
                            self._create_finding(
                                title=f"Scope Inflation: denied action '{action}' succeeded on {tool.name}",
                                severity=Severity.HIGH,
                                target_url=url,
                                outcome=AttackOutcome.VULNERABLE,
                                description=(
                                    f"Tool '{tool.name}' accepted action '{action}' which "
                                    f"should be denied per policy configuration."
                                ),
                                impact="Privilege escalation via scope inflation.",
                                recommendation="Implement scope-based authz checks for all operations.",
                            )
                        )
        return findings

    def _decode_jwt_unsafe(self, token: str) -> dict[str, Any]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {}
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return {}
