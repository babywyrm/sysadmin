"""MCP10: Data Exfiltration via Tool Chaining — Rate Limit & DLP Testing."""

from __future__ import annotations

import hashlib
from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

EXFIL_SCENARIOS = [
    {
        "id": "chunked_slack",
        "description": "Send sensitive data in multiple small Slack messages to bypass payload caps",
        "action": "message.send",
        "chunks": 20,
        "chunk_size": 500,
    },
    {
        "id": "webhook_burst",
        "description": "Exfil via rapid webhook posts to attacker-controlled endpoint",
        "action": "webhook.post",
        "chunks": 15,
        "chunk_size": 1000,
    },
    {
        "id": "email_drip",
        "description": "Slow-drip exfil via email tool over extended window",
        "action": "email.send",
        "chunks": 10,
        "chunk_size": 2000,
    },
    {
        "id": "issue_creation",
        "description": "Exfil via issue/ticket body in project management tools",
        "action": "issue.create",
        "chunks": 5,
        "chunk_size": 4000,
    },
]

CANARY_DATA = (
    "SLAYER_EXFIL_CANARY_"
    "The quick brown fox jumps over the lazy dog. "
    "SSN: 123-45-6789. CC: 4111-1111-1111-1111. "
    "API_KEY: sk-test-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX. "
)


class ExfiltrationModule(AttackModule):
    """Tests rate limiting, DLP, and payload caps on egress-capable tools.

    Simulates data exfiltration patterns:
        1. Chunked messages that bypass per-message size limits
        2. Burst sends that should trigger volume alerts
        3. Slow-drip patterns designed to stay under per-window thresholds
        4. DLP evasion with sensitive data patterns
    """

    id: ClassVar[str] = "exfiltration-routing"
    name: ClassVar[str] = "Data Exfiltration via Tool Chain"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.CONTEXT_LEAKAGE
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.EXFILTRATION_VIA_CHAINING,
        PlaybookThreatID.CROSS_TENANT_MEMORY_LEAK,
    ]
    description: ClassVar[str] = (
        "Tests rate limiting, DLP gates, and payload caps on egress tools"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.MEDIUM,
        Severity.HIGH,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting Exfiltration assessment")

        for tool in self.ctx.config.tools:
            if not tool.egress_actions:
                continue

            for scenario in EXFIL_SCENARIOS:
                if scenario["action"] not in tool.egress_actions:
                    continue
                finding = await self._execute_with_safeguards(
                    self._test_exfil_scenario, tool, scenario
                )
                if finding:
                    findings.append(finding)

        return findings

    async def _test_exfil_scenario(self, tool, scenario: dict) -> Finding | None:
        url = f"{tool.base_url}{tool.execute_path}"
        successful_sends = 0
        blocked_sends = 0
        dlp_triggered = False

        chunks = self._generate_chunks(scenario["chunks"], scenario["chunk_size"])

        for i, chunk in enumerate(chunks):
            payload = {
                "action": scenario["action"],
                "target": "__slayer_exfil_test__",
                "body": chunk,
                "metadata": {"chunk": i, "total": len(chunks)},
            }

            async with self.ctx.http_client.post(
                url,
                json=payload,
                headers=self.ctx.get_auth_headers(tool.auth_profile),
            ) as response:
                status = response.status
                body = await response.text()

            if status in (200, 201, 202):
                successful_sends += 1
            elif status == 429:
                blocked_sends += 1
                break
            elif "dlp" in body.lower() or "blocked" in body.lower():
                dlp_triggered = True
                blocked_sends += 1
                break
            else:
                blocked_sends += 1

        if successful_sends == scenario["chunks"]:
            return self._create_finding(
                title=f"Exfil Unblocked: {scenario['id']} via {tool.name} ({successful_sends}/{scenario['chunks']} sent)",
                severity=Severity.HIGH,
                target_url=url,
                outcome=AttackOutcome.VULNERABLE,
                description=(
                    f"All {successful_sends} chunks sent successfully via "
                    f"'{scenario['action']}' on '{tool.name}'. "
                    f"No rate limit or DLP gate triggered. "
                    f"Scenario: {scenario['description']}"
                ),
                impact=(
                    "Attacker can exfiltrate data via tool chaining without "
                    "triggering volume controls or content inspection."
                ),
                recommendation=(
                    "Implement per-session rate limits on egress actions. "
                    "Add DLP content inspection for sensitive patterns. "
                    "Cap per-session output volume across all egress channels."
                ),
                evidence={
                    "scenario_id": scenario["id"],
                    "tool": tool.name,
                    "action": scenario["action"],
                    "chunks_sent": successful_sends,
                    "chunks_blocked": blocked_sends,
                    "dlp_triggered": dlp_triggered,
                    "data_hash": hashlib.sha256(
                        "".join(chunks).encode()
                    ).hexdigest()[:16],
                },
                blue_team_signal="D03: chunked high-volume output alert",
            )

        if successful_sends > 0 and not dlp_triggered:
            return self._create_finding(
                title=f"Partial Exfil: {scenario['id']} via {tool.name} ({successful_sends}/{scenario['chunks']} before rate limit)",
                severity=Severity.MEDIUM,
                target_url=url,
                outcome=AttackOutcome.PARTIALLY_VULNERABLE,
                description=(
                    f"Rate limit triggered after {successful_sends} chunks, but "
                    f"no DLP inspection detected sensitive content in the "
                    f"payloads that were successfully sent."
                ),
                impact="Partial exfil possible before rate limit kicks in.",
                recommendation=(
                    "Lower rate limit thresholds. Add DLP content inspection "
                    "in addition to volume controls."
                ),
                evidence={
                    "scenario_id": scenario["id"],
                    "tool": tool.name,
                    "chunks_sent": successful_sends,
                    "chunks_blocked": blocked_sends,
                    "dlp_triggered": False,
                },
                blue_team_signal="D03: chunked output + D04: secret pattern in payload",
            )

        return None

    @staticmethod
    def _generate_chunks(count: int, size: int) -> list[str]:
        base = CANARY_DATA
        chunks = []
        for i in range(count):
            chunk = f"[chunk {i}/{count}] "
            remaining = size - len(chunk)
            repetitions = (remaining // len(base)) + 1
            chunk += (base * repetitions)[:remaining]
            chunks.append(chunk)
        return chunks
