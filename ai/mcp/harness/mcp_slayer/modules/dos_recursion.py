"""MCP-T10: Resource Exhaustion — missing depth / size / fan-out guardrails.

Agentic tool surfaces that parse structured input or drive tool-call chains
must bound the work a single request can trigger. Without caps, an attacker can
turn one small request into unbounded CPU/memory/recursion — a denial-of-service
that also stalls every other tenant sharing the worker pool.

This module sends a small, bounded set of abusive-shaped probes (deeply nested
input, a self-referential loop request, a large fan-out, and an expansion bomb)
and classifies the response:

* **2xx** — the endpoint accepted and processed the abusive payload with no
  visible limit -> ``VULNERABLE``.
* **503 / 504** — the endpoint appears to have been overwhelmed (overload or
  timeout) -> ``PARTIALLY_VULNERABLE`` (availability already impacted).
* **4xx** — the endpoint rejected the payload (a working guardrail) -> no finding.

Probes are intentionally bounded (and run under the engine's rate-limit /
timeout safeguards) so the assessment demonstrates the missing guardrail
without actually flooding the target. Maps to playbook threat MCP-T10.
"""

from __future__ import annotations

from typing import Any, ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

# Bounded probe magnitudes — large enough to exceed any sane limit, small enough
# not to constitute a real flood.
_NESTING_DEPTH = 256
_LOOP_DEPTH = 10_000
_FANOUT_COUNT = 2_000
_EXPANSION_FACTOR = 1_000_000

_SUCCESS_STATUSES = (200, 201, 202)
_OVERLOAD_STATUSES = (503, 504)

DOS_SCENARIOS = [
    {
        "id": "deep_nesting",
        "description": "Deeply nested JSON object to exhaust the parser/stack",
        "severity": Severity.HIGH,
    },
    {
        "id": "self_referential_loop",
        "description": "Request an unbounded self-referential tool-call loop",
        "severity": Severity.HIGH,
    },
    {
        "id": "large_fanout",
        "description": "Single request fanning out to thousands of targets",
        "severity": Severity.MEDIUM,
    },
    {
        "id": "expansion_bomb",
        "description": "Small input requesting exponential expansion",
        "severity": Severity.HIGH,
    },
]


class DosRecursionModule(AttackModule):
    """Probes for missing depth/size/fan-out limits on structured-input tools.

    A hardened endpoint rejects each abusive probe with a 4xx; accepting it
    (2xx) signals an unbounded-work path, and a 503/504 signals the endpoint was
    already overwhelmed by the probe.
    """

    id: ClassVar[str] = "dos-recursion"
    name: ClassVar[str] = "Resource Exhaustion via Recursion/Fan-out"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.COMMAND_INJECTION
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.HALLUCINATION_DRIVEN_DESTRUCTION,
    ]
    description: ClassVar[str] = (
        "Probes for missing depth/size/fan-out limits that enable resource exhaustion"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.MEDIUM,
        Severity.HIGH,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting Resource Exhaustion assessment")

        for tool in self.ctx.config.tools:
            if not tool.recursion_endpoints:
                continue
            for endpoint in tool.recursion_endpoints:
                for scenario in DOS_SCENARIOS:
                    finding = await self._execute_with_safeguards(
                        self._test_scenario, tool, endpoint, scenario
                    )
                    if finding:
                        findings.append(finding)

        return findings

    async def _test_scenario(self, tool, endpoint: str, scenario: dict) -> Finding | None:
        url = f"{tool.base_url}{endpoint}"
        payload = self._build_payload(scenario["id"])

        async with self.ctx.http_client.post(
            url, json=payload, headers=self.ctx.get_auth_headers(tool.auth_profile)
        ) as response:
            status = response.status

        if status in _SUCCESS_STATUSES:
            return self._build_finding(
                tool,
                url,
                endpoint,
                scenario,
                outcome=AttackOutcome.VULNERABLE,
                severity=scenario["severity"],
                status=status,
                detail=(
                    "endpoint accepted and processed the abusive payload with no "
                    "visible limit"
                ),
            )
        if status in _OVERLOAD_STATUSES:
            return self._build_finding(
                tool,
                url,
                endpoint,
                scenario,
                outcome=AttackOutcome.PARTIALLY_VULNERABLE,
                severity=Severity.MEDIUM,
                status=status,
                detail=(
                    f"endpoint returned {status} (overload/timeout), indicating the "
                    "probe already degraded availability"
                ),
            )
        return None

    def _build_finding(
        self,
        tool,
        url: str,
        endpoint: str,
        scenario: dict,
        *,
        outcome: AttackOutcome,
        severity: Severity,
        status: int,
        detail: str,
    ) -> Finding:
        return self._create_finding(
            title=f"Resource Exhaustion: {scenario['id']} on {tool.name}",
            severity=severity,
            target_url=url,
            outcome=outcome,
            description=(
                f"Endpoint '{endpoint}' on tool '{tool.name}' did not enforce a "
                f"limit for probe '{scenario['id']}' ({scenario['description']}): "
                f"{detail} (HTTP {status})."
            ),
            impact=(
                "A single small request can drive unbounded CPU, memory, or "
                "recursion, denying service to all tenants sharing the worker pool "
                "and inflating compute cost."
            ),
            recommendation=(
                "Enforce hard limits before processing: max JSON nesting depth, "
                "max payload/array size, max tool-call recursion depth, and a "
                "per-request work/time budget. Reject over-limit input with 4xx "
                "and apply per-principal concurrency caps."
            ),
            evidence={
                "scenario_id": scenario["id"],
                "tool": tool.name,
                "endpoint": endpoint,
                "response_status": status,
            },
            blue_team_signal="D11: request work-budget exceeded / D03: fan-out spike",
        )

    @staticmethod
    def _build_payload(scenario_id: str) -> dict[str, Any]:
        payload: dict[str, Any] = {"probe": scenario_id, "marker": "SLAYER_DOS"}

        if scenario_id == "deep_nesting":
            node: Any = "leaf"
            for _ in range(_NESTING_DEPTH):
                node = {"n": node}
            payload["data"] = node
        elif scenario_id == "self_referential_loop":
            payload.update(
                {"action": "recurse", "depth": _LOOP_DEPTH, "callback": "self"}
            )
        elif scenario_id == "large_fanout":
            payload.update(
                {"action": "broadcast", "targets": [f"t{i}" for i in range(_FANOUT_COUNT)]}
            )
        elif scenario_id == "expansion_bomb":
            payload.update(
                {"action": "expand", "factor": _EXPANSION_FACTOR, "seed": "A" * 64}
            )

        return payload
