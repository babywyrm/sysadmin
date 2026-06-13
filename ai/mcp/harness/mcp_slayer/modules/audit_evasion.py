"""MCP08: Audit Evasion — accountability gaps in the action audit trail.

Strong audit logging is what lets responders attribute an agent action to the
human principal that triggered it. This module performs marked actions through
a tool while applying known evasion techniques, then queries the tool's audit
log surface to verify the action was recorded faithfully and attributed to the
real caller. Three failures are tested:

* **Misattribution** — a client-supplied "on behalf of" header is accepted and
  the action is logged against a forged principal.
* **Suppression** — an ``_no_audit``/``silent`` flag causes the action to
  execute but never appear in the audit log.
* **Forgery** — CRLF/log-injection in a request field lets the caller plant
  fabricated audit lines.

Maps to playbook threat MCP-T13 (audit log evasion). Each scenario requires a
configured ``audit_log_endpoint`` so the result can be confirmed against the
recorded trail rather than guessed from the action response.
"""

from __future__ import annotations

from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

# Distinctive principal we ask the server to attribute actions to. If it shows
# up in the audit trail, a client-supplied identity header was trusted.
SPOOF_PRINCIPAL = "slayer_phantom_user"

# Fabricated audit line we try to smuggle through a CRLF-injectable field.
FORGED_LOG_LINE = "actor=administrator action=GRANT_ALL outcome=success"

_SUCCESS_STATUSES = (200, 201, 202)

AUDIT_SCENARIOS = [
    {
        "id": "obo_header_spoof",
        "description": "Supply a client-controlled on-behalf-of identity header",
        "headers": {
            "X-On-Behalf-Of": SPOOF_PRINCIPAL,
            "X-Forwarded-User": SPOOF_PRINCIPAL,
        },
        "body": {"action": "read_record", "record_id": "audit-probe"},
        "severity": Severity.CRITICAL,
    },
    {
        "id": "audit_suppression_flag",
        "description": "Request action with audit-suppression flags set",
        "headers": {},
        "body": {
            "action": "read_record",
            "record_id": "audit-probe",
            "_no_audit": True,
            "silent": True,
            "audit": False,
        },
        "severity": Severity.HIGH,
    },
    {
        "id": "log_injection_crlf",
        "description": "Inject a forged audit line via CRLF in a logged field",
        "headers": {},
        "body": {
            "action": "comment",
            "note": f"probe\r\n{FORGED_LOG_LINE}\r\n",
        },
        "severity": Severity.HIGH,
    },
]


class AuditEvasionModule(AttackModule):
    """Verifies that performed actions are faithfully attributed in the audit log.

    For each scenario the module performs a marked action, then queries the
    configured audit endpoint for that marker. A finding is raised when the
    spoofed principal was recorded, the action was suppressed from the log, or a
    forged line was accepted verbatim.
    """

    id: ClassVar[str] = "audit-evasion"
    name: ClassVar[str] = "Audit Trail Evasion"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.LACK_OF_AUDIT
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.AUDIT_LOG_EVASION,
    ]
    description: ClassVar[str] = (
        "Verifies action attribution, suppression, and forgery resistance in audit logs"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.HIGH,
        Severity.CRITICAL,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting Audit Evasion assessment")

        for tool in self.ctx.config.tools:
            if not tool.audit_log_endpoint:
                continue
            for scenario in AUDIT_SCENARIOS:
                finding = await self._execute_with_safeguards(
                    self._test_scenario, tool, scenario
                )
                if finding:
                    findings.append(finding)

        return findings

    async def _test_scenario(self, tool, scenario: dict) -> Finding | None:
        marker = f"SLAYER_AUDIT_{scenario['id']}"
        exec_url = f"{tool.base_url}{tool.execute_path}"

        body = dict(scenario["body"])
        body["marker"] = marker
        headers = self.ctx.get_auth_headers(tool.auth_profile)
        headers.update(scenario["headers"])

        async with self.ctx.http_client.post(
            exec_url, json=body, headers=headers
        ) as response:
            exec_status = response.status

        # If the action itself was blocked there is nothing to (mis)record.
        if exec_status not in _SUCCESS_STATUSES:
            return None

        audit_body = await self._query_audit(tool, marker)
        if audit_body is None:
            return None  # cannot verify the trail -> no claim

        evaded, detail = self._evaluate(scenario["id"], marker, audit_body)
        if not evaded:
            return None

        return self._create_finding(
            title=f"Audit Evasion: {scenario['id']} on {tool.name}",
            severity=scenario["severity"],
            target_url=exec_url,
            outcome=AttackOutcome.VULNERABLE,
            description=(
                f"Action performed via '{tool.name}' using technique "
                f"'{scenario['id']}' ({scenario['description']}) was not faithfully "
                f"recorded in the audit log: {detail}. The audit trail therefore "
                f"cannot be trusted to attribute this action to its real caller."
            ),
            impact=(
                "Responders cannot reliably attribute agent actions to the "
                "originating principal, breaking accountability, incident "
                "reconstruction, and non-repudiation."
            ),
            recommendation=(
                "Derive the audit actor solely from the authenticated principal — "
                "never from client-supplied identity headers. Make audit writes "
                "mandatory and tamper-evident (append-only, no caller-controlled "
                "suppression flags), and encode/escape all logged field values to "
                "neutralize CRLF/log injection."
            ),
            evidence={
                "scenario_id": scenario["id"],
                "tool": tool.name,
                "marker": marker,
                "detail": detail,
            },
            blue_team_signal="D06: missing/forged audit event / D01: actor mismatch",
        )

    async def _query_audit(self, tool, marker: str) -> str | None:
        url = f"{tool.base_url}{tool.audit_log_endpoint}"
        async with self.ctx.http_client.post(
            url,
            json={"query": marker},
            headers=self.ctx.get_auth_headers(tool.auth_profile),
        ) as response:
            if response.status != 200:
                return None
            return await response.text()

    @staticmethod
    def _evaluate(scenario_id: str, marker: str, audit_body: str) -> tuple[bool, str]:
        """Return (evaded, human-readable detail) for a scenario's audit result."""
        if scenario_id == "obo_header_spoof":
            if SPOOF_PRINCIPAL in audit_body:
                return True, f"action attributed to forged principal '{SPOOF_PRINCIPAL}'"
            return False, ""
        if scenario_id == "audit_suppression_flag":
            if marker not in audit_body:
                return True, "action absent from audit log (suppression flag honored)"
            return False, ""
        if scenario_id == "log_injection_crlf":
            if FORGED_LOG_LINE in audit_body:
                return True, "fabricated audit line accepted verbatim (CRLF injection)"
            return False, ""
        return False, ""
