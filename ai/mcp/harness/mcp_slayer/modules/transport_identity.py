"""MCP-T45–T49: Transport Identity Dilution (Agent Chain, Lanes 2 & 4).

When agents call other agents or invoke tools across hop boundaries, the
original user's identity is frequently lost because:

  Transport B (direct REST/gRPC): orchestrator forwards its own bearer
    token to sub-agent HTTP endpoint. Audit shows service identity only.
    (MCP-T45)

  Transport C (in-process SDK): delegated human token cached in SDK memory.
    Subsequent in-process hops reuse the cache without re-validation; no
    fresh OBO per hop.
    (MCP-T46 — cache exposure; MCP-T47 — chain dilution)

  Transport D (subprocess): parent injects token via env var or stdin.
    Child subprocess can act with parent credentials; audit attributes to
    child process, not original user.
    (MCP-T48)

  Transport E (LLM function-calling): full conversation context including
    credentials and injected instructions is propagated to every function
    dispatch. Provider sees all; user identity is erased.
    (MCP-T49)

The fix in every case is RFC 8693 On-Behalf-Of (OBO) token exchange per hop,
narrowing scope and maintaining the `act` chain for audit attribution.

This module probes for common identity-dilution patterns across MCP servers
that expose multi-agent or sub-service call patterns.
"""

from __future__ import annotations

import re
from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

_TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

# ── Transport B patterns ──────────────────────────────────────────────────────
# Tools that call downstream services directly (not through the MCP gateway).
_TRANSPORT_B_RE = re.compile(
    r"(?i)(call|invoke|forward|delegate|dispatch|relay).{0,20}"
    r"(agent|service|api|upstream|backend|downstream|endpoint)"
)

# ── Transport C patterns ──────────────────────────────────────────────────────
# Tools exposing SDK cache reads or in-process delegation.
_TRANSPORT_C_RE = re.compile(
    r"(?i)(cache|sdk|session|context|memory|store).{0,20}"
    r"(token|credential|auth|identity|key|secret)"
)

# ── Transport D patterns ──────────────────────────────────────────────────────
# Tools that spawn subprocesses or workers.
_TRANSPORT_D_RE = re.compile(
    r"(?i)(spawn|fork|exec|run.{0,10}process|subprocess|worker|task|job)"
)

# ── Transport E patterns ──────────────────────────────────────────────────────
# Tools using native LLM function-calling / tool_use dispatch.
_TRANSPORT_E_RE = re.compile(
    r"(?i)(function.?call|tool.?use|tool.?dispatch|llm.?invoke|ai.?function|"
    r"model.?tool|assistant.?call)"
)

# Parameter that passes a credential or token explicitly.
_CRED_PARAM_RE = re.compile(
    r"(?i)(token|credential|auth|bearer|key|secret|jwt|api.?key|access.?token)"
)

# Marker for OBO / act-chain presence in responses.
_OBO_SIGNAL_RE = re.compile(
    r"(?i)(act_claim|on.behalf.of|obo|delegat|x-original-user|x-forwarded-user"
    r"|sub.*act|acting.as)"
)


class TransportIdentityModule(AttackModule):
    """Probes multi-agent and sub-service call patterns for identity dilution.

    Identifies tools that cross transport boundaries (B/C/D/E) and checks
    whether the call propagates the original user identity or collapses it
    to a service account. Verifies RFC 8693 OBO signal where present.
    """

    id: ClassVar[str] = "transport-identity"
    name: ClassVar[str] = "Transport Identity Dilution (T45–T49)"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.TOKEN_MISMANAGEMENT
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.AGENT_CHAIN_TRANSPORT_B_IDENTITY,
        PlaybookThreatID.SDK_CREDENTIAL_CACHE_EXPOSURE,
        PlaybookThreatID.AGENT_CHAIN_TRANSPORT_C_IDENTITY,
        PlaybookThreatID.AGENT_CHAIN_SUBPROCESS_CRED,
        PlaybookThreatID.AGENT_CHAIN_FUNCTION_CALL_LEAK,
    ]
    description: ClassVar[str] = (
        "Identifies tools that cross transport boundaries (B/C/D/E) and checks "
        "whether user identity is preserved across hops via OBO token exchange."
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.HIGH,
        Severity.CRITICAL,
    )

    # (pattern, transport_code, threat_id, risk_description)
    _TRANSPORT_CHECKS: ClassVar[list[tuple]] = [
        (
            _TRANSPORT_B_RE,
            "B",
            PlaybookThreatID.AGENT_CHAIN_TRANSPORT_B_IDENTITY,
            "Direct REST/gRPC — service identity forwarded, user identity lost",
        ),
        (
            _TRANSPORT_C_RE,
            "C",
            PlaybookThreatID.SDK_CREDENTIAL_CACHE_EXPOSURE,
            "In-process SDK cache — stale delegated token reused across hops",
        ),
        (
            _TRANSPORT_D_RE,
            "D",
            PlaybookThreatID.AGENT_CHAIN_SUBPROCESS_CRED,
            "Subprocess — parent token injected via env; audit attributes to child",
        ),
        (
            _TRANSPORT_E_RE,
            "E",
            PlaybookThreatID.AGENT_CHAIN_FUNCTION_CALL_LEAK,
            "LLM function-calling — full context propagated; user identity erased",
        ),
    ]

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
                desc = entry.get("description", "")
                schema = entry.get("inputSchema", {})
                props = schema.get("properties", {}) if isinstance(schema, dict) else {}
                surface = name + " " + desc

                for pattern, transport, threat_id, risk in self._TRANSPORT_CHECKS:
                    if not pattern.search(surface):
                        continue

                    # Identify any credential-forwarding parameters.
                    cred_params = [k for k in props if _CRED_PARAM_RE.search(k)]
                    has_obo = _OBO_SIGNAL_RE.search(desc)

                    severity = Severity.HIGH if has_obo else Severity.CRITICAL
                    findings.append(
                        self._build_finding(
                            tool, url, name, desc, transport,
                            threat_id, risk, cred_params, bool(has_obo), severity
                        )
                    )
            return findings
        return []

    def _build_finding(
        self, tool, endpoint: str, tool_name: str, desc: str,
        transport: str, threat_id: PlaybookThreatID, risk: str,
        cred_params: list[str], has_obo: bool, severity: Severity
    ) -> Finding:
        obo_note = (
            " (OBO signal detected in description — verify RFC 8693 `act` chain is complete)"
            if has_obo else
            " (No OBO/delegation signal found — likely service-identity forwarding)"
        )
        return self._create_finding(
            title=(
                f"Transport {transport} identity dilution: '{tool_name}' on '{tool.name}'"
            ),
            severity=severity,
            target_url=endpoint,
            outcome=AttackOutcome.PARTIALLY_VULNERABLE if has_obo else AttackOutcome.VULNERABLE,
            target_tool=tool_name,
            description=(
                f"Tool '{tool_name}' crosses a Transport {transport} boundary. "
                f"Risk: {risk}.{obo_note}"
                + (f" Credential-forwarding params detected: {cred_params}." if cred_params else "")
            ),
            impact=(
                "Audit log shows service account, not the original user. Downstream "
                "resources are accessed with inflated ambient authority — confused "
                "deputy at the infrastructure layer. RFC 8693 `act` chain not "
                "preserved → attribution failure + potential privilege escalation."
            ),
            recommendation=(
                "Perform RFC 8693 OBO token exchange at every hop boundary: "
                "derive a scoped token (`sub`=original user, `act`=calling agent, "
                "audience=target tool, TTL≤15min). Never forward the original bearer "
                "token across transport boundaries. Cap delegation depth at 3."
            ),
            evidence={
                "tool_name": tool_name,
                "description_excerpt": desc[:150],
                "transport": transport,
                "threat_id": str(threat_id),
                "cred_forwarding_params": cred_params,
                "obo_signal_present": has_obo,
            },
            blue_team_signal=f"D13: Transport {transport} identity dilution — check `act` chain",
        )
