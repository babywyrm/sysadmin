"""MCP03: Tool Poisoning — malicious instructions hidden in tool metadata.

A poisoned MCP server advertises tools whose *descriptions* or *schemas* carry
hidden instructions aimed at the agent rather than the human (zero-width text,
HTML-comment payloads, "ignore previous instructions" phrasing, or embedded
exfiltration URLs). Because the agent reads these descriptions as trusted
context when deciding which tool to call, the content can hijack behavior even
though no user ever sees it.

This module pulls a tool's advertised schema/description surface (e.g. a
JSON-RPC ``tools/list`` response) and inspects every descriptor for poisoning
indicators. Maps to playbook threat MCP-T08 (supply chain via content).
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

# JSON-RPC tools/list probe — the standard way an MCP client enumerates a
# server's advertised tools and their descriptions.
TOOLS_LIST_REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

# Zero-width / invisible characters used to smuggle instructions past human
# review while remaining fully readable to the model.
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff\u00ad]")

# Instruction-injection phrasing aimed at the agent, not the user.
_INSTRUCTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"(?i)ignore (?:all |any )?(?:previous|prior|above) instructions"
    ),
    "conceal_from_user": re.compile(
        r"(?i)do not (?:tell|inform|mention|reveal|show)[^.\n]{0,40}user"
    ),
    "imperative_override": re.compile(
        r"(?i)you (?:must|should) (?:always|now|first|immediately)\b"
    ),
    "system_role_inject": re.compile(r"(?i)(?:<\s*system\s*>|^\s*system\s*:)", re.MULTILINE),
    "preamble_hook": re.compile(
        r"(?i)before (?:using|calling|invoking) (?:any|this|the) tool"
    ),
}

# Strong signals that the hidden instruction routes data to an attacker.
_EXFIL_PATTERNS: dict[str, re.Pattern[str]] = {
    "exfil_routing": re.compile(
        r"(?i)(?:send|forward|post|upload|exfiltrate)[^.\n]{0,40}"
        r"(?:results?|output|data|credential|secret|token|key)"
    ),
    "embedded_url": re.compile(r"(?i)https?://(?!localhost|127\.0\.0\.1)[a-z0-9.\-]+"),
    "data_uri": re.compile(r"(?i)data:[a-z/]+;base64,"),
    "hidden_html": re.compile(r"(?i)<!--|--!?>|display\s*:\s*none|<\s*script"),
}


class ToolPoisoningModule(AttackModule):
    """Inspects advertised tool descriptions/schemas for hidden agent instructions.

    A descriptor is flagged when it contains invisible characters, instruction
    phrasing directed at the model, or data-exfiltration routing. Exfil routing,
    invisible text, and hidden HTML are treated as the critical signals because
    they indicate deliberate concealment rather than sloppy documentation.
    """

    id: ClassVar[str] = "tool-poisoning"
    name: ClassVar[str] = "Tool Description Poisoning"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.TOOL_POISONING
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.SUPPLY_CHAIN_VIA_CONTENT,
    ]
    description: ClassVar[str] = (
        "Inspects advertised tool descriptions/schemas for hidden agent instructions"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.HIGH,
        Severity.CRITICAL,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting Tool Poisoning assessment")

        for tool in self.ctx.config.tools:
            if not tool.schema_endpoints:
                continue
            for endpoint in tool.schema_endpoints:
                endpoint_findings = await self._execute_with_safeguards(
                    self._inspect_endpoint, tool, endpoint
                )
                findings.extend(endpoint_findings)

        return findings

    async def _inspect_endpoint(self, tool, endpoint: str) -> list[Finding]:
        url = f"{tool.base_url}{endpoint}"
        async with self.ctx.http_client.post(
            url,
            json=TOOLS_LIST_REQUEST,
            headers=self.ctx.get_auth_headers(tool.auth_profile),
        ) as response:
            if response.status != 200:
                return []
            body = await response.text()

        findings: list[Finding] = []
        for descriptor_name, descriptor_text in self._extract_descriptors(body):
            indicators = self._detect_poisoning(descriptor_text)
            if not indicators:
                continue
            findings.append(
                self._build_finding(tool, url, endpoint, descriptor_name, indicators)
            )
        return findings

    def _build_finding(
        self, tool, url: str, endpoint: str, descriptor_name: str, indicators: set[str]
    ) -> Finding:
        critical_signals = {
            "zero_width_chars",
            "exfil_routing",
            "embedded_url",
            "data_uri",
            "hidden_html",
        }
        severity = (
            Severity.CRITICAL if indicators & critical_signals else Severity.HIGH
        )
        return self._create_finding(
            title=f"Tool Poisoning: hidden instructions in '{descriptor_name}' on {tool.name}",
            severity=severity,
            target_url=url,
            outcome=AttackOutcome.VULNERABLE,
            description=(
                f"The advertised descriptor '{descriptor_name}' exposed by tool "
                f"'{tool.name}' at '{endpoint}' contains content directed at the "
                f"agent rather than the user. Detected indicators: "
                f"{', '.join(sorted(indicators))}. The model reads tool descriptions "
                f"as trusted context, so this content can steer tool selection or "
                f"action without any human-visible prompt."
            ),
            impact=(
                "An attacker who controls the server's advertised metadata can "
                "covertly redirect the agent — leaking data, invoking unintended "
                "tools, or suppressing user-facing disclosure — without touching "
                "the conversation the user sees."
            ),
            recommendation=(
                "Treat tool descriptions/schemas as untrusted input: strip "
                "zero-width and bidi control characters, reject descriptions "
                "containing instruction-like or routing content, pin/verify server "
                "metadata against a reviewed allowlist, and surface raw tool "
                "descriptions to operators during onboarding review."
            ),
            evidence={
                "tool": tool.name,
                "endpoint": endpoint,
                "descriptor": descriptor_name,
                "indicators": sorted(indicators),
            },
            blue_team_signal="D07: tool metadata drift / D08: zero-width content in schema",
        )

    @staticmethod
    def _extract_descriptors(body: str) -> list[tuple[str, str]]:
        """Return (name, text) pairs for each advertised tool descriptor.

        Parses a JSON-RPC ``tools/list`` shape when possible; otherwise falls
        back to treating the whole response body as a single descriptor so a
        non-standard surface is still inspected.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return [("<raw-response>", body)]

        tools = ToolPoisoningModule._locate_tools(data)
        if not tools:
            return [("<raw-response>", body)]

        descriptors: list[tuple[str, str]] = []
        for entry in tools:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "<unnamed>"))
            # The description plus any schema text is what the model ingests.
            text_parts = [str(entry.get("description", ""))]
            if "inputSchema" in entry:
                text_parts.append(json.dumps(entry["inputSchema"]))
            descriptors.append((name, "\n".join(text_parts)))
        return descriptors

    @staticmethod
    def _locate_tools(data: Any) -> list[Any]:
        if isinstance(data, dict):
            result = data.get("result", data)
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                return result["tools"]
            if isinstance(data.get("tools"), list):
                return data["tools"]
        if isinstance(data, list):
            return data
        return []

    @staticmethod
    def _detect_poisoning(text: str) -> set[str]:
        indicators: set[str] = set()
        if _ZERO_WIDTH_RE.search(text):
            indicators.add("zero_width_chars")
        for name, pattern in _INSTRUCTION_PATTERNS.items():
            if pattern.search(text):
                indicators.add(name)
        for name, pattern in _EXFIL_PATTERNS.items():
            if pattern.search(text):
                indicators.add(name)
        return indicators
