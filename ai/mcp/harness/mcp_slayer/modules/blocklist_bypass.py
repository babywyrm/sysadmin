"""MCP-T44: Blocklist Bypass via Incomplete Input Filter.

Exec tools that block `bash`, `python`, or `sh` by keyword often miss the
broader set of runtimes available on any standard Linux system:
perl, ruby, lua, awk, node (Node.js), php, tclsh, and shell metacharacter
chains. An attacker who knows the blocked list can trivially substitute any
of these to achieve identical code execution.

This module iterates every tool with `command`, `exec`, or `run`-style
parameters and tests whether the blocklist is comprehensive or only covers
the obvious keywords.

Maps to MCP-T44 (Blocklist Bypass) / OWASP MCP05 (Command Injection).
"""

from __future__ import annotations

import re
from typing import ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID

_TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

# Interpreters to probe — ordered by how often they're missed.
_BYPASS_PROBES: list[tuple[str, str]] = [
    ("perl -e 'print \"CANARY\"'", "perl"),
    ("ruby -e 'puts \"CANARY\"'", "ruby"),
    ("lua -e 'print(\"CANARY\")'", "lua"),
    (r"awk 'BEGIN{print \"CANARY\"}'", "awk"),
    ("node -e 'console.log(\"CANARY\")'", "node"),
    ("php -r 'echo \"CANARY\";'", "php"),
    ("python3 -c 'print(\"CANARY\")'", "python3"),
]

# Parameters that suggest a command-execution surface.
_EXEC_PARAM_RE = re.compile(
    r"(?i)^(command|cmd|exec|run|query|script|payload|instruction|input)$"
)

# CANARY detection in response (plain or JSON-embedded).
_CANARY_RE = re.compile(r"CANARY")


def _call(name: str, param: str, value: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": name, "arguments": {param: value}},
    }


class BlocklistBypassModule(AttackModule):
    """Probes exec-capable tools for incomplete interpreter blocklists.

    Submits canary payloads via alternative runtimes and checks whether
    CANARY appears in the response (interpreter ran) or the call is rejected
    (blocklist is comprehensive / interpreter not present).
    """

    id: ClassVar[str] = "blocklist-bypass"
    name: ClassVar[str] = "Blocklist Bypass via Incomplete Input Filter"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.COMMAND_INJECTION
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.BLOCKLIST_BYPASS_INTERPRETER,
    ]
    description: ClassVar[str] = (
        "Tests exec-capable tools for interpreter blocklist gaps using "
        "perl, ruby, lua, awk, node, php, and python3 canary payloads."
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
                schema = entry.get("inputSchema", {})
                props = schema.get("properties", {}) if isinstance(schema, dict) else {}
                exec_param = next((k for k in props if _EXEC_PARAM_RE.match(k)), None)
                if not exec_param:
                    continue
                for payload, runtime in _BYPASS_PROBES:
                    f = await self._test_payload(tool, url, name, exec_param, payload, runtime)
                    if f:
                        findings.append(f)
            return findings
        return []

    async def _test_payload(
        self, tool, endpoint: str, tool_name: str, param: str, payload: str, runtime: str
    ) -> Finding | None:
        try:
            async with self.ctx.http_client.post(
                endpoint,
                json=_call(tool_name, param, payload),
                headers=self.ctx.get_auth_headers(tool.auth_profile),
            ) as r:
                resp = await r.text()
        except Exception:
            return None

        if not _CANARY_RE.search(resp):
            return None  # Blocked or interpreter absent.

        return self._create_finding(
            title=f"Blocklist bypass via {runtime}: tool '{tool_name}' executed canary",
            severity=Severity.CRITICAL,
            target_url=endpoint,
            outcome=AttackOutcome.VULNERABLE,
            target_tool=tool_name,
            description=(
                f"Tool '{tool_name}' executed code via `{runtime}` even though "
                f"primary interpreters may be blocked. Canary string appeared in "
                f"the response, confirming execution. Payload: `{payload}`."
            ),
            impact=(
                "Attacker can achieve arbitrary code execution by substituting an "
                "unlisted interpreter, achieving the same outcome as a direct shell "
                "injection while evading keyword-based blocklists."
            ),
            recommendation=(
                "Replace keyword blocklists with an explicit interpreter allowlist "
                "(default-deny execution). Normalise commands before scanning. "
                "Apply seccomp/AppArmor to restrict exec syscalls to approved binaries."
            ),
            evidence={
                "tool_name": tool_name,
                "parameter": param,
                "runtime": runtime,
                "payload": payload,
                "response_snippet": resp[:80],
            },
            blue_team_signal="D08: interpreter bypass canary executed",
        )
