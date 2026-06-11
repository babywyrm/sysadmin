"""MCP01: Token Validation — JWT claim enforcement testing."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, ClassVar

from mcp_slayer.models import AttackCategory, AttackOutcome, Finding, Severity
from mcp_slayer.modules.base import AttackModule
from mcp_slayer.taxonomy import PlaybookThreatID


class TokenValidationModule(AttackModule):
    """Tests JWT validation rigor at tool boundaries.

    Attack scenarios:
        1. Expired token acceptance (exp claim in the past)
        2. Missing audience claim (no aud field)
        3. Algorithm confusion (alg: none)
        4. Tampered claims (modified sub/role without re-signing)
        5. Empty signature (signature stripped)
    """

    id: ClassVar[str] = "token-validation"
    name: ClassVar[str] = "Token Validation Bypass"
    owasp_category: ClassVar[AttackCategory] = AttackCategory.TOKEN_MISMANAGEMENT
    playbook_threats: ClassVar[list[PlaybookThreatID]] = [
        PlaybookThreatID.CONFUSED_DEPUTY,
        PlaybookThreatID.TOKEN_AUDIENCE_BYPASS,
    ]
    description: ClassVar[str] = (
        "Tests JWT validation rigor: expiry, audience, algorithm, signature"
    )
    severity_range: ClassVar[tuple[Severity, Severity]] = (
        Severity.HIGH,
        Severity.CRITICAL,
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.logger.info("Starting Token Validation assessment")

        for tool in self.ctx.config.tools:
            token = await self._obtain_valid_token(tool)
            if not token:
                continue

            tests = [
                ("expired_token", self._make_expired_token(token)),
                ("no_audience", self._strip_claim(token, "aud")),
                ("alg_none", self._set_alg_none(token)),
                ("tampered_role", self._tamper_claim(token, "role", "admin")),
                ("empty_signature", self._strip_signature(token)),
            ]

            for test_id, crafted_token in tests:
                if not crafted_token:
                    continue
                finding = await self._execute_with_safeguards(
                    self._test_token, tool, test_id, crafted_token
                )
                if finding:
                    findings.append(finding)

        return findings

    async def _obtain_valid_token(self, tool) -> str | None:
        auth_profile = self.ctx.get_auth_profile(tool.auth_profile)
        if auth_profile and auth_profile.type == "bearer" and auth_profile.token:
            return auth_profile.token.get_secret_value()
        return None

    async def _test_token(self, tool, test_id: str, token: str) -> Finding | None:
        url = f"{tool.base_url}{tool.execute_path}"

        async with self.ctx.http_client.post(
            url,
            json={"action": "health"},
            headers={"Authorization": f"Bearer {token}"},
        ) as response:
            status = response.status

        if status in (200, 201, 202):
            severity = Severity.CRITICAL if test_id in ("alg_none", "empty_signature") else Severity.HIGH
            return self._create_finding(
                title=f"Token Validation Bypass: {test_id} on {tool.name}",
                severity=severity,
                target_url=url,
                outcome=AttackOutcome.VULNERABLE,
                description=(
                    f"Tool '{tool.name}' accepted a {test_id} token. "
                    f"This indicates insufficient JWT validation."
                ),
                impact=self._impact_for_test(test_id),
                recommendation=self._recommendation_for_test(test_id),
                evidence={
                    "test_id": test_id,
                    "tool": tool.name,
                    "response_status": status,
                },
                blue_team_signal="D09: JTI replay / D01: audience mismatch in auth logs",
            )
        return None

    def _make_expired_token(self, token: str) -> str | None:
        return self._modify_payload(token, {"exp": int(time.time()) - 3600})

    def _strip_claim(self, token: str, claim: str) -> str | None:
        payload = self._decode_payload(token)
        if not payload or claim not in payload:
            return None
        del payload[claim]
        return self._rebuild_token(token, payload)

    def _set_alg_none(self, token: str) -> str | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = self._b64_decode_json(parts[0])
        if not header:
            return None
        header["alg"] = "none"
        new_header = self._b64_encode_json(header)
        return f"{new_header}.{parts[1]}."

    def _tamper_claim(self, token: str, claim: str, value: Any) -> str | None:
        return self._modify_payload(token, {claim: value})

    def _strip_signature(self, token: str) -> str | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        return f"{parts[0]}.{parts[1]}."

    def _modify_payload(self, token: str, updates: dict) -> str | None:
        payload = self._decode_payload(token)
        if not payload:
            return None
        payload.update(updates)
        return self._rebuild_token(token, payload)

    def _rebuild_token(self, original: str, new_payload: dict) -> str:
        parts = original.split(".")
        new_payload_b64 = self._b64_encode_json(new_payload)
        return f"{parts[0]}.{new_payload_b64}.{parts[2]}"

    def _decode_payload(self, token: str) -> dict | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        return self._b64_decode_json(parts[1])

    @staticmethod
    def _b64_decode_json(segment: str) -> dict | None:
        try:
            padding = 4 - len(segment) % 4
            if padding != 4:
                segment += "=" * padding
            return json.loads(base64.urlsafe_b64decode(segment))
        except Exception:
            return None

    @staticmethod
    def _b64_encode_json(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @staticmethod
    def _impact_for_test(test_id: str) -> str:
        impacts = {
            "expired_token": "Stolen tokens remain valid indefinitely, defeating rotation.",
            "no_audience": "Tokens can be replayed across any tool regardless of intent.",
            "alg_none": "Complete auth bypass — attacker can forge arbitrary tokens.",
            "tampered_role": "Privilege escalation by modifying claims without re-signing.",
            "empty_signature": "Signature validation disabled — tokens are not cryptographically verified.",
        }
        return impacts.get(test_id, "Auth bypass.")

    @staticmethod
    def _recommendation_for_test(test_id: str) -> str:
        recs = {
            "expired_token": "Reject tokens where exp < current time. Use short TTLs (5 min).",
            "no_audience": "Require and validate the aud claim at every tool boundary.",
            "alg_none": "Reject alg:none. Allowlist only expected algorithms (RS256, ES256).",
            "tampered_role": "Always verify signature before reading claims. Never trust unsigned payloads.",
            "empty_signature": "Reject tokens with empty or missing signatures.",
        }
        return recs.get(test_id, "Implement full JWT validation per RFC 7519.")
