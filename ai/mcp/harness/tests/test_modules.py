"""Tests for the attack modules.

These use a scripted fake HTTP client so module logic (payload generation,
response interpretation, finding construction) is exercised without a live
target. The real `SlayerContext` is reused — only its `http_client` is faked.
"""

from __future__ import annotations

import pytest

from mcp_slayer.config import (
    AuthProfile,
    GatewayTarget,
    SlayerConfig,
    ToolTarget,
)
from mcp_slayer.engine import SlayerContext
from mcp_slayer.models import AttackOutcome
from mcp_slayer.modules.exfiltration import ExfiltrationModule
from mcp_slayer.modules.prompt_injection import (
    INJECTION_PAYLOADS,
    PromptInjectionModule,
)
from mcp_slayer.modules.token_validation import TokenValidationModule


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def __aenter__(self) -> _FakeResponse:
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def text(self) -> str:
        return self._body


class _FakeHTTPClient:
    """Returns scripted responses and records every request made."""

    def __init__(self, responder):
        self._responder = responder
        self.requests: list[dict] = []

    def post(self, url, json=None, headers=None):
        self.requests.append({"url": url, "json": json, "headers": headers})
        status, body = self._responder(url, json, headers)
        return _FakeResponse(status, body)


def _make_context(tool: ToolTarget, responder, *, token: str | None = None) -> SlayerContext:
    auth_profiles = [AuthProfile(name="default", type="none")]
    if token is not None:
        auth_profiles = [AuthProfile(name="default", type="bearer", token=token)]

    config = SlayerConfig(
        authorized=True,
        gateway=GatewayTarget(base_url="https://gw.example.com"),
        tools=[tool],
        auth_profiles=auth_profiles,
    )
    ctx = SlayerContext(config)
    ctx.http_client = _FakeHTTPClient(responder)
    return ctx


# --------------------------------------------------------------------------- #
# Prompt Injection
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_prompt_injection_flags_canary_echo():
    tool = ToolTarget(
        name="doc-reader",
        base_url="http://tool.local:8080",
        injection_endpoints=["/ingest"],
    )
    # Server echoes the payload back, leaking the canary.
    ctx = _make_context(tool, lambda url, body, hdr: (200, body["input"]))

    findings = await PromptInjectionModule(ctx).run()

    assert len(findings) == len(INJECTION_PAYLOADS)  # one finding per payload
    assert all(f.outcome == AttackOutcome.VULNERABLE for f in findings)
    assert all(f.evidence["canary_found"] for f in findings)


@pytest.mark.asyncio
async def test_prompt_injection_clean_server_no_findings():
    tool = ToolTarget(
        name="doc-reader",
        base_url="http://tool.local:8080",
        injection_endpoints=["/ingest"],
    )
    # Server sanitizes output — canary never appears.
    ctx = _make_context(tool, lambda url, body, hdr: (200, "ok, content stored"))

    findings = await PromptInjectionModule(ctx).run()

    assert findings == []


@pytest.mark.asyncio
async def test_prompt_injection_skips_tools_without_injection_endpoints():
    tool = ToolTarget(name="calc", base_url="http://tool.local:8080")
    ctx = _make_context(tool, lambda url, body, hdr: (200, "SLAYER_CANARY_LEAKED"))

    findings = await PromptInjectionModule(ctx).run()

    assert findings == []
    assert ctx.http_client.requests == []  # no endpoints => no traffic


# --------------------------------------------------------------------------- #
# Token Validation
# --------------------------------------------------------------------------- #

# header.payload.signature — payload decodes to {"sub":"u","aud":"a","role":"user","exp":<future>}
_VALID_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ1IiwiYXVkIjoiYSIsInJvbGUiOiJ1c2VyIiwiZXhwIjo0MTAyNDQ0ODAwfQ."
    "c2lnbmF0dXJl"
)


@pytest.mark.asyncio
async def test_token_validation_flags_accepted_forged_tokens():
    tool = ToolTarget(name="api", base_url="http://tool.local:8080")
    # Permissive server accepts everything.
    ctx = _make_context(
        tool, lambda url, body, hdr: (200, "ok"), token=_VALID_JWT
    )

    findings = await TokenValidationModule(ctx).run()

    test_ids = {f.evidence["test_id"] for f in findings}
    assert test_ids == {
        "expired_token",
        "no_audience",
        "alg_none",
        "tampered_role",
        "empty_signature",
    }
    # alg:none and empty signature are the crypto-bypass criticals.
    crit = {f.evidence["test_id"] for f in findings if f.severity.value == "CRITICAL"}
    assert crit == {"alg_none", "empty_signature"}


@pytest.mark.asyncio
async def test_token_validation_strict_server_no_findings():
    tool = ToolTarget(name="api", base_url="http://tool.local:8080")
    # Strict server rejects every forged token.
    ctx = _make_context(
        tool, lambda url, body, hdr: (401, "unauthorized"), token=_VALID_JWT
    )

    findings = await TokenValidationModule(ctx).run()

    assert findings == []


@pytest.mark.asyncio
async def test_token_validation_skips_when_no_bearer_token():
    tool = ToolTarget(name="api", base_url="http://tool.local:8080")
    # No bearer token configured -> module cannot craft tokens.
    ctx = _make_context(tool, lambda url, body, hdr: (200, "ok"))

    findings = await TokenValidationModule(ctx).run()

    assert findings == []
    assert ctx.http_client.requests == []


# --------------------------------------------------------------------------- #
# Exfiltration
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_exfiltration_flags_unblocked_egress():
    tool = ToolTarget(
        name="slack",
        base_url="http://tool.local:8080",
        egress_actions=["message.send"],
    )
    # Server accepts every chunk -> full exfil.
    ctx = _make_context(tool, lambda url, body, hdr: (200, "sent"))

    findings = await ExfiltrationModule(ctx).run()

    assert len(findings) == 1
    f = findings[0]
    assert f.outcome == AttackOutcome.VULNERABLE
    assert f.evidence["scenario_id"] == "chunked_slack"
    assert f.evidence["chunks_sent"] == 20


@pytest.mark.asyncio
async def test_exfiltration_partial_when_rate_limited():
    tool = ToolTarget(
        name="slack",
        base_url="http://tool.local:8080",
        egress_actions=["message.send"],
    )
    state = {"n": 0}

    def responder(url, body, hdr):
        state["n"] += 1
        return (429, "rate limited") if state["n"] > 3 else (200, "sent")

    ctx = _make_context(tool, responder)

    findings = await ExfiltrationModule(ctx).run()

    assert len(findings) == 1
    f = findings[0]
    assert f.outcome == AttackOutcome.PARTIALLY_VULNERABLE
    assert f.evidence["chunks_sent"] == 3


@pytest.mark.asyncio
async def test_exfiltration_skips_non_egress_tools():
    tool = ToolTarget(name="calc", base_url="http://tool.local:8080")
    ctx = _make_context(tool, lambda url, body, hdr: (200, "sent"))

    findings = await ExfiltrationModule(ctx).run()

    assert findings == []
    assert ctx.http_client.requests == []
