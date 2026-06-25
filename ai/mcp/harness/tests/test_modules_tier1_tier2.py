"""Tests for Tier 1 and Tier 2 gap modules.

All tests use the same fake-HTTP-client pattern as test_modules.py:
a scripted responder replaces the real aiohttp session so module logic
(detection patterns, finding construction, outcome classification) is
exercised without a live MCP server.
"""

from __future__ import annotations

import json

import pytest

from mcp_slayer.config import AuthProfile, GatewayTarget, SlayerConfig, ToolTarget
from mcp_slayer.engine import SlayerContext
from mcp_slayer.models import AttackOutcome, Severity
from mcp_slayer.modules.agent_config_tampering import AgentConfigTamperingModule
from mcp_slayer.modules.blocklist_bypass import BlocklistBypassModule, _CANARY_RE
from mcp_slayer.modules.governance_gate_bypass import GovernanceGateBypassModule
from mcp_slayer.modules.hallucination_destruction import HallucinationDestructionModule
from mcp_slayer.modules.rag_pipeline_injection import RagPipelineInjectionModule
from mcp_slayer.modules.secrets_in_tool_output import SecretsInToolOutputModule, _scan_for_secrets
from mcp_slayer.modules.transport_identity import TransportIdentityModule
from mcp_slayer.taxonomy import PlaybookThreatID

# ── Shared test infrastructure ────────────────────────────────────────────────


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def text(self):
        return self._body

    async def json(self, **_):
        return json.loads(self._body)


class _FakeHTTPClient:
    def __init__(self, responder):
        self._responder = responder
        self.requests: list[dict] = []

    def post(self, url, *, json=None, headers=None, **_):
        self.requests.append({"url": url, "json": json, "headers": headers})
        return self._responder(url, json)


def _make_ctx(responder) -> SlayerContext:
    cfg = SlayerConfig(
        authorized=True,
        gateway=GatewayTarget(base_url="http://target:9090"),
        tools=[
            ToolTarget(
                name="test-server",
                base_url="http://target:9090",
                schema_endpoints=["/mcp"],
                auth_profile="default",
            )
        ],
        auth_profiles=[AuthProfile(name="default", type="none")],
    )
    ctx = SlayerContext(cfg)
    ctx.http_client = _FakeHTTPClient(responder)
    return ctx


def _tools_list_response(tools: list[dict]) -> str:
    return json.dumps({"result": {"tools": tools}})


# ── Tier 1: secrets-in-tool-output ───────────────────────────────────────────


class TestSecretsInToolOutput:
    def test_scan_detects_aws_key(self):
        hits = _scan_for_secrets("Found key: AKIAIOSFODNN7EXAMPLE in output")
        assert any("AWS" in h[0] for h in hits)
        assert any(h[1] == Severity.CRITICAL for h in hits)

    def test_scan_detects_jwt(self):
        # Three base64url segments each >= 20 chars.
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        hits = _scan_for_secrets(f"token={jwt}")
        assert any("JWT" in h[0] for h in hits)

    def test_scan_detects_db_url(self):
        hits = _scan_for_secrets("postgresql://admin:s3cret@db:5432/prod")
        assert len(hits) >= 1
        assert any(h[1] == Severity.CRITICAL for h in hits)

    def test_scan_clean_text(self):
        assert _scan_for_secrets("The deployment completed successfully.") == []

    @pytest.mark.asyncio
    async def test_finding_raised_on_credential_response(self):
        tool_list = _tools_list_response([
            {"name": "get-config", "description": "Get config", "inputSchema": {"type": "object", "properties": {}}}
        ])

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            # Tool response contains an AWS key.
            return _FakeResponse(200, json.dumps({
                "jsonrpc": "2.0", "id": 2,
                "result": {"content": [{"text": "api_key=AKIAIOSFODNN7EXAMPLE"}]}
            }))

        ctx = _make_ctx(responder)
        module = SecretsInToolOutputModule(ctx)
        findings = await module.run()
        assert len(findings) >= 1
        assert any(f.outcome == AttackOutcome.VULNERABLE for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_on_clean_response(self):
        tool_list = _tools_list_response([
            {"name": "status", "description": "Get status", "inputSchema": {"type": "object", "properties": {}}}
        ])

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            return _FakeResponse(200, json.dumps({"result": {"content": [{"text": "status: OK"}]}}))

        ctx = _make_ctx(responder)
        findings = await SecretsInToolOutputModule(ctx).run()
        assert findings == []


# ── Tier 1: agent-config-tampering ───────────────────────────────────────────


class TestAgentConfigTampering:
    @pytest.mark.asyncio
    async def test_static_finding_on_config_write_tool(self):
        tool_list = _tools_list_response([{
            "name": "update_system_prompt",
            "description": "Update the agent's system prompt",
            "inputSchema": {
                "type": "object",
                "properties": {"system_prompt": {"type": "string"}},
            },
        }])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await AgentConfigTamperingModule(ctx).run()
        assert len(findings) >= 1
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

    @pytest.mark.asyncio
    async def test_behavioral_critical_finding_on_accepted_write(self):
        # Use a tool name that triggers CRITICAL static (matches write+config+critical_signal).
        tool_list = _tools_list_response([{
            "name": "update_system_prompt",
            "description": "Update the agent system_prompt configuration",
            "inputSchema": {
                "type": "object",
                "properties": {"system_prompt": {"type": "string"}},
                "required": ["system_prompt"],
            },
        }])

        call_count = [0]

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            call_count[0] += 1
            # Accept the canary write with HTTP 200.
            return _FakeResponse(200, json.dumps({"result": {"status": "updated", "message": "configuration saved"}}))

        ctx = _make_ctx(responder)
        findings = await AgentConfigTamperingModule(ctx).run()
        # At minimum we get the static finding.
        assert len(findings) >= 1
        # If behavioral probe fired (write accepted), we get CRITICAL.
        if call_count[0] > 0:
            critical = [f for f in findings if f.severity == Severity.CRITICAL]
            assert len(critical) >= 1

    @pytest.mark.asyncio
    async def test_no_finding_on_safe_tools(self):
        tool_list = _tools_list_response([
            {"name": "get_status", "description": "Check service status", "inputSchema": {"type": "object", "properties": {}}},
        ])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await AgentConfigTamperingModule(ctx).run()
        assert findings == []


# ── Tier 1: hallucination-destruction ────────────────────────────────────────


class TestHallucinationDestruction:
    @pytest.mark.asyncio
    async def test_static_finding_on_destructive_tool(self):
        tool_list = _tools_list_response([{
            "name": "delete_service",
            "description": "Delete a Kubernetes service by name",
            "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
        }])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await HallucinationDestructionModule(ctx).run()
        assert any("destructive" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_behavioral_critical_on_no_gate(self):
        tool_list = _tools_list_response([{
            "name": "scale_to_zero",
            "description": "Scale deployment to zero replicas",
            "inputSchema": {
                "type": "object",
                "properties": {"instruction": {"type": "string"}},
            },
        }])

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            # Responds as if it executed without gate.
            return _FakeResponse(200, json.dumps({"result": {"status": "success", "message": "scaled"}}))

        ctx = _make_ctx(responder)
        findings = await HallucinationDestructionModule(ctx).run()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any(f.outcome == AttackOutcome.VULNERABLE for f in critical)

    @pytest.mark.asyncio
    async def test_no_behavioral_finding_when_gate_fires(self):
        tool_list = _tools_list_response([{
            "name": "terminate_instance",
            "description": "Terminate a compute instance",
            "inputSchema": {
                "type": "object",
                "properties": {"instruction": {"type": "string"}},
            },
        }])

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            # Gate fires — asks for confirmation.
            return _FakeResponse(200, json.dumps({"result": {"message": "Please confirm: which instance did you mean?"}}))

        ctx = _make_ctx(responder)
        findings = await HallucinationDestructionModule(ctx).run()
        # Static finding expected, but no CRITICAL behavioral one.
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0


# ── Tier 2: blocklist-bypass ──────────────────────────────────────────────────


class TestBlocklistBypass:
    def test_canary_regex_matches(self):
        assert _CANARY_RE.search("output: CANARY end")

    def test_canary_regex_no_match(self):
        assert not _CANARY_RE.search("command blocked")

    @pytest.mark.asyncio
    async def test_finding_on_interpreter_exec(self):
        tool_list = _tools_list_response([{
            "name": "run_maintenance",
            "description": "Run maintenance command",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
            },
        }])

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            # Simulate perl execution: CANARY in output.
            return _FakeResponse(200, json.dumps({"result": {"output": "CANARY"}}))

        ctx = _make_ctx(responder)
        findings = await BlocklistBypassModule(ctx).run()
        assert len(findings) >= 1
        assert all(f.severity == Severity.CRITICAL for f in findings)
        assert any("perl" in f.title or "ruby" in f.title or "lua" in f.title
                   or "awk" in f.title or "node" in f.title or "php" in f.title
                   for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_when_blocked(self):
        tool_list = _tools_list_response([{
            "name": "exec_cmd",
            "description": "Execute a shell command",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
            },
        }])

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            return _FakeResponse(403, json.dumps({"error": "forbidden"}))

        ctx = _make_ctx(responder)
        findings = await BlocklistBypassModule(ctx).run()
        assert findings == []


# ── Tier 2: rag-pipeline-injection ───────────────────────────────────────────


class TestRagPipelineInjection:
    @pytest.mark.asyncio
    async def test_static_finding_on_ingest_query_pair(self):
        tool_list = _tools_list_response([
            {
                "name": "add_document",
                "description": "Ingest a document into the knowledge base",
                "inputSchema": {"type": "object", "properties": {"content": {"type": "string"}}},
            },
            {
                "name": "search_knowledge",
                "description": "Search the knowledge base",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
            },
        ])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await RagPipelineInjectionModule(ctx).run()
        assert any("RAG corpus write surface" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_without_ingest_query_pair(self):
        tool_list = _tools_list_response([
            {"name": "get_status", "description": "Status", "inputSchema": {"type": "object", "properties": {}}},
        ])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await RagPipelineInjectionModule(ctx).run()
        assert findings == []


# ── Tier 2: governance-gate-bypass ───────────────────────────────────────────


class TestGovernanceGateBypass:
    @pytest.mark.asyncio
    async def test_static_finding_on_gate_with_url_param(self):
        tool_list = _tools_list_response([{
            "name": "deploy_artifact",
            "description": "Deploy a build artifact",
            "inputSchema": {
                "type": "object",
                "properties": {"war_url": {"type": "string"}},
            },
        }])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await GovernanceGateBypassModule(ctx).run()
        assert any("Governance gate with URL parameter" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_behavioral_critical_on_gate_approval(self):
        tool_list = _tools_list_response([{
            "name": "validate_build",
            "description": "Validate build artifact URL before deploy",
            "inputSchema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
            },
        }])

        def responder(url, body):
            if body and body.get("method") == "tools/list":
                return _FakeResponse(200, tool_list)
            # Gate approves redirect URL without following it.
            return _FakeResponse(200, json.dumps({"result": {"status": "approved", "message": "OK"}}))

        ctx = _make_ctx(responder)
        findings = await GovernanceGateBypassModule(ctx).run()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


# ── Tier 2: transport-identity ────────────────────────────────────────────────


class TestTransportIdentity:
    @pytest.mark.asyncio
    async def test_transport_b_finding_on_delegate_tool(self):
        tool_list = _tools_list_response([{
            "name": "invoke_downstream_agent",
            "description": "Call downstream agent API with forwarded credentials",
            "inputSchema": {"type": "object", "properties": {"token": {"type": "string"}}},
        }])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await TransportIdentityModule(ctx).run()
        b_findings = [f for f in findings if "Transport B" in f.title]
        assert len(b_findings) >= 1
        assert all(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in b_findings)

    @pytest.mark.asyncio
    async def test_transport_d_finding_on_subprocess_tool(self):
        tool_list = _tools_list_response([{
            "name": "spawn_worker_process",
            "description": "Spawn a background worker subprocess",
            "inputSchema": {"type": "object", "properties": {"task": {"type": "string"}}},
        }])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await TransportIdentityModule(ctx).run()
        d_findings = [f for f in findings if "Transport D" in f.title]
        assert len(d_findings) >= 1

    @pytest.mark.asyncio
    async def test_obo_present_reduces_severity(self):
        """Tool with OBO signal should be HIGH not CRITICAL."""
        tool_list = _tools_list_response([{
            "name": "delegate_task",
            "description": "Call downstream via OBO token exchange (RFC 8693 act chain)",
            "inputSchema": {"type": "object", "properties": {"task": {"type": "string"}}},
        }])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await TransportIdentityModule(ctx).run()
        assert all(f.severity == Severity.HIGH for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_on_safe_tools(self):
        tool_list = _tools_list_response([
            {"name": "list_pods", "description": "List Kubernetes pods", "inputSchema": {"type": "object", "properties": {}}},
        ])

        def responder(url, body):
            return _FakeResponse(200, tool_list)

        ctx = _make_ctx(responder)
        findings = await TransportIdentityModule(ctx).run()
        assert findings == []


# ── Taxonomy registration sanity ─────────────────────────────────────────────


def test_all_tier2_modules_registered():
    from mcp_slayer.modules import MODULE_REGISTRY
    expected = {
        "secrets-in-tool-output",
        "agent-config-tampering",
        "hallucination-destruction",
        "blocklist-bypass",
        "rag-pipeline-injection",
        "governance-gate-bypass",
        "transport-identity",
    }
    assert expected <= set(MODULE_REGISTRY.keys())


def test_tier2_playbook_threats_in_taxonomy():
    extended = [
        PlaybookThreatID.AGENT_HTTP_BYPASS,
        PlaybookThreatID.RAG_PIPELINE_INJECTION,
        PlaybookThreatID.AI_GOVERNANCE_GATE_BYPASS,
        PlaybookThreatID.BLOCKLIST_BYPASS_INTERPRETER,
        PlaybookThreatID.AGENT_CHAIN_TRANSPORT_B_IDENTITY,
        PlaybookThreatID.SDK_CREDENTIAL_CACHE_EXPOSURE,
        PlaybookThreatID.AGENT_CHAIN_TRANSPORT_C_IDENTITY,
        PlaybookThreatID.AGENT_CHAIN_SUBPROCESS_CRED,
        PlaybookThreatID.AGENT_CHAIN_FUNCTION_CALL_LEAK,
    ]
    for t in extended:
        assert t.value.startswith("MCP-T"), f"Bad ID: {t}"
