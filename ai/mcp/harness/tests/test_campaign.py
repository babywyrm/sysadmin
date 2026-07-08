"""Tests for the campaign runner — multi-stage chain orchestration.

Tests cover:
- Model construction and validation
- ABRS scoring
- Chain YAML loading (built-in campaigns)
- Campaign runner execution with mocked modules
- Gate logic (stop_on_block, continue_always, stop_on_vuln)
- Dependency resolution and skipping
- Finding propagation between stages
- Kill switch abort
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_slayer.campaign.models import (
    ABRSScore,
    CampaignDefinition,
    CampaignResult,
    StageDefinition,
    StageGate,
    StageResult,
)
from mcp_slayer.campaign.runner import (
    CampaignRunner,
    load_builtin_campaigns,
    load_campaign,
)
from mcp_slayer.config import AuthProfile, GatewayTarget, SlayerConfig, ToolTarget
from mcp_slayer.engine import SlayerContext
from mcp_slayer.models import AttackOutcome, Finding, Severity
from mcp_slayer.taxonomy import PlaybookThreatID


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _make_config() -> SlayerConfig:
    return SlayerConfig(
        authorized=True,
        gateway=GatewayTarget(base_url="https://gw.example.com"),
        tools=[
            ToolTarget(
                name="test-tool",
                base_url="http://tool.local:8080",
                injection_endpoints=["/ingest"],
                egress_actions=["send_email"],
                retrieval_endpoints=["/query"],
                schema_endpoints=["/schema"],
                recursion_endpoints=["/recurse"],
            )
        ],
        auth_profiles=[AuthProfile(name="default", type="none")],
    )


def _make_ctx() -> SlayerContext:
    config = _make_config()
    ctx = SlayerContext(config)
    ctx.kill_switch_active = False
    return ctx


def _make_finding(
    outcome: AttackOutcome = AttackOutcome.VULNERABLE,
    severity: Severity = Severity.HIGH,
    module: str = "test-module",
) -> Finding:
    return Finding(
        owasp_category="MCP01",
        playbook_threat_ids=[PlaybookThreatID.PROMPT_INJECTION_DIRECT],
        title="Test finding for campaign runner validation",
        severity=severity,
        target_url="http://tool.local:8080/execute",
        attack_module=module,
        outcome=outcome,
        description="This is a test finding generated during campaign runner testing workflow.",
        impact="Demonstrates vulnerability in test context for validation",
        recommendation="Apply appropriate controls as specified in remediation guide",
    )


def _simple_campaign(
    gate: StageGate = StageGate.STOP_ON_BLOCK,
) -> CampaignDefinition:
    return CampaignDefinition(
        id="test-campaign",
        name="Test Campaign",
        description="Unit test campaign with two stages",
        stages=[
            StageDefinition(
                id="stage-1",
                module="prompt-injection-canary",
                action="First stage",
                gate=gate,
            ),
            StageDefinition(
                id="stage-2",
                module="exfiltration-routing",
                action="Second stage",
                gate=StageGate.CONTINUE_ALWAYS,
                depends_on=["stage-1"],
                inject_from_prior=True,
            ),
        ],
        abrs_reachable_agents=3,
        abrs_avg_tool_scope=2.5,
        abrs_memory_persistence_days=7,
        abrs_isolation_boundaries=2,
    )


# --------------------------------------------------------------------------- #
# Model Tests
# --------------------------------------------------------------------------- #


class TestABRSScore:
    def test_contained(self):
        abrs = ABRSScore(
            reachable_agents=1,
            avg_tool_scope=1.0,
            memory_persistence_days=0,
            isolation_boundaries=2,
        ).compute()
        assert abrs.score < 5
        assert abrs.risk_level == "Contained"

    def test_elevated(self):
        abrs = ABRSScore(
            reachable_agents=3,
            avg_tool_scope=2.0,
            memory_persistence_days=2,
            isolation_boundaries=1,
        ).compute()
        assert 5 <= abrs.score < 20
        assert abrs.risk_level == "Elevated"

    def test_critical(self):
        abrs = ABRSScore(
            reachable_agents=5,
            avg_tool_scope=3.0,
            memory_persistence_days=5,
            isolation_boundaries=2,
        ).compute()
        assert 20 <= abrs.score < 100
        assert abrs.risk_level == "Critical"

    def test_systemic(self):
        abrs = ABRSScore(
            reachable_agents=10,
            avg_tool_scope=5.0,
            memory_persistence_days=365,
            isolation_boundaries=1,
        ).compute()
        assert abrs.score >= 100
        assert abrs.risk_level == "Systemic"


class TestCampaignResult:
    def test_compute_summary(self):
        result = CampaignResult(
            campaign_id="test",
            campaign_name="Test",
            stage_results=[
                StageResult(
                    stage_id="s1",
                    module_id="m1",
                    outcome=AttackOutcome.VULNERABLE,
                    findings=[_make_finding()],
                    alert_fired=False,
                ),
                StageResult(
                    stage_id="s2",
                    module_id="m2",
                    outcome=AttackOutcome.BLOCKED,
                    findings=[_make_finding(AttackOutcome.BLOCKED)],
                    alert_fired=True,
                ),
                StageResult(
                    stage_id="s3",
                    module_id="m3",
                    outcome=AttackOutcome.SKIPPED,
                    skipped=True,
                    skip_reason="dep unmet",
                ),
            ],
        )
        result.compute_summary()

        assert result.stages_total == 3
        assert result.stages_executed == 2
        assert result.stages_vulnerable == 1
        assert result.stages_blocked == 1
        assert result.stages_skipped == 1
        assert result.detection_rate == 0.5
        assert result.max_severity == Severity.HIGH


class TestStageDefinition:
    def test_defaults(self):
        stage = StageDefinition(
            id="s1",
            module="prompt-injection-canary",
            action="Test action",
        )
        assert stage.gate == StageGate.STOP_ON_BLOCK
        assert stage.depends_on == []
        assert stage.inject_from_prior is False

    def test_all_fields(self):
        stage = StageDefinition(
            id="s1",
            module="tool-poisoning",
            action="Poison tool",
            taxonomy_ids=[PlaybookThreatID.SUPPLY_CHAIN_VIA_CONTENT],
            gate=StageGate.CONTINUE_ALWAYS,
            depends_on=["s0"],
            inject_from_prior=True,
            timeout_seconds=60,
        )
        assert stage.gate == StageGate.CONTINUE_ALWAYS
        assert stage.timeout_seconds == 60


# --------------------------------------------------------------------------- #
# Chain Loading Tests
# --------------------------------------------------------------------------- #


class TestChainLoading:
    def test_load_builtin_campaigns(self):
        campaigns = load_builtin_campaigns()
        assert len(campaigns) == 5

    def test_builtin_campaigns_have_required_fields(self):
        for c in load_builtin_campaigns():
            assert c.id
            assert c.name
            assert c.description
            assert len(c.stages) >= 2
            for stage in c.stages:
                assert stage.id
                assert stage.module
                assert stage.action

    def test_builtin_campaign_ids_unique(self):
        campaigns = load_builtin_campaigns()
        ids = [c.id for c in campaigns]
        assert len(ids) == len(set(ids))

    def test_all_stage_modules_exist_in_registry(self):
        from mcp_slayer.modules import MODULE_REGISTRY

        campaigns = load_builtin_campaigns()
        for c in campaigns:
            for stage in c.stages:
                assert stage.module in MODULE_REGISTRY, (
                    f"Campaign '{c.id}' stage '{stage.id}' references "
                    f"unknown module '{stage.module}'"
                )

    def test_stage_dependencies_reference_valid_ids(self):
        for c in load_builtin_campaigns():
            stage_ids = {s.id for s in c.stages}
            for stage in c.stages:
                for dep in stage.depends_on:
                    assert dep in stage_ids, (
                        f"Campaign '{c.id}' stage '{stage.id}' depends on "
                        f"'{dep}' which is not a stage in this campaign"
                    )

    def test_load_single_chain_file(self):
        chains_dir = Path(__file__).parent.parent / "mcp_slayer" / "campaign" / "chains"
        chain_files = list(chains_dir.glob("*.yaml"))
        assert chain_files
        c = load_campaign(chain_files[0])
        assert isinstance(c, CampaignDefinition)


# --------------------------------------------------------------------------- #
# Runner Tests
# --------------------------------------------------------------------------- #


class TestCampaignRunner:
    @pytest.mark.asyncio
    async def test_all_stages_vulnerable(self):
        ctx = _make_ctx()
        runner = CampaignRunner(ctx)
        campaign = _simple_campaign()

        vuln_finding = _make_finding(AttackOutcome.VULNERABLE)

        with patch.dict(
            "mcp_slayer.modules.MODULE_REGISTRY",
            {
                "prompt-injection-canary": _mock_module_class([vuln_finding]),
                "exfiltration-routing": _mock_module_class([vuln_finding]),
            },
        ):
            result = await runner.execute(campaign)

        assert result.stages_executed == 2
        assert result.stages_vulnerable == 2
        assert result.halted_at_stage is None

    @pytest.mark.asyncio
    async def test_stop_on_block_halts_campaign(self):
        ctx = _make_ctx()
        runner = CampaignRunner(ctx)
        campaign = _simple_campaign(gate=StageGate.STOP_ON_BLOCK)

        blocked_finding = _make_finding(AttackOutcome.BLOCKED)

        with patch.dict(
            "mcp_slayer.modules.MODULE_REGISTRY",
            {
                "prompt-injection-canary": _mock_module_class([blocked_finding]),
                "exfiltration-routing": _mock_module_class([_make_finding()]),
            },
        ):
            result = await runner.execute(campaign)

        assert result.halted_at_stage == "stage-1"
        assert result.stages_executed == 1

    @pytest.mark.asyncio
    async def test_continue_always_proceeds_after_block(self):
        ctx = _make_ctx()
        runner = CampaignRunner(ctx)
        campaign = CampaignDefinition(
            id="test",
            name="Test",
            description="Test continue_always gate",
            stages=[
                StageDefinition(
                    id="s1",
                    module="prompt-injection-canary",
                    action="First",
                    gate=StageGate.CONTINUE_ALWAYS,
                ),
                StageDefinition(
                    id="s2",
                    module="exfiltration-routing",
                    action="Second",
                    gate=StageGate.CONTINUE_ALWAYS,
                ),
            ],
        )

        blocked = _make_finding(AttackOutcome.BLOCKED)
        vuln = _make_finding(AttackOutcome.VULNERABLE)

        with patch.dict(
            "mcp_slayer.modules.MODULE_REGISTRY",
            {
                "prompt-injection-canary": _mock_module_class([blocked]),
                "exfiltration-routing": _mock_module_class([vuln]),
            },
        ):
            result = await runner.execute(campaign)

        assert result.halted_at_stage is None
        assert result.stages_executed == 2

    @pytest.mark.asyncio
    async def test_dependency_skip(self):
        ctx = _make_ctx()
        runner = CampaignRunner(ctx)
        campaign = CampaignDefinition(
            id="test",
            name="Test Dep Skip",
            description="Stage 2 depends on stage 1 which is blocked",
            stages=[
                StageDefinition(
                    id="s1",
                    module="prompt-injection-canary",
                    action="First",
                    gate=StageGate.CONTINUE_ALWAYS,
                ),
                StageDefinition(
                    id="s2",
                    module="exfiltration-routing",
                    action="Second (depends on s1 vuln)",
                    depends_on=["s1"],
                    gate=StageGate.CONTINUE_ALWAYS,
                ),
            ],
        )

        blocked = _make_finding(AttackOutcome.BLOCKED)

        with patch.dict(
            "mcp_slayer.modules.MODULE_REGISTRY",
            {
                "prompt-injection-canary": _mock_module_class([blocked]),
                "exfiltration-routing": _mock_module_class([_make_finding()]),
            },
        ):
            result = await runner.execute(campaign)

        assert result.stages_skipped == 1
        s2 = result.stage_results[1]
        assert s2.skipped is True
        assert "dependency not met" in s2.skip_reason

    @pytest.mark.asyncio
    async def test_kill_switch_aborts(self):
        ctx = _make_ctx()
        ctx.kill_switch_active = True
        runner = CampaignRunner(ctx)
        campaign = _simple_campaign()

        result = await runner.execute(campaign)

        assert result.halted_at_stage == "stage-1"
        assert result.halt_reason == "kill_switch"

    @pytest.mark.asyncio
    async def test_unknown_module_returns_error(self):
        ctx = _make_ctx()
        runner = CampaignRunner(ctx)
        campaign = CampaignDefinition(
            id="test",
            name="Test Unknown",
            description="References a module that does not exist",
            stages=[
                StageDefinition(
                    id="s1",
                    module="nonexistent-module",
                    action="This should error",
                    gate=StageGate.CONTINUE_ALWAYS,
                ),
                StageDefinition(
                    id="s2",
                    module="prompt-injection-canary",
                    action="Second",
                    gate=StageGate.CONTINUE_ALWAYS,
                ),
            ],
        )

        with patch.dict(
            "mcp_slayer.modules.MODULE_REGISTRY",
            {"prompt-injection-canary": _mock_module_class([_make_finding()])},
        ):
            result = await runner.execute(campaign)

        assert result.stage_results[0].outcome == AttackOutcome.ERROR
        assert "not in registry" in result.stage_results[0].error

    @pytest.mark.asyncio
    async def test_abrs_computed(self):
        ctx = _make_ctx()
        runner = CampaignRunner(ctx)
        campaign = _simple_campaign()

        with patch.dict(
            "mcp_slayer.modules.MODULE_REGISTRY",
            {
                "prompt-injection-canary": _mock_module_class([_make_finding()]),
                "exfiltration-routing": _mock_module_class([_make_finding()]),
            },
        ):
            result = await runner.execute(campaign)

        assert result.abrs is not None
        assert result.abrs.score > 0
        assert result.abrs.risk_level in (
            "Contained",
            "Elevated",
            "Critical",
            "Systemic",
        )

    @pytest.mark.asyncio
    async def test_finding_propagation(self):
        ctx = _make_ctx()
        runner = CampaignRunner(ctx)
        campaign = _simple_campaign()

        vuln = _make_finding(AttackOutcome.VULNERABLE)
        received_context = []

        class FakeModule:
            injected_context = None

            def __init__(self, ctx):
                pass

            async def run(self):
                if self.injected_context:
                    received_context.extend(self.injected_context)
                return [vuln]

        with patch.dict(
            "mcp_slayer.modules.MODULE_REGISTRY",
            {
                "prompt-injection-canary": _mock_module_class([vuln]),
                "exfiltration-routing": FakeModule,
            },
        ):
            await runner.execute(campaign)

        assert len(received_context) == 1
        assert received_context[0]["outcome"] == "VULNERABLE"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _mock_module_class(findings: list[Finding]):
    """Create a mock module class that returns predetermined findings."""

    class MockModule:
        injected_context = None

        def __init__(self, ctx):
            pass

        async def run(self):
            return findings

    return MockModule
