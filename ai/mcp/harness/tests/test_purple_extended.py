"""Tests for canary deployment, dashboard trending, and regression suite."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_slayer.models import AttackOutcome, Finding, Severity
from mcp_slayer.purple.canary import (
    CanaryDeployer,
    CanaryMonitor,
    CanaryStatus,
    CanaryType,
    DeployedCanary,
)
from mcp_slayer.purple.dashboard import (
    DashboardStore,
    DrillSnapshot,
    TrendMetrics,
    format_dashboard,
)
from mcp_slayer.purple.regression import (
    RegressionCase,
    RegressionSuite,
)
from mcp_slayer.taxonomy import PlaybookThreatID


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_finding(module: str = "prompt-injection-canary") -> Finding:
    return Finding(
        owasp_category="MCP06",
        playbook_threat_ids=[PlaybookThreatID.PROMPT_INJECTION_DIRECT],
        title="Confirmed vulnerability for regression testing workflow",
        severity=Severity.HIGH,
        target_url="http://tool.local:8080/execute",
        attack_module=module,
        outcome=AttackOutcome.VULNERABLE,
        description="Injection payload echoed canary in agent response context during testing.",
        impact="Demonstrates that tool output flows into agent reasoning without sanitization",
        recommendation="Apply output classifiers and content tagging to tool responses before injection",
        evidence={"payload_id": "ignore_previous", "canary_token": "SLAYER_TEST_001"},
    )


# --------------------------------------------------------------------------- #
# Canary Tests
# --------------------------------------------------------------------------- #


class TestCanaryDeployer:
    def test_generate_token_format(self):
        deployer = CanaryDeployer(namespace="test")
        token = deployer.generate_token()
        assert token.startswith("MCPCANARY-test-")
        assert len(token) > 20

    def test_tokens_are_unique(self):
        deployer = CanaryDeployer()
        tokens = [deployer.generate_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_plant_creates_canary(self):
        deployer = CanaryDeployer()
        canary = deployer.plant(
            CanaryType.RAG_CORPUS,
            "/docs/policy.md",
            description="Test canary",
        )
        assert canary.canary_type == CanaryType.RAG_CORPUS
        assert canary.location == "/docs/policy.md"
        assert canary.is_active
        assert canary.status == CanaryStatus.ACTIVE

    def test_plant_suite_creates_6(self):
        deployer = CanaryDeployer()
        canaries = deployer.plant_suite()
        assert len(canaries) == 6
        types = {c.canary_type for c in canaries}
        assert CanaryType.RAG_CORPUS in types
        assert CanaryType.CREDENTIAL in types

    def test_active_canaries_property(self):
        deployer = CanaryDeployer()
        deployer.plant(CanaryType.DOCUMENT, "/doc1")
        deployer.plant(CanaryType.DOCUMENT, "/doc2")
        deployer._deployed[0].status = CanaryStatus.DISABLED
        assert len(deployer.active_canaries) == 1

    def test_fingerprint(self):
        deployer = CanaryDeployer()
        canary = deployer.plant(CanaryType.CREDENTIAL, "/creds")
        assert len(canary.fingerprint) == 16


class TestCanaryMonitor:
    @pytest.mark.asyncio
    async def test_no_alerts_when_clean(self):
        deployer = CanaryDeployer()
        canaries = [deployer.plant(CanaryType.RAG_CORPUS, "/doc")]
        monitor = CanaryMonitor(
            canaries=canaries,
            check_functions=[lambda token: []],
        )
        alerts = await monitor.check()
        assert alerts == []

    @pytest.mark.asyncio
    async def test_alert_on_detection(self):
        deployer = CanaryDeployer()
        canary = deployer.plant(CanaryType.CREDENTIAL, "/creds")

        def check_fn(token):
            return [{"location": "attacker-server-log", "type": "exfiltration"}]

        monitor = CanaryMonitor(canaries=[canary], check_functions=[check_fn])
        alerts = await monitor.check()

        assert len(alerts) == 1
        assert alerts[0].detected_in == "attacker-server-log"
        assert alerts[0].violation_type == "exfiltration"
        assert canary.status == CanaryStatus.TRIGGERED

    @pytest.mark.asyncio
    async def test_summary(self):
        deployer = CanaryDeployer()
        c1 = deployer.plant(CanaryType.RAG_CORPUS, "/doc1")
        c2 = deployer.plant(CanaryType.CREDENTIAL, "/creds")
        c2.status = CanaryStatus.TRIGGERED

        monitor = CanaryMonitor(canaries=[c1, c2], check_functions=[])
        s = monitor.summary()
        assert s["total_canaries"] == 2
        assert s["triggered"] == 1


# --------------------------------------------------------------------------- #
# Dashboard Tests
# --------------------------------------------------------------------------- #


class TestDashboardStore:
    def test_save_and_load(self, tmp_path):
        store = DashboardStore(tmp_path / "drills.jsonl")
        snapshot = DrillSnapshot(
            drill_id="drill-001",
            timestamp=datetime(2026, 7, 8, 10, 0, 0, tzinfo=UTC),
            findings_total=15,
            findings_critical=2,
            detection_rate=0.75,
            mean_mttd_ms=5000.0,
            max_mttd_ms=12000,
            coverage_by_category={"MCP06": 1.0, "MCP02": 0.5},
        )
        store.save_snapshot(snapshot)

        loaded = store.load_snapshots()
        assert len(loaded) == 1
        assert loaded[0].drill_id == "drill-001"
        assert loaded[0].detection_rate == 0.75

    def test_multiple_snapshots(self, tmp_path):
        store = DashboardStore(tmp_path / "drills.jsonl")
        for i in range(5):
            store.save_snapshot(DrillSnapshot(
                drill_id=f"drill-{i:03d}",
                timestamp=datetime(2026, 7, i + 1, 10, 0, 0, tzinfo=UTC),
                findings_total=10,
                findings_critical=1,
                detection_rate=0.5 + i * 0.1,
                mean_mttd_ms=10000.0 - i * 1000,
                max_mttd_ms=15000,
                coverage_by_category={"MCP06": 0.5 + i * 0.1},
            ))

        loaded = store.load_snapshots()
        assert len(loaded) == 5

    def test_compute_trends(self, tmp_path):
        store = DashboardStore(tmp_path / "drills.jsonl")
        for i in range(6):
            store.save_snapshot(DrillSnapshot(
                drill_id=f"drill-{i:03d}",
                timestamp=datetime(2026, 7, i + 1, 10, 0, 0, tzinfo=UTC),
                findings_total=10,
                findings_critical=1,
                detection_rate=0.5 + i * 0.08,
                mean_mttd_ms=10000.0 - i * 1500,
                max_mttd_ms=15000,
                coverage_by_category={"MCP06": 0.5 + i * 0.1},
            ))

        trends = store.compute_trends()
        assert trends.total_drills == 6
        assert trends.mttd_improving is True
        assert trends.best_detection_rate > trends.worst_detection_rate

    def test_detect_regressions(self, tmp_path):
        store = DashboardStore(tmp_path / "drills.jsonl")
        store.save_snapshot(DrillSnapshot(
            drill_id="drill-001",
            timestamp=datetime(2026, 7, 1, tzinfo=UTC),
            findings_total=5, findings_critical=0,
            detection_rate=0.8, mean_mttd_ms=5000, max_mttd_ms=8000,
            coverage_by_category={"MCP06": 1.0, "MCP02": 0.8},
        ))
        store.save_snapshot(DrillSnapshot(
            drill_id="drill-002",
            timestamp=datetime(2026, 7, 8, tzinfo=UTC),
            findings_total=5, findings_critical=0,
            detection_rate=0.6, mean_mttd_ms=7000, max_mttd_ms=10000,
            coverage_by_category={"MCP06": 0.5, "MCP02": 0.8},
        ))

        regressions = store.detect_regressions()
        assert len(regressions) == 1
        assert "MCP06" in regressions[0]

    def test_format_dashboard(self, tmp_path):
        store = DashboardStore(tmp_path / "drills.jsonl")
        store.save_snapshot(DrillSnapshot(
            drill_id="d1", timestamp=datetime(2026, 7, 1, tzinfo=UTC),
            findings_total=5, findings_critical=1,
            detection_rate=0.7, mean_mttd_ms=4000, max_mttd_ms=8000,
            coverage_by_category={"MCP06": 0.8},
        ))
        trends = store.compute_trends()
        output = format_dashboard(trends)
        assert "Purple Team Dashboard" in output
        assert "70%" in output


# --------------------------------------------------------------------------- #
# Regression Suite Tests
# --------------------------------------------------------------------------- #


class TestRegressionSuite:
    def test_add_from_finding(self, tmp_path):
        suite = RegressionSuite(tmp_path / "regressions.json")
        finding = _make_finding()
        case = suite.add_from_finding(finding)

        assert case.source_finding_id == finding.id
        assert case.attack_module == "prompt-injection-canary"
        assert case.expected_outcome == AttackOutcome.BLOCKED
        assert "payload_id" in case.payload

    def test_no_duplicates(self, tmp_path):
        suite = RegressionSuite(tmp_path / "regressions.json")
        finding = _make_finding()
        suite.add_from_finding(finding)
        suite.add_from_finding(finding)
        assert len(suite.cases) == 1

    def test_batch_from_findings(self, tmp_path):
        suite = RegressionSuite(tmp_path / "regressions.json")
        findings = [
            _make_finding(module="prompt-injection-canary"),
            _make_finding(module="exfiltration-routing"),
            Finding(
                owasp_category="MCP02",
                title="Blocked finding should not generate regression case",
                severity=Severity.MEDIUM,
                target_url="http://x:8080/exec",
                attack_module="confused-deputy",
                outcome=AttackOutcome.BLOCKED,
                description="This attack was blocked and should not create a regression test case",
                impact="No impact because defense worked correctly in this test scenario",
                recommendation="No action needed since the control is already effective here",
            ),
        ]
        cases = suite.add_from_findings(findings)
        assert len(cases) == 2  # Only VULNERABLE findings

    def test_persistence(self, tmp_path):
        path = tmp_path / "regressions.json"
        suite1 = RegressionSuite(path)
        suite1.add_from_finding(_make_finding())

        suite2 = RegressionSuite(path)
        assert len(suite2.cases) == 1

    def test_mark_verified(self, tmp_path):
        suite = RegressionSuite(tmp_path / "regressions.json")
        case = suite.add_from_finding(_make_finding())
        suite.mark_verified(case.id, fixed=True)

        assert suite.cases[0].verified_fixed is True
        assert suite.cases[0].last_verified is not None

    def test_summary(self, tmp_path):
        suite = RegressionSuite(tmp_path / "regressions.json")
        suite.add_from_finding(_make_finding(module="prompt-injection-canary"))
        suite.add_from_finding(_make_finding(module="exfiltration-routing"))

        s = suite.summary()
        assert s["total_cases"] == 2
        assert s["pending_verification"] == 2
        assert "prompt-injection-canary" in s["by_module"]
