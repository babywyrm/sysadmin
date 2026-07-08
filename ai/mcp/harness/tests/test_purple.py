"""Tests for purple team automation — SIEM sinks and detection correlation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mcp_slayer.models import AttackOutcome, Finding, Severity
from mcp_slayer.purple.detection import (
    CorrelationReport,
    DetectionCorrelator,
    DetectionResult,
    DetectionStatus,
    DetectionWindow,
    format_correlation_report,
)
from mcp_slayer.purple.siem import (
    DatadogSink,
    ElasticSink,
    SIEMEvent,
    SplunkHECSink,
    create_sink,
)
from mcp_slayer.taxonomy import PlaybookThreatID


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_finding(
    module: str = "prompt-injection-canary",
    severity: Severity = Severity.HIGH,
    signal: str | None = "D07: injection_classifier match",
) -> Finding:
    return Finding(
        owasp_category="MCP06",
        playbook_threat_ids=[PlaybookThreatID.PROMPT_INJECTION_DIRECT],
        title="Test finding for purple team validation testing",
        severity=severity,
        target_url="http://tool.local:8080/execute",
        attack_module=module,
        outcome=AttackOutcome.VULNERABLE,
        description="Generated during purple team test to validate SIEM integration flow.",
        impact="Demonstrates purple team detection validation capability works end to end",
        recommendation="Apply detection rules matching the expected blue team signal pattern",
        blue_team_signal=signal,
        discovered_at=datetime(2026, 7, 8, 10, 0, 0, tzinfo=UTC),
    )


# --------------------------------------------------------------------------- #
# SIEM Event Tests
# --------------------------------------------------------------------------- #


class TestSIEMEvent:
    def test_from_finding(self):
        finding = _make_finding()
        event = SIEMEvent.from_finding(finding, run_id="test-run-001")
        assert event.severity == "HIGH"
        assert event.category == "MCP06"
        assert event.attack_module == "prompt-injection-canary"
        assert event.outcome == "VULNERABLE"
        assert event.tags["run_id"] == "test-run-001"
        assert "MCP-T01" in event.threat_ids

    def test_timestamp_preserved(self):
        finding = _make_finding()
        event = SIEMEvent.from_finding(finding)
        assert "2026-07-08" in event.timestamp


# --------------------------------------------------------------------------- #
# SIEM Sink Tests (unit — no network)
# --------------------------------------------------------------------------- #


class TestSplunkSink:
    def test_construction(self):
        sink = SplunkHECSink(
            endpoint="https://hec.test:8088",
            token="test-token",
            index="test_index",
        )
        assert sink.sink_id == "splunk"
        assert sink.stats["sent"] == 0
        assert sink.stats["buffered"] == 0

    @pytest.mark.asyncio
    async def test_buffering(self):
        sink = SplunkHECSink(
            endpoint="https://hec.test:8088",
            token="test-token",
            batch_size=10,
        )
        finding = _make_finding()
        await sink.send(finding)
        assert sink.stats["buffered"] == 1

    @pytest.mark.asyncio
    async def test_batch_triggers_flush(self):
        sink = SplunkHECSink(
            endpoint="https://hec.test:8088",
            token="test-token",
            batch_size=2,
        )
        # Override _send_batch to avoid network
        sent_batches = []
        sink._send_batch = lambda events: _fake_send(sent_batches, events)

        await sink.send(_make_finding())
        assert sink.stats["buffered"] == 1
        await sink.send(_make_finding())
        assert sink.stats["buffered"] == 0
        assert len(sent_batches) == 1
        assert len(sent_batches[0]) == 2


class TestElasticSink:
    def test_construction(self):
        sink = ElasticSink(
            endpoint="https://elastic.test:9200",
            api_key="test-key",
        )
        assert sink.sink_id == "elastic"

    def test_index_name_format(self):
        sink = ElasticSink(endpoint="https://test:9200")
        name = sink._index_name()
        assert name.startswith("mcp-slayer-findings-")
        assert "." in name  # date separator


class TestDatadogSink:
    def test_construction(self):
        sink = DatadogSink(api_key="test-key", site="datadoghq.eu")
        assert sink.sink_id == "datadog"
        assert sink.site == "datadoghq.eu"


class TestCreateSink:
    def test_disabled_returns_none(self):
        from mcp_slayer.config import SIEMIntegration

        class FakeConfig:
            siem = SIEMIntegration(enabled=False)

        assert create_sink(FakeConfig()) is None

    def test_splunk_type(self):
        from pydantic import SecretStr
        from mcp_slayer.config import SIEMIntegration

        class FakeConfig:
            siem = SIEMIntegration(
                enabled=True,
                type="splunk",
                endpoint="https://hec.test:8088",
                api_key=SecretStr("tok"),
                index_name="idx",
            )

        sink = create_sink(FakeConfig())
        assert isinstance(sink, SplunkHECSink)

    def test_elastic_type(self):
        from pydantic import SecretStr
        from mcp_slayer.config import SIEMIntegration

        class FakeConfig:
            siem = SIEMIntegration(
                enabled=True,
                type="elastic",
                endpoint="https://es.test:9200",
                api_key=SecretStr("key"),
            )

        sink = create_sink(FakeConfig())
        assert isinstance(sink, ElasticSink)

    def test_datadog_type(self):
        from pydantic import SecretStr
        from mcp_slayer.config import SIEMIntegration

        class FakeConfig:
            siem = SIEMIntegration(
                enabled=True,
                type="datadog",
                api_key=SecretStr("dd-key"),
            )

        sink = create_sink(FakeConfig())
        assert isinstance(sink, DatadogSink)


# --------------------------------------------------------------------------- #
# Detection Correlation Tests
# --------------------------------------------------------------------------- #


class TestDetectionWindow:
    def test_after_attack(self):
        attack_time = datetime(2026, 7, 8, 10, 0, 0, tzinfo=UTC)
        window = DetectionWindow.after_attack(attack_time, window_s=120.0)
        assert window.start < attack_time
        assert window.end > attack_time
        assert window.max_wait_s == 120.0


class TestDetectionCorrelator:
    @pytest.mark.asyncio
    async def test_all_detected(self):
        def fetcher(finding, window):
            return [{
                "id": "alert-1",
                "timestamp": finding.discovered_at.isoformat(),
                "rule": "D07: injection_classifier match",
            }]

        correlator = DetectionCorrelator(alert_fetcher=fetcher)
        findings = [_make_finding(), _make_finding(module="exfiltration-routing")]
        report = await correlator.correlate(findings)

        assert report.detected == 2
        assert report.missed == 0
        assert report.detection_rate == 1.0

    @pytest.mark.asyncio
    async def test_all_missed(self):
        correlator = DetectionCorrelator(alert_fetcher=lambda f, w: [])
        findings = [_make_finding(), _make_finding()]
        report = await correlator.correlate(findings)

        assert report.detected == 0
        assert report.missed == 2
        assert report.detection_rate == 0.0

    @pytest.mark.asyncio
    async def test_delayed_detection(self):
        def fetcher(finding, window):
            late_time = finding.discovered_at + timedelta(seconds=90)
            return [{"id": "alert-late", "timestamp": late_time.isoformat()}]

        correlator = DetectionCorrelator(
            alert_fetcher=fetcher,
            mttd_threshold_ms=30000,
        )
        findings = [_make_finding()]
        report = await correlator.correlate(findings)

        assert report.results[0].detection_status == DetectionStatus.DELAYED
        assert report.results[0].mttd_ms == 90000

    @pytest.mark.asyncio
    async def test_mttd_calculation(self):
        def fetcher(finding, window):
            detect_time = finding.discovered_at + timedelta(seconds=5)
            return [{"id": "a1", "timestamp": detect_time.isoformat(), "rule": "r1"}]

        correlator = DetectionCorrelator(alert_fetcher=fetcher)
        findings = [_make_finding()]
        report = await correlator.correlate(findings)

        assert report.results[0].mttd_ms == 5000
        assert report.mean_mttd_ms == 5000

    @pytest.mark.asyncio
    async def test_fetcher_exception_handled(self):
        def failing_fetcher(finding, window):
            raise ConnectionError("SIEM unreachable")

        correlator = DetectionCorrelator(alert_fetcher=failing_fetcher)
        findings = [_make_finding()]
        report = await correlator.correlate(findings)

        assert report.results[0].detection_status == DetectionStatus.MISSED
        assert "error" in report.results[0].notes.lower()

    @pytest.mark.asyncio
    async def test_coverage_by_category(self):
        def mixed_fetcher(finding, window):
            if finding.attack_module == "prompt-injection-canary":
                return [{"id": "a1", "timestamp": finding.discovered_at.isoformat()}]
            return []

        correlator = DetectionCorrelator(alert_fetcher=mixed_fetcher)
        findings = [
            _make_finding(module="prompt-injection-canary"),
            _make_finding(module="exfiltration-routing"),
        ]
        report = await correlator.correlate(findings)
        assert report.coverage_by_category.get("MCP06") == 0.5


class TestCorrelationReport:
    def test_compute(self):
        report = CorrelationReport(
            results=[
                DetectionResult(
                    finding_id="f1", attack_module="m1", owasp_category="MCP06",
                    expected_signal="sig", detection_status=DetectionStatus.DETECTED,
                    mttd_ms=2000,
                ),
                DetectionResult(
                    finding_id="f2", attack_module="m2", owasp_category="MCP06",
                    expected_signal="sig", detection_status=DetectionStatus.MISSED,
                ),
            ]
        )
        report.compute()
        assert report.detection_rate == 0.5
        assert report.mean_mttd_ms == 2000
        assert report.max_mttd_ms == 2000

    def test_format_report(self):
        report = CorrelationReport(
            results=[
                DetectionResult(
                    finding_id="f1", attack_module="prompt-injection-canary",
                    owasp_category="MCP06", expected_signal="D07",
                    detection_status=DetectionStatus.DETECTED, mttd_ms=3000,
                ),
            ]
        )
        report.compute()
        output = format_correlation_report(report)
        assert "Detection Validation Report" in output
        assert "prompt-injection-canary" in output
        assert "DETECTED" in output


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


async def _fake_send(tracker: list, events: list[SIEMEvent]) -> bool:
    tracker.append(events)
    return True
