"""Detection validation framework — correlate attacks with SIEM alerts.

After executing an attack (module or campaign), the detection correlator
queries the SIEM for corresponding alerts within a time window. This
measures Mean Time To Detect (MTTD) and validates that detection rules
actually fire for each attack class.

The framework answers: "Did the blue team's detection rules catch what
the red team just did, and how quickly?"
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Callable

from mcp_slayer.models import Finding


class DetectionStatus(StrEnum):
    """Whether a detection fired for a given attack."""

    DETECTED = "DETECTED"
    MISSED = "MISSED"
    DELAYED = "DELAYED"
    PARTIAL = "PARTIAL"


@dataclass
class DetectionResult:
    """Correlation result for a single finding → alert pair."""

    finding_id: str
    attack_module: str
    owasp_category: str
    expected_signal: str | None
    detection_status: DetectionStatus
    alert_id: str | None = None
    alert_rule: str | None = None
    mttd_ms: int | None = None
    alert_severity: str | None = None
    notes: str = ""


@dataclass
class DetectionWindow:
    """Time window for searching SIEM alerts after an attack."""

    start: datetime
    end: datetime
    max_wait_s: float = 300.0

    @classmethod
    def after_attack(cls, attack_time: datetime, window_s: float = 300.0) -> DetectionWindow:
        return cls(
            start=attack_time - timedelta(seconds=5),
            end=attack_time + timedelta(seconds=window_s),
            max_wait_s=window_s,
        )


@dataclass
class CorrelationReport:
    """Aggregate report from correlating a set of findings with SIEM alerts."""

    findings_total: int = 0
    detected: int = 0
    missed: int = 0
    delayed: int = 0
    partial: int = 0
    detection_rate: float = 0.0
    mean_mttd_ms: float | None = None
    max_mttd_ms: int | None = None
    results: list[DetectionResult] = field(default_factory=list)
    coverage_by_category: dict[str, float] = field(default_factory=dict)

    def compute(self) -> None:
        self.findings_total = len(self.results)
        self.detected = sum(1 for r in self.results if r.detection_status == DetectionStatus.DETECTED)
        self.missed = sum(1 for r in self.results if r.detection_status == DetectionStatus.MISSED)
        self.delayed = sum(1 for r in self.results if r.detection_status == DetectionStatus.DELAYED)
        self.partial = sum(1 for r in self.results if r.detection_status == DetectionStatus.PARTIAL)

        if self.findings_total > 0:
            self.detection_rate = (self.detected + self.partial) / self.findings_total

        mttd_values = [r.mttd_ms for r in self.results if r.mttd_ms is not None]
        if mttd_values:
            self.mean_mttd_ms = sum(mttd_values) / len(mttd_values)
            self.max_mttd_ms = max(mttd_values)

        # Coverage by OWASP category
        by_cat: dict[str, list[bool]] = {}
        for r in self.results:
            by_cat.setdefault(r.owasp_category, []).append(
                r.detection_status in (DetectionStatus.DETECTED, DetectionStatus.PARTIAL)
            )
        self.coverage_by_category = {
            cat: sum(hits) / len(hits) for cat, hits in by_cat.items()
        }


class DetectionCorrelator:
    """Correlates attack findings with SIEM alerts.

    The correlator uses a pluggable alert_fetcher function to query
    the SIEM for alerts matching an attack's signature within a time
    window. This decouples the correlation logic from any specific
    SIEM implementation.

    Usage:
        correlator = DetectionCorrelator(
            alert_fetcher=my_splunk_query_func,
            detection_window_s=120.0,
            mttd_threshold_ms=30000,
        )
        report = await correlator.correlate(findings)
    """

    def __init__(
        self,
        alert_fetcher: Callable[[Finding, DetectionWindow], list[dict[str, Any]]],
        detection_window_s: float = 300.0,
        mttd_threshold_ms: int = 60000,
    ):
        self.alert_fetcher = alert_fetcher
        self.detection_window_s = detection_window_s
        self.mttd_threshold_ms = mttd_threshold_ms
        self.logger = logging.getLogger("slayer.detection")

    async def correlate(self, findings: list[Finding]) -> CorrelationReport:
        """Correlate a list of findings with SIEM alerts."""
        report = CorrelationReport()

        for finding in findings:
            window = DetectionWindow.after_attack(
                finding.discovered_at, window_s=self.detection_window_s
            )
            result = await self._correlate_single(finding, window)
            report.results.append(result)

        report.compute()

        self.logger.info(
            f"Detection correlation: {report.detected}/{report.findings_total} detected "
            f"({report.detection_rate:.0%}), "
            f"MTTD={report.mean_mttd_ms:.0f}ms" if report.mean_mttd_ms else ""
        )

        return report

    async def _correlate_single(
        self, finding: Finding, window: DetectionWindow
    ) -> DetectionResult:
        """Attempt to correlate a single finding with SIEM alerts."""
        try:
            alerts = self.alert_fetcher(finding, window)
        except Exception as e:
            self.logger.error(f"Alert fetch failed for {finding.id}: {e}")
            return DetectionResult(
                finding_id=finding.id,
                attack_module=finding.attack_module,
                owasp_category=finding.owasp_category.value,
                expected_signal=finding.blue_team_signal,
                detection_status=DetectionStatus.MISSED,
                notes=f"Alert fetch error: {e}",
            )

        if not alerts:
            return DetectionResult(
                finding_id=finding.id,
                attack_module=finding.attack_module,
                owasp_category=finding.owasp_category.value,
                expected_signal=finding.blue_team_signal,
                detection_status=DetectionStatus.MISSED,
            )

        # Find the earliest matching alert
        earliest = min(alerts, key=lambda a: a.get("timestamp", ""))
        alert_time_str = earliest.get("timestamp", "")

        # Calculate MTTD
        mttd_ms = None
        if alert_time_str:
            try:
                alert_time = datetime.fromisoformat(alert_time_str)
                delta = alert_time - finding.discovered_at
                mttd_ms = int(delta.total_seconds() * 1000)
            except (ValueError, TypeError):
                pass

        # Classify detection quality
        if mttd_ms is not None and mttd_ms > self.mttd_threshold_ms:
            status = DetectionStatus.DELAYED
        elif len(alerts) > 0:
            # Check if the alert matches the expected signal
            if finding.blue_team_signal:
                matched = any(
                    finding.blue_team_signal.lower() in str(a).lower()
                    for a in alerts
                )
                status = DetectionStatus.DETECTED if matched else DetectionStatus.PARTIAL
            else:
                status = DetectionStatus.DETECTED
        else:
            status = DetectionStatus.MISSED

        return DetectionResult(
            finding_id=finding.id,
            attack_module=finding.attack_module,
            owasp_category=finding.owasp_category.value,
            expected_signal=finding.blue_team_signal,
            detection_status=status,
            alert_id=earliest.get("id"),
            alert_rule=earliest.get("rule", earliest.get("search_name")),
            mttd_ms=mttd_ms,
            alert_severity=earliest.get("severity"),
        )


def format_correlation_report(report: CorrelationReport) -> str:
    """Format a CorrelationReport as a readable table."""
    lines = [
        "Detection Validation Report",
        "=" * 60,
        f"Total findings:  {report.findings_total}",
        f"Detected:        {report.detected} ({report.detection_rate:.0%})",
        f"Missed:          {report.missed}",
        f"Delayed:         {report.delayed}",
        f"Partial:         {report.partial}",
        "",
    ]

    if report.mean_mttd_ms:
        lines.append(f"Mean MTTD:       {report.mean_mttd_ms:.0f}ms ({report.mean_mttd_ms/1000:.1f}s)")
    if report.max_mttd_ms:
        lines.append(f"Max MTTD:        {report.max_mttd_ms}ms ({report.max_mttd_ms/1000:.1f}s)")

    if report.coverage_by_category:
        lines.extend(["", "Coverage by OWASP Category:", "-" * 40])
        for cat, rate in sorted(report.coverage_by_category.items()):
            bar = "█" * int(rate * 20) + "░" * (20 - int(rate * 20))
            lines.append(f"  {cat:<8} {bar} {rate:.0%}")

    if report.results:
        lines.extend(["", "Per-Finding Results:", "-" * 60])
        for r in report.results:
            status_icon = {
                DetectionStatus.DETECTED: "✅",
                DetectionStatus.MISSED: "❌",
                DetectionStatus.DELAYED: "⏰",
                DetectionStatus.PARTIAL: "⚠️",
            }[r.detection_status]
            mttd_str = f" ({r.mttd_ms}ms)" if r.mttd_ms else ""
            lines.append(
                f"  {status_icon} {r.attack_module:<28} {r.detection_status.value}{mttd_str}"
            )

    return "\n".join(lines)
