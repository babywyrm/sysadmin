"""MTTD/MTTR tracking and historical trending.

Stores drill results over time and provides aggregate metrics for
measuring security operations effectiveness. Each drill run produces
a snapshot; the dashboard renders trends across snapshots.

Metrics tracked:
- MTTD (Mean Time To Detect) — how fast blue detects red's actions
- MTTR (Mean Time To Respond) — how fast blue remediates findings
- Detection coverage — which attack categories have working detections
- Regression tracking — previously-caught attacks that now slip through
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_slayer.purple.detection import CorrelationReport, DetectionStatus


@dataclass
class DrillSnapshot:
    """A single purple team drill's results, stored for trending."""

    drill_id: str
    timestamp: datetime
    findings_total: int
    findings_critical: int
    detection_rate: float
    mean_mttd_ms: float | None
    max_mttd_ms: int | None
    coverage_by_category: dict[str, float]
    campaigns_run: list[str] = field(default_factory=list)
    modules_tested: list[str] = field(default_factory=list)
    regressions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_correlation(
        cls,
        drill_id: str,
        report: CorrelationReport,
        findings_total: int = 0,
        findings_critical: int = 0,
        campaigns: list[str] | None = None,
        modules: list[str] | None = None,
    ) -> DrillSnapshot:
        return cls(
            drill_id=drill_id,
            timestamp=datetime.now(UTC),
            findings_total=findings_total,
            findings_critical=findings_critical,
            detection_rate=report.detection_rate,
            mean_mttd_ms=report.mean_mttd_ms,
            max_mttd_ms=report.max_mttd_ms,
            coverage_by_category=report.coverage_by_category,
            campaigns_run=campaigns or [],
            modules_tested=modules or [],
        )


@dataclass
class TrendMetrics:
    """Computed trend metrics across multiple drill snapshots."""

    total_drills: int = 0
    date_range: tuple[str, str] | None = None
    mttd_trend: list[tuple[str, float | None]] = field(default_factory=list)
    detection_rate_trend: list[tuple[str, float]] = field(default_factory=list)
    coverage_improvement: dict[str, float] = field(default_factory=dict)
    regressions_total: int = 0
    best_detection_rate: float = 0.0
    worst_detection_rate: float = 1.0
    mttd_improving: bool = False


class DashboardStore:
    """Persistent storage for drill snapshots.

    Uses a simple JSON-lines file for portability. Each line is a
    serialized DrillSnapshot.
    """

    def __init__(self, store_path: Path):
        self.store_path = store_path
        self.logger = logging.getLogger("slayer.dashboard")

    def save_snapshot(self, snapshot: DrillSnapshot) -> None:
        """Append a drill snapshot to the store."""
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "drill_id": snapshot.drill_id,
            "timestamp": snapshot.timestamp.isoformat(),
            "findings_total": snapshot.findings_total,
            "findings_critical": snapshot.findings_critical,
            "detection_rate": snapshot.detection_rate,
            "mean_mttd_ms": snapshot.mean_mttd_ms,
            "max_mttd_ms": snapshot.max_mttd_ms,
            "coverage_by_category": snapshot.coverage_by_category,
            "campaigns_run": snapshot.campaigns_run,
            "modules_tested": snapshot.modules_tested,
            "regressions": snapshot.regressions,
            "metadata": snapshot.metadata,
        }
        with self.store_path.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")

        self.logger.info(f"Saved drill snapshot: {snapshot.drill_id}")

    def load_snapshots(self) -> list[DrillSnapshot]:
        """Load all drill snapshots from the store."""
        if not self.store_path.exists():
            return []

        snapshots = []
        for line in self.store_path.read_text().strip().split("\n"):
            if not line:
                continue
            data = json.loads(line)
            snapshots.append(DrillSnapshot(
                drill_id=data["drill_id"],
                timestamp=datetime.fromisoformat(data["timestamp"]),
                findings_total=data["findings_total"],
                findings_critical=data["findings_critical"],
                detection_rate=data["detection_rate"],
                mean_mttd_ms=data.get("mean_mttd_ms"),
                max_mttd_ms=data.get("max_mttd_ms"),
                coverage_by_category=data.get("coverage_by_category", {}),
                campaigns_run=data.get("campaigns_run", []),
                modules_tested=data.get("modules_tested", []),
                regressions=data.get("regressions", []),
                metadata=data.get("metadata", {}),
            ))
        return snapshots

    def compute_trends(self, last_n: int = 20) -> TrendMetrics:
        """Compute trend metrics from stored snapshots."""
        snapshots = self.load_snapshots()[-last_n:]
        if not snapshots:
            return TrendMetrics()

        metrics = TrendMetrics(total_drills=len(snapshots))

        # Date range
        metrics.date_range = (
            snapshots[0].timestamp.strftime("%Y-%m-%d"),
            snapshots[-1].timestamp.strftime("%Y-%m-%d"),
        )

        # MTTD trend
        metrics.mttd_trend = [
            (s.timestamp.strftime("%Y-%m-%d"), s.mean_mttd_ms)
            for s in snapshots
        ]

        # Detection rate trend
        metrics.detection_rate_trend = [
            (s.timestamp.strftime("%Y-%m-%d"), s.detection_rate)
            for s in snapshots
        ]

        # Best/worst
        rates = [s.detection_rate for s in snapshots]
        metrics.best_detection_rate = max(rates)
        metrics.worst_detection_rate = min(rates)

        # MTTD improving? Compare first half to second half
        mttd_values = [s.mean_mttd_ms for s in snapshots if s.mean_mttd_ms is not None]
        if len(mttd_values) >= 4:
            mid = len(mttd_values) // 2
            first_half_avg = sum(mttd_values[:mid]) / mid
            second_half_avg = sum(mttd_values[mid:]) / (len(mttd_values) - mid)
            metrics.mttd_improving = second_half_avg < first_half_avg

        # Coverage improvement: compare first and last snapshot
        if len(snapshots) >= 2:
            first = snapshots[0].coverage_by_category
            last = snapshots[-1].coverage_by_category
            for cat in set(list(first.keys()) + list(last.keys())):
                delta = last.get(cat, 0.0) - first.get(cat, 0.0)
                if delta != 0:
                    metrics.coverage_improvement[cat] = delta

        # Total regressions
        metrics.regressions_total = sum(len(s.regressions) for s in snapshots)

        return metrics

    def detect_regressions(self) -> list[str]:
        """Identify attack categories that were previously detected but now missed.

        Compares the latest snapshot against the prior snapshot to find
        categories where detection coverage decreased.
        """
        snapshots = self.load_snapshots()
        if len(snapshots) < 2:
            return []

        prior = snapshots[-2].coverage_by_category
        latest = snapshots[-1].coverage_by_category

        regressions = []
        for cat, prior_rate in prior.items():
            latest_rate = latest.get(cat, 0.0)
            if prior_rate > 0 and latest_rate < prior_rate:
                regressions.append(
                    f"{cat}: {prior_rate:.0%} → {latest_rate:.0%}"
                )

        return regressions


def format_dashboard(metrics: TrendMetrics) -> str:
    """Render trend metrics as a readable dashboard."""
    lines = [
        "MCP-SLAYER Purple Team Dashboard",
        "=" * 50,
        f"Drills tracked:       {metrics.total_drills}",
    ]

    if metrics.date_range:
        lines.append(f"Period:               {metrics.date_range[0]} → {metrics.date_range[1]}")

    lines.extend([
        f"Best detection rate:  {metrics.best_detection_rate:.0%}",
        f"Worst detection rate: {metrics.worst_detection_rate:.0%}",
        f"MTTD improving:       {'Yes ↓' if metrics.mttd_improving else 'No ↑'}",
        f"Total regressions:    {metrics.regressions_total}",
    ])

    if metrics.detection_rate_trend:
        lines.extend(["", "Detection Rate Trend:", "-" * 40])
        for date, rate in metrics.detection_rate_trend[-10:]:
            bar = "█" * int(rate * 20) + "░" * (20 - int(rate * 20))
            lines.append(f"  {date} {bar} {rate:.0%}")

    if metrics.mttd_trend:
        lines.extend(["", "MTTD Trend (ms):", "-" * 40])
        for date, mttd in metrics.mttd_trend[-10:]:
            mttd_str = f"{mttd:.0f}ms" if mttd else "N/A"
            lines.append(f"  {date} {mttd_str}")

    if metrics.coverage_improvement:
        lines.extend(["", "Coverage Changes (first → latest):", "-" * 40])
        for cat, delta in sorted(metrics.coverage_improvement.items(), key=lambda x: x[1]):
            direction = "↑" if delta > 0 else "↓"
            lines.append(f"  {cat:<8} {direction} {abs(delta):.0%}")

    return "\n".join(lines)
