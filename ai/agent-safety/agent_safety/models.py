from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity.lower(), 99) <= SEVERITY_RANK.get(
        threshold.lower(), 99
    )


@dataclass(frozen=True)
class Finding:
    scanner: str
    rule_id: str
    severity: str
    label: str
    path: str | None
    line: int | None
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "label": self.label,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def has_findings_at_or_above(self, threshold: str) -> bool:
        return any(
            severity_meets_threshold(finding.severity, threshold)
            for finding in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": list(self.errors),
        }
