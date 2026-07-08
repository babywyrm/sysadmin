"""Regression test suite from confirmed findings.

When a vulnerability is confirmed during a drill, this module generates
a minimal, deterministic test case that can be run in CI to ensure the
vulnerability stays fixed. If a regression test starts passing again
(the attack succeeds), it means a previously-remediated vulnerability
has resurfaced.

This closes the loop: red finds → blue fixes → regression prevents drift.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_slayer.models import AttackOutcome, Finding


@dataclass
class RegressionCase:
    """A single regression test case derived from a confirmed finding."""

    id: str
    source_finding_id: str
    attack_module: str
    owasp_category: str
    target_url: str
    target_tool: str | None
    payload: dict[str, Any]
    expected_outcome: AttackOutcome
    description: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_verified: datetime | None = None
    verified_fixed: bool = False
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_finding_id": self.source_finding_id,
            "attack_module": self.attack_module,
            "owasp_category": self.owasp_category,
            "target_url": self.target_url,
            "target_tool": self.target_tool,
            "payload": self.payload,
            "expected_outcome": self.expected_outcome.value,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "last_verified": self.last_verified.isoformat() if self.last_verified else None,
            "verified_fixed": self.verified_fixed,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RegressionCase:
        return cls(
            id=data["id"],
            source_finding_id=data["source_finding_id"],
            attack_module=data["attack_module"],
            owasp_category=data["owasp_category"],
            target_url=data["target_url"],
            target_tool=data.get("target_tool"),
            payload=data["payload"],
            expected_outcome=AttackOutcome(data["expected_outcome"]),
            description=data["description"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_verified=datetime.fromisoformat(data["last_verified"]) if data.get("last_verified") else None,
            verified_fixed=data.get("verified_fixed", False),
            tags=data.get("tags", {}),
        )


class RegressionSuite:
    """Manages regression test cases — creation, storage, and execution.

    Regression cases are stored as a JSON file that can be committed
    to the repository and run in CI.
    """

    def __init__(self, suite_path: Path):
        self.suite_path = suite_path
        self.logger = logging.getLogger("slayer.regression")
        self._cases: list[RegressionCase] = []
        self._load()

    def _load(self) -> None:
        """Load existing cases from disk."""
        if self.suite_path.exists():
            data = json.loads(self.suite_path.read_text())
            self._cases = [RegressionCase.from_dict(c) for c in data.get("cases", [])]
            self.logger.info(f"Loaded {len(self._cases)} regression cases")

    def _save(self) -> None:
        """Persist cases to disk."""
        self.suite_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": "1.0",
            "updated_at": datetime.now(UTC).isoformat(),
            "total_cases": len(self._cases),
            "cases": [c.to_dict() for c in self._cases],
        }
        self.suite_path.write_text(json.dumps(data, indent=2, default=str))

    def add_from_finding(self, finding: Finding) -> RegressionCase:
        """Generate a regression case from a confirmed vulnerability finding."""
        case_id = f"reg-{finding.id}"

        # Extract payload from evidence if available
        payload = {}
        if finding.evidence:
            payload = {
                k: v for k, v in finding.evidence.items()
                if k in ("payload", "payload_id", "runtime", "parameter", "canary_token")
            }
        if finding.request_sample:
            payload["request_sample"] = finding.request_sample

        case = RegressionCase(
            id=case_id,
            source_finding_id=finding.id,
            attack_module=finding.attack_module,
            owasp_category=finding.owasp_category.value,
            target_url=str(finding.target_url),
            target_tool=finding.target_tool,
            payload=payload,
            expected_outcome=AttackOutcome.BLOCKED,
            description=(
                f"Regression for {finding.title}. "
                f"Original finding: {finding.description[:100]}"
            ),
            tags=finding.tags,
        )

        # Avoid duplicates
        existing_ids = {c.source_finding_id for c in self._cases}
        if finding.id not in existing_ids:
            self._cases.append(case)
            self._save()
            self.logger.info(f"Added regression case: {case_id} from {finding.id}")
        else:
            self.logger.debug(f"Regression case already exists for {finding.id}")

        return case

    def add_from_findings(self, findings: list[Finding]) -> list[RegressionCase]:
        """Batch-create regression cases from vulnerable findings."""
        vulnerable = [
            f for f in findings
            if f.outcome in (AttackOutcome.VULNERABLE, AttackOutcome.PARTIALLY_VULNERABLE)
        ]
        cases = [self.add_from_finding(f) for f in vulnerable]
        self.logger.info(f"Generated {len(cases)} regression cases from {len(findings)} findings")
        return cases

    def mark_verified(self, case_id: str, fixed: bool = True) -> None:
        """Mark a regression case as verified (fixed or still vulnerable)."""
        for case in self._cases:
            if case.id == case_id:
                case.last_verified = datetime.now(UTC)
                case.verified_fixed = fixed
                self._save()
                return

    @property
    def cases(self) -> list[RegressionCase]:
        return self._cases

    @property
    def pending_verification(self) -> list[RegressionCase]:
        """Cases that haven't been verified as fixed yet."""
        return [c for c in self._cases if not c.verified_fixed]

    @property
    def verified_fixed(self) -> list[RegressionCase]:
        """Cases confirmed as remediated."""
        return [c for c in self._cases if c.verified_fixed]

    def summary(self) -> dict[str, Any]:
        return {
            "total_cases": len(self._cases),
            "pending_verification": len(self.pending_verification),
            "verified_fixed": len(self.verified_fixed),
            "by_module": {
                mod: sum(1 for c in self._cases if c.attack_module == mod)
                for mod in set(c.attack_module for c in self._cases)
            },
            "by_category": {
                cat: sum(1 for c in self._cases if c.owasp_category == cat)
                for cat in set(c.owasp_category for c in self._cases)
            },
        }
