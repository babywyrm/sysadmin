"""Tests for core models."""

import pytest

from mcp_slayer.models import (
    AttackCategory,
    AttackOutcome,
    Evidence,
    Finding,
    Severity,
)
from mcp_slayer.taxonomy import PlaybookThreatID


def test_severity_ordering():
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL


def test_severity_cvss_range():
    assert Severity.CRITICAL.cvss_range == (9.0, 10.0)
    assert Severity.INFO.cvss_range == (0.0, 0.0)


def test_evidence_hash_is_stable():
    data = {"key": "value", "nested": {"a": 1}}
    e1 = Evidence(raw_data=data, source="test")
    e2 = Evidence(raw_data=data, source="test")
    assert e1.hash == e2.hash


def test_evidence_sanitize():
    data = {"username": "admin", "password": "secret123", "action": "read"}
    ev = Evidence(raw_data=data, source="test")
    sanitized = ev.sanitize(["password"])
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["username"] == "admin"


def test_finding_creation():
    finding = Finding(
        owasp_category=AttackCategory.PRIVILEGE_ESCALATION,
        playbook_threat_ids=[PlaybookThreatID.CONFUSED_DEPUTY],
        title="Test finding with sufficient length for validation",
        severity=Severity.HIGH,
        target_url="https://tool.example.com/execute",
        attack_module="confused-deputy",
        outcome=AttackOutcome.VULNERABLE,
        description="A detailed description of the vulnerability that is long enough to pass validation requirements.",
        impact="High impact on system security posture.",
        recommendation="Implement JWT audience validation at every tool boundary endpoint.",
    )
    assert finding.owasp_category == AttackCategory.PRIVILEGE_ESCALATION
    assert PlaybookThreatID.CONFUSED_DEPUTY in finding.playbook_threat_ids
    assert finding.id.startswith("MCP-")


def test_finding_cvss_severity_mismatch_raises():
    with pytest.raises(ValueError, match="CVSS"):
        Finding(
            owasp_category=AttackCategory.COMMAND_INJECTION,
            title="SSRF test finding with enough length for validation",
            severity=Severity.HIGH,
            target_url="https://tool.example.com/execute",
            attack_module="ssrf-metadata",
            outcome=AttackOutcome.VULNERABLE,
            cvss_score=3.0,  # LOW range, but severity is HIGH
            description="Description long enough for validation requirements to pass correctly.",
            impact="Should raise because CVSS mismatches severity.",
            recommendation="Fix the CVSS score to match the declared severity level.",
        )
