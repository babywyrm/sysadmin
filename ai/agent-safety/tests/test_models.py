import unittest

from agent_safety.models import Finding, ScanResult, severity_meets_threshold


class ModelTests(unittest.TestCase):
    def test_finding_serializes_with_stable_shape(self):
        finding = Finding(
            scanner="control_files",
            rule_id="PROMPT_IGNORE_INSTRUCTIONS",
            severity="high",
            label="prompt injection",
            path="skills/demo/SKILL.md",
            line=7,
            snippet="Ignore previous instructions",
        )

        self.assertEqual(
            {
                "scanner": "control_files",
                "rule_id": "PROMPT_IGNORE_INSTRUCTIONS",
                "severity": "high",
                "label": "prompt injection",
                "path": "skills/demo/SKILL.md",
                "line": 7,
                "snippet": "Ignore previous instructions",
            },
            finding.to_dict(),
        )

    def test_scan_result_reports_threshold_findings(self):
        result = ScanResult(
            findings=[
                Finding(
                    scanner="tool_calls",
                    rule_id="ARG_EXFIL_DESTINATION",
                    severity="critical",
                    label="external destination",
                    path=None,
                    line=None,
                    snippet="https://example.org",
                )
            ]
        )

        self.assertTrue(result.has_findings)
        self.assertTrue(result.has_findings_at_or_above("high"))
        self.assertEqual(1, result.to_dict()["finding_count"])

    def test_severity_threshold_comparison_is_ordered(self):
        self.assertTrue(severity_meets_threshold("critical", "medium"))
        self.assertTrue(severity_meets_threshold("medium", "medium"))
        self.assertFalse(severity_meets_threshold("low", "medium"))


if __name__ == "__main__":
    unittest.main()
