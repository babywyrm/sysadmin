import tempfile
import unittest
from pathlib import Path

from agent_safety.policies import Policy, load_policy


class PolicyTests(unittest.TestCase):
    def test_default_policy_matches_runtime_defaults(self):
        self.assertEqual(
            Policy(
                severity_threshold="medium",
                max_file_bytes=1048576,
                max_findings=25,
            ),
            load_policy(),
        )

    def test_default_policy_file_matches_runtime_defaults(self):
        policy = load_policy("policies/default.json")

        self.assertEqual("medium", policy.severity_threshold)
        self.assertEqual(1048576, policy.max_file_bytes)
        self.assertEqual(25, policy.max_findings)

    def test_strict_policy_uses_low_threshold_and_higher_finding_cap(self):
        policy = load_policy("policies/strict.json")

        self.assertEqual("low", policy.severity_threshold)
        self.assertEqual(1048576, policy.max_file_bytes)
        self.assertEqual(100, policy.max_findings)

    def test_policy_loader_rejects_non_object_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_policy(str(path))


if __name__ == "__main__":
    unittest.main()
