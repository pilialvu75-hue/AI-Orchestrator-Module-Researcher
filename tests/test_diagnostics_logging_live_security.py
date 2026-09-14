from __future__ import annotations

import json
import unittest
from pathlib import Path


PROOF = (
    Path(__file__).parents[1]
    / "proofs"
    / "controlled-scans"
    / "diagnostics.logging"
    / "live-security-preflights-2026-09-14.json"
)


class DiagnosticsLoggingLiveSecurityProofTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(PROOF.read_text(encoding="utf-8"))
        cls.results = {
            item["candidate"]: item
            for item in cls.payload["results"]
        }

    def test_proof_never_claims_library_certification_or_execution(self) -> None:
        self.assertFalse(self.payload["certification_asserted"])
        self.assertFalse(self.payload["library_accessed"])
        self.assertFalse(self.payload["library_write_attempted"])
        self.assertFalse(self.payload["executed_untrusted_code"])

    def test_official_logging_candidate_is_fully_clear(self) -> None:
        result = self.results["dart-lang/core:pkgs/logging"]
        self.assertEqual(result["state"], "CLEAR")
        self.assertTrue(result["security"]["admission_eligible"])
        self.assertTrue(result["vulnerability"]["database_checked"])
        self.assertTrue(result["vulnerability"]["admission_eligible"])
        self.assertEqual(result["supply_chain"]["runtime_dependencies"], [])

    def test_talker_is_fail_closed_for_override_and_symlink(self) -> None:
        result = self.results["Frezyx/talker:packages/talker"]
        self.assertEqual(result["state"], "REVIEW")
        self.assertFalse(result["security"]["admission_eligible"])
        rules = {finding["rule_id"] for finding in result["security"]["findings"]}
        self.assertIn("pub_dependency_override_requires_review", rules)
        self.assertIn("symlink_requires_review", rules)
        self.assertFalse(result["vulnerability"]["database_checked"])

    def test_sourcehorizon_is_source_clear_but_vulnerability_review(self) -> None:
        result = self.results["SourceHorizon/logger"]
        self.assertEqual(result["state"], "REVIEW")
        self.assertTrue(result["security"]["admission_eligible"])
        self.assertEqual(result["security"]["findings"], [])
        self.assertFalse(result["vulnerability"]["database_checked"])
        self.assertFalse(result["vulnerability"]["admission_eligible"])
        self.assertEqual(
            set(result["vulnerability"]["unresolved"]),
            {
                "version_unresolved:Pub:clock:^1.1.0",
                "version_unresolved:Pub:meta:^1.0.0",
            },
        )

    def test_decision_does_not_lower_security_bar_for_second_green(self) -> None:
        decision = self.payload["decision"]
        self.assertEqual(
            decision["preferred_security_clear_candidate"],
            "dart-lang/core:pkgs/logging",
        )
        self.assertIn("fail-closed", decision["next_action"])


if __name__ == "__main__":
    unittest.main()
