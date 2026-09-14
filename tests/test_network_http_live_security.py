from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = (
    ROOT
    / "proofs"
    / "first-real-scan"
    / "network.http"
    / "live-security-preflights-2026-09-14.json"
)


class NetworkHttpLiveSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(PROOF.read_text(encoding="utf-8"))
        cls.results = {item["repository"]: item for item in cls.payload["results"]}

    def test_proof_preserves_non_certifying_boundary(self) -> None:
        self.assertEqual(self.payload["capability_id"], "network.http")
        self.assertFalse(self.payload["certification_asserted"])
        self.assertFalse(self.payload["functional_or_contract_fit_asserted"])
        self.assertFalse(self.payload["library_accessed"])
        self.assertFalse(self.payload["library_write_attempted"])
        self.assertFalse(self.payload["executed_untrusted_code"])

    def test_two_independent_candidates_are_pinned(self) -> None:
        self.assertEqual(
            set(self.results),
            {"dart-lang/http", "cfug/dio"},
        )
        for item in self.results.values():
            self.assertEqual(len(item["commit_sha"]), 40)
            self.assertEqual(len(item["tree_sha"]), 40)
            self.assertTrue(item["component_path"])

    def test_package_http_source_and_runtime_supply_chain_are_clear(self) -> None:
        item = self.results["dart-lang/http"]
        self.assertEqual(item["state"], "REVIEW")
        self.assertEqual(item["security"]["verdict"], "CLEAR")
        self.assertTrue(item["security"]["admission_eligible"])
        self.assertEqual(item["security"]["findings"], [])
        self.assertEqual(item["supply_chain"]["verdict"], "CLEAR")
        self.assertTrue(item["supply_chain"]["admission_eligible"])
        self.assertIn(
            "dev_dependencies",
            item["supply_chain"]["excluded_non_runtime_dependency"],
        )

    def test_package_http_vulnerability_gate_remains_fail_closed_on_ranges(self) -> None:
        vulnerability = self.results["dart-lang/http"]["vulnerability"]
        self.assertEqual(vulnerability["verdict"], "REVIEW")
        self.assertFalse(vulnerability["database_checked"])
        self.assertFalse(vulnerability["admission_eligible"])
        self.assertEqual(vulnerability["queried_components"], 0)
        self.assertEqual(vulnerability["hits"], [])
        self.assertTrue(vulnerability["unresolved"])
        self.assertTrue(
            all(
                value.startswith("version_unresolved:Pub:")
                for value in vulnerability["unresolved"]
            )
        )

    def test_dio_keeps_test_tls_findings_visible(self) -> None:
        item = self.results["cfug/dio"]
        self.assertEqual(item["state"], "REVIEW")
        self.assertEqual(item["security"]["verdict"], "REVIEW")
        findings = item["security"]["findings"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {finding["rule_id"] for finding in findings},
            {"tls_certificate_validation_bypass"},
        )
        self.assertTrue(
            all(finding["path"].startswith("dio/test/") for finding in findings)
        )
        self.assertTrue(all(finding["severity"] == "HIGH" for finding in findings))

    def test_dio_dev_dependency_does_not_contaminate_runtime_supply_chain(self) -> None:
        item = self.results["cfug/dio"]
        self.assertEqual(item["supply_chain"]["verdict"], "CLEAR")
        self.assertTrue(item["supply_chain"]["admission_eligible"])
        self.assertIn(
            "dev_dependencies",
            item["supply_chain"]["excluded_non_runtime_dependency"],
        )
        vulnerability = item["vulnerability"]
        self.assertEqual(vulnerability["verdict"], "NOT_ANALYZED")
        self.assertFalse(vulnerability["database_checked"])
        self.assertEqual(
            vulnerability["unresolved"],
            ["earlier_security_or_supply_chain_gate_not_clear"],
        )


if __name__ == "__main__":
    unittest.main()
