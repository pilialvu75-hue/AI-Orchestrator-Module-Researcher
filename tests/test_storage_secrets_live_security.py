from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = (
    ROOT
    / "proofs"
    / "first-real-scan"
    / "storage.secrets"
    / "live-security-preflights-2026-09-14.json"
)


class StorageSecretsLiveSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(PROOF.read_text(encoding="utf-8"))
        cls.results = cls.payload["results"]

    def test_proof_preserves_non_certifying_boundary(self) -> None:
        self.assertEqual(self.payload["capability_id"], "storage.secrets")
        self.assertFalse(self.payload["certification_asserted"])
        self.assertFalse(self.payload["functional_or_contract_fit_asserted"])
        self.assertFalse(self.payload["library_accessed"])
        self.assertFalse(self.payload["library_write_attempted"])
        self.assertFalse(self.payload["executed_untrusted_code"])

    def test_two_independent_candidates_are_pinned(self) -> None:
        self.assertEqual(len(self.results), 2)
        repositories = {item["repository"] for item in self.results}
        self.assertEqual(
            repositories,
            {
                "juliansteenbakker/flutter_secure_storage",
                "JohnGalt1717/webauthn_secure_storage",
            },
        )
        for item in self.results:
            self.assertEqual(len(item["commit_sha"]), 40)
            self.assertEqual(len(item["tree_sha"]), 40)
            self.assertTrue(item["component_path"])

    def test_both_sources_are_clear_without_execution(self) -> None:
        for item in self.results:
            with self.subTest(candidate=item["candidate"]):
                security = item["security"]
                self.assertEqual(security["verdict"], "CLEAR")
                self.assertTrue(security["complete"])
                self.assertTrue(security["admission_eligible"])
                self.assertEqual(security["findings"], [])
                self.assertEqual(security["opaque_artifacts"], [])
                self.assertEqual(security["submodules"], [])
                self.assertEqual(security["symlinks"], [])

    def test_vulnerability_gate_remains_fail_closed_on_ranges(self) -> None:
        for item in self.results:
            with self.subTest(candidate=item["candidate"]):
                self.assertEqual(item["state"], "REVIEW")
                vulnerability = item["vulnerability"]
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

    def test_primary_package_supply_chain_is_clear(self) -> None:
        for item in self.results:
            with self.subTest(candidate=item["candidate"]):
                supply_chain = item["supply_chain"]
                self.assertEqual(supply_chain["verdict"], "CLEAR")
                self.assertTrue(supply_chain["admission_eligible"])
                self.assertTrue(
                    supply_chain["primary_manifest"].endswith("/pubspec.yaml")
                )


if __name__ == "__main__":
    unittest.main()
