from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "release.update_manager"


class ReleaseUpdateManagerProofTest(unittest.TestCase):
    @staticmethod
    def _json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_contract_detail_gap_is_explicit(self) -> None:
        comparison = self._json(PROOF / "comparison.json")
        self.assertTrue(comparison["contract_detail_gap"])
        self.assertEqual(comparison["decision"], "COMPOSE_OR_SPLIT_CONTRACT")
        self.assertEqual(comparison["requested_targets"], ["android", "desktop"])
        self.assertEqual(
            comparison["coverage"]["single_candidate_complete_android_and_desktop"], []
        )
        self.assertTrue((PROOF / "CONTRACT_DETAIL_GAP.md").is_file())

    def test_two_independent_partial_candidates_are_not_falsely_admitted(self) -> None:
        background = self._json(
            PROOF / "781flyingdutchman-background-downloader.dossier.json"
        )
        updater = self._json(PROOF / "mantreshkhurana-app-updater.dossier.json")

        self.assertNotEqual(background["fingerprint"], updater["fingerprint"])
        self.assertEqual(background["candidate"]["source_version"], "9.6.1")
        self.assertIsNone(background["candidate"]["source_tag"])
        self.assertEqual(updater["candidate"]["source_version"], "2.1.0")
        self.assertEqual(updater["candidate"]["source_tag"], "2.1.0")

        for dossier in (background, updater):
            self.assertEqual(dossier["lifecycle"], "SCREENED")
            self.assertTrue(dossier["integration_assessment"]["contract_detail_gap"])
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertFalse(dossier["evidence"]["security"]["certification_eligible"])
            self.assertFalse(dossier["evidence"]["security"]["untrusted_code_executed"])
            self.assertEqual(
                dossier["capability"]["contract_id"], "release.update_manager.v1"
            )
            self.assertEqual(dossier["capability"]["targets"], ["android", "desktop"])

        self.assertEqual(
            background["research_recommendation"], "SHORTLIST_AS_TRANSFER_COMPONENT"
        )
        self.assertEqual(
            updater["research_recommendation"],
            "SHORTLIST_AS_DISCOVERY_POLICY_COMPONENT",
        )

    def test_dry_run_manifests_remain_discovered_only(self) -> None:
        manifests = sorted((PROOF / "dry-run").glob("*/0.1.0/manifest.json"))
        self.assertEqual(len(manifests), 2)

        commits: set[str] = set()
        for path in manifests:
            manifest = self._json(path)
            self.assertEqual(manifest["status"], "discovered")
            self.assertEqual(manifest["capabilities"], ["release.update_manager"])
            self.assertEqual(manifest["platforms"], ["android", "desktop"])
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            self.assertIn("contract detail gap", " ".join(manifest["integration"]["known_constraints"]))
            self.assertEqual(
                manifest["connector"]["provides"][0]["contract_id"],
                "release.update_manager.v1",
            )
            commit = manifest["provenance"]["source_commit"]
            self.assertEqual(len(commit), 40)
            commits.add(commit)

        self.assertEqual(len(commits), 2)

    def test_screened_desktop_reference_is_not_promoted(self) -> None:
        screened = self._json(PROOF / "aguilaair-updat.screened.json")
        self.assertEqual(screened["lifecycle"], "SCREENED")
        self.assertEqual(
            screened["research_recommendation"], "REFERENCE_DESKTOP_APPLY_FLOW"
        )
        self.assertFalse(screened["security"]["certification_eligible"])

    def test_proof_contains_no_library_certification_paths(self) -> None:
        relative_files = [
            path.relative_to(PROOF).as_posix()
            for path in PROOF.rglob("*")
            if path.is_file()
        ]
        self.assertFalse(any(path.startswith("modules/") for path in relative_files))
        self.assertFalse(any(path == "catalog/index.json" for path in relative_files))


if __name__ == "__main__":
    unittest.main()
