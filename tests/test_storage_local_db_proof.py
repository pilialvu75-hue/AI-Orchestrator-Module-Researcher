from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "storage.local_db"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} is not a JSON object")
    return value


class StorageLocalDbProofTests(unittest.TestCase):
    def test_two_independent_shortlisted_candidates(self) -> None:
        dossiers = [
            load(PROOF / "simolus3-drift.dossier.json"),
            load(PROOF / "isar-community-isar-community.dossier.json"),
        ]
        self.assertEqual({d["lifecycle"] for d in dossiers}, {"SHORTLISTED"})
        self.assertEqual(
            {d["candidate"]["repository"] for d in dossiers},
            {"simolus3/drift", "isar-community/isar-community"},
        )
        self.assertEqual(len({d["fingerprint"] for d in dossiers}), 2)
        for dossier in dossiers:
            candidate = dossier["candidate"]
            self.assertTrue(SHA40.fullmatch(candidate["commit_sha"]))
            self.assertTrue(SHA40.fullmatch(candidate["tree_sha"]))
            self.assertEqual(
                dossier["capability"]["contract_id"],
                "storage.local_db.v1",
            )
            self.assertEqual(candidate["platforms"], ["android", "desktop"])
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertFalse(
                dossier["evidence"]["security"]["untrusted_code_executed"]
            )
            self.assertEqual(
                dossier["evidence"]["benchmark"]["status"],
                "PLANNED_NOT_EXECUTED",
            )

    def test_release_provenance_is_explicit(self) -> None:
        drift = load(PROOF / "simolus3-drift.dossier.json")
        isar = load(PROOF / "isar-community-isar-community.dossier.json")
        self.assertEqual(drift["candidate"]["source_tag"], "drift-2.35.0")
        self.assertTrue(drift["candidate"]["release_tag_verified"])
        self.assertTrue(
            drift["evidence"]["maintenance"]["release_commit_verified_signature"]
        )
        self.assertEqual(isar["candidate"]["source_tag"], "3.3.2")
        self.assertTrue(isar["candidate"]["release_tag_verified"])
        self.assertFalse(
            isar["evidence"]["maintenance"]["release_commit_verified_signature"]
        )

    def test_dry_run_manifests_stop_at_discovered(self) -> None:
        paths = sorted((PROOF / "dry-run").glob("*/0.1.0/manifest.json"))
        self.assertEqual(len(paths), 2)
        for path in paths:
            manifest = load(path)
            self.assertEqual(manifest["status"], "discovered")
            self.assertEqual(manifest["platforms"], ["android", "desktop"])
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            connector = manifest["connector"]
            self.assertEqual(connector["standard"], "ai-orchestrator-lego")
            self.assertEqual(connector["standard_version"], "1.0.0")
            provided = connector["provides"]
            self.assertEqual(len(provided), 1)
            self.assertEqual(provided[0]["capability_id"], "storage.local_db")
            self.assertEqual(provided[0]["contract_id"], "storage.local_db.v1")
            self.assertEqual(provided[0]["contract_version"], "1.0")
            source_commit = manifest["provenance"]["source_commit"]
            self.assertTrue(SHA40.fullmatch(source_commit))
            self.assertEqual(source_commit, manifest["payload"]["upstream_commit"])
            path_text = str(path).replace("\\", "/")
            self.assertNotIn("/modules/", path_text)
            self.assertNotIn("catalog/index.json", path_text)

    def test_comparison_records_objectbox_license_boundary(self) -> None:
        comparison = load(PROOF / "comparison.json")
        self.assertTrue(comparison["dry_run"])
        self.assertEqual(comparison["capability_id"], "storage.local_db")
        self.assertEqual(comparison["contract_id"], "storage.local_db.v1")
        self.assertEqual(len(comparison["candidate_order"]), 2)
        self.assertIn("simolus3/drift@2.35.0", comparison["candidate_order"])
        self.assertIn(
            "isar-community/isar-community@3.3.2",
            comparison["candidate_order"],
        )
        screened = comparison["screened_out"]
        self.assertEqual(len(screened), 1)
        self.assertIn("objectbox/objectbox-dart@5.3.2", screened[0]["candidate"])
        self.assertIn("Binary License", screened[0]["reason"])
        self.assertTrue(
            any(
                "draft logical Library contract" in item
                for item in comparison["limitations"]
            )
        )


if __name__ == "__main__":
    unittest.main()
