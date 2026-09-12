from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "first-real-scan" / "network.http"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} is not a JSON object")
    return value


class RealScanProofTests(unittest.TestCase):
    def test_two_independent_shortlisted_candidates(self) -> None:
        dossiers = [
            load(PROOF / "cfug-dio.dossier.json"),
            load(PROOF / "dart-lang-http.dossier.json"),
        ]
        self.assertEqual({d["lifecycle"] for d in dossiers}, {"SHORTLISTED"})
        repositories = {d["candidate"]["repository"] for d in dossiers}
        self.assertEqual(repositories, {"cfug/dio", "dart-lang/http"})
        fingerprints = {d["fingerprint"] for d in dossiers}
        self.assertEqual(len(fingerprints), 2)
        for dossier in dossiers:
            self.assertTrue(SHA40.fullmatch(dossier["candidate"]["commit_sha"]))
            self.assertTrue(SHA40.fullmatch(dossier["candidate"]["tree_sha"]))
            self.assertEqual(dossier["capability"]["contract_id"], "network.http.v1")
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertFalse(dossier["evidence"]["security"]["untrusted_code_executed"])
            self.assertEqual(
                dossier["evidence"]["benchmark"]["status"],
                "PLANNED_NOT_EXECUTED",
            )

    def test_provenance_distinguishes_verified_tag_from_untagged_release(self) -> None:
        dio = load(PROOF / "cfug-dio.dossier.json")
        http = load(PROOF / "dart-lang-http.dossier.json")
        self.assertEqual(dio["candidate"]["source_version"], "5.11.1")
        self.assertEqual(dio["candidate"]["source_tag"], "dio_v5.11.1")
        self.assertTrue(dio["candidate"]["release_tag_verified"])
        self.assertEqual(http["candidate"]["source_version"], "1.6.0")
        self.assertIsNone(http["candidate"]["source_tag"])
        self.assertFalse(http["candidate"]["release_tag_verified"])

    def test_dry_run_manifests_match_library_exchange_boundary(self) -> None:
        paths = sorted((PROOF / "dry-run").glob("*/0.1.0/manifest.json"))
        self.assertEqual(len(paths), 2)
        for path in paths:
            manifest = load(path)
            self.assertEqual(manifest["status"], "discovered")
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            connector = manifest["connector"]
            self.assertEqual(connector["standard"], "ai-orchestrator-lego")
            self.assertEqual(connector["standard_version"], "1.0.0")
            provided = connector["provides"]
            self.assertEqual(len(provided), 1)
            self.assertEqual(provided[0]["capability_id"], "network.http")
            self.assertEqual(provided[0]["contract_id"], "network.http.v1")
            self.assertEqual(provided[0]["contract_version"], "1.0")
            source_commit = manifest["provenance"]["source_commit"]
            self.assertTrue(SHA40.fullmatch(source_commit))
            self.assertEqual(source_commit, manifest["payload"]["upstream_commit"])
            path_text = str(path).replace("\\", "/")
            self.assertNotIn("/modules/", path_text)
            self.assertNotIn("catalog/index.json", path_text)

    def test_comparison_keeps_both_candidates(self) -> None:
        comparison = load(PROOF / "comparison.json")
        self.assertTrue(comparison["dry_run"])
        self.assertEqual(comparison["capability_id"], "network.http")
        self.assertEqual(comparison["contract_id"], "network.http.v1")
        self.assertEqual(len(comparison["candidate_order"]), 2)
        self.assertIn("dart-lang/http@1.6.0", comparison["candidate_order"])
        self.assertIn("cfug/dio@5.11.1", comparison["candidate_order"])
        self.assertIn("Both candidates shortlisted", comparison["outcome"])


if __name__ == "__main__":
    unittest.main()
