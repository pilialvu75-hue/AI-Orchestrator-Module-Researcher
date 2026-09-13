from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "auth.session"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} is not a JSON object")
    return value


class AuthSessionProofTests(unittest.TestCase):
    def test_two_independent_shortlisted_candidates(self) -> None:
        dossiers = [
            load(PROOF / "appsup-dart-openid-client.dossier.json"),
            load(PROOF / "bdaya-dev-oidc.dossier.json"),
        ]
        self.assertEqual({d["lifecycle"] for d in dossiers}, {"SHORTLISTED"})
        self.assertEqual(
            {d["candidate"]["repository"] for d in dossiers},
            {"appsup-dart/openid_client", "Bdaya-Dev/oidc"},
        )
        self.assertEqual(len({d["fingerprint"] for d in dossiers}), 2)
        for dossier in dossiers:
            candidate = dossier["candidate"]
            self.assertTrue(SHA40.fullmatch(candidate["commit_sha"]))
            self.assertTrue(SHA40.fullmatch(candidate["tree_sha"]))
            self.assertEqual(dossier["capability"]["contract_id"], "auth.session.v1")
            self.assertEqual(candidate["platforms"], ["android", "desktop", "web"])
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertFalse(dossier["evidence"]["security"]["untrusted_code_executed"])
            self.assertEqual(
                dossier["evidence"]["benchmark"]["status"],
                "PLANNED_NOT_EXECUTED",
            )

    def test_provenance_keeps_untagged_package_versions_explicit(self) -> None:
        openid = load(PROOF / "appsup-dart-openid-client.dossier.json")
        oidc = load(PROOF / "bdaya-dev-oidc.dossier.json")
        self.assertEqual(openid["candidate"]["source_version"], "0.4.10+1")
        self.assertEqual(oidc["candidate"]["source_version"], "4.0.0")
        for dossier in (openid, oidc):
            self.assertIsNone(dossier["candidate"]["source_tag"])
            self.assertFalse(dossier["candidate"]["release_tag_verified"])

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
            self.assertEqual(provided[0]["capability_id"], "auth.session")
            self.assertEqual(provided[0]["contract_id"], "auth.session.v1")
            self.assertEqual(provided[0]["contract_version"], "1.0")
            source_commit = manifest["provenance"]["source_commit"]
            self.assertTrue(SHA40.fullmatch(source_commit))
            self.assertEqual(source_commit, manifest["payload"]["upstream_commit"])
            path_text = str(path).replace("\\", "/")
            self.assertNotIn("/modules/", path_text)
            self.assertNotIn("catalog/index.json", path_text)

    def test_comparison_preserves_tradeoff_and_draft_contract_limit(self) -> None:
        comparison = load(PROOF / "comparison.json")
        self.assertTrue(comparison["dry_run"])
        self.assertEqual(comparison["capability_id"], "auth.session")
        self.assertEqual(comparison["contract_id"], "auth.session.v1")
        self.assertEqual(len(comparison["candidate_order"]), 2)
        self.assertIn("Bdaya-Dev/oidc@4.0.0", comparison["candidate_order"])
        self.assertIn(
            "appsup-dart/openid_client@0.4.10+1",
            comparison["candidate_order"],
        )
        self.assertIn("Both candidates shortlisted", comparison["outcome"])
        self.assertTrue(
            any(
                "draft logical Library contract" in item
                for item in comparison["limitations"]
            )
        )


if __name__ == "__main__":
    unittest.main()
