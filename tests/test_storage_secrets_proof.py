from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "first-real-scan" / "storage.secrets"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} is not a JSON object")
    return value


class StorageSecretsProofTests(unittest.TestCase):
    def test_two_independent_candidates_are_shortlisted_but_not_certified(self) -> None:
        dossiers = [
            load(PROOF / "juliansteenbakker-flutter_secure_storage.dossier.json"),
            load(PROOF / "johngalt1717-webauthn_secure_storage.dossier.json"),
        ]
        repositories = {d["candidate"]["repository"] for d in dossiers}
        self.assertEqual(
            repositories,
            {
                "juliansteenbakker/flutter_secure_storage",
                "JohnGalt1717/webauthn_secure_storage",
            },
        )
        for dossier in dossiers:
            self.assertEqual(dossier["lifecycle"], "SHORTLISTED")
            self.assertTrue(SHA40.fullmatch(dossier["candidate"]["commit_sha"]))
            self.assertEqual(dossier["capability"]["contract_id"], "storage.secrets.v1")
            security = dossier["evidence"]["security"]
            self.assertEqual(security["admission_gate"], "NOT_RUN_FULL_SOURCE")
            self.assertFalse(security["certification_eligible"])
            self.assertFalse(security["reviewed"])
            self.assertFalse(security["untrusted_code_executed"])

    def test_release_provenance_is_not_invented(self) -> None:
        mature = load(PROOF / "juliansteenbakker-flutter_secure_storage.dossier.json")
        emerging = load(PROOF / "johngalt1717-webauthn_secure_storage.dossier.json")
        self.assertEqual(mature["candidate"]["source_version"], "11.1.1")
        self.assertEqual(
            mature["candidate"]["source_tag"],
            "flutter_secure_storage-v11.1.1",
        )
        self.assertTrue(mature["candidate"]["release_tag_verified"])
        self.assertEqual(emerging["candidate"]["source_version"], "0.2.3")
        self.assertIsNone(emerging["candidate"]["source_tag"])
        self.assertFalse(emerging["candidate"]["release_tag_verified"])

    def test_dry_run_manifests_stay_outside_library_certified_paths(self) -> None:
        paths = sorted((PROOF / "dry-run").glob("*/0.1.0/manifest.json"))
        self.assertEqual(len(paths), 2)
        for path in paths:
            manifest = load(path)
            self.assertEqual(manifest["status"], "discovered")
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            provided = manifest["connector"]["provides"]
            self.assertEqual(len(provided), 1)
            self.assertEqual(provided[0]["capability_id"], "storage.secrets")
            self.assertEqual(provided[0]["contract_id"], "storage.secrets.v1")
            self.assertEqual(manifest["connector"]["standard"], "ai-orchestrator-lego")
            self.assertEqual(manifest["connector"]["standard_version"], "1.0.0")
            self.assertTrue(SHA40.fullmatch(manifest["payload"]["upstream_commit"]))
            self.assertEqual(
                manifest["payload"]["upstream_commit"],
                manifest["provenance"]["source_commit"],
            )
            text = str(path).replace("\\", "/")
            self.assertNotIn("/modules/", text)
            self.assertNotIn("catalog/index.json", text)

    def test_comparison_keeps_maturity_as_security_signal(self) -> None:
        comparison = load(PROOF / "comparison.json")
        self.assertTrue(comparison["dry_run"])
        self.assertEqual(comparison["capability_id"], "storage.secrets")
        self.assertEqual(len(comparison["candidate_order"]), 2)
        self.assertEqual(
            comparison["human_recommendation"]["default"],
            "juliansteenbakker/flutter_secure_storage 11.1.1",
        )
        self.assertIn("Full-source static admission gate not yet run", comparison["limitations"])


if __name__ == "__main__":
    unittest.main()
