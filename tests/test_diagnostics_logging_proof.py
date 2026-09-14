from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "diagnostics.logging"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DiagnosticsLoggingProofTests(unittest.TestCase):
    def test_selected_candidates_are_independent_and_not_security_admitted(self) -> None:
        dart = load(PROOF / "dart-lang-core-logging.dossier.json")
        talker = load(PROOF / "frezyx-talker.dossier.json")

        self.assertNotEqual(dart["candidate"]["repository"], talker["candidate"]["repository"])
        self.assertNotEqual(dart["fingerprint"], talker["fingerprint"])
        self.assertEqual(64, len(dart["fingerprint"]))
        self.assertEqual(64, len(talker["fingerprint"]))

        for dossier in (dart, talker):
            self.assertEqual("diagnostics.logging.v1", dossier["capability"]["contract_id"])
            self.assertEqual(["android", "desktop", "web"], dossier["capability"]["targets"])
            self.assertEqual("SCREENED", dossier["lifecycle"])
            self.assertEqual("SHORTLIST", dossier["research_recommendation"])
            self.assertFalse(dossier["certification_eligible"])
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertEqual(
                "NOT_EXECUTED_MANUAL_PROOF",
                dossier["evidence"]["security"]["admission_gate"]["status"],
            )
            self.assertEqual(40, len(dossier["candidate"]["commit_sha"]))
            self.assertEqual(40, len(dossier["candidate"]["tree_sha"]))

    def test_provenance_preserves_verified_tag_and_missing_talker_tag(self) -> None:
        dart = load(PROOF / "dart-lang-core-logging.dossier.json")
        talker = load(PROOF / "frezyx-talker.dossier.json")

        self.assertEqual("logging-v1.3.0", dart["candidate"]["source_tag"])
        self.assertTrue(dart["candidate"]["release_tag_verified"])
        self.assertEqual("pkgs/logging", dart["candidate"]["component_path"])

        self.assertIsNone(talker["candidate"]["source_tag"])
        self.assertFalse(talker["candidate"]["release_tag_verified"])
        self.assertEqual("packages/talker", talker["candidate"]["component_path"])
        self.assertIn("No v5.1.20", talker["candidate"]["source_tag_note"])

    def test_dry_run_manifests_stop_at_discovered(self) -> None:
        paths = (
            PROOF
            / "dry-run"
            / "diagnostics.logging.dart-lang.logging"
            / "0.1.0"
            / "manifest.json",
            PROOF
            / "dry-run"
            / "diagnostics.logging.frezyx.talker"
            / "0.1.0"
            / "manifest.json",
        )
        fingerprints = set()
        for path in paths:
            manifest = load(path)
            self.assertEqual("discovered", manifest["status"])
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            self.assertEqual(["android", "desktop", "web"], manifest["platforms"])
            provided = manifest["connector"]["provides"][0]
            self.assertEqual("diagnostics.logging", provided["capability_id"])
            self.assertEqual("diagnostics.logging.v1", provided["contract_id"])
            self.assertTrue(str(path).startswith(str(PROOF)))
            fingerprints.add(manifest["provenance"]["source_task_id"])
        self.assertEqual(2, len(fingerprints))

    def test_screened_fallback_is_not_misrepresented_as_rejected(self) -> None:
        screened = load(PROOF / "sourcehorizon-logger.screened.json")
        self.assertEqual("SCREENED_ALTERNATIVE", screened["status"])
        self.assertTrue(screened["assessment"]["technically_valid"])
        self.assertFalse(screened["assessment"]["security_admission_performed"])
        self.assertFalse(screened["assessment"]["certification_eligible"])


if __name__ == "__main__":
    unittest.main()
