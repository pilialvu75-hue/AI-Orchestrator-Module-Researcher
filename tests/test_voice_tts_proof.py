from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "voice.tts"


class VoiceTtsProofTest(unittest.TestCase):
    @staticmethod
    def _json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_two_independent_tts_candidates_are_recorded(self) -> None:
        sherpa = self._json(PROOF / "k2-fsa-sherpa-onnx.dossier.json")
        espeak = self._json(PROOF / "espeak-ng-espeak-ng.dossier.json")

        self.assertNotEqual(sherpa["fingerprint"], espeak["fingerprint"])
        self.assertEqual(sherpa["candidate"]["source_version"], "1.13.8")
        self.assertEqual(sherpa["candidate"]["source_tag"], "v1.13.8")
        self.assertEqual(espeak["candidate"]["source_version"], "1.52.0")
        self.assertEqual(espeak["candidate"]["source_tag"], "1.52.0")

    def test_required_platform_matrix_is_not_overclaimed(self) -> None:
        sherpa = self._json(PROOF / "k2-fsa-sherpa-onnx.dossier.json")
        espeak = self._json(PROOF / "espeak-ng-espeak-ng.dossier.json")

        sherpa_platform = sherpa["evidence"]["platform"]
        self.assertTrue(sherpa_platform["android"]["supported"])
        self.assertTrue(sherpa_platform["desktop"]["supported"])
        self.assertTrue(sherpa_platform["raspberry_pi"]["supported_upstream"])

        espeak_platform = espeak["evidence"]["platform"]
        self.assertTrue(espeak_platform["android"]["supported"])
        self.assertTrue(espeak_platform["desktop"]["supported"])
        self.assertFalse(espeak_platform["raspberry_pi"]["supported_upstream"])
        self.assertTrue(espeak_platform["raspberry_pi"]["architecture_candidate"])

    def test_extended_ios_macos_observations_do_not_change_required_targets(self) -> None:
        dossiers = [
            self._json(PROOF / "k2-fsa-sherpa-onnx.dossier.json"),
            self._json(PROOF / "espeak-ng-espeak-ng.dossier.json"),
        ]
        for dossier in dossiers:
            self.assertEqual(
                dossier["capability"]["targets"],
                ["android", "desktop", "raspberry_pi"],
            )
            self.assertIn("extended", dossier["evidence"]["platform"])

    def test_manual_research_does_not_claim_security_admission(self) -> None:
        dossiers = [
            self._json(PROOF / "k2-fsa-sherpa-onnx.dossier.json"),
            self._json(PROOF / "espeak-ng-espeak-ng.dossier.json"),
        ]
        for dossier in dossiers:
            self.assertEqual(dossier["lifecycle"], "SCREENED")
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertFalse(dossier["evidence"]["security"]["certification_eligible"])
            self.assertFalse(dossier["evidence"]["security"]["untrusted_code_executed"])
            self.assertEqual(dossier["capability"]["contract_id"], "voice.tts.v1")

    def test_dry_run_manifests_remain_discovered_only(self) -> None:
        manifests = sorted((PROOF / "dry-run").glob("*/0.1.0/manifest.json"))
        self.assertEqual(len(manifests), 2)

        commits: set[str] = set()
        for path in manifests:
            manifest = self._json(path)
            self.assertEqual(manifest["status"], "discovered")
            self.assertEqual(manifest["capabilities"], ["voice.tts"])
            self.assertEqual(
                manifest["platforms"],
                ["android", "desktop", "raspberry_pi"],
            )
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            self.assertEqual(
                manifest["connector"]["provides"][0]["contract_id"],
                "voice.tts.v1",
            )
            commit = manifest["provenance"]["source_commit"]
            self.assertEqual(len(commit), 40)
            commits.add(commit)

        self.assertEqual(len(commits), 2)

    def test_comparison_prefers_sherpa_and_keeps_espeak_constraints(self) -> None:
        comparison = self._json(PROOF / "comparison.json")
        self.assertEqual(
            comparison["decision"],
            "PREFER_SHERPA_ONNX_KEEP_ESPEAK_NG_CONSTRAINED_FALLBACK",
        )
        self.assertEqual(comparison["contract_detail_status"], "logical_boundary_only")
        self.assertEqual(
            comparison["requested_targets"],
            ["android", "desktop", "raspberry_pi"],
        )
        self.assertFalse(comparison["safety"]["library_write"])
        self.assertFalse(comparison["safety"]["cantiere_write"])
        self.assertFalse(comparison["safety"]["certification_claimed"])


if __name__ == "__main__":
    unittest.main()
