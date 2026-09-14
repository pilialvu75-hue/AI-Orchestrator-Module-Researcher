from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "voice.stt"


class VoiceSttProofTest(unittest.TestCase):
    @staticmethod
    def _json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_two_independent_stt_candidates_are_recorded(self) -> None:
        sherpa = self._json(PROOF / "k2-fsa-sherpa-onnx.dossier.json")
        whisper = self._json(PROOF / "ggml-org-whisper-cpp.dossier.json")

        self.assertNotEqual(sherpa["fingerprint"], whisper["fingerprint"])
        self.assertEqual(sherpa["candidate"]["source_version"], "1.13.8")
        self.assertEqual(sherpa["candidate"]["source_tag"], "v1.13.8")
        self.assertEqual(whisper["candidate"]["source_version"], "1.9.4")
        self.assertEqual(whisper["candidate"]["source_tag"], "v1.9.4")

    def test_platform_evidence_includes_raspberry_pi_explicitly(self) -> None:
        sherpa = self._json(PROOF / "k2-fsa-sherpa-onnx.dossier.json")
        whisper = self._json(PROOF / "ggml-org-whisper-cpp.dossier.json")

        for dossier in (sherpa, whisper):
            platform = dossier["evidence"]["platform"]
            self.assertTrue(platform["android"]["supported"])
            self.assertTrue(platform["desktop"]["supported"])
            self.assertTrue(platform["raspberry_pi"]["supported_upstream"])

    def test_manual_research_does_not_claim_security_admission(self) -> None:
        dossiers = [
            self._json(PROOF / "k2-fsa-sherpa-onnx.dossier.json"),
            self._json(PROOF / "ggml-org-whisper-cpp.dossier.json"),
        ]
        for dossier in dossiers:
            self.assertEqual(dossier["lifecycle"], "SCREENED")
            self.assertEqual(dossier["research_recommendation"], "SHORTLIST")
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertFalse(dossier["evidence"]["security"]["certification_eligible"])
            self.assertFalse(dossier["evidence"]["security"]["untrusted_code_executed"])
            self.assertEqual(dossier["capability"]["contract_id"], "voice.stt.v1")
            self.assertEqual(
                dossier["capability"]["targets"],
                ["android", "desktop", "raspberry_pi"],
            )

    def test_dry_run_manifests_remain_discovered_only(self) -> None:
        manifests = sorted((PROOF / "dry-run").glob("*/0.1.0/manifest.json"))
        self.assertEqual(len(manifests), 2)

        commits: set[str] = set()
        for path in manifests:
            manifest = self._json(path)
            self.assertEqual(manifest["status"], "discovered")
            self.assertEqual(manifest["capabilities"], ["voice.stt"])
            self.assertEqual(
                manifest["platforms"],
                ["android", "desktop", "raspberry_pi"],
            )
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            self.assertEqual(
                manifest["connector"]["provides"][0]["contract_id"],
                "voice.stt.v1",
            )
            commit = manifest["provenance"]["source_commit"]
            self.assertEqual(len(commit), 40)
            commits.add(commit)

        self.assertEqual(len(commits), 2)

    def test_comparison_prefers_sherpa_but_keeps_engine_neutral_boundary(self) -> None:
        comparison = self._json(PROOF / "comparison.json")
        self.assertEqual(
            comparison["decision"],
            "PREFER_SHERPA_ONNX_KEEP_WHISPER_CPP_ALTERNATIVE",
        )
        self.assertEqual(comparison["contract_detail_status"], "logical_boundary_only")
        self.assertEqual(
            comparison["requested_targets"],
            ["android", "desktop", "raspberry_pi"],
        )
        self.assertFalse(comparison["safety"]["library_write"])
        self.assertFalse(comparison["safety"]["cantiere_write"])


if __name__ == "__main__":
    unittest.main()
