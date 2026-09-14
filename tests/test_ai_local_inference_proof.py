from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "ai.local_inference"


class AiLocalInferenceProofTest(unittest.TestCase):
    @staticmethod
    def _json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_two_independent_runtime_candidates_are_recorded(self) -> None:
        llama = self._json(PROOF / "ggml-org-llama-cpp.dossier.json")
        ort = self._json(PROOF / "microsoft-onnxruntime-genai.dossier.json")

        self.assertNotEqual(llama["fingerprint"], ort["fingerprint"])
        self.assertEqual(llama["candidate"]["source_version"], "0.4.0")
        self.assertEqual(llama["candidate"]["source_tag"], "v0.4.0")
        self.assertEqual(ort["candidate"]["source_version"], "0.15.2")
        self.assertEqual(ort["candidate"]["source_tag"], "v0.15.2")
        self.assertNotEqual(
            llama["evidence"]["functional"]["model_ecosystem"],
            ort["evidence"]["functional"]["model_ecosystem"],
        )

    def test_manual_research_does_not_claim_security_admission(self) -> None:
        dossiers = [
            self._json(PROOF / "ggml-org-llama-cpp.dossier.json"),
            self._json(PROOF / "microsoft-onnxruntime-genai.dossier.json"),
        ]
        for dossier in dossiers:
            self.assertEqual(dossier["lifecycle"], "SCREENED")
            self.assertEqual(dossier["research_recommendation"], "SHORTLIST")
            self.assertFalse(dossier["evidence"]["security"]["reviewed"])
            self.assertFalse(dossier["evidence"]["security"]["certification_eligible"])
            self.assertFalse(dossier["evidence"]["security"]["untrusted_code_executed"])
            self.assertEqual(
                dossier["capability"]["contract_id"], "ai.local_inference.v1"
            )
            self.assertEqual(
                dossier["capability"]["targets"],
                ["android", "desktop", "raspberry_pi"],
            )

    def test_raspberry_pi_evidence_is_not_overclaimed(self) -> None:
        llama = self._json(PROOF / "ggml-org-llama-cpp.dossier.json")
        ort = self._json(PROOF / "microsoft-onnxruntime-genai.dossier.json")

        for dossier in (llama, ort):
            pi = dossier["evidence"]["platform"]["raspberry_pi"]
            self.assertTrue(pi["architecture_candidate"])
            self.assertFalse(pi["raspberry_pi_specific_tested"])

        comparison = self._json(PROOF / "comparison.json")
        self.assertFalse(
            comparison["safety"]["raspberry_pi_specific_runtime_test_run"]
        )

    def test_dry_run_manifests_remain_discovered_only(self) -> None:
        manifests = sorted((PROOF / "dry-run").glob("*/0.1.0/manifest.json"))
        self.assertEqual(len(manifests), 2)

        commits: set[str] = set()
        for path in manifests:
            manifest = self._json(path)
            self.assertEqual(manifest["status"], "discovered")
            self.assertEqual(manifest["capabilities"], ["ai.local_inference"])
            self.assertEqual(
                manifest["platforms"],
                ["android", "desktop", "raspberry_pi"],
            )
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertFalse(manifest["security"]["reviewed"])
            self.assertEqual(
                manifest["connector"]["provides"][0]["contract_id"],
                "ai.local_inference.v1",
            )
            commit = manifest["provenance"]["source_commit"]
            self.assertEqual(len(commit), 40)
            commits.add(commit)

        self.assertEqual(len(commits), 2)

    def test_comparison_keeps_library_contract_provider_neutral(self) -> None:
        comparison = self._json(PROOF / "comparison.json")
        self.assertEqual(
            comparison["decision"],
            "PREFER_LLAMA_CPP_KEEP_ONNXRUNTIME_GENAI_ALTERNATIVE",
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
