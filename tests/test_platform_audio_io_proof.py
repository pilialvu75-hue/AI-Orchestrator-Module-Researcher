from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.audio_io"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformAudioIoProofTest(unittest.TestCase):
    def test_need_is_staged_and_contract_is_draft(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(
            comparison["need_source"],
            "catalog/needs.platform-extension.json",
        )
        self.assertEqual(comparison["need_authority"], "staged_not_authoritative")
        self.assertEqual(comparison["priority"], "high")
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "platform.audio_io.v1")
        self.assertEqual(contract["status"], "draft")
        self.assertTrue(contract["detail_gap"])

    def test_two_independent_candidates_cover_six_standard_targets(self) -> None:
        comparison = _load("comparison.json")
        candidates = comparison["candidates"]
        assert isinstance(candidates, list)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            {str(item["id"]) for item in candidates},
            {"WAMF/audio_io", "flutter-webrtc/flutter-webrtc"},
        )
        for item in candidates:
            self.assertEqual(
                set(item["research_targets"]),
                {"android", "windows", "linux", "macos", "ios", "web"},
            )
            self.assertEqual(item["missing_required_target_declarations"], ["raspberry_pi"])

        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["two_candidate_independence_satisfied"])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])

    def test_raspberry_pi_gap_remains_explicit(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(
            set(comparison["required_targets"]),
            {"android", "windows", "linux", "macos", "ios", "web", "raspberry_pi"},
        )
        coverage = comparison["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        for target in ("android", "windows", "linux", "macos", "ios", "web"):
            self.assertEqual(coverage[target], 2)
        self.assertEqual(coverage["raspberry_pi"], 0)
        self.assertFalse(comparison["per_target_candidate_depth_satisfied"])
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertEqual(decision["coverage_blockers"], ["raspberry_pi:0/2"])

    def test_live_preflights_are_source_clear_but_vulnerability_review(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        self.assertFalse(live["certification_asserted"])
        self.assertFalse(live["functional_or_contract_fit_asserted"])
        self.assertFalse(live["library_accessed"])
        self.assertFalse(live["library_write_attempted"])
        self.assertFalse(live["executed_untrusted_code"])

        results = live["results"]
        assert isinstance(results, list)
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result["state"], "REVIEW")
            self.assertFalse(result["security_preflight_clear"])
            security = result["security"]
            assert isinstance(security, dict)
            self.assertEqual(security["verdict"], "CLEAR")
            self.assertTrue(security["complete"])
            self.assertTrue(security["admission_eligible"])
            self.assertEqual(security["findings"], [])
            vulnerability = result["vulnerability"]
            assert isinstance(vulnerability, dict)
            self.assertEqual(vulnerability["verdict"], "REVIEW")
            self.assertFalse(vulnerability["database_checked"])
            self.assertFalse(vulnerability["admission_eligible"])
            self.assertEqual(vulnerability["queried_components"], 0)

    def test_audio_io_is_not_overclaimed_for_raspberry_pi(self) -> None:
        dossier = _load("wamf-audio-io.dossier.json")
        targets = dossier["target_evidence"]
        assert isinstance(targets, dict)
        self.assertFalse(targets["raspberry_pi_counted"])
        self.assertEqual(targets["required_but_not_proven"], ["raspberry_pi"])
        decision = dossier["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["counts_for_raspberry_pi"])
        self.assertFalse(decision["runtime_certified"])
        self.assertFalse(decision["submission_ready"])

    def test_webrtc_embedded_label_is_not_treated_as_pi_proof(self) -> None:
        dossier = _load("flutter-webrtc.dossier.json")
        targets = dossier["target_evidence"]
        assert isinstance(targets, dict)
        self.assertEqual(targets["additional_upstream_label"], "embedded/elinux")
        self.assertFalse(targets["raspberry_pi_counted"])
        decision = dossier["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["counts_for_raspberry_pi"])
        self.assertFalse(decision["certification_asserted"])

    def test_security_results_never_claim_osv_clean_without_exact_versions(self) -> None:
        for name in ("wamf-audio-io.dossier.json", "flutter-webrtc.dossier.json"):
            dossier = _load(name)
            security = dossier["security"]
            assert isinstance(security, dict)
            self.assertEqual(security["source_verdict"], "CLEAR")
            self.assertEqual(security["supply_chain_verdict"], "CLEAR")
            self.assertEqual(security["vulnerability_verdict"], "REVIEW")
            self.assertFalse(security["vulnerability_database_checked"])
            self.assertGreater(len(security["unresolved_runtime_dependencies"]), 0)
            self.assertFalse(security["certification_eligible"])
            self.assertFalse(security["executed_untrusted_code"])


if __name__ == "__main__":
    unittest.main()
