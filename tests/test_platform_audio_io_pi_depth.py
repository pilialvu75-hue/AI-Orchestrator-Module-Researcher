from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.audio_io"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformAudioIoPiDepthTest(unittest.TestCase):
    def test_discovery_depth_is_closed_for_every_required_target(self) -> None:
        comparison = _load("comparison.json")
        coverage = comparison["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        self.assertEqual(
            set(coverage),
            {"android", "windows", "linux", "macos", "ios", "web", "raspberry_pi"},
        )
        self.assertTrue(all(value >= 2 for value in coverage.values()))
        self.assertTrue(comparison["per_target_candidate_depth_satisfied"])
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["discovery_depth_closed"])
        self.assertEqual(decision["coverage_blockers"], [])

    def test_pi_depth_uses_two_independent_native_families(self) -> None:
        comparison = _load("comparison.json")
        candidates = comparison["candidates"]
        assert isinstance(candidates, list)
        pi_candidates = [
            item
            for item in candidates
            if isinstance(item, dict) and "raspberry_pi" in item["research_targets"]
        ]
        self.assertEqual(len(pi_candidates), 2)
        self.assertEqual(
            {item["id"] for item in pi_candidates},
            {"mackron/miniaudio", "PortAudio/portaudio"},
        )
        self.assertTrue(all(item["native_adapter_required"] for item in pi_candidates))
        self.assertTrue(all(not item["security_admitted"] for item in pi_candidates))
        self.assertTrue(all(not item["runtime_validated"] for item in pi_candidates))

    def test_depth_closure_never_claims_admission_or_certification(self) -> None:
        comparison = _load("comparison.json")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["security_admission_closed"])
        self.assertFalse(decision["contract_conformance_closed"])
        self.assertFalse(decision["runtime_validation_closed"])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["runtime_certified"])
        self.assertFalse(decision["certification_asserted"])
        self.assertFalse(decision["library_write_attempted"])

    def test_live_pi_security_results_remain_fail_closed(self) -> None:
        live = _load("live-security-pi-depth-2026-09-15.json")
        self.assertFalse(live["certification_asserted"])
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
            self.assertEqual(security["verdict"], "REVIEW")
            self.assertFalse(security["admission_eligible"])
            self.assertEqual(security["critical_findings"], 0)
            supply_chain = result["supply_chain"]
            assert isinstance(supply_chain, dict)
            self.assertEqual(supply_chain["verdict"], "NOT_ANALYZED")
            vulnerability = result["vulnerability"]
            assert isinstance(vulnerability, dict)
            self.assertFalse(vulnerability["database_checked"])
            self.assertEqual(vulnerability["queried_components"], 0)

    def test_miniaudio_pi_evidence_is_exact_commit_and_adapter_is_not_claimed(self) -> None:
        dossier = _load("mackron-miniaudio-pi.dossier.json")
        candidate = dossier["candidate"]
        assert isinstance(candidate, dict)
        self.assertEqual(
            candidate["commit_sha"],
            "9634bedb5b5a2ca38c1ee7108a9358a4e233f14d",
        )
        evidence = dossier["raspberry_pi_evidence"]
        assert isinstance(evidence, dict)
        self.assertTrue(evidence["explicit_upstream_support"])
        self.assertEqual(evidence["evidence_kind"], "pinned_repository_readme")
        adaptation = dossier["adaptation"]
        assert isinstance(adaptation, dict)
        self.assertTrue(adaptation["kind"] == "native_adapter_required")
        self.assertFalse(adaptation["flutter_plugin_ready"])
        self.assertFalse(adaptation["runtime_validation_completed"])

    def test_portaudio_pi_evidence_does_not_hide_security_review(self) -> None:
        dossier = _load("portaudio-pi.dossier.json")
        evidence = dossier["raspberry_pi_evidence"]
        assert isinstance(evidence, dict)
        self.assertTrue(evidence["explicit_upstream_support"])
        self.assertEqual(evidence["evidence_kind"], "official_project_wiki")
        security = dossier["security"]
        assert isinstance(security, dict)
        self.assertEqual(security["verdict"], "REVIEW")
        self.assertFalse(security["admission_eligible"])
        self.assertFalse(security["vulnerability_database_checked"])
        decision = dossier["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["counts_for_raspberry_pi_research_depth"])
        self.assertFalse(decision["security_admitted"])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])


if __name__ == "__main__":
    unittest.main()
