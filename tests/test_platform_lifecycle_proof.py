from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.lifecycle"

def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))

class PlatformLifecycleProofTest(unittest.TestCase):
    def test_need_is_staged_and_contract_is_draft(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(comparison["need_source"], "catalog/needs.platform-extension.json")
        self.assertEqual(comparison["need_status"], "needed")
        self.assertEqual(comparison["need_authority"], "staged_not_authoritative")
        self.assertEqual(comparison["priority"], "high")
        self.assertEqual(comparison["desired_candidates_per_target"], 2)
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "platform.lifecycle.v1")
        self.assertEqual(contract["status"], "draft")
        self.assertTrue(contract["detail_gap"])

    def test_all_required_targets_have_two_candidates(self) -> None:
        comparison = _load("comparison.json")
        required = {"android", "windows", "linux", "macos", "ios", "web", "raspberry_pi"}
        self.assertEqual(set(comparison["required_targets"]), required)
        coverage = comparison["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        for target in required:
            self.assertGreaterEqual(coverage[target], 2)
        self.assertTrue(comparison["per_target_candidate_depth_satisfied"])

    def test_independence_is_event_source_aware(self) -> None:
        comparison = _load("comparison.json")
        pairs = comparison["independent_event_source_pairs"]
        assert isinstance(pairs, dict)
        self.assertEqual(set(pairs), {"android", "windows", "linux", "macos", "ios", "web", "raspberry_pi"})
        self.assertEqual(pairs["android"], ["huanguan1978/app_lifecycle_protector", "ajinasokan/flutter_fgbg"])
        self.assertEqual(pairs["ios"], ["huanguan1978/app_lifecycle_protector", "ajinasokan/flutter_fgbg"])
        self.assertEqual(pairs["raspberry_pi"], ["isoos/shutdown", "doodlezucc/dart_graceful"])
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertIn("not treated as semantically interchangeable", contract["non_equivalence_policy"])

    def test_security_admission_remains_fail_closed(self) -> None:
        comparison = _load("comparison.json")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["discovery_depth_closed"])
        self.assertFalse(decision["security_admission_closed"])
        self.assertFalse(decision["contract_conformance_closed"])
        self.assertFalse(decision["runtime_validation_closed"])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["runtime_certified"])
        self.assertFalse(decision["certification_asserted"])
        self.assertFalse(decision["library_write_attempted"])

    def test_live_preflights_preserve_exact_states(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        for flag in ("certification_asserted", "functional_or_contract_fit_asserted", "library_accessed", "library_write_attempted", "executed_untrusted_code"):
            self.assertFalse(live[flag])
        results = live["results"]
        assert isinstance(results, list)
        by_repo = {str(item["repository"]): item for item in results}
        self.assertEqual(by_repo["ajinasokan/flutter_fgbg"]["state"], "CLEAR")
        self.assertTrue(by_repo["ajinasokan/flutter_fgbg"]["vulnerability"]["database_checked"])
        self.assertEqual(by_repo["ajinasokan/flutter_fgbg"]["vulnerability"]["hits"], [])
        self.assertEqual(by_repo["isoos/shutdown"]["state"], "CLEAR")
        self.assertEqual(by_repo["huanguan1978/app_lifecycle_protector"]["state"], "REVIEW")
        self.assertEqual(by_repo["doodlezucc/dart_graceful"]["state"], "REVIEW")
        self.assertEqual(by_repo["doodlezucc/dart_graceful"]["source"]["findings"][0]["rule_id"], "process_execution")

    def test_rate_limited_candidates_are_not_security_admitted(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        deferred = live["deferred"]
        assert isinstance(deferred, list)
        self.assertEqual({item["repository"] for item in deferred}, {"chenenyu/lifecycle", "leanflutter/window_manager", "zonble/flutter_window_close"})
        for item in deferred:
            self.assertEqual(item["state"], "DEFERRED_RATE_LIMIT")
            self.assertTrue(item["counted_for_discovery"])
            self.assertFalse(item["security_admitted"])

    def test_raspberry_pi_depth_does_not_claim_runtime_readiness(self) -> None:
        comparison = _load("comparison.json")
        candidates = comparison["candidates"]
        assert isinstance(candidates, list)
        pi = {item["id"]: item for item in candidates if "raspberry_pi" in item["research_targets"]}
        self.assertEqual(set(pi), {"isoos/shutdown", "doodlezucc/dart_graceful"})
        for item in pi.values():
            self.assertFalse(item["runtime_validated"])
        self.assertEqual(pi["doodlezucc/dart_graceful"]["known_constraint"], "Dart SDK >=2.16.0 <3.0.0")

if __name__ == "__main__":
    unittest.main()
