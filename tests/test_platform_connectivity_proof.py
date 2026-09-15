from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.connectivity"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformConnectivityProofTest(unittest.TestCase):
    def test_need_and_contract_are_staged(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(comparison["capability_id"], "platform.connectivity")
        self.assertEqual(comparison["need_status"], "needed")
        self.assertEqual(comparison["need_authority"], "staged_not_authoritative")
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["status"], "draft")
        self.assertTrue(contract["detail_gap"])

    def test_all_required_targets_have_two_candidates(self) -> None:
        comparison = _load("comparison.json")
        required = {
            "android",
            "windows",
            "linux",
            "macos",
            "ios",
            "web",
            "raspberry_pi",
        }
        self.assertEqual(set(comparison["required_targets"]), required)
        coverage = comparison["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        for target in required:
            self.assertGreaterEqual(coverage[target], 2)

    def test_transport_and_reachability_are_independent(self) -> None:
        comparison = _load("comparison.json")
        pairs = comparison["independent_signal_pairs"]
        assert isinstance(pairs, dict)
        expected = [
            "fluttercommunity/connectivity_plus",
            "OutdatedGuy/internet_connection_checker_plus",
        ]
        for pair in pairs.values():
            self.assertEqual(pair, expected)
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertIn("does not prove Internet reachability", contract["non_equivalence_policy"])

    def test_metering_and_admission_remain_open(self) -> None:
        comparison = _load("comparison.json")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["discovery_depth_closed"])
        self.assertFalse(decision["metering_contract_closed"])
        self.assertFalse(decision["security_admission_closed"])
        self.assertFalse(decision["contract_conformance_closed"])
        self.assertFalse(decision["runtime_validation_closed"])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["runtime_certified"])

    def test_api_timeouts_are_not_security_verdicts(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        self.assertEqual(live["results"], [])
        deferred = live["deferred"]
        assert isinstance(deferred, list)
        self.assertEqual(len(deferred), 2)
        for item in deferred:
            self.assertEqual(item["state"], "DEFERRED_API_TIMEOUT")
            self.assertTrue(item["counted_for_discovery"])
            self.assertFalse(item["security_admitted"])

    def test_no_library_or_execution_claims(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        for flag in (
            "certification_asserted",
            "functional_or_contract_fit_asserted",
            "library_accessed",
            "library_write_attempted",
            "executed_untrusted_code",
        ):
            self.assertFalse(live[flag])


if __name__ == "__main__":
    unittest.main()
