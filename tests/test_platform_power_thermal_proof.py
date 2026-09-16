from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.power_thermal"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformPowerThermalProofTest(unittest.TestCase):
    def test_staged_need_and_draft_contract(self) -> None:
        data = _load("comparison.json")
        self.assertEqual(data["need_status"], "needed")
        self.assertEqual(data["need_authority"], "staged_not_authoritative")
        self.assertEqual(data["desired_candidates_per_target"], 2)
        contract = data["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "platform.power_thermal.v1")
        self.assertEqual(contract["status"], "draft")
        self.assertTrue(contract["detail_gap"])

    def test_two_candidates_per_required_target(self) -> None:
        data = _load("comparison.json")
        required = {
            "android", "windows", "linux", "macos",
            "ios", "web", "raspberry_pi",
        }
        self.assertEqual(set(data["required_targets"]), required)
        coverage = data["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        self.assertTrue(all(coverage[target] >= 2 for target in required))
        self.assertTrue(data["per_target_candidate_depth_satisfied"])

    def test_pairs_keep_distinct_signal_families(self) -> None:
        data = _load("comparison.json")
        pairs = data["independent_signal_pairs"]
        assert isinstance(pairs, dict)
        self.assertEqual(
            pairs["windows"],
            [
                "fluttercommunity/battery_plus",
                "LibreHardwareMonitor/LibreHardwareMonitor",
            ],
        )
        self.assertEqual(
            pairs["raspberry_pi"],
            ["lm-sensors/lm-sensors", "raspberrypi/utils-vcgencmd"],
        )
        contract = data["contract"]
        assert isinstance(contract, dict)
        self.assertIn(
            "not semantically interchangeable",
            contract["non_equivalence_policy"],
        )

    def test_discovery_is_closed_but_admission_is_not(self) -> None:
        data = _load("comparison.json")
        decision = data["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["discovery_depth_closed"])
        for key in (
            "security_admission_closed",
            "contract_conformance_closed",
            "runtime_validation_closed",
            "submission_ready",
            "runtime_certified",
            "certification_asserted",
            "library_write_attempted",
        ):
            self.assertFalse(decision[key])

    def test_live_states_preserve_clear_review_and_blocked(self) -> None:
        live = _load("live-security-preflights-2026-09-16.json")
        results = live["results"]
        assert isinstance(results, list)
        states = {str(item["repository"]): item["state"] for item in results}
        self.assertEqual(states["muxable/flutter_thermal"], "CLEAR")
        self.assertEqual(states["fluttercommunity/plus_plugins"], "REVIEW")
        self.assertEqual(
            states["LibreHardwareMonitor/LibreHardwareMonitor"],
            "BLOCKED",
        )
        self.assertEqual(states["lm-sensors/lm-sensors"], "REVIEW")
        self.assertEqual(states["exelban/stats"], "REVIEW")
        self.assertEqual(states["raspberrypi/utils"], "REVIEW")
        self.assertEqual(states["jodinathan/js_bindings"], "REVIEW")

    def test_blocked_and_legacy_sources_are_not_admitted(self) -> None:
        live = _load("live-security-preflights-2026-09-16.json")
        results = live["results"]
        assert isinstance(results, list)
        blocked = next(
            item for item in results
            if item["repository"] == "LibreHardwareMonitor/LibreHardwareMonitor"
        )
        source = blocked["source"]
        assert isinstance(source, dict)
        self.assertEqual(source["verdict"], "BLOCK")
        self.assertFalse(blocked["security_preflight_clear"])

        data = _load("comparison.json")
        candidates = data["candidates"]
        assert isinstance(candidates, list)
        web = next(
            item for item in candidates
            if item["id"] == "jodinathan/js_bindings-compute-pressure"
        )
        self.assertFalse(web["security_admitted"])
        self.assertIn("discontinued", web["known_constraint"])

    def test_pi_hardware_validation_stays_open(self) -> None:
        data = _load("comparison.json")
        decision = data["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["raspberry_pi_hardware_validation_closed"])


if __name__ == "__main__":
    unittest.main()
