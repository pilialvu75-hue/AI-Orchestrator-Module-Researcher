from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.permissions"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformPermissionsProofTest(unittest.TestCase):
    def test_need_is_staged_and_contract_is_draft(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(
            comparison["need_source"],
            "catalog/needs.platform-extension.json",
        )
        self.assertEqual(comparison["need_status"], "needed")
        self.assertEqual(comparison["priority"], "high")
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "platform.permissions.v1")
        self.assertEqual(contract["status"], "draft")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])

    def test_required_targets_are_not_collapsed(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(
            set(comparison["required_targets"]),
            {"android", "windows", "linux", "macos", "ios", "web"},
        )
        candidates = comparison["candidates"]
        assert isinstance(candidates, list)
        self.assertEqual(len(candidates), 2)

        by_id = {str(item["id"]): item for item in candidates}
        baseflow = by_id["Baseflow/flutter-permission-handler:permission_handler"]
        device = by_id["arcas0803/device_permission"]
        self.assertEqual(
            set(baseflow["missing_required_target_declarations"]),
            {"linux", "macos"},
        )
        self.assertEqual(device["missing_required_target_declarations"], [])

    def test_static_clear_does_not_bypass_vulnerability_review(self) -> None:
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

            supply = result["supply_chain"]
            assert isinstance(supply, dict)
            self.assertEqual(supply["verdict"], "CLEAR")
            self.assertTrue(supply["admission_eligible"])

            vulnerability = result["vulnerability"]
            assert isinstance(vulnerability, dict)
            self.assertEqual(vulnerability["verdict"], "REVIEW")
            self.assertFalse(vulnerability["database_checked"])
            self.assertFalse(vulnerability["admission_eligible"])
            self.assertEqual(vulnerability["queried_components"], 0)
            self.assertTrue(vulnerability["unresolved"])

    def test_license_provenance_mismatch_is_preserved(self) -> None:
        dossier = _load("arcas-device-permission.dossier.json")
        candidate = dossier["candidate"]
        assert isinstance(candidate, dict)
        self.assertIsNone(candidate["license_spdx"])
        self.assertEqual(candidate["upstream_license_file"], "MIT")
        security = dossier["security"]
        assert isinstance(security, dict)
        self.assertFalse(security["certification_eligible"])

    def test_two_candidate_independence_is_not_overstated(self) -> None:
        comparison = _load("comparison.json")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["two_candidate_independence_satisfied"])
        self.assertIsNone(decision["single_winner"])

    def test_runtime_target_validation_remains_open(self) -> None:
        baseflow = _load("baseflow-permission-handler.dossier.json")
        device = _load("arcas-device-permission.dossier.json")
        for dossier in (baseflow, device):
            evidence = dossier["evidence"]
            assert isinstance(evidence, dict)
            self.assertFalse(evidence["runtime_target_validation_completed"])
            decision = dossier["decision"]
            assert isinstance(decision, dict)
            self.assertFalse(decision["submission_ready"])
            self.assertFalse(decision["certification_asserted"])


if __name__ == "__main__":
    unittest.main()
