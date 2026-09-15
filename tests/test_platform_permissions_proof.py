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
        self.assertEqual(len(candidates), 3)

        by_id = {str(item["id"]): item for item in candidates}
        baseflow = by_id[
            "Baseflow/flutter-permission-handler:permission_handler"
        ]
        device = by_id["arcas0803/device_permission"]
        plus = by_id["jagadeeshchoudhary/permission_plus"]
        self.assertEqual(
            set(baseflow["missing_required_target_declarations"]),
            {"linux", "macos"},
        )
        self.assertEqual(device["missing_required_target_declarations"], [])
        self.assertEqual(plus["missing_required_target_declarations"], [])

    def test_per_target_research_depth_is_now_satisfied(self) -> None:
        comparison = _load("comparison.json")
        self.assertTrue(comparison["per_target_candidate_depth_satisfied"])
        coverage = comparison["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        self.assertEqual(coverage["android"], 3)
        self.assertEqual(coverage["windows"], 3)
        self.assertEqual(coverage["ios"], 3)
        self.assertEqual(coverage["web"], 3)
        self.assertEqual(coverage["linux"], 2)
        self.assertEqual(coverage["macos"], 2)
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["per_target_candidate_depth_satisfied"])
        self.assertEqual(decision["coverage_blockers"], [])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])

    def test_first_ring_stays_fail_closed(self) -> None:
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

    def test_permission_plus_backends_are_pinned_but_not_certified(self) -> None:
        dossier = _load("jagadeesh-permission-plus.dossier.json")
        backends = dossier["federated_backends"]
        assert isinstance(backends, dict)
        linux = backends["linux"]
        apple = backends["apple"]
        assert isinstance(linux, dict)
        assert isinstance(apple, dict)
        self.assertEqual(linux["source_security"], "CLEAR")
        self.assertEqual(linux["vulnerability_verdict"], "REVIEW")
        self.assertEqual(apple["source_security"], "CLEAR")
        self.assertEqual(apple["vulnerability_verdict"], "REVIEW")

        decision = dossier["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["counts_toward_research_target_depth"])
        self.assertFalse(decision["runtime_certified"])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])

    def test_depth_preflight_does_not_bypass_admission(self) -> None:
        live = _load("live-security-depth-2026-09-15.json")
        self.assertFalse(live["certification_asserted"])
        self.assertFalse(live["functional_or_contract_fit_asserted"])
        self.assertFalse(live["library_accessed"])
        self.assertFalse(live["library_write_attempted"])
        self.assertFalse(live["executed_untrusted_code"])

        results = live["results"]
        assert isinstance(results, list)
        by_id = {str(item["candidate"]): item for item in results}
        for candidate in (
            "jagadeeshchoudhary/permission_plus",
            "jagadeeshchoudhary/permission_plus_linux",
            "jagadeeshchoudhary/permission_plus_apple",
        ):
            result = by_id[candidate]
            self.assertEqual(result["source_security"], "CLEAR")
            self.assertEqual(result["supply_chain"], "CLEAR")
            self.assertEqual(result["vulnerability"], "REVIEW")
            self.assertFalse(result["vulnerability_database_checked"])

        manager = by_id["manojprajapati1999/permission_manager"]
        self.assertEqual(manager["source_security"], "REVIEW")
        self.assertEqual(manager["vulnerability"], "NOT_ANALYZED")

    def test_permission_manager_is_rejected_from_depth_counting(self) -> None:
        rejected = _load("manoj-permission-manager.rejected.json")
        decision = rejected["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["shortlisted"])
        self.assertFalse(decision["counted_toward_research_target_depth"])
        self.assertFalse(decision["submission_ready"])
        functional = rejected["functional_review"]
        assert isinstance(functional, dict)
        self.assertFalse(functional["linux_counts_as_implemented_candidate"])

    def test_license_provenance_mismatch_is_preserved(self) -> None:
        dossier = _load("arcas-device-permission.dossier.json")
        candidate = dossier["candidate"]
        assert isinstance(candidate, dict)
        self.assertIsNone(candidate["license_spdx"])
        self.assertEqual(candidate["upstream_license_file"], "MIT")
        security = dossier["security"]
        assert isinstance(security, dict)
        self.assertFalse(security["certification_eligible"])

    def test_independence_is_not_overstated(self) -> None:
        comparison = _load("comparison.json")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["two_candidate_independence_satisfied"])
        self.assertIsNone(decision["single_winner"])

    def test_runtime_target_validation_remains_open(self) -> None:
        dossiers = (
            _load("baseflow-permission-handler.dossier.json"),
            _load("arcas-device-permission.dossier.json"),
            _load("jagadeesh-permission-plus.dossier.json"),
        )
        for dossier in dossiers:
            evidence = dossier["evidence"]
            assert isinstance(evidence, dict)
            self.assertFalse(evidence["runtime_target_validation_completed"])
            decision = dossier["decision"]
            assert isinstance(decision, dict)
            self.assertFalse(decision["submission_ready"])
            self.assertFalse(decision["certification_asserted"])


if __name__ == "__main__":
    unittest.main()
