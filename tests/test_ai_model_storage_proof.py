from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "ai.model_storage"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class AiModelStorageProofTest(unittest.TestCase):
    def test_staged_need_and_draft_contract(self) -> None:
        data = _load("comparison.json")
        self.assertEqual(data["need_status"], "needed")
        self.assertEqual(data["need_authority"], "staged_not_authoritative")
        self.assertEqual(data["desired_candidates_per_target"], 2)
        contract = data["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "ai.model_storage.v1")
        self.assertEqual(contract["status"], "draft")
        self.assertTrue(contract["detail_gap"])

    def test_two_candidates_per_required_target(self) -> None:
        data = _load("comparison.json")
        required = {
            "android",
            "windows",
            "linux",
            "macos",
            "ios",
            "raspberry_pi",
        }
        self.assertEqual(set(data["required_targets"]), required)
        coverage = data["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        self.assertTrue(all(coverage[target] >= 2 for target in required))
        self.assertTrue(data["per_target_candidate_depth_satisfied"])

    def test_raspberry_pi_pair_is_linux_research_only(self) -> None:
        data = _load("comparison.json")
        pairs = data["independent_candidate_pairs"]
        assert isinstance(pairs, dict)
        self.assertEqual(
            pairs["raspberry_pi"],
            ["whuppi/cellar", "NathanKolbas/huggingface_hub_dart"],
        )
        candidates = data["candidates"]
        assert isinstance(candidates, list)
        by_id = {str(item["id"]): item for item in candidates}
        for candidate_id in pairs["raspberry_pi"]:
            candidate = by_id[candidate_id]
            self.assertFalse(candidate["raspberry_pi_validated"])

    def test_discovery_closes_without_integration_or_certification(self) -> None:
        data = _load("comparison.json")
        decision = data["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["discovery_depth_closed"])
        self.assertTrue(decision["composite_strategy_required"])
        self.assertIsNone(decision["single_winner"])
        for key in (
            "security_admission_closed",
            "contract_conformance_closed",
            "runtime_validation_closed",
            "integrity_policy_validation_closed",
            "migration_validation_closed",
            "quota_and_disk_pressure_validation_closed",
            "background_transfer_policy_closed",
            "raspberry_pi_hardware_validation_closed",
            "submission_ready",
            "runtime_certified",
            "certification_asserted",
            "library_write_attempted",
        ):
            self.assertFalse(decision[key])

    def test_live_states_preserve_clear_and_review(self) -> None:
        live = _load("live-security-preflights-2026-09-17.json")
        results = live["results"]
        assert isinstance(results, list)
        by_repo = {str(item["repository"]): item for item in results}
        self.assertEqual(by_repo["whuppi/cellar"]["state"], "CLEAR")
        self.assertEqual(
            by_repo["NathanKolbas/huggingface_hub_dart"]["state"],
            "REVIEW",
        )
        self.assertEqual(
            by_repo["landxcape/resumable_downloader"]["state"],
            "REVIEW",
        )

    def test_cellar_clear_includes_osv(self) -> None:
        live = _load("live-security-preflights-2026-09-17.json")
        results = live["results"]
        assert isinstance(results, list)
        cellar = next(item for item in results if item["repository"] == "whuppi/cellar")
        vulnerability = cellar["vulnerability"]
        assert isinstance(vulnerability, dict)
        self.assertEqual(vulnerability["verdict"], "CLEAR")
        self.assertTrue(vulnerability["database_checked"])
        self.assertEqual(vulnerability["hits"], [])
        self.assertEqual(vulnerability["queried_components"], 49)

    def test_review_reasons_are_not_erased(self) -> None:
        live = _load("live-security-preflights-2026-09-17.json")
        results = live["results"]
        assert isinstance(results, list)
        by_repo = {str(item["repository"]): item for item in results}
        hf_security = by_repo["NathanKolbas/huggingface_hub_dart"]["security"]
        resumable_vuln = by_repo["landxcape/resumable_downloader"]["vulnerability"]
        assert isinstance(hf_security, dict)
        assert isinstance(resumable_vuln, dict)
        self.assertIn("secret_environment_access", hf_security["finding_rule_ids"])
        self.assertEqual(resumable_vuln["verdict"], "REVIEW")
        self.assertGreater(len(resumable_vuln["unresolved"]), 0)

    def test_no_live_result_executes_writes_or_certifies(self) -> None:
        live = _load("live-security-preflights-2026-09-17.json")
        self.assertFalse(live["library_accessed"])
        self.assertFalse(live["library_write_attempted"])
        self.assertFalse(live["executed_untrusted_code"])
        self.assertFalse(live["certification_asserted"])
        results = live["results"]
        assert isinstance(results, list)
        for item in results:
            self.assertFalse(item["library_write_attempted"])
            self.assertFalse(item["executed_untrusted_code"])
            self.assertFalse(item["certification_asserted"])


if __name__ == "__main__":
    unittest.main()
