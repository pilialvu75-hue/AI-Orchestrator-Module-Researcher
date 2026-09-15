from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.background_execution"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformBackgroundExecutionProofTest(unittest.TestCase):
    def test_need_is_staged_and_contract_is_draft(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(comparison["need_source"], "catalog/needs.platform-extension.json")
        self.assertEqual(comparison["need_status"], "needed")
        self.assertEqual(comparison["need_authority"], "staged_not_authoritative")
        self.assertEqual(comparison["priority"], "high")
        self.assertEqual(comparison["desired_candidates_per_target"], 2)
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "platform.background_execution.v1")
        self.assertEqual(contract["status"], "draft")
        self.assertTrue(contract["detail_gap"])

    def test_required_targets_have_two_research_candidates(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(
            set(comparison["required_targets"]),
            {"android", "windows", "linux", "macos", "ios", "raspberry_pi"},
        )
        coverage = comparison["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        for target in comparison["required_targets"]:
            self.assertGreaterEqual(coverage[target], 2)
        self.assertTrue(comparison["per_target_candidate_depth_satisfied"])
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertEqual(decision["coverage_blockers"], [])
        self.assertTrue(decision["discovery_depth_closed"])
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])

    def test_mobile_and_service_semantics_are_not_collapsed(self) -> None:
        comparison = _load("comparison.json")
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertIn(
            "not treated as semantically interchangeable",
            contract["non_equivalence_policy"],
        )
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["composite_strategy_required"])
        self.assertIsNone(decision["single_winner"])

    def test_raspberry_pi_uses_two_systemd_families_but_is_not_runtime_certified(self) -> None:
        comparison = _load("comparison.json")
        candidates = comparison["candidates"]
        assert isinstance(candidates, list)
        pi = {
            str(item["id"]): item
            for item in candidates
            if "raspberry_pi" in item["research_targets"]
        }
        self.assertEqual(
            set(pi),
            {"OmnyGrid/dart_service_manager", "kardianos/service"},
        )
        for item in pi.values():
            self.assertIn("official Raspberry Pi", item["raspberry_pi_evidence"])
            self.assertFalse(item["runtime_validated"])

    def test_blocked_pi_alternatives_do_not_count(self) -> None:
        alternatives = _load("researched-alternatives.json")
        items = alternatives["alternatives"]
        assert isinstance(items, list)
        by_id = {str(item["id"]): item for item in items}
        self.assertEqual(by_id["runwisp/runwisp"]["state"], "BLOCKED")
        self.assertFalse(by_id["runwisp/runwisp"]["counted"])
        self.assertEqual(
            by_id["chipsenkbeil/service-manager-rs"]["state"],
            "BLOCKED",
        )
        self.assertFalse(by_id["chipsenkbeil/service-manager-rs"]["counted"])

    def test_live_preflights_preserve_fail_closed_security(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        for flag in (
            "certification_asserted",
            "functional_or_contract_fit_asserted",
            "library_accessed",
            "library_write_attempted",
            "executed_untrusted_code",
        ):
            self.assertFalse(live[flag])

        results = live["results"]
        assert isinstance(results, list)
        self.assertEqual(len(results), 8)
        by_repo = {str(item["repository"]): item for item in results}

        auto = by_repo["seena98/auto_start_flutter"]
        self.assertEqual(auto["state"], "CLEAR")
        self.assertTrue(auto["security_preflight_clear"])
        self.assertEqual(auto["vulnerability"]["verdict"], "CLEAR")
        self.assertTrue(auto["vulnerability"]["database_checked"])
        self.assertEqual(auto["vulnerability"]["hits"], [])

        kardianos = by_repo["kardianos/service"]
        self.assertEqual(kardianos["state"], "REVIEW")
        self.assertEqual(kardianos["source"]["verdict"], "CLEAR")
        self.assertTrue(kardianos["vulnerability"]["database_checked"])
        hits = kardianos["vulnerability"]["hits"]
        assert isinstance(hits, list)
        self.assertEqual({hit["id"] for hit in hits}, {"GO-2026-5024"})

        self.assertEqual(by_repo["runwisp/runwisp"]["state"], "BLOCKED")
        self.assertEqual(
            by_repo["chipsenkbeil/service-manager-rs"]["state"],
            "BLOCKED",
        )

    def test_pub_candidates_do_not_claim_osv_clear_without_exact_versions(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        results = live["results"]
        assert isinstance(results, list)
        by_repo = {str(item["repository"]): item for item in results}
        for repo in (
            "fluttercommunity/flutter_workmanager",
            "OmnyGrid/dart_service_manager",
        ):
            result = by_repo[repo]
            self.assertEqual(result["state"], "REVIEW")
            self.assertEqual(result["source"]["verdict"], "CLEAR")
            self.assertEqual(result["supply_chain"]["verdict"], "CLEAR")
            self.assertFalse(result["vulnerability"]["database_checked"])
            self.assertGreater(len(result["vulnerability"]["unresolved"]), 0)


if __name__ == "__main__":
    unittest.main()
