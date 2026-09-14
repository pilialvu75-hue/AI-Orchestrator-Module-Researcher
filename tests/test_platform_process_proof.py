from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.process"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformProcessProofTest(unittest.TestCase):
    def test_need_is_staged_and_contract_is_draft(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(
            comparison["need_source"],
            "catalog/needs.platform-extension.json",
        )
        self.assertEqual(comparison["need_status"], "needed")
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "platform.process.v1")
        self.assertEqual(contract["status"], "draft")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])

    def test_two_independent_candidates_are_retained(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(comparison["desired_candidates"], 2)
        self.assertEqual(
            set(comparison["required_targets"]),
            {"windows", "linux", "macos", "raspberry_pi"},
        )
        candidates = comparison["candidates"]
        assert isinstance(candidates, list)
        self.assertEqual(len(candidates), 2)
        ids = {str(item["id"]) for item in candidates}
        self.assertEqual(
            ids,
            {
                "dart-lang/tools:pkgs/process",
                "tekartik/process_run.dart:packages/process_run",
            },
        )

    def test_expected_process_execution_stays_review_required(self) -> None:
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
            security = result["security"]
            assert isinstance(security, dict)
            self.assertEqual(security["verdict"], "REVIEW")
            self.assertTrue(security["complete"])
            self.assertFalse(security["admission_eligible"])
            findings = security["findings"]
            assert isinstance(findings, list)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule_id"], "process_execution")
            self.assertEqual(findings[0]["severity"], "HIGH")

            supply = result["supply_chain"]
            assert isinstance(supply, dict)
            self.assertEqual(supply["verdict"], "CLEAR")

            vulnerability = result["vulnerability"]
            assert isinstance(vulnerability, dict)
            self.assertEqual(vulnerability["verdict"], "NOT_ANALYZED")
            self.assertFalse(vulnerability["database_checked"])

    def test_process_run_does_not_invent_release_tag(self) -> None:
        dossier = _load("tekartik-process-run.dossier.json")
        candidate = dossier["candidate"]
        assert isinstance(candidate, dict)
        self.assertIsNone(candidate["release_tag"])
        evidence = dossier["evidence"]
        assert isinstance(evidence, dict)
        self.assertFalse(evidence["release_tag_verified"])
        self.assertTrue(evidence["source_version_verified_from_pinned_manifest"])

    def test_security_policy_gaps_remain_explicit(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        decision = live["decision"]
        assert isinstance(decision, dict)
        gaps = set(decision["contract_gaps"])
        self.assertIn("whether shell invocation is permitted", gaps)
        self.assertIn("process-tree cancellation and kill semantics", gaps)
        self.assertIn("privilege boundary and platform-specific restrictions", gaps)


if __name__ == "__main__":
    unittest.main()
