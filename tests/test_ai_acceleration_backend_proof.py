from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "ai.acceleration_backend"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class AiAccelerationBackendProofTest(unittest.TestCase):
    def test_staged_need_and_draft_contract(self) -> None:
        data = _load("comparison.json")
        self.assertEqual(data["need_status"], "needed")
        self.assertEqual(data["need_authority"], "staged_not_authoritative")
        self.assertEqual(data["desired_candidates_per_target"], 2)
        contract = data["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "ai.acceleration_backend.v1")
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
            "web",
            "raspberry_pi",
        }
        self.assertEqual(set(data["required_targets"]), required)
        coverage = data["per_target_candidate_coverage"]
        assert isinstance(coverage, dict)
        self.assertTrue(all(coverage[target] >= 2 for target in required))
        self.assertTrue(data["per_target_candidate_depth_satisfied"])

    def test_native_and_web_pairs_are_explicit(self) -> None:
        data = _load("comparison.json")
        pairs = data["independent_candidate_pairs"]
        assert isinstance(pairs, dict)
        native = ["ggml-org/llama.cpp", "microsoft/onnxruntime"]
        for target in (
            "android",
            "windows",
            "linux",
            "macos",
            "ios",
            "raspberry_pi",
        ):
            self.assertEqual(pairs[target], native)
        self.assertEqual(
            pairs["web"],
            ["microsoft/onnxruntime", "ngxson/wllama"],
        )

    def test_discovery_closes_without_admission_or_certification(self) -> None:
        data = _load("comparison.json")
        decision = data["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["discovery_depth_closed"])
        for key in (
            "security_admission_closed",
            "contract_conformance_closed",
            "runtime_validation_closed",
            "backend_probe_contract_closed",
            "model_compatibility_validation_closed",
            "target_hardware_validation_closed",
            "raspberry_pi_hardware_validation_closed",
            "web_browser_validation_closed",
            "submission_ready",
            "runtime_certified",
            "certification_asserted",
            "library_write_attempted",
        ):
            self.assertFalse(decision[key])

    def test_full_repo_verdicts_are_preserved(self) -> None:
        live = _load("live-security-preflights-2026-09-16.json")
        results = live["results"]
        assert isinstance(results, list)
        full = {
            str(item["repository"]): item
            for item in results
            if item["scope"] == "full_repository"
        }
        self.assertEqual(full["ggml-org/llama.cpp"]["state"], "BLOCKED")
        self.assertEqual(full["microsoft/onnxruntime"]["state"], "REVIEW")
        self.assertEqual(full["ngxson/wllama"]["state"], "REVIEW")
        for item in full.values():
            self.assertFalse(item["security_preflight_clear"])

    def test_scoped_scans_stay_review_and_not_admitted(self) -> None:
        live = _load("live-security-preflights-2026-09-16.json")
        results = live["results"]
        assert isinstance(results, list)
        scoped = {
            str(item["repository"]): item
            for item in results
            if item["scope"] != "full_repository"
        }
        llama = scoped["ggml-org/llama.cpp"]
        onnx = scoped["microsoft/onnxruntime"]
        self.assertEqual(llama["state"], "REVIEW")
        self.assertEqual(onnx["state"], "REVIEW")
        llama_security = llama["security"]
        onnx_security = onnx["security"]
        assert isinstance(llama_security, dict)
        assert isinstance(onnx_security, dict)
        self.assertTrue(llama_security["complete"])
        self.assertFalse(onnx_security["complete"])
        self.assertFalse(llama_security["admission_eligible"])
        self.assertFalse(onnx_security["admission_eligible"])

    def test_scoped_findings_keep_scan_limit_and_process_risk(self) -> None:
        live = _load("live-security-preflights-2026-09-16.json")
        results = live["results"]
        assert isinstance(results, list)
        scoped = {
            str(item["repository"]): item
            for item in results
            if item["scope"] != "full_repository"
        }
        llama_security = scoped["ggml-org/llama.cpp"]["security"]
        onnx_security = scoped["microsoft/onnxruntime"]["security"]
        assert isinstance(llama_security, dict)
        assert isinstance(onnx_security, dict)
        llama_rules = set(llama_security["finding_rule_ids"])
        onnx_rules = set(onnx_security["finding_rule_ids"])
        self.assertIn("process_execution", llama_rules)
        self.assertIn("scan_file_budget_exceeded", onnx_rules)

    def test_no_live_result_writes_or_certifies(self) -> None:
        live = _load("live-security-preflights-2026-09-16.json")
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
