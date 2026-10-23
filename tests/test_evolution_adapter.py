from __future__ import annotations

import unittest

from researcher.evolution import EvolutionWorkItem, EvolutionWorker
from researcher.evolution_adapter import EvolutionAdapter


def _work() -> EvolutionWorkItem:
    return EvolutionWorkItem(
        proposal_id="proposal-1",
        capability_id="ai.acceleration_backend",
        knowledge_delta=("practice:ci_present",),
        acceptance_gates=(
            "implementation_tests_pass",
            "security_gates_pass",
            "regression_tests_pass",
            "library_contract_pass",
        ),
    )


def _passing_gates() -> dict[str, bool]:
    return {
        "implementation_tests_pass": True,
        "security_gates_pass": True,
        "regression_tests_pass": True,
        "library_contract_pass": True,
    }


class EvolutionAdapterTests(unittest.TestCase):
    def test_adapter_accepts_only_complete_passing_evidence(self) -> None:
        result = EvolutionAdapter().validate_result(
            _work(),
            candidate_ref="artifact://candidate/proposal-1",
            gate_results=_passing_gates(),
        )
        payload = result.as_dict()
        self.assertEqual(payload["output_type"], "validated_candidate_module")
        self.assertTrue(payload["accepted"])
        self.assertEqual(
            payload["mutation_policy"],
            "isolated_candidate_no_library_mutation",
        )
        self.assertTrue(all(payload["evidence"].values()))

    def test_adapter_preserves_failed_gate_as_not_accepted(self) -> None:
        gates = _passing_gates()
        gates["security_gates_pass"] = False
        result = EvolutionAdapter().validate_result(
            _work(),
            candidate_ref="artifact://candidate/proposal-1",
            gate_results=gates,
        )
        self.assertFalse(result.evidence.accepted)
        self.assertFalse(result.as_dict()["evidence"]["security_gates_pass"])

    def test_adapter_rejects_incomplete_evidence(self) -> None:
        gates = _passing_gates()
        del gates["library_contract_pass"]
        with self.assertRaisesRegex(ValueError, "Missing acceptance gate evidence"):
            EvolutionAdapter().validate_result(
                _work(),
                candidate_ref="artifact://candidate/proposal-1",
                gate_results=gates,
            )

    def test_builder_request_is_isolated_and_not_publishable(self) -> None:
        request = EvolutionWorker.prepare_builder_request(None, _work())
        self.assertEqual(request["execution_boundary"], "isolated_builder")
        self.assertFalse(request["library_publish_allowed"])
        self.assertEqual(request["proposal_id"], "proposal-1")
        self.assertIn("candidate_ref", request["required_manifest_fields"])

    def test_builder_manifest_is_not_self_certifying(self) -> None:
        manifest = {
            "proposal_id": "proposal-1",
            "capability_id": "ai.acceleration_backend",
            "candidate_ref": "artifact://candidate/proposal-1",
            "accepted": True,
        }
        result = EvolutionAdapter().validate_build_manifest(_work(), manifest)
        self.assertFalse(result.evidence.accepted)
        self.assertFalse(any(result.evidence.as_dict().values()))
        with self.assertRaisesRegex(ValueError, "proposal_id"):
            EvolutionAdapter().validate_build_manifest(
                _work(), {**manifest, "proposal_id": "other"},
            )
        with self.assertRaisesRegex(ValueError, "candidate_ref"):
            EvolutionAdapter().validate_build_manifest(
                _work(), {**manifest, "candidate_ref": None},
            )

    def test_adapter_rejects_unverified_gate_values(self) -> None:
        gates = _passing_gates()
        gates["security_gates_pass"] = "true"
        with self.assertRaisesRegex(ValueError, "must be boolean"):
            EvolutionAdapter().validate_result(
                _work(),
                candidate_ref="artifact://candidate/proposal-1",
                gate_results=gates,
            )

    def test_adapter_rejects_empty_candidate_reference(self) -> None:
        with self.assertRaisesRegex(ValueError, "candidate_ref is required"):
            EvolutionAdapter().validate_result(
                _work(),
                candidate_ref=" ",
                gate_results=_passing_gates(),
            )


if __name__ == "__main__":
    unittest.main()
