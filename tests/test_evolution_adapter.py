from __future__ import annotations

import pytest

from researcher.evolution import EvolutionWorkItem
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


def test_adapter_accepts_only_complete_passing_evidence() -> None:
    result = EvolutionAdapter().validate_result(
        _work(),
        candidate_ref="artifact://candidate/proposal-1",
        gate_results=_passing_gates(),
    )

    payload = result.as_dict()
    assert payload["output_type"] == "validated_candidate_module"
    assert payload["accepted"] is True
    assert payload["mutation_policy"] == "isolated_candidate_no_library_mutation"
    assert all(payload["evidence"].values())


def test_adapter_preserves_failed_gate_as_not_accepted() -> None:
    gates = _passing_gates()
    gates["security_gates_pass"] = False

    result = EvolutionAdapter().validate_result(
        _work(),
        candidate_ref="artifact://candidate/proposal-1",
        gate_results=gates,
    )

    assert result.evidence.accepted is False
    assert result.as_dict()["evidence"]["security_gates_pass"] is False


def test_adapter_rejects_incomplete_evidence() -> None:
    gates = _passing_gates()
    del gates["library_contract_pass"]

    with pytest.raises(ValueError, match="Missing acceptance gate evidence"):
        EvolutionAdapter().validate_result(
            _work(),
            candidate_ref="artifact://candidate/proposal-1",
            gate_results=gates,
        )


def test_adapter_rejects_empty_candidate_reference() -> None:
    with pytest.raises(ValueError, match="candidate_ref is required"):
        EvolutionAdapter().validate_result(
            _work(),
            candidate_ref=" ",
            gate_results=_passing_gates(),
        )
