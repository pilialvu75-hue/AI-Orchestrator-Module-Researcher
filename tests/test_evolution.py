from __future__ import annotations

from researcher.evolution import EvolutionWorker
from researcher.evolution_adapter import EvolutionAdapter
from researcher.state import SQLiteStateStore


def test_evolution_worker_claims_once_and_requires_validation(tmp_path) -> None:
    state = SQLiteStateStore(tmp_path / "researcher.db")
    assert state.record_improvement_proposal(
        proposal_id="p1",
        capability_id="network.http",
        novelty=("topic:retry",),
        acceptance_gates=("implementation_tests_pass", "security_gates_pass"),
    )

    worker = EvolutionWorker(state)
    item = worker.claim_next()
    assert item is not None
    assert item.proposal_id == "p1"
    assert item.capability_id == "network.http"
    assert item.mutation_policy == "isolated_candidate_no_library_mutation"
    assert worker.claim_next() is None

    assert worker.begin_validation("p1")
    assert worker.complete_validation("p1", accepted=True)
    assert not worker.complete_validation("p1", accepted=True)


def test_invalid_transition_cannot_skip_validation(tmp_path) -> None:
    state = SQLiteStateStore(tmp_path / "researcher.db")
    assert state.record_improvement_proposal(
        proposal_id="p2",
        capability_id="voice.stt",
        novelty=("language:cpp",),
        acceptance_gates=("regression_tests_pass",),
    )
    assert not state.transition_improvement_proposal(
        "p2", expected_state="PROPOSED", new_state="ACCEPTED"
    )


def test_failed_dispatch_claim_can_be_requeued_and_reclaimed(tmp_path) -> None:
    state = SQLiteStateStore(tmp_path / "researcher.db")
    assert state.record_improvement_proposal(
        proposal_id="retry-1",
        capability_id="network.http",
        novelty=("practice:tests_present",),
        acceptance_gates=("implementation_tests_pass",),
    )
    first = state.claim_improvement_proposal()
    assert first is not None
    assert first["proposal_id"] == "retry-1"
    assert state.requeue_improvement_proposal("retry-1")
    second = state.claim_improvement_proposal()
    assert second is not None
    assert second["proposal_id"] == "retry-1"
    assert not state.requeue_improvement_proposal("missing")


def test_recover_queued_improvement_proposals_restores_library_gate(tmp_path) -> None:
    state = SQLiteStateStore(tmp_path / "researcher.db")
    for proposal_id in ("legacy-1", "legacy-2"):
        assert state.record_improvement_proposal(
            proposal_id=proposal_id,
            capability_id="ai.acceleration_backend",
            novelty=("practice:ci_present",),
            acceptance_gates=("security_gates_pass",),
        )
        claimed = state.claim_improvement_proposal()
        assert claimed is not None
        assert claimed["proposal_id"] == proposal_id

    recovered = state.recover_queued_improvement_proposals(limit=8)
    assert recovered == ["legacy-1", "legacy-2"]

    pending = state.pending_implementation_requests(limit=8)
    assert [item["proposal_id"] for item in pending] == ["legacy-1", "legacy-2"]
    assert all(item["state"] == "PROPOSED" for item in pending)
    assert state.recover_queued_improvement_proposals(limit=8) == []


def _full_gate_results(*, security: bool = True) -> dict[str, bool]:
    return {
        "implementation_tests_pass": True,
        "security_gates_pass": security,
        "regression_tests_pass": True,
        "library_contract_pass": True,
    }


def _record_full_gate_proposal(state: SQLiteStateStore, proposal_id: str) -> None:
    assert state.record_improvement_proposal(
        proposal_id=proposal_id,
        capability_id="ai.acceleration_backend",
        novelty=("practice:ci_present",),
        acceptance_gates=(
            "implementation_tests_pass",
            "security_gates_pass",
            "regression_tests_pass",
            "library_contract_pass",
        ),
    )


def test_validated_candidate_completes_as_accepted(tmp_path) -> None:
    state = SQLiteStateStore(tmp_path / "researcher.db")
    _record_full_gate_proposal(state, "candidate-pass")
    worker = EvolutionWorker(state)
    work = worker.claim_next()
    assert work is not None
    assert worker.begin_validation(work.proposal_id)

    candidate = EvolutionAdapter().validate_result(
        work,
        candidate_ref="artifact://candidate/candidate-pass",
        gate_results=_full_gate_results(),
    )
    assert worker.complete_candidate(candidate)
    assert not worker.complete_candidate(candidate)


def test_validated_candidate_with_failed_gate_completes_as_rejected(tmp_path) -> None:
    state = SQLiteStateStore(tmp_path / "researcher.db")
    _record_full_gate_proposal(state, "candidate-fail")
    worker = EvolutionWorker(state)
    work = worker.claim_next()
    assert work is not None
    assert worker.begin_validation(work.proposal_id)

    candidate = EvolutionAdapter().validate_result(
        work,
        candidate_ref="artifact://candidate/candidate-fail",
        gate_results=_full_gate_results(security=False),
    )
    assert not candidate.evidence.accepted
    assert worker.complete_candidate(candidate)
    assert not worker.complete_candidate(candidate)


def test_complete_candidate_rejects_unvalidated_payload(tmp_path) -> None:
    state = SQLiteStateStore(tmp_path / "researcher.db")
    worker = EvolutionWorker(state)
    try:
        worker.complete_candidate({"proposal_id": "forged"})
    except TypeError as error:
        assert "ValidatedCandidateModule is required" in str(error)
    else:
        raise AssertionError("unvalidated payload must fail closed")


def test_complete_candidate_rejects_invalid_boundary_and_gate_types(tmp_path) -> None:
    from researcher.evolution_adapter import EvolutionGateEvidence, ValidatedCandidateModule
    import pytest

    state = SQLiteStateStore(tmp_path / "researcher.db")
    _record_full_gate_proposal(state, "guarded")
    worker = EvolutionWorker(state)
    work = worker.claim_next()
    assert work is not None
    assert worker.begin_validation("guarded")

    for candidate in (
        ValidatedCandidateModule("guarded", "ai.acceleration_backend", "", EvolutionGateEvidence(True, True, True, True)),
        ValidatedCandidateModule("guarded", "ai.acceleration_backend", "artifact://test", EvolutionGateEvidence(True, True, True, True), mutation_policy="library_direct_write"),
        ValidatedCandidateModule("guarded", "ai.acceleration_backend", "artifact://test", EvolutionGateEvidence(1, True, True, True)),
    ):
        with pytest.raises(ValueError):
            worker.complete_candidate(candidate)

    valid = EvolutionAdapter().validate_result(work, candidate_ref="artifact://test", gate_results=_full_gate_results())
    assert worker.complete_candidate(valid)
