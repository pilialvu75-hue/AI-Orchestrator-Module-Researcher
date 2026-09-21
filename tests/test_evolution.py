from __future__ import annotations

from researcher.evolution import EvolutionWorker
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
