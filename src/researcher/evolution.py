from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .state import SQLiteStateStore


@dataclass(frozen=True)
class EvolutionWorkItem:
    proposal_id: str
    capability_id: str
    knowledge_delta: tuple[str, ...]
    acceptance_gates: tuple[str, ...]
    mutation_policy: str = "isolated_candidate_no_library_mutation"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "work_type": "module_evolution",
            "proposal_id": self.proposal_id,
            "capability_id": self.capability_id,
            "knowledge_delta": self.knowledge_delta,
            "acceptance_gates": self.acceptance_gates,
            "mutation_policy": self.mutation_policy,
            "required_output": "validated_candidate_module",
        }


class EvolutionWorker:
    """Consumes research deltas without ever mutating the stable Library directly."""

    def __init__(self, state: SQLiteStateStore) -> None:
        self.state = state

    def claim_next(self) -> EvolutionWorkItem | None:
        request = self.state.claim_improvement_proposal()
        if request is None:
            return None
        return EvolutionWorkItem(
            proposal_id=str(request["proposal_id"]),
            capability_id=str(request["capability_id"]),
            knowledge_delta=tuple(request["knowledge_delta"]),
            acceptance_gates=tuple(request["acceptance_gates"]),
        )

    def begin_validation(self, proposal_id: str) -> bool:
        return self.state.transition_improvement_proposal(
            proposal_id,
            expected_state="QUEUED",
            new_state="VALIDATING",
        )

    def complete_validation(self, proposal_id: str, *, accepted: bool) -> bool:
        return self.state.transition_improvement_proposal(
            proposal_id,
            expected_state="VALIDATING",
            new_state="ACCEPTED" if accepted else "REJECTED",
        )
