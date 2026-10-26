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

    @staticmethod
    def prepare_builder_request(work: EvolutionWorkItem) -> dict[str, Any]:
        """Prepare an isolated build request, never a Library publication."""
        if not work.proposal_id or not work.capability_id:
            raise ValueError("Evolution proposal and capability are required")
        request = work.as_dict()
        request["execution_boundary"] = "isolated_builder"
        request["library_publish_allowed"] = False
        request["required_manifest_fields"] = [
            "proposal_id",
            "capability_id",
            "candidate_ref",
        ]
        return request

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

    def complete_candidate(self, candidate: Any) -> bool:
        """Finalize only an adapter-validated candidate bound to this proposal.

        Import is local to keep the state machine independent from adapter
        construction while still enforcing the concrete validated output type.
        """
        from .evolution_adapter import ValidatedCandidateModule

        if not isinstance(candidate, ValidatedCandidateModule):
            raise TypeError("ValidatedCandidateModule is required")
        if (
            not candidate.proposal_id
            or not candidate.capability_id
            or not isinstance(candidate.candidate_ref, str)
            or not candidate.candidate_ref.strip()
            or candidate.mutation_policy != "isolated_candidate_no_library_mutation"
        ):
            raise ValueError("Candidate identity, reference, or mutation boundary invalid")
        from .evolution_adapter import EvolutionGateEvidence

        evidence = candidate.evidence
        if not isinstance(evidence, EvolutionGateEvidence) or any(
            type(value) is not bool for value in evidence.as_dict().values()
        ):
            raise ValueError("Candidate requires explicit boolean gate evidence")
        return self.complete_validation(
            candidate.proposal_id,
            accepted=candidate.evidence.accepted,
        )
