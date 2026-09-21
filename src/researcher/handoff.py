from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .knowledge import ImprovementProposal


@dataclass(frozen=True)
class ImplementationRequest:
    """Stable handoff contract from Researcher to an implementation engine."""

    schema_version: int
    request_type: str
    proposal_id: str
    capability_id: str
    objective: str
    knowledge_delta: tuple[str, ...]
    acceptance_gates: tuple[str, ...]
    mutation_policy: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def implementation_request(proposal: ImprovementProposal) -> ImplementationRequest:
    return ImplementationRequest(
        schema_version=1,
        request_type="library_module_improvement",
        proposal_id=proposal.proposal_id,
        capability_id=proposal.capability_id,
        objective=(
            "Evaluate and implement only the useful capability delta; preserve "
            "existing behavior unless tests justify a change."
        ),
        knowledge_delta=proposal.novelty,
        acceptance_gates=proposal.acceptance_gates,
        mutation_policy="isolated_candidate_no_library_mutation",
    )
