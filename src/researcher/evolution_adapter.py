from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .evolution import EvolutionWorkItem


@dataclass(frozen=True)
class EvolutionGateEvidence:
    implementation_tests_pass: bool
    security_gates_pass: bool
    regression_tests_pass: bool
    library_contract_pass: bool

    def as_dict(self) -> dict[str, bool]:
        return {
            "implementation_tests_pass": self.implementation_tests_pass,
            "security_gates_pass": self.security_gates_pass,
            "regression_tests_pass": self.regression_tests_pass,
            "library_contract_pass": self.library_contract_pass,
        }

    @property
    def accepted(self) -> bool:
        return all(self.as_dict().values())


@dataclass(frozen=True)
class ValidatedCandidateModule:
    proposal_id: str
    capability_id: str
    candidate_ref: str
    evidence: EvolutionGateEvidence
    mutation_policy: str = "isolated_candidate_no_library_mutation"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "output_type": "validated_candidate_module",
            "proposal_id": self.proposal_id,
            "capability_id": self.capability_id,
            "candidate_ref": self.candidate_ref,
            "evidence": self.evidence.as_dict(),
            "accepted": self.evidence.accepted,
            "mutation_policy": self.mutation_policy,
        }


class EvolutionAdapter:
    """Validates an isolated implementation result against its Researcher work item.

    This class deliberately does not build source code and does not mutate the Library.
    It is the fail-closed boundary between an external/isolated implementation engine
    and the Researcher proposal state machine.
    """

    def validate_build_manifest(
        self, work: EvolutionWorkItem, manifest: Mapping[str, Any]
    ) -> ValidatedCandidateModule:
        """Receive an isolated builder artifact without accepting its own test claims."""
        if manifest.get("proposal_id") != work.proposal_id:
            raise ValueError("Builder proposal_id mismatch")
        if manifest.get("capability_id") != work.capability_id:
            raise ValueError("Builder capability_id mismatch")
        ref = manifest.get("candidate_ref")
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError("Builder candidate_ref is required")
        return self.validate_result(
            work,
            candidate_ref=ref,
            gate_results={gate: False for gate in work.acceptance_gates},
        )

    def validate_result(
        self,
        work: EvolutionWorkItem,
        *,
        candidate_ref: str,
        gate_results: Mapping[str, bool],
    ) -> ValidatedCandidateModule:
        candidate_ref = candidate_ref.strip()
        if not candidate_ref:
            raise ValueError("candidate_ref is required")

        required = tuple(work.acceptance_gates)
        missing = [gate for gate in required if gate not in gate_results]
        if missing:
            raise ValueError("Missing acceptance gate evidence: " + ", ".join(missing))

        unknown = sorted(set(gate_results) - set(required))
        if unknown:
            raise ValueError("Unexpected acceptance gate evidence: " + ", ".join(unknown))

        expected = {
            "implementation_tests_pass",
            "security_gates_pass",
            "regression_tests_pass",
            "library_contract_pass",
        }
        if set(required) != expected:
            raise ValueError("Evolution work item acceptance gates diverge from contract")

        # Refuse non-boolean evidence instead of silently treating it as a failed
        # gate; the implementation runner must report explicit verified results.
        invalid = [gate for gate in required if type(gate_results[gate]) is not bool]
        if invalid:
            raise ValueError("Acceptance gate evidence must be boolean: " + ", ".join(invalid))

        evidence = EvolutionGateEvidence(
            implementation_tests_pass=gate_results["implementation_tests_pass"] is True,
            security_gates_pass=gate_results["security_gates_pass"] is True,
            regression_tests_pass=gate_results["regression_tests_pass"] is True,
            library_contract_pass=gate_results["library_contract_pass"] is True,
        )
        return ValidatedCandidateModule(
            proposal_id=work.proposal_id,
            capability_id=work.capability_id,
            candidate_ref=candidate_ref,
            evidence=evidence,
            mutation_policy=work.mutation_policy,
        )
