from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .models import Contract, Dossier, Need
from .submission import LibrarySubmissionClient
from .target_coverage import candidate_research_targets


@dataclass
class TargetScopedSubmissionClient:
    """Narrow discovered intake targets to the Researcher's target evidence.

    This does not certify a platform. It only prevents a candidate discovered for
    one target from being presented to the Library as if Researcher had researched
    every target requested by the capability.
    """

    base: LibrarySubmissionClient

    def submit(
        self,
        need: Need,
        contract: Contract,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any]:
        researched = candidate_research_targets(need, dossier.candidate)
        scoped_need = replace(need, targets=researched) if researched else need
        return self.base.submit(scoped_need, contract, standard_version, dossier)

    def resume_pending(self) -> list[dict[str, Any]]:
        resume = getattr(self.base, "resume_pending", None)
        if not callable(resume):
            return []
        value = resume()
        if not isinstance(value, list):
            raise RuntimeError("submission resume returned an invalid result")
        return [item for item in value if isinstance(item, dict)]
