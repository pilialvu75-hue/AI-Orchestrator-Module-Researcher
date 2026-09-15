from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from .discovery.base import DiscoveryProvider
from .models import Candidate, Need


class TargetAwareDiscoveryProvider:
    """Add per-target discovery evidence without pretending it is certification.

    The wrapped provider still resolves immutable candidate provenance. This layer
    only varies the discovery query by target and records which target-specific
    searches produced each candidate. Library runtime validation remains the only
    authority for certified target support.
    """

    name = "target-aware"

    def __init__(self, base: DiscoveryProvider) -> None:
        self.base = base

    @staticmethod
    def _candidate_key(candidate: Candidate) -> tuple[str, str, str]:
        component_path = str(candidate.extra.get("component_path") or "")
        return (candidate.repository.lower(), candidate.commit_sha.lower(), component_path)

    @staticmethod
    def _annotate(
        candidate: Candidate,
        targets: Iterable[str],
    ) -> Candidate:
        normalized = sorted({str(target).strip().lower() for target in targets if str(target).strip()})
        extra = dict(candidate.extra)
        existing = {
            str(target).strip().lower()
            for target in extra.get("research_targets", [])
            if str(target).strip()
        }
        extra["research_targets"] = sorted(existing | set(normalized))
        evidence = extra.get("target_discovery_evidence")
        evidence_map = dict(evidence) if isinstance(evidence, dict) else {}
        for target in normalized:
            evidence_map[target] = "github_targeted_repository_search"
        extra["target_discovery_evidence"] = evidence_map
        extra["target_support_certified"] = False
        return replace(candidate, extra=extra)

    def discover(self, need: Need, limit: int = 8) -> list[Candidate]:
        return self.discover_for_targets(need, need.targets, limit=limit)

    def discover_for_targets(
        self,
        need: Need,
        targets: Iterable[str],
        *,
        limit: int = 8,
    ) -> list[Candidate]:
        required = {target.lower() for target in need.targets}
        requested = tuple(
            sorted(
                {
                    str(target).strip().lower()
                    for target in targets
                    if str(target).strip().lower() in required
                }
            )
        )
        if not requested:
            return []

        # Search deeper than the desired depth because target-specific queries can
        # overlap heavily. The overall return cap can never be smaller than the
        # theoretical per-target depth requested by the Library need.
        per_target_limit = max(4, min(20, need.desired_candidates * 3))
        overall_limit = max(limit, need.desired_candidates * len(requested))
        merged: dict[tuple[str, str, str], Candidate] = {}

        for target in requested:
            targeted_need = replace(
                need,
                title=f"{need.title} {target}",
                targets=(target,),
            )
            for candidate in self.base.discover(targeted_need, limit=per_target_limit):
                key = self._candidate_key(candidate)
                annotated = self._annotate(candidate, (target,))
                previous = merged.get(key)
                if previous is None:
                    merged[key] = annotated
                    continue
                previous_targets = previous.extra.get("research_targets", [])
                merged[key] = self._annotate(annotated, previous_targets)

        ranked = sorted(
            merged.values(),
            key=lambda candidate: (
                -len(candidate.extra.get("research_targets", [])),
                -candidate.stars,
                candidate.repository.lower(),
            ),
        )
        return ranked[:overall_limit]
