from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from .discovery.base import DiscoveryProvider
from .models import Candidate, Need


_TARGET_QUERY_TERMS = {
    "android": "android mobile",
    "windows": "windows desktop",
    "linux": "linux desktop",
    "macos": "macos apple desktop",
    "ios": "apple iphone mobile",
    "web": "browser javascript web platform",
    "raspberry_pi": "raspberry linux arm",
    "desktop": "desktop windows linux macos",
}


def _normalized_targets(values: Iterable[object]) -> tuple[str, ...]:
    normalized = {
        str(value).strip().lower()
        for value in values
        if str(value).strip()
    }
    return tuple(sorted(normalized))


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
        self.last_discovery_diagnostics: dict[str, str | int] = {
            "status": "NOT_RUN",
            "targets_requested": 0,
            "queries_attempted": 0,
            "search_hits": 0,
            "unique_repository_hits": 0,
            "candidates_returned": 0,
            "rate_limited_targets": 0,
            "core_rate_limited_targets": 0,
        }

    @staticmethod
    def _candidate_key(candidate: Candidate) -> tuple[str, str, str]:
        component_path = str(candidate.extra.get("component_path") or "")
        return (candidate.repository.lower(), candidate.commit_sha.lower(), component_path)

    @staticmethod
    def _annotate(
        candidate: Candidate,
        targets: Iterable[str],
    ) -> Candidate:
        normalized = _normalized_targets(targets)
        extra = dict(candidate.extra)
        raw_existing = extra.get("research_targets", [])
        existing = (
            _normalized_targets(raw_existing)
            if isinstance(raw_existing, (list, tuple, set, frozenset))
            else ()
        )
        extra["research_targets"] = sorted(set(existing) | set(normalized))
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
            target
            for target in _normalized_targets(targets)
            if target in required
        )
        diagnostics: dict[str, str | int] = {
            "status": "RUNNING",
            "targets_requested": len(requested),
            "queries_attempted": 0,
            "search_hits": 0,
            "unique_repository_hits": 0,
            "candidates_returned": 0,
            "rate_limited_targets": 0,
            "core_rate_limited_targets": 0,
        }
        self.last_discovery_diagnostics = diagnostics
        if not requested:
            diagnostics["status"] = "NO_REQUIRED_TARGETS"
            return []

        # Search deeper than the desired depth because target-specific queries can
        # overlap heavily. The overall return cap can never be smaller than the
        # theoretical per-target depth requested by the Library need.
        per_target_limit = max(4, min(20, need.desired_candidates * 3))
        overall_limit = max(limit, need.desired_candidates * len(requested))
        merged: dict[tuple[str, str, str], Candidate] = {}

        for target in requested:
            query_terms = _TARGET_QUERY_TERMS.get(target, target.replace("_", " "))
            targeted_need = replace(
                need,
                title=f"{need.title} {query_terms}",
                targets=(target,),
            )
            target_candidates = self.base.discover(targeted_need, limit=per_target_limit)
            evidence = getattr(self.base, "last_discovery_diagnostics", {})
            if isinstance(evidence, dict):
                for metric in (
                    "queries_attempted",
                    "search_hits",
                    "unique_repository_hits",
                ):
                    value = evidence.get(metric, 0)
                    if type(value) is int and value >= 0:
                        diagnostics[metric] = int(diagnostics[metric]) + value
                if (
                    evidence.get("search_quota_exhausted", 0)
                    or evidence.get("status") == "SEARCH_RATE_LIMITED"
                ):
                    diagnostics["rate_limited_targets"] = (
                        int(diagnostics["rate_limited_targets"]) + 1
                    )
                if (
                    evidence.get("core_quota_exhausted", 0)
                    or evidence.get("status") == "CORE_RATE_LIMITED"
                ):
                    diagnostics["core_rate_limited_targets"] = (
                        int(diagnostics["core_rate_limited_targets"]) + 1
                    )
            for candidate in target_candidates:
                key = self._candidate_key(candidate)
                annotated = self._annotate(candidate, (target,))
                previous = merged.get(key)
                if previous is None:
                    merged[key] = annotated
                    continue
                raw_previous = previous.extra.get("research_targets", [])
                previous_targets = (
                    _normalized_targets(raw_previous)
                    if isinstance(raw_previous, (list, tuple, set, frozenset))
                    else ()
                )
                merged[key] = self._annotate(annotated, previous_targets)

        ranked = sorted(
            merged.values(),
            key=lambda candidate: (
                -len(candidate.extra.get("research_targets", [])),
                -candidate.stars,
                candidate.repository.lower(),
            ),
        )
        output = ranked[:overall_limit]
        diagnostics["candidates_returned"] = len(output)
        if output:
            diagnostics["status"] = "CANDIDATES_FOUND"
        elif diagnostics["core_rate_limited_targets"]:
            diagnostics["status"] = "CORE_RATE_LIMITED"
        elif diagnostics["rate_limited_targets"]:
            diagnostics["status"] = "SEARCH_RATE_LIMITED"
        elif diagnostics["search_hits"]:
            diagnostics["status"] = "SEARCH_HITS_UNRESOLVED"
        else:
            diagnostics["status"] = "NO_SEARCH_HITS"
        return output
