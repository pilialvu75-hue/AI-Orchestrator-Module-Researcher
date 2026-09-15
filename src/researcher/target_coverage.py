from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable

from .models import Candidate, Dossier, Need

if TYPE_CHECKING:
    from .state import SQLiteStateStore


_SCHEMA_VERSION = 1
_KEY_PREFIX = "target_coverage:"


def _key(capability_id: str) -> str:
    return f"{_KEY_PREFIX}{capability_id}"


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        raw: Iterable[object] = (value,)
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw = value
    else:
        return ()
    values = {str(item).strip().lower() for item in raw if str(item).strip()}
    return tuple(sorted(values))


def candidate_research_targets(need: Need, candidate: Candidate) -> tuple[str, ...]:
    """Return candidate targets backed by explicit Researcher discovery evidence.

    `research_targets` is deliberately weaker than Library certification. It only
    means the candidate was researched for that target and therefore may count
    toward discovery-depth planning. The Library still requires per-target runtime
    evidence before certified support can be advertised.
    """

    required = {target.lower() for target in need.targets}
    raw = _strings(candidate.extra.get("research_targets"))
    return tuple(target for target in raw if target in required)


@dataclass(frozen=True)
class TargetCoverageSnapshot:
    desired_per_target: int
    counts: dict[str, int]
    gaps: dict[str, int]
    tracked_candidates: int

    @property
    def tracked(self) -> bool:
        return self.tracked_candidates > 0

    @property
    def complete(self) -> bool:
        return bool(self.counts) and all(gap == 0 for gap in self.gaps.values())

    @property
    def total_gap(self) -> int:
        return sum(self.gaps.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "policy": "desired_candidates_per_required_target",
            "desired_per_target": self.desired_per_target,
            "counts": dict(self.counts),
            "gaps": dict(self.gaps),
            "tracked_candidates": self.tracked_candidates,
            "tracked": self.tracked,
            "complete": self.complete,
            "certification_asserted": False,
        }


def _snapshot(need: Need, records: dict[str, tuple[str, ...]]) -> TargetCoverageSnapshot:
    desired = max(1, int(need.desired_candidates))
    counts = {target.lower(): 0 for target in need.targets}
    for targets in records.values():
        for target in set(targets):
            if target in counts:
                counts[target] += 1
    gaps = {target: max(0, desired - count) for target, count in counts.items()}
    return TargetCoverageSnapshot(
        desired_per_target=desired,
        counts=counts,
        gaps=gaps,
        tracked_candidates=len(records),
    )


def load_target_coverage(
    state: SQLiteStateStore,
    need: Need,
) -> TargetCoverageSnapshot:
    payload = state.get_json(_key(need.capability_id), {})
    if not isinstance(payload, dict) or int(payload.get("schema_version", 0) or 0) != 1:
        return _snapshot(need, {})
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, dict):
        return _snapshot(need, {})
    records: dict[str, tuple[str, ...]] = {}
    required = {target.lower() for target in need.targets}
    for fingerprint, raw_targets in raw_candidates.items():
        targets = tuple(target for target in _strings(raw_targets) if target in required)
        if targets:
            records[str(fingerprint)] = targets
    return _snapshot(need, records)


def record_target_coverage(
    state: SQLiteStateStore,
    need: Need,
    fingerprint: str,
    candidate: Candidate,
) -> TargetCoverageSnapshot:
    targets = candidate_research_targets(need, candidate)
    current = state.get_json(_key(need.capability_id), {})
    payload = (
        current
        if isinstance(current, dict) and int(current.get("schema_version", 0) or 0) == 1
        else {"schema_version": _SCHEMA_VERSION, "candidates": {}}
    )
    raw_candidates = payload.get("candidates")
    candidates = dict(raw_candidates) if isinstance(raw_candidates, dict) else {}
    if targets:
        candidates[fingerprint] = list(targets)
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "capability_id": need.capability_id,
            "desired_per_target": max(1, int(need.desired_candidates)),
            "required_targets": list(need.targets),
            "candidates": candidates,
        }
        state.set_json(_key(need.capability_id), payload)
    return load_target_coverage(state, need)


def select_for_target_gaps(
    need: Need,
    snapshot: TargetCoverageSnapshot,
    dossiers: Iterable[Dossier],
) -> list[Dossier]:
    """Greedily choose the smallest useful candidate set for current target gaps."""

    remaining = dict(snapshot.gaps)
    pending = list(dossiers)
    selected: list[Dossier] = []
    while pending and any(value > 0 for value in remaining.values()):
        ranked: list[tuple[int, float, str, Dossier, tuple[str, ...]]] = []
        for dossier in pending:
            targets = candidate_research_targets(need, dossier.candidate)
            gain = sum(1 for target in targets if remaining.get(target, 0) > 0)
            ranked.append(
                (
                    gain,
                    dossier.scores.recommendation,
                    dossier.fingerprint,
                    dossier,
                    targets,
                )
            )
        ranked.sort(key=lambda item: (-item[0], -item[1], item[2]))
        gain, _, _, chosen, targets = ranked[0]
        if gain <= 0:
            break
        selected.append(chosen)
        pending.remove(chosen)
        for target in targets:
            if remaining.get(target, 0) > 0:
                remaining[target] -= 1
    return selected
