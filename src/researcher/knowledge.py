from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from .analysis import classify_license
from .models import Candidate, utc_now


@dataclass(frozen=True)
class ResearchSource:
    """Compact, non-code research memory for a discovered upstream source."""

    schema_version: int
    capability_id: str
    source_id: str
    repository: str
    commit_sha: str
    upstream_url: str
    direct_reuse: bool
    research_use: bool
    license_classification: str
    license_spdx: str | None
    signals: tuple[str, ...]
    observed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def research_source_id(capability_id: str, candidate: Candidate) -> str:
    raw = f"{capability_id}\n{candidate.repository}\n{candidate.commit_sha}".encode()
    return hashlib.sha256(raw).hexdigest()


def source_signals(candidate: Candidate) -> tuple[str, ...]:
    """Store useful metadata signals, never a copy of upstream source code."""
    signals: set[str] = set()
    if candidate.language:
        signals.add(f"language:{candidate.language.lower()}")
    signals.update(f"topic:{topic.lower()}" for topic in candidate.topics)
    manifests = candidate.extra.get("dependency_manifests", [])
    if isinstance(manifests, list):
        signals.update(f"manifest:{item}" for item in manifests if isinstance(item, str))
    if candidate.archived:
        signals.add("archived")
    return tuple(sorted(signals))


def research_source(capability_id: str, candidate: Candidate) -> ResearchSource:
    license_info = classify_license(candidate.license_spdx)
    return ResearchSource(
        schema_version=1,
        capability_id=capability_id,
        source_id=research_source_id(capability_id, candidate),
        repository=candidate.repository,
        commit_sha=candidate.commit_sha,
        upstream_url=candidate.upstream_url,
        direct_reuse=bool(license_info.get("direct_reuse")),
        research_use=bool(license_info.get("research_use")),
        license_classification=str(license_info["classification"]),
        license_spdx=candidate.license_spdx,
        signals=source_signals(candidate),
        observed_at=utc_now(),
    )


def novelty_delta(previous_signals: set[str], source: ResearchSource) -> tuple[str, ...]:
    """Return only knowledge signals not already present in the capability memory."""
    return tuple(sorted(set(source.signals) - previous_signals))


def compact_json(source: ResearchSource) -> str:
    return json.dumps(source.to_dict(), sort_keys=True, separators=(",", ":"))


def improvement_signal(
    knowledge: dict[str, Any],
    novelty: tuple[str, ...],
    *,
    minimum_new_signals: int = 1,
) -> dict[str, Any]:
    """Gate evolution work: no rebuild when a discovery adds no knowledge."""
    source_count = int(knowledge.get("source_count", 0))
    novelty_count = len(novelty)
    if novelty_count < minimum_new_signals:
        return {
            "action": "NO_CHANGE",
            "reason": "no_material_novelty",
            "novelty_count": novelty_count,
            "source_count": source_count,
        }
    return {
        "action": "CONSIDER_IMPROVEMENT",
        "reason": "new_capability_knowledge",
        "novelty_count": novelty_count,
        "source_count": source_count,
    }


@dataclass(frozen=True)
class ImprovementProposal:
    schema_version: int
    proposal_id: str
    capability_id: str
    action: str
    reason: str
    source_count: int
    novelty: tuple[str, ...]
    acceptance_gates: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_improvement_proposal(
    capability_id: str,
    knowledge: dict[str, Any],
    novelty: tuple[str, ...],
) -> ImprovementProposal | None:
    decision = improvement_signal(knowledge, novelty)
    if decision["action"] != "CONSIDER_IMPROVEMENT":
        return None
    fingerprint = hashlib.sha256(
        (capability_id + "\n" + "\n".join(sorted(novelty))).encode()
    ).hexdigest()
    return ImprovementProposal(
        schema_version=1,
        proposal_id=fingerprint,
        capability_id=capability_id,
        action="EVALUATE_IMPROVEMENT",
        reason=str(decision["reason"]),
        source_count=int(decision["source_count"]),
        novelty=tuple(sorted(novelty)),
        acceptance_gates=(
            "implementation_tests_pass",
            "security_gates_pass",
            "regression_tests_pass",
            "library_contract_pass",
        ),
    )
