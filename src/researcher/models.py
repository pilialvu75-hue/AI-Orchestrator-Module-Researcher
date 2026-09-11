from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ResearchMode(StrEnum):
    SEEDING = "SEEDING"
    MAINTENANCE = "MAINTENANCE"
    IMPROVEMENT = "IMPROVEMENT"


@dataclass(frozen=True)
class Need:
    capability_id: str
    title: str
    priority: str
    desired_candidates: int
    status: str
    targets: tuple[str, ...]
    notes: str | None = None


@dataclass(frozen=True)
class Contract:
    capability_id: str
    contract_id: str
    contract_version: str
    status: str


@dataclass(frozen=True)
class Candidate:
    provider: str
    repository: str
    upstream_url: str
    owner: str
    name: str
    commit_sha: str
    release_tag: str | None
    default_branch: str
    acquired_at: str
    license_spdx: str | None
    license_file_url: str | None
    stars: int
    forks: int
    open_issues: int
    pushed_at: str | None
    archived: bool
    language: str | None
    topics: tuple[str, ...] = ()
    description: str | None = None
    homepage: str | None = None
    size_kb: int | None = None
    has_issues: bool = True
    has_wiki: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScoreCard:
    functional_fit: float
    contract_fit: float
    maintenance: float
    security: float
    license_fit: float
    platform_fit: float
    test_quality: float
    integration_cost: float
    performance: float
    footprint: float
    documentation: float
    recommendation: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Dossier:
    schema_version: int
    capability_id: str
    candidate: Candidate
    fingerprint: str
    scores: ScoreCard
    lifecycle: str
    warnings: tuple[str, ...]
    integration_estimate: dict[str, Any]
    security_evidence: dict[str, Any]
    maintenance_evidence: dict[str, Any]
    license_evidence: dict[str, Any]
    dependency_evidence: dict[str, Any]
    benchmark_plan: dict[str, Any]
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data
