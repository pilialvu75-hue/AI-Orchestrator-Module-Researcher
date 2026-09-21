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
