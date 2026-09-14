from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_CAPABILITY = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ALLOWED_LIFECYCLES = {"SCREENED", "SHORTLISTED"}


@dataclass(frozen=True)
class PinnedProof:
    capability_id: str
    contract_id: str
    repository: str
    commit_sha: str
    source_version: str | None
    release_tag: str | None
    proof_path: Path


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Pinned proof {label} must be a JSON object")
    return value


def _shortlist_recommended(raw: dict[str, Any]) -> bool:
    research = str(raw.get("research_recommendation") or "").strip().upper()
    recommendation = str(raw.get("recommendation") or "").strip().upper()
    lifecycle = str(raw.get("lifecycle") or "").strip().upper()
    return (
        research == "SHORTLIST"
        or recommendation.startswith("SHORTLIST")
        or lifecycle == "SHORTLISTED"
    )


def load_pinned_proof(path: Path, proof_root: Path) -> PinnedProof:
    """Load identity from a committed research proof without trusting its admission claims.

    Only files below the configured proof root are accepted. The returned fields identify
    the immutable upstream source; live repository metadata and every security gate are
    re-run by the operational admission path.
    """

    root = proof_root.resolve()
    resolved = path.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise ValueError("Pinned proof path must stay under the proofs directory")
    if resolved.suffix.lower() != ".json":
        raise ValueError("Pinned proof must be a JSON dossier")

    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Pinned proof is unreadable JSON") from exc
    payload = _object(raw, "root")
    if payload.get("schema_version") != 1:
        raise ValueError("Pinned proof schema_version must be 1")

    capability = _object(payload.get("capability"), "capability")
    candidate = _object(payload.get("candidate"), "candidate")
    capability_id = str(capability.get("capability_id") or "").strip()
    contract_id = str(capability.get("contract_id") or "").strip()
    repository = str(candidate.get("repository") or "").strip()
    commit_sha = str(candidate.get("commit_sha") or "").strip().lower()
    provider = str(candidate.get("provider") or "").strip().lower()
    lifecycle = str(payload.get("lifecycle") or "").strip().upper()

    if not _CAPABILITY.fullmatch(capability_id):
        raise ValueError("Pinned proof capability_id is invalid")
    if contract_id != f"{capability_id}.v1":
        raise ValueError("Pinned proof contract_id does not match capability v1 boundary")
    if provider != "github":
        raise ValueError("Pinned proof provider must be github")
    if not _REPOSITORY.fullmatch(repository):
        raise ValueError("Pinned proof repository must be owner/name")
    if not _SHA40.fullmatch(commit_sha):
        raise ValueError("Pinned proof commit_sha must be a full lowercase SHA-1")
    if lifecycle not in _ALLOWED_LIFECYCLES:
        raise ValueError("Pinned proof lifecycle is not eligible for operational admission")
    if not _shortlist_recommended(payload):
        raise ValueError("Pinned proof is not research-shortlisted")

    source_version_raw = candidate.get("source_version")
    release_tag_raw = candidate.get("source_tag")
    source_version = (
        None if source_version_raw in {None, ""} else str(source_version_raw).strip()
    )
    release_tag = None if release_tag_raw in {None, ""} else str(release_tag_raw).strip()
    if source_version is not None and len(source_version) > 128:
        raise ValueError("Pinned proof source_version is too long")
    if release_tag is not None and len(release_tag) > 128:
        raise ValueError("Pinned proof source_tag is too long")

    return PinnedProof(
        capability_id=capability_id,
        contract_id=contract_id,
        repository=repository,
        commit_sha=commit_sha,
        source_version=source_version,
        release_tag=release_tag,
        proof_path=resolved,
    )
