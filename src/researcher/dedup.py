from __future__ import annotations

import hashlib

from .models import Candidate


def candidate_fingerprint(capability_id: str, candidate: Candidate) -> str:
    parts = [
        candidate.provider.lower(),
        candidate.repository.lower(),
        candidate.commit_sha.lower(),
        capability_id.lower(),
    ]
    component_path = str(candidate.extra.get("component_path") or "").strip().lower()
    if component_path:
        parts.append(component_path)
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
