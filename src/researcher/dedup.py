from __future__ import annotations

import hashlib

from .models import Candidate


def candidate_fingerprint(capability_id: str, candidate: Candidate) -> str:
    raw = "|".join(
        (
            candidate.provider.lower(),
            candidate.repository.lower(),
            candidate.commit_sha.lower(),
            capability_id.lower(),
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
