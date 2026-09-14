from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import replace
from typing import Any

from .github_api import GitHubApi, GitHubResponse
from .models import Candidate
from .rate_limit import RateLimitManager

_MAX_LICENSE_BYTES = 512 * 1024
_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")


def _normalized(text: str) -> str:
    return " ".join(text.lower().split())


def classify_license_text(text: str) -> str | None:
    """Conservatively recognize common SPDX licenses from immutable license text.

    A file may contain bundled third-party notices after the repository's primary
    license. When more than one signature is present, the earliest recognized
    license in the file wins. Unknown or ambiguous text remains unclassified.
    """

    value = _normalized(text)
    signatures: tuple[tuple[str, tuple[str, ...]], ...] = (
        (
            "BSD-3-Clause",
            (
                "redistribution and use in source and binary forms, with or without modification",
                "neither the name of the copyright holder nor the names of its contributors",
            ),
        ),
        (
            "BSD-2-Clause",
            (
                "redistribution and use in source and binary forms, with or without modification",
                "redistributions in binary form must reproduce the above copyright notice",
            ),
        ),
        (
            "MIT",
            (
                "permission is hereby granted, free of charge, to any person obtaining a copy",
                'the software is provided "as is"',
            ),
        ),
        (
            "Apache-2.0",
            (
                "apache license version 2.0, january 2004",
                "http://www.apache.org/licenses/",
            ),
        ),
        (
            "MPL-2.0",
            (
                "mozilla public license version 2.0",
                "http://mozilla.org/mpl/2.0/",
            ),
        ),
        (
            "ISC",
            (
                "permission to use, copy, modify, and/or distribute this software for any purpose with or without fee",
                'the software is provided "as is"',
            ),
        ),
        (
            "Zlib",
            (
                "this software is provided 'as-is', without any express or implied warranty",
                "permission is granted to anyone to use this software for any purpose",
            ),
        ),
    )

    matches: list[tuple[int, int, str]] = []
    for priority, (spdx, markers) in enumerate(signatures):
        positions = [value.find(marker) for marker in markers]
        if all(position >= 0 for position in positions):
            matches.append((min(positions), priority, spdx))
    if not matches:
        return None
    matches.sort()
    return matches[0][2]


class ImmutableLicenseEvidenceResolver:
    """Fill missing SPDX metadata from the exact pinned license file only."""

    def __init__(self, api: GitHubApi, rate_limits: RateLimitManager) -> None:
        self.api = api
        self.rate_limits = rate_limits

    def _get(self, path: str) -> GitHubResponse:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            self.rate_limits.record_backoff(
                decision.retry_after_seconds,
                "immutable_license_rate_limit",
            )
            raise RuntimeError(
                f"GitHub rate limit exhausted; retry after {decision.retry_after_seconds}s"
            )
        response = self.api.get(path)
        self.rate_limits.observe_headers(response.headers)
        return response

    @staticmethod
    def _license_path(candidate: Candidate) -> str | None:
        url = candidate.license_file_url
        if not url:
            return None
        prefix = (
            f"https://github.com/{candidate.repository}/blob/"
            f"{candidate.commit_sha}/"
        )
        if not url.startswith(prefix):
            return None
        raw_path = urllib.parse.unquote(url[len(prefix) :])
        if (
            not raw_path
            or raw_path.startswith("/")
            or "\\" in raw_path
            or any(segment in {"", ".", ".."} for segment in raw_path.split("/"))
        ):
            return None
        return raw_path

    @staticmethod
    def _with_provenance(
        candidate: Candidate,
        *,
        source: str,
        path: str | None = None,
        blob_sha: str | None = None,
    ) -> Candidate:
        extra = dict(candidate.extra)
        extra["license_provenance"] = source
        if path is not None:
            extra["license_file_path"] = path
        if blob_sha is not None:
            extra["license_file_blob_sha"] = blob_sha
        return replace(candidate, extra=extra)

    def enrich(self, candidate: Candidate) -> Candidate:
        if candidate.license_spdx:
            return self._with_provenance(
                candidate,
                source="github_repository_metadata",
            )

        path = self._license_path(candidate)
        if path is None:
            return self._with_provenance(
                candidate,
                source="unresolved",
            )

        repository_path = "/".join(
            urllib.parse.quote(part, safe="")
            for part in candidate.repository.split("/", 1)
        )
        encoded_path = "/".join(
            urllib.parse.quote(part, safe="") for part in path.split("/")
        )
        ref = urllib.parse.quote(candidate.commit_sha, safe="")
        response = self._get(
            f"/repos/{repository_path}/contents/{encoded_path}?ref={ref}"
        )
        payload: dict[str, Any] = (
            response.data if isinstance(response.data, dict) else {}
        )
        if payload.get("type") not in {None, "file"}:
            return self._with_provenance(
                candidate,
                source="immutable_license_file_unreadable",
                path=path,
            )
        size = int(payload.get("size") or 0)
        if size > _MAX_LICENSE_BYTES:
            return self._with_provenance(
                candidate,
                source="immutable_license_file_too_large",
                path=path,
            )
        blob_sha_raw = str(payload.get("sha") or "")
        blob_sha = blob_sha_raw.lower() if _SHA40.fullmatch(blob_sha_raw) else None
        if payload.get("encoding") != "base64" or not payload.get("content"):
            return self._with_provenance(
                candidate,
                source="immutable_license_file_unreadable",
                path=path,
                blob_sha=blob_sha,
            )
        try:
            encoded = str(payload["content"]).replace("\n", "")
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > _MAX_LICENSE_BYTES:
                raise ValueError("decoded license exceeds size limit")
            text = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return self._with_provenance(
                candidate,
                source="immutable_license_file_unreadable",
                path=path,
                blob_sha=blob_sha,
            )

        spdx = classify_license_text(text)
        if spdx is None:
            return self._with_provenance(
                candidate,
                source="immutable_license_file_unrecognized",
                path=path,
                blob_sha=blob_sha,
            )
        enriched = replace(candidate, license_spdx=spdx)
        return self._with_provenance(
            enriched,
            source="immutable_license_file",
            path=path,
            blob_sha=blob_sha,
        )
