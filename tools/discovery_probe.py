"""Read-only, bounded, real GitHub discovery evidence for the Researcher PR.

This probe never asks for a Library credential and never submits a candidate.
It collects only public repository identity, immutable commit, and license
metadata; admission and certification remain separate workflows.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from researcher.discovery.github import GitHubDiscoveryProvider
from researcher.github_api import GitHubApi, GitHubApiError
from researcher.models import Candidate, Need
from researcher.rate_limit import RateLimitManager
from researcher.state import SQLiteStateStore


_PROBE_NEEDS = (
    Need(
        capability_id="ai.acceleration_backend",
        title="Target-specific local inference acceleration backend",
        priority="high",
        desired_candidates=2,
        status="needed",
        targets=("android",),
    ),
    Need(
        capability_id="storage.secrets",
        title="Secure local storage / secrets abstraction",
        priority="high",
        desired_candidates=2,
        status="needed",
        targets=("android",),
    ),
)


def report_candidate(candidate: Candidate) -> dict[str, Any]:
    """Report upstream metadata, never imply security or Library approval."""
    return {
        "repository": candidate.repository,
        "commit_sha": candidate.commit_sha,
        "license_spdx": candidate.license_spdx,
        "source_stable": candidate.extra.get("source_stable"),
        "security_approved": False,
        "library_certified": False,
    }


def probe_need(
    provider: GitHubDiscoveryProvider,
    need: Need,
    *,
    limit: int = 2,
) -> dict[str, Any]:
    """A single bounded discovery call; no admission, downloads or execution."""
    if not 1 <= limit <= 2:
        raise ValueError("Live probe limit must be 1 or 2")
    try:
        candidates = provider.discover(need, limit=limit)
        raw_diagnostics = getattr(provider, "last_discovery_diagnostics", {})
        diagnostics = (
            {
                key: value
                for key, value in raw_diagnostics.items()
                if key in {
                    "status", "queries_attempted", "search_hits",
                    "unique_repository_hits", "candidates_returned",
                }
                and (type(value) is str or type(value) is int)
            }
            if isinstance(raw_diagnostics, dict) else {}
        )
        return {
            "capability_id": need.capability_id,
            "status": "CANDIDATES_OBSERVED" if candidates else "NO_CANDIDATES",
            "diagnostics": diagnostics,
            "candidates": [report_candidate(item) for item in candidates],
        }
    except GitHubApiError as exc:
        # GitHub status is safe to surface, unlike exception bodies which may
        # contain upstream response payloads or operational internals.
        return {
            "capability_id": need.capability_id,
            "status": "GITHUB_API_ERROR",
            "http_status": exc.status,
            "candidates": [],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded read-only Researcher probe")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="researcher-discovery-probe-") as tmp:
        state = SQLiteStateStore(Path(tmp) / "state.db")
        provider = GitHubDiscoveryProvider(
            GitHubApi(os.environ.get("GITHUB_TOKEN")), RateLimitManager(state)
        )
        rows = [probe_need(provider, need) for need in _PROBE_NEEDS]
    report = {
        "schema": "ai-orchestrator.researcher-live-discovery-proof.v1",
        "mode": "READ_ONLY",
        "results": rows,
        "candidate_count": sum(len(row["candidates"]) for row in rows),
        "library_accessed": False,
        "library_write_attempted": False,
        "source_code_executed": False,
        "certification_asserted": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True))
    if any(row["status"] == "GITHUB_API_ERROR" for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
