from __future__ import annotations

from typing import Any

from .models import Candidate, Need


class BenchmarkCoordinator:
    """Builds safe benchmark plans; V1 never executes untrusted candidate code."""

    def plan(self, need: Need, candidate: Candidate) -> dict[str, Any]:
        return {
            "status": "PLANNED_NOT_EXECUTED",
            "reason": "V1 metadata pre-screen; untrusted code execution is disabled",
            "capability_id": need.capability_id,
            "repository": candidate.repository,
            "commit_sha": candidate.commit_sha,
            "targets": list(need.targets),
            "required_sandbox": {
                "ephemeral_filesystem": True,
                "secrets": "none",
                "network": "disabled_by_default",
                "cpu_limit": True,
                "memory_limit": True,
                "timeout": True,
                "cleanup": "mandatory",
            },
            "metrics": ["correctness", "latency", "resource_usage", "footprint"],
        }
