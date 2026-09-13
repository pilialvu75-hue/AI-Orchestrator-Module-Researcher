from __future__ import annotations

from typing import Any

from .models import Candidate, Need


class BenchmarkCoordinator:
    """Builds safe benchmark plans; Researcher never executes candidates here."""

    def plan(self, need: Need, candidate: Candidate) -> dict[str, Any]:
        return {
            "status": "PLANNED_NOT_EXECUTED",
            "reason": (
                "Sandbox policy/planning exists, but no untrusted-code executor is enabled."
            ),
            "capability_id": need.capability_id,
            "repository": candidate.repository,
            "commit_sha": candidate.commit_sha,
            "targets": list(need.targets),
            "sandbox_foundation": {
                "planner": "researcher.sandbox.DockerSandboxPlanner",
                "executor_enabled": False,
                "trusted_image_digest_required": True,
                "candidate_source_mount": "read_only",
                "root_filesystem": "read_only",
                "secrets": "none",
                "network": "none",
                "capabilities": "drop_all",
                "no_new_privileges": True,
                "host_devices": "none",
                "docker_socket": "forbidden",
                "project_repository_mounts": "forbidden",
                "cpu_limit": True,
                "memory_limit": True,
                "pid_limit": True,
                "wall_clock_limit": True,
                "ephemeral_work_tmpfs": True,
                "cleanup": "mandatory_when_executor_exists",
            },
            "metrics": ["correctness", "latency", "resource_usage", "footprint"],
        }
