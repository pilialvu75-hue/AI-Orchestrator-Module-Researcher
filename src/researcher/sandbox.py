from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Sequence


_IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_TEMP_HOST_ROOT = str(PurePosixPath("/") / "tmp")
_FORBIDDEN_HOST_FRAGMENTS = (
    "/.git",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "AI-Orchestrator-Module-Researcher",
    "AI-Orchestrator-Module-Library",
    "Ai-orchestrator-riserva",
)


class SandboxPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class SandboxLimits:
    cpus: float = 1.0
    memory_mb: int = 512
    pids: int = 64
    work_tmpfs_mb: int = 256
    tmp_tmpfs_mb: int = 64
    wall_clock_seconds: int = 120

    def validate(self) -> None:
        if not 0 < self.cpus <= 4:
            raise SandboxPolicyError("sandbox cpus must be >0 and <=4")
        if not 64 <= self.memory_mb <= 4096:
            raise SandboxPolicyError("sandbox memory_mb must be between 64 and 4096")
        if not 8 <= self.pids <= 256:
            raise SandboxPolicyError("sandbox pids must be between 8 and 256")
        if not 16 <= self.work_tmpfs_mb <= 1024:
            raise SandboxPolicyError("sandbox work_tmpfs_mb must be between 16 and 1024")
        if not 16 <= self.tmp_tmpfs_mb <= 512:
            raise SandboxPolicyError("sandbox tmp_tmpfs_mb must be between 16 and 512")
        if not 1 <= self.wall_clock_seconds <= 600:
            raise SandboxPolicyError("sandbox wall_clock_seconds must be between 1 and 600")


@dataclass(frozen=True)
class SandboxInput:
    staged_source_path: str
    candidate_fingerprint: str
    commit_sha: str
    content_sha256: str

    def validate(self) -> None:
        if not self.staged_source_path.startswith("/"):
            raise SandboxPolicyError("sandbox source path must be absolute")
        normalized = str(PurePosixPath(self.staged_source_path))
        if normalized in {"/", _TEMP_HOST_ROOT, "/var", "/home"}:
            raise SandboxPolicyError("sandbox source path is too broad")
        if any(fragment.lower() in normalized.lower() for fragment in _FORBIDDEN_HOST_FRAGMENTS):
            raise SandboxPolicyError("sandbox source path references a protected host location")
        if ".." in PurePosixPath(self.staged_source_path).parts:
            raise SandboxPolicyError("sandbox source path must not contain parent traversal")
        if not re.fullmatch(r"[0-9a-f]{64}", self.candidate_fingerprint):
            raise SandboxPolicyError("candidate fingerprint must be a SHA-256 hex digest")
        if not re.fullmatch(r"[0-9a-f]{40}", self.commit_sha):
            raise SandboxPolicyError("candidate commit must be a full Git SHA-1")
        if not re.fullmatch(r"[0-9a-f]{64}", self.content_sha256):
            raise SandboxPolicyError("candidate content hash must be a SHA-256 hex digest")


@dataclass(frozen=True)
class SandboxPlan:
    runtime: str
    image: str
    argv: tuple[str, ...]
    limits: SandboxLimits
    network: str
    root_filesystem_read_only: bool
    capabilities_dropped: tuple[str, ...]
    no_new_privileges: bool
    source_mount_read_only: bool
    privileged: bool
    host_devices: tuple[str, ...]
    secrets_mounted: bool
    execution_enabled: bool
    execution_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "image": self.image,
            "argv": list(self.argv),
            "limits": {
                "cpus": self.limits.cpus,
                "memory_mb": self.limits.memory_mb,
                "pids": self.limits.pids,
                "work_tmpfs_mb": self.limits.work_tmpfs_mb,
                "tmp_tmpfs_mb": self.limits.tmp_tmpfs_mb,
                "wall_clock_seconds": self.limits.wall_clock_seconds,
            },
            "network": self.network,
            "root_filesystem_read_only": self.root_filesystem_read_only,
            "capabilities_dropped": list(self.capabilities_dropped),
            "no_new_privileges": self.no_new_privileges,
            "source_mount_read_only": self.source_mount_read_only,
            "privileged": self.privileged,
            "host_devices": list(self.host_devices),
            "secrets_mounted": self.secrets_mounted,
            "execution_enabled": self.execution_enabled,
            "execution_reason": self.execution_reason,
        }


class DockerSandboxPlanner:
    """Build hardened Docker argv only; this class never executes it."""

    def __init__(
        self,
        trusted_image: str,
        limits: SandboxLimits | None = None,
    ) -> None:
        if not _IMAGE_DIGEST.fullmatch(trusted_image):
            raise SandboxPolicyError(
                "trusted sandbox image must be pinned as name@sha256:<64 hex>"
            )
        self.trusted_image = trusted_image
        self.limits = limits or SandboxLimits()
        self.limits.validate()

    @staticmethod
    def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
        rendered = tuple(command)
        if not rendered:
            raise SandboxPolicyError("sandbox command must not be empty")
        for item in rendered:
            if not isinstance(item, str) or not item or "\x00" in item:
                raise SandboxPolicyError("sandbox command contains an invalid argument")
        return rendered

    def plan(self, source: SandboxInput, command: Sequence[str]) -> SandboxPlan:
        source.validate()
        candidate_command = self._validate_command(command)
        memory = f"{self.limits.memory_mb}m"
        work_tmpfs = (
            "/work:rw,nosuid,nodev,size="
            f"{self.limits.work_tmpfs_mb}m,mode=0700,uid=65532,gid=65532"
        )
        scratch_tmpfs = (
            "/scratch-tmp:rw,noexec,nosuid,nodev,size="
            f"{self.limits.tmp_tmpfs_mb}m,mode=0700,uid=65532,gid=65532"
        )
        argv = (
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(self.limits.pids),
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--cpus",
            str(self.limits.cpus),
            "--user",
            "65532:65532",
            "--tmpfs",
            work_tmpfs,
            "--tmpfs",
            scratch_tmpfs,
            "--mount",
            f"type=bind,src={source.staged_source_path},dst=/candidate,readonly",
            "--workdir",
            "/work",
            self.trusted_image,
            *candidate_command,
        )
        return SandboxPlan(
            runtime="docker",
            image=self.trusted_image,
            argv=argv,
            limits=self.limits,
            network="none",
            root_filesystem_read_only=True,
            capabilities_dropped=("ALL",),
            no_new_privileges=True,
            source_mount_read_only=True,
            privileged=False,
            host_devices=(),
            secrets_mounted=False,
            execution_enabled=False,
            execution_reason=(
                "foundation-only: untrusted candidate execution remains disabled until "
                "a separately approved sandbox executor exists"
            ),
        )
