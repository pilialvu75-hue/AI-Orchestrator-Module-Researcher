from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .models import ResearchMode


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    mode: ResearchMode
    dry_run: bool
    allow_library_write: bool
    github_token: str | None
    library_repository: str
    library_ref: str
    data_dir: Path
    maintenance_interval_seconds: int
    seeding_interval_seconds: int
    improvement_interval_seconds: int
    dashboard_host: str
    dashboard_port: int
    library_github_token: str | None = None
    diagnostics_enabled: bool = False
    diagnostics_github_token: str | None = None
    diagnostics_repository: str = "pilialvu75-hue/Ai-orchestrator-diagnostics"
    diagnostics_instance_id: str | None = None
    diagnostics_producer_version: str | None = None
    github_api_base: str = "https://api.github.com"
    github_uploads_base: str = "https://uploads.github.com"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            mode=ResearchMode(os.getenv("RESEARCHER_MODE", "SEEDING").upper()),
            dry_run=_bool("DRY_RUN", True),
            allow_library_write=_bool("ALLOW_LIBRARY_WRITE", False),
            github_token=os.getenv("GITHUB_TOKEN") or None,
            library_repository=os.getenv(
                "LIBRARY_REPOSITORY", "pilialvu75-hue/AI-Orchestrator-Module-Library"
            ),
            library_ref=os.getenv("LIBRARY_REF", "main"),
            data_dir=Path(os.getenv("DATA_DIR", "./data")),
            maintenance_interval_seconds=int(
                os.getenv("MAINTENANCE_INTERVAL_SECONDS", "21600")
            ),
            seeding_interval_seconds=int(os.getenv("SEEDING_INTERVAL_SECONDS", "900")),
            improvement_interval_seconds=int(
                os.getenv("IMPROVEMENT_INTERVAL_SECONDS", "86400")
            ),
            dashboard_host=os.getenv("DASHBOARD_HOST", "127.0.0.1"),
            dashboard_port=int(os.getenv("DASHBOARD_PORT", "8080")),
            library_github_token=os.getenv("LIBRARY_GITHUB_TOKEN") or None,
            diagnostics_enabled=_bool("DIAGNOSTICS_ENABLED", False),
            diagnostics_github_token=os.getenv("DIAGNOSTICS_GITHUB_TOKEN") or None,
            diagnostics_repository=os.getenv(
                "DIAGNOSTICS_REPOSITORY", "pilialvu75-hue/Ai-orchestrator-diagnostics"
            ),
            diagnostics_instance_id=os.getenv("DIAGNOSTICS_INSTANCE_ID") or None,
            diagnostics_producer_version=(
                os.getenv("DIAGNOSTICS_PRODUCER_VERSION")
                or os.getenv("RESEARCHER_COMMIT")
                or None
            ),
            github_api_base=os.getenv("GITHUB_API_BASE", "https://api.github.com"),
            github_uploads_base=os.getenv(
                "GITHUB_UPLOADS_BASE", "https://uploads.github.com"
            ),
        )
