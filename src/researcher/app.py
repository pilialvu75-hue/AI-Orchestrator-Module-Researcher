from __future__ import annotations

import platform
import re
import uuid
from dataclasses import dataclass

from . import __version__
from .comparison import ComparisonEngine
from .component_security import ComponentAwareGitHubSecurityScanner
from .config import Config
from .diagnostics_bridge import GitHubDiagnosticsBridge
from .discovery.github import GitHubDiscoveryProvider
from .dossiers import DossierStore
from .engine import ResearchEngine
from .github_api import GitHubApi
from .library import GitHubLibrarySource
from .observability import EventLevel, EventLogger
from .rate_limit import RateLimitManager
from .restart_safe_engine import RestartSafeResearchEngine
from .scoped_api import ScopedLibraryWriteApi
from .scoring import CandidateScorer
from .state import SQLiteStateStore
from .submission import (
    DryRunSubmissionClient,
    GitHubIntakePrSubmissionClient,
    LibrarySubmissionClient,
)
from .target_discovery import TargetAwareDiscoveryProvider
from .target_submission import TargetScopedSubmissionClient
from .vulnerability import OsvClient, OsvVulnerabilityScanner
from .vulnerability_admission import GitHubVulnerabilityAdmissionScanner


_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_VERSION = re.compile(r"^[A-Za-z0-9._+/\-]{1,128}$")


@dataclass
class App:
    config: Config
    state: SQLiteStateStore
    engine: ResearchEngine
    events: EventLogger
    diagnostics: GitHubDiagnosticsBridge | None


def _diagnostics_instance(config: Config, state: SQLiteStateStore) -> str:
    existing = config.diagnostics_instance_id or state.get_json("diagnostics_instance_id")
    if existing is None:
        existing = str(uuid.uuid4())
    value = str(existing)
    if not _ID.fullmatch(value):
        raise ValueError("DIAGNOSTICS_INSTANCE_ID must be a safe stable identifier")
    state.set_json("diagnostics_instance_id", value)
    return value


def _producer_version(config: Config) -> str:
    value = config.diagnostics_producer_version or __version__
    if not _VERSION.fullmatch(value):
        raise ValueError("Diagnostics producer version/commit is invalid")
    return value


def build_app(config: Config) -> App:
    config.data_dir.mkdir(parents=True, exist_ok=True)
    state = SQLiteStateStore(config.data_dir / "researcher.db")
    diagnostics_opted_in = bool(
        config.diagnostics_enabled and config.diagnostics_github_token
    )
    events = EventLogger(state, diagnostics_enabled=diagnostics_opted_in)

    source_api = GitHubApi(
        config.github_token,
        config.github_api_base,
        uploads_base_url=config.github_uploads_base,
    )
    library_api = GitHubApi(
        config.library_github_token or config.github_token,
        config.github_api_base,
        user_agent=f"AI-Orchestrator-Module-Researcher-Library/{__version__}",
        uploads_base_url=config.github_uploads_base,
    )
    library = GitHubLibrarySource(
        library_api,
        config.library_repository,
        config.library_ref,
        config.data_dir / "cache",
    )
    rate_limits = RateLimitManager(state)
    discovery = TargetAwareDiscoveryProvider(
        GitHubDiscoveryProvider(source_api, rate_limits)
    )
    security_scanner = ComponentAwareGitHubSecurityScanner(source_api, rate_limits)
    vulnerability_scanner = GitHubVulnerabilityAdmissionScanner(
        source_api,
        rate_limits,
        OsvVulnerabilityScanner(OsvClient()),
    )
    dossiers = DossierStore(config.data_dir)

    diagnostics: GitHubDiagnosticsBridge | None = None
    if config.diagnostics_enabled:
        if config.diagnostics_github_token:
            diagnostics_api = GitHubApi(
                config.diagnostics_github_token,
                config.github_api_base,
                user_agent="AI-Orchestrator-Module-Researcher-Diagnostics/2.0",
                uploads_base_url=config.github_uploads_base,
            )
            diagnostics = GitHubDiagnosticsBridge(
                diagnostics_api,
                state,
                config.diagnostics_repository,
                instance_id=_diagnostics_instance(config, state),
                producer_version=_producer_version(config),
                platform_name=platform.system().lower(),
            )
            state.set_json(
                "diagnostics_status",
                {"state": "READY", "tag": diagnostics.tag},
            )
            events.emit(
                EventLevel.INFO,
                "diagnostics",
                "diagnostics_configured",
                {"result": "READY"},
            )
        else:
            state.set_json(
                "diagnostics_status",
                {"state": "MISCONFIGURED", "error_type": "MissingDiagnosticsToken"},
            )
            events.emit(
                EventLevel.WARNING,
                "diagnostics",
                "diagnostics_misconfigured",
                {"result": "MISCONFIGURED", "error_type": "MissingDiagnosticsToken"},
            )
    else:
        state.set_json("diagnostics_status", {"state": "DISABLED"})

    submission: LibrarySubmissionClient
    if config.dry_run:
        submission = DryRunSubmissionClient(dossiers)
    else:
        if not config.allow_library_write:
            raise RuntimeError(
                "Fail-closed: DRY_RUN=false requires ALLOW_LIBRARY_WRITE=true"
            )
        if not config.library_github_token:
            raise RuntimeError(
                "Fail-closed: real Library writes require LIBRARY_GITHUB_TOKEN"
            )
        submission_api = ScopedLibraryWriteApi(
            source_api,
            library_api,
            config.library_repository,
        )
        submission = GitHubIntakePrSubmissionClient(
            submission_api,
            config.library_repository,
            state,
            config.library_ref,
        )
    submission = TargetScopedSubmissionClient(submission)

    engine = RestartSafeResearchEngine(
        library,
        library,
        discovery,
        state,
        dossiers,
        CandidateScorer(),
        ComparisonEngine(),
        submission,
        config.mode,
        security_scanner=security_scanner,
        vulnerability_scanner=vulnerability_scanner,
        event_logger=events,
    )
    return App(
        config=config,
        state=state,
        engine=engine,
        events=events,
        diagnostics=diagnostics,
    )
