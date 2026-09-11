from __future__ import annotations

from dataclasses import dataclass

from .comparison import ComparisonEngine
from .config import Config
from .discovery.github import GitHubDiscoveryProvider
from .dossiers import DossierStore
from .engine import ResearchEngine
from .github_api import GitHubApi
from .library import GitHubLibrarySource
from .rate_limit import RateLimitManager
from .scoring import CandidateScorer
from .state import SQLiteStateStore
from .submission import (
    DryRunSubmissionClient,
    GitHubIntakePrSubmissionClient,
    LibrarySubmissionClient,
)


@dataclass
class App:
    config: Config
    state: SQLiteStateStore
    engine: ResearchEngine


def build_app(config: Config) -> App:
    config.data_dir.mkdir(parents=True, exist_ok=True)
    state = SQLiteStateStore(config.data_dir / "researcher.db")
    api = GitHubApi(config.github_token, config.github_api_base)
    library = GitHubLibrarySource(
        api,
        config.library_repository,
        config.library_ref,
        config.data_dir / "cache",
    )
    rate_limits = RateLimitManager(state)
    discovery = GitHubDiscoveryProvider(api, rate_limits)
    dossiers = DossierStore(config.data_dir)

    submission: LibrarySubmissionClient
    if config.dry_run:
        submission = DryRunSubmissionClient(dossiers)
    else:
        if not config.allow_library_write:
            raise RuntimeError(
                "Fail-closed: DRY_RUN=false requires ALLOW_LIBRARY_WRITE=true"
            )
        submission = GitHubIntakePrSubmissionClient(
            api,
            config.library_repository,
            config.library_ref,
        )

    engine = ResearchEngine(
        library,
        library,
        discovery,
        state,
        dossiers,
        CandidateScorer(),
        ComparisonEngine(),
        submission,
        config.mode,
    )
    return App(config=config, state=state, engine=engine)
