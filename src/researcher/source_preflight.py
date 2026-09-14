from __future__ import annotations

from typing import Any

from .component_candidate import ComponentCandidateResolver
from .component_security import ComponentAwareGitHubSecurityScanner
from .config import Config
from .github_api import GitHubApi
from .rate_limit import RateLimitManager
from .security_gate import SecurityVerdict
from .state import SQLiteStateStore
from .vulnerability import OsvClient, OsvVulnerabilityScanner
from .vulnerability_admission import (
    GitHubVulnerabilityAdmissionScanner,
    VulnerabilityAdmissionResult,
)


def _preflight_state(
    security_verdict: SecurityVerdict,
    security_eligible: bool,
    vulnerability: VulnerabilityAdmissionResult,
) -> str:
    if security_verdict == SecurityVerdict.BLOCK:
        return "BLOCKED"
    if security_eligible and vulnerability.admission_eligible:
        return "CLEAR"
    return "REVIEW"


def run_source_preflight(
    config: Config,
    state: SQLiteStateStore,
    repository: str,
    commit_sha: str,
    *,
    component_path: str | None = None,
    release_tag: str | None = None,
    source_version: str | None = None,
) -> dict[str, Any]:
    """Evaluate immutable upstream source without reading or writing the Library.

    This is deliberately narrower than Library admission. It verifies source
    provenance, static security, supply-chain evidence and OSV vulnerability
    evidence. Functional/contract fit and Library certification remain separate.
    """

    api = GitHubApi(
        config.github_token,
        config.github_api_base,
        uploads_base_url=config.github_uploads_base,
    )
    rate_limits = RateLimitManager(state)
    candidate = ComponentCandidateResolver(api, rate_limits).resolve(
        repository,
        commit_sha,
        component_path=component_path,
        release_tag=release_tag,
        source_version=source_version,
    )
    security = ComponentAwareGitHubSecurityScanner(api, rate_limits).scan(candidate)
    vulnerability = GitHubVulnerabilityAdmissionScanner(
        api,
        rate_limits,
        OsvVulnerabilityScanner(OsvClient()),
    ).scan(candidate, security)

    return {
        "state": _preflight_state(
            security.verdict,
            security.admission_eligible,
            vulnerability,
        ),
        "security_preflight_clear": (
            security.admission_eligible and vulnerability.admission_eligible
        ),
        "candidate": {
            "provider": candidate.provider,
            "repository": candidate.repository,
            "commit_sha": candidate.commit_sha,
            "component_path": candidate.extra.get("component_path"),
            "name": candidate.name,
            "release_tag": candidate.release_tag,
            "source_version": candidate.extra.get("source_version"),
            "license": candidate.license_spdx,
            "provenance_tree_sha": candidate.extra.get("provenance_tree_sha"),
        },
        "security": security.to_dict(),
        "vulnerability": vulnerability.to_dict(),
        "library_accessed": False,
        "library_write_attempted": False,
        "functional_or_contract_fit_asserted": False,
        "certification_asserted": False,
        "executed_untrusted_code": False,
    }
