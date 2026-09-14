from __future__ import annotations

import urllib.parse
from typing import Any

from .component_candidate import normalize_component_path
from .github_api import GitHubApi, GitHubResponse
from .models import Candidate
from .rate_limit import RateLimitManager
from .security_admission import FullTreeSecurityReport, GitHubFullTreeSecurityScanner


class _ComponentTreeApi(GitHubApi):
    """Filter exactly one recursive tree response to an admitted component subtree."""

    def __init__(
        self,
        base: GitHubApi,
        repository: str,
        tree_sha: str,
        component_path: str,
    ) -> None:
        self._base = base
        repo_path = "/".join(
            urllib.parse.quote(part, safe="") for part in repository.split("/", 1)
        )
        tree_ref = urllib.parse.quote(tree_sha, safe="")
        self._tree_endpoint = f"/repos/{repo_path}/git/trees/{tree_ref}?recursive=1"
        self._component_path = component_path

    def get(self, path: str) -> GitHubResponse:
        response = self._base.get(path)
        if path != self._tree_endpoint:
            return response
        payload = response.data if isinstance(response.data, dict) else {}
        entries = payload.get("tree")
        if not isinstance(entries, list):
            return response
        prefix = self._component_path + "/"
        filtered = [
            item
            for item in entries
            if isinstance(item, dict)
            and (
                str(item.get("path") or "") == self._component_path
                or str(item.get("path") or "").startswith(prefix)
            )
        ]
        if not filtered:
            raise ValueError("security scope component path is absent from pinned tree")
        scoped: dict[str, Any] = dict(payload)
        scoped["tree"] = filtered
        return GitHubResponse(data=scoped, headers=response.headers)


class ComponentAwareGitHubSecurityScanner:
    """Use the existing fail-closed scanner, optionally on an explicit component subtree."""

    def __init__(self, api: GitHubApi, rate_limits: RateLimitManager) -> None:
        self.api = api
        self.rate_limits = rate_limits
        self.root_scanner = GitHubFullTreeSecurityScanner(api, rate_limits)

    def scan(self, candidate: Candidate) -> FullTreeSecurityReport:
        component_path = normalize_component_path(
            None
            if candidate.extra.get("component_path") is None
            else str(candidate.extra["component_path"])
        )
        if component_path is None:
            return self.root_scanner.scan(candidate)

        tree_sha = str(candidate.extra.get("provenance_tree_sha") or "")
        if len(tree_sha) != 40:
            return FullTreeSecurityReport.not_scanned(
                candidate,
                "component scan requires a verified root tree SHA",
            )
        scoped_api = _ComponentTreeApi(
            self.api,
            candidate.repository,
            tree_sha,
            component_path,
        )
        scanner = GitHubFullTreeSecurityScanner(
            scoped_api,
            self.rate_limits,
        )
        return scanner.scan(candidate)
