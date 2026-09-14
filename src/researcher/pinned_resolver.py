from __future__ import annotations

import urllib.parse
from typing import Any

from .github_api import GitHubApi, GitHubResponse
from .models import Candidate, utc_now
from .pinned_proof import PinnedProof
from .rate_limit import RateLimitManager

_DEPENDENCY_MANIFESTS = {
    "build.gradle",
    "build.gradle.kts",
    "cargo.toml",
    "go.mod",
    "package.json",
    "pom.xml",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
}
_LICENSE_FILES = {
    "copying",
    "copying.md",
    "copying.txt",
    "license",
    "license.md",
    "license.txt",
}
_TEST_DIRS = {"test", "tests", "spec", "specs"}


class PinnedCandidateResolver:
    """Rebuild candidate metadata from GitHub while preserving the proof's exact SHA."""

    def __init__(self, api: GitHubApi, rate_limits: RateLimitManager) -> None:
        self.api = api
        self.rate_limits = rate_limits

    def _observe(self, response: GitHubResponse) -> None:
        self.rate_limits.observe_headers(response.headers)

    def _get(self, path: str) -> GitHubResponse:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            self.rate_limits.record_backoff(
                decision.retry_after_seconds,
                "pinned_candidate_rate_limit",
            )
            raise RuntimeError(
                f"GitHub rate limit exhausted; retry after {decision.retry_after_seconds}s"
            )
        response = self.api.get(path)
        self._observe(response)
        return response

    @staticmethod
    def _basename(path: str) -> str:
        return path.rsplit("/", 1)[-1]

    def _tree_evidence(
        self,
        repository: str,
        commit_sha: str,
        commit_data: dict[str, Any],
    ) -> dict[str, Any]:
        commit_meta = commit_data.get("commit")
        tree_meta = commit_meta.get("tree") if isinstance(commit_meta, dict) else None
        tree_sha = str(tree_meta.get("sha", "")) if isinstance(tree_meta, dict) else ""
        if not tree_sha:
            raise RuntimeError("Pinned commit does not expose a tree SHA")
        tree = self._get(f"/repos/{repository}/git/trees/{tree_sha}?recursive=1")
        tree_data = tree.data if isinstance(tree.data, dict) else {}
        if bool(tree_data.get("truncated", False)):
            raise RuntimeError("Pinned repository tree is truncated; fail closed")
        raw_entries = tree_data.get("tree")
        if not isinstance(raw_entries, list):
            raise RuntimeError("Pinned repository tree response is invalid")
        paths = [
            str(entry.get("path", ""))
            for entry in raw_entries
            if isinstance(entry, dict) and entry.get("path")
        ]
        lower_paths = [path.lower() for path in paths]
        tests_present = any(
            any(segment in _TEST_DIRS for segment in path.split("/"))
            or self._basename(path).endswith("_test.dart")
            or self._basename(path).startswith("test_")
            for path in lower_paths
        )
        dependency_manifests = sorted(
            path
            for path in paths
            if self._basename(path.lower()) in _DEPENDENCY_MANIFESTS
        )[:50]
        license_paths = sorted(
            path for path in paths if self._basename(path.lower()) in _LICENSE_FILES
        )
        license_file_url = None
        if license_paths:
            encoded = urllib.parse.quote(license_paths[0], safe="/")
            license_file_url = (
                f"https://github.com/{repository}/blob/{commit_sha}/{encoded}"
            )
        return {
            "tests_present": tests_present,
            "ci_present": any(path.startswith(".github/workflows/") for path in lower_paths),
            "readme_present": any(
                self._basename(path).startswith("readme") for path in lower_paths
            ),
            "dependency_manifests": dependency_manifests,
            "license_file_url": license_file_url,
            "security_policy_present": any(
                self._basename(path) in {"security.md", "security.txt"}
                for path in lower_paths
            ),
            "dependabot_present": any(
                path in {".github/dependabot.yml", ".github/dependabot.yaml"}
                for path in lower_paths
            ),
            "codeql_present": any(
                path.startswith(".github/workflows/") and "codeql" in self._basename(path)
                for path in lower_paths
            ),
            "provenance_tree_sha": tree_sha,
        }

    def _verify_release_tag(self, proof: PinnedProof) -> bool:
        if proof.release_tag is None:
            return False
        tag = urllib.parse.quote(proof.release_tag, safe="")
        response = self._get(f"/repos/{proof.repository}/commits/{tag}")
        data = response.data if isinstance(response.data, dict) else {}
        if str(data.get("sha", "")) != proof.commit_sha:
            raise RuntimeError("Pinned proof source_tag does not resolve to pinned commit")
        return True

    def resolve(self, proof: PinnedProof) -> Candidate:
        repo_response = self._get(f"/repos/{proof.repository}")
        meta = repo_response.data if isinstance(repo_response.data, dict) else {}
        full_name = str(meta.get("full_name") or "")
        if full_name.lower() != proof.repository.lower():
            raise RuntimeError("Pinned repository identity changed or could not be verified")

        commit_response = self._get(
            f"/repos/{proof.repository}/commits/{proof.commit_sha}"
        )
        commit_data = (
            commit_response.data if isinstance(commit_response.data, dict) else {}
        )
        if str(commit_data.get("sha", "")) != proof.commit_sha:
            raise RuntimeError("Pinned commit identity could not be verified")
        tree = self._tree_evidence(proof.repository, proof.commit_sha, commit_data)
        release_verified = self._verify_release_tag(proof)

        license_spdx: str | None = None
        license_meta = meta.get("license")
        if isinstance(license_meta, dict):
            value = license_meta.get("spdx_id")
            license_spdx = None if value in {None, "NOASSERTION"} else str(value)
        owner_raw = meta.get("owner")
        owner = (
            str(owner_raw.get("login"))
            if isinstance(owner_raw, dict) and owner_raw.get("login")
            else proof.repository.split("/", 1)[0]
        )
        raw_topics = meta.get("topics")
        topics = raw_topics if isinstance(raw_topics, list) else []
        branch = str(meta.get("default_branch") or "main")
        source_stable = None
        if proof.source_version:
            lowered = proof.source_version.lower()
            source_stable = not any(
                marker in lowered
                for marker in ("alpha", "beta", "-rc", ".dev", "snapshot", "wip")
            )

        return Candidate(
            provider="github",
            repository=proof.repository,
            upstream_url=str(
                meta.get("html_url") or f"https://github.com/{proof.repository}"
            ),
            owner=owner,
            name=str(meta.get("name") or proof.repository.split("/", 1)[1]),
            commit_sha=proof.commit_sha,
            release_tag=proof.release_tag if release_verified else None,
            default_branch=branch,
            acquired_at=utc_now(),
            license_spdx=license_spdx,
            license_file_url=(
                None
                if tree.get("license_file_url") is None
                else str(tree["license_file_url"])
            ),
            stars=int(meta.get("stargazers_count") or 0),
            forks=int(meta.get("forks_count") or 0),
            open_issues=int(meta.get("open_issues_count") or 0),
            pushed_at=None if meta.get("pushed_at") is None else str(meta["pushed_at"]),
            archived=bool(meta.get("archived", False)),
            language=None if meta.get("language") is None else str(meta["language"]),
            topics=tuple(str(topic) for topic in topics),
            description=None if meta.get("description") is None else str(meta["description"]),
            homepage=None if meta.get("homepage") is None else str(meta["homepage"]),
            size_kb=None if meta.get("size") is None else int(meta["size"]),
            has_issues=bool(meta.get("has_issues", True)),
            has_wiki=bool(meta.get("has_wiki", False)),
            extra={
                "fork": bool(meta.get("fork", False)),
                "disabled": bool(meta.get("disabled", False)),
                "visibility": meta.get("visibility"),
                "tests_present": bool(tree.get("tests_present")),
                "ci_present": bool(tree.get("ci_present")),
                "readme_present": bool(tree.get("readme_present")),
                "dependency_manifests": list(tree.get("dependency_manifests", [])),
                "tree_truncated": False,
                "security_policy_present": bool(tree.get("security_policy_present")),
                "dependabot_present": bool(tree.get("dependabot_present")),
                "codeql_present": bool(tree.get("codeql_present")),
                "provenance_tree_sha": tree.get("provenance_tree_sha"),
                "release_tag_verified": release_verified,
                "source_version": proof.source_version,
                "source_stable": source_stable,
                "release_resolution_strategy": "pinned_proof",
                "proof_path": str(proof.proof_path),
            },
        )
