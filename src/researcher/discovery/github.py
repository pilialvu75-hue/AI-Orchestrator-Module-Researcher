from __future__ import annotations

import urllib.parse
from typing import Any

from ..github_api import GitHubApi, GitHubApiError, GitHubResponse
from ..models import Candidate, Need, utc_now
from ..rate_limit import RateLimitManager
from .dart_release import DartStableReleaseResolver


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


class GitHubDiscoveryProvider:
    name = "github"

    def __init__(self, api: GitHubApi, rate_limits: RateLimitManager) -> None:
        self.api = api
        self.rate_limits = rate_limits
        self.dart_releases = DartStableReleaseResolver(api, self._observe)

    @staticmethod
    def _queries(need: Need) -> tuple[str, ...]:
        # Capability IDs are internal taxonomy, not necessarily words used by
        # upstream projects. Start precise, then relax deterministically so an
        # internal label such as ai.acceleration_backend cannot make discovery
        # permanently return zero results.
        title_terms = " ".join(
            word for word in need.title.replace("/", " ").split() if len(word) >= 4
        )
        capability_words = [
            word for word in need.capability_id.replace(".", " ").replace("_", " ").split()
            if len(word) >= 3
        ]
        capability_terms = " ".join(capability_words)
        raw = (
            f"{title_terms} {capability_terms}".strip(),
            title_terms.strip(),
            capability_terms.strip(),
        )
        seen: set[str] = set()
        queries: list[str] = []
        for terms in raw:
            if not terms or terms in seen:
                continue
            seen.add(terms)
            queries.append(f"{terms} in:name,description,readme archived:false")
        return tuple(queries)

    def _observe(self, response: GitHubResponse) -> None:
        self.rate_limits.observe_headers(response.headers)

    def _release_tag_for_commit(self, full_name: str, sha: str) -> str | None:
        try:
            release = self.api.get(f"/repos/{full_name}/releases/latest")
            self._observe(release)
            release_data = release.data if isinstance(release.data, dict) else {}
            raw_tag = release_data.get("tag_name")
            if not raw_tag:
                return None
            tag = str(raw_tag)
            tagged = self.api.get(
                f"/repos/{full_name}/commits/{urllib.parse.quote(tag, safe='')}"
            )
            self._observe(tagged)
            tagged_data = tagged.data if isinstance(tagged.data, dict) else {}
            return tag if str(tagged_data.get("sha", "")) == sha else None
        except GitHubApiError as exc:
            if exc.status in {403, 404, 422}:
                return None
            raise

    def _inspect_tree(
        self,
        full_name: str,
        sha: str,
        commit_data: dict[str, Any],
    ) -> dict[str, Any]:
        commit_meta = commit_data.get("commit")
        tree_meta = commit_meta.get("tree") if isinstance(commit_meta, dict) else None
        tree_sha = str(tree_meta.get("sha", "")) if isinstance(tree_meta, dict) else ""
        if not tree_sha:
            return {
                "tests_present": False,
                "ci_present": False,
                "readme_present": False,
                "dependency_manifests": [],
                "license_file_url": None,
                "tree_truncated": None,
                "security_policy_present": False,
                "dependabot_present": False,
                "codeql_present": False,
            }

        try:
            tree = self.api.get(f"/repos/{full_name}/git/trees/{tree_sha}?recursive=1")
            self._observe(tree)
        except GitHubApiError as exc:
            if exc.status in {403, 404, 409, 422}:
                return {
                    "tests_present": False,
                    "ci_present": False,
                    "readme_present": False,
                    "dependency_manifests": [],
                    "license_file_url": None,
                    "tree_truncated": None,
                    "security_policy_present": False,
                    "dependabot_present": False,
                    "codeql_present": False,
                }
            raise

        tree_data = tree.data if isinstance(tree.data, dict) else {}
        raw_entries = tree_data.get("tree")
        entries = raw_entries if isinstance(raw_entries, list) else []
        paths = [
            str(entry.get("path", ""))
            for entry in entries
            if isinstance(entry, dict) and entry.get("path")
        ]
        lower_paths = [path.lower() for path in paths]

        def basename(path: str) -> str:
            return path.rsplit("/", 1)[-1]

        tests_present = any(
            any(segment in _TEST_DIRS for segment in path.split("/"))
            or basename(path).endswith("_test.dart")
            or basename(path).startswith("test_")
            for path in lower_paths
        )
        dependency_manifests = sorted(
            path for path in paths if basename(path.lower()) in _DEPENDENCY_MANIFESTS
        )[:50]
        license_paths = sorted(
            path for path in paths if basename(path.lower()) in _LICENSE_FILES
        )
        license_file_url = None
        if license_paths:
            encoded = urllib.parse.quote(license_paths[0], safe="/")
            license_file_url = f"https://github.com/{full_name}/blob/{sha}/{encoded}"

        return {
            "tests_present": tests_present,
            "ci_present": any(path.startswith(".github/workflows/") for path in lower_paths),
            "readme_present": any(basename(path).startswith("readme") for path in lower_paths),
            "dependency_manifests": dependency_manifests,
            "license_file_url": license_file_url,
            "tree_truncated": bool(tree_data.get("truncated", False)),
            "security_policy_present": any(
                basename(path) in {"security.md", "security.txt"} for path in lower_paths
            ),
            "dependabot_present": any(
                path in {".github/dependabot.yml", ".github/dependabot.yaml"}
                for path in lower_paths
            ),
            "codeql_present": any(
                path.startswith(".github/workflows/") and "codeql" in basename(path)
                for path in lower_paths
            ),
            "provenance_tree_sha": tree_sha,
        }

    def _resolve_source(
        self,
        full_name: str,
        repo_name: str,
        branch_sha: str,
        branch_commit: dict[str, Any],
    ) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
        branch_tree = self._inspect_tree(full_name, branch_sha, branch_commit)
        manifests = [str(item) for item in branch_tree.get("dependency_manifests", [])]
        resolution = self.dart_releases.resolve(
            full_name,
            repo_name,
            branch_sha,
            manifests,
        )
        selected_sha = resolution.commit_sha
        selected_commit = branch_commit
        selected_tree = branch_tree
        if selected_sha != branch_sha:
            resolved = self.api.get(f"/repos/{full_name}/commits/{selected_sha}")
            self._observe(resolved)
            selected_commit = resolved.data if isinstance(resolved.data, dict) else {}
            if str(selected_commit.get("sha", "")) != selected_sha:
                raise RuntimeError(
                    f"Resolved source commit mismatch for {full_name}: {selected_sha}"
                )
            selected_tree = self._inspect_tree(full_name, selected_sha, selected_commit)

        release_metadata: dict[str, Any] = {
            "source_version": resolution.source_version,
            "source_stable": resolution.source_stable,
            "source_manifest_path": resolution.manifest_path,
            "release_resolution_strategy": resolution.strategy,
            "latest_stable_version": resolution.latest_stable_version,
        }
        return selected_sha, selected_commit, selected_tree, release_metadata

    def discover(self, need: Need, limit: int = 8) -> list[Candidate]:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            self.rate_limits.record_backoff(
                decision.retry_after_seconds,
                "github_rate_limit",
            )
            return []
        items: list[Any] = []
        seen_repositories: set[str] = set()
        for raw_query in self._queries(need):
            query = urllib.parse.quote(raw_query, safe="")
            response = self.api.get(
                f"/search/repositories?q={query}&sort=updated&order=desc&per_page={min(limit, 20)}"
            )
            self._observe(response)
            data = response.data
            raw_items = data.get("items", []) if isinstance(data, dict) else []
            for raw in raw_items:
                if not isinstance(raw, dict):
                    continue
                full_name = str(raw.get("full_name", "")).lower()
                if not full_name or full_name in seen_repositories:
                    continue
                seen_repositories.add(full_name)
                items.append(raw)
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        candidates: list[Candidate] = []
        for raw in items:
            if not isinstance(raw, dict):
                continue
            full_name = str(raw.get("full_name", ""))
            if not full_name or "/" not in full_name:
                continue
            repo = self.api.get(f"/repos/{full_name}")
            self._observe(repo)
            meta = repo.data if isinstance(repo.data, dict) else {}
            branch = str(meta.get("default_branch") or "main")
            commit = self.api.get(
                f"/repos/{full_name}/commits/{urllib.parse.quote(branch, safe='')}"
            )
            self._observe(commit)
            branch_commit = commit.data if isinstance(commit.data, dict) else {}
            branch_sha = str(branch_commit.get("sha", ""))
            if len(branch_sha) < 12:
                continue

            repo_name = str(meta.get("name") or full_name.split("/", 1)[1])
            sha, _, tree_evidence, release_metadata = self._resolve_source(
                full_name,
                repo_name,
                branch_sha,
                branch_commit,
            )
            release_tag = self._release_tag_for_commit(full_name, sha)

            license_spdx: str | None = None
            license_meta = meta.get("license")
            if isinstance(license_meta, dict):
                key = license_meta.get("spdx_id")
                license_spdx = None if key is None else str(key)

            owner_raw = meta.get("owner")
            owner = (
                str(owner_raw.get("login"))
                if isinstance(owner_raw, dict) and owner_raw.get("login")
                else full_name.split("/", 1)[0]
            )
            raw_topics = meta.get("topics")
            topics: list[Any] = raw_topics if isinstance(raw_topics, list) else []
            candidates.append(
                Candidate(
                    provider=self.name,
                    repository=full_name,
                    upstream_url=str(meta.get("html_url") or f"https://github.com/{full_name}"),
                    owner=owner,
                    name=repo_name,
                    commit_sha=sha,
                    release_tag=release_tag,
                    default_branch=branch,
                    acquired_at=utc_now(),
                    license_spdx=license_spdx,
                    license_file_url=(
                        None
                        if tree_evidence.get("license_file_url") is None
                        else str(tree_evidence["license_file_url"])
                    ),
                    stars=int(meta.get("stargazers_count") or 0),
                    forks=int(meta.get("forks_count") or 0),
                    open_issues=int(meta.get("open_issues_count") or 0),
                    pushed_at=(
                        None if meta.get("pushed_at") is None else str(meta["pushed_at"])
                    ),
                    archived=bool(meta.get("archived", False)),
                    language=None if meta.get("language") is None else str(meta["language"]),
                    topics=tuple(str(topic) for topic in topics),
                    description=(
                        None
                        if meta.get("description") is None
                        else str(meta["description"])
                    ),
                    homepage=None if meta.get("homepage") is None else str(meta["homepage"]),
                    size_kb=None if meta.get("size") is None else int(meta["size"]),
                    has_issues=bool(meta.get("has_issues", True)),
                    has_wiki=bool(meta.get("has_wiki", False)),
                    extra={
                        "fork": bool(meta.get("fork", False)),
                        "disabled": bool(meta.get("disabled", False)),
                        "visibility": meta.get("visibility"),
                        "tests_present": bool(tree_evidence.get("tests_present")),
                        "ci_present": bool(tree_evidence.get("ci_present")),
                        "readme_present": bool(tree_evidence.get("readme_present")),
                        "dependency_manifests": list(
                            tree_evidence.get("dependency_manifests", [])
                        ),
                        "tree_truncated": tree_evidence.get("tree_truncated"),
                        "security_policy_present": bool(
                            tree_evidence.get("security_policy_present")
                        ),
                        "dependabot_present": bool(tree_evidence.get("dependabot_present")),
                        "codeql_present": bool(tree_evidence.get("codeql_present")),
                        "provenance_tree_sha": tree_evidence.get("provenance_tree_sha"),
                        "release_tag_verified": release_tag is not None,
                        **release_metadata,
                    },
                )
            )
        return candidates
