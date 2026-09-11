from __future__ import annotations

import urllib.parse
from typing import Any

from ..github_api import GitHubApi, GitHubApiError
from ..models import Candidate, Need, utc_now
from ..rate_limit import RateLimitManager


class GitHubDiscoveryProvider:
    name = "github"

    def __init__(self, api: GitHubApi, rate_limits: RateLimitManager) -> None:
        self.api = api
        self.rate_limits = rate_limits

    @staticmethod
    def _query(need: Need) -> str:
        title_terms = " ".join(
            word for word in need.title.replace("/", " ").split() if len(word) >= 4
        )
        capability_terms = " ".join(need.capability_id.replace(".", " ").split())
        return f"{title_terms} {capability_terms} in:name,description,readme archived:false"

    def discover(self, need: Need, limit: int = 8) -> list[Candidate]:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            self.rate_limits.record_backoff(
                decision.retry_after_seconds,
                "github_rate_limit",
            )
            return []
        query = urllib.parse.quote(self._query(need), safe="")
        response = self.api.get(
            f"/search/repositories?q={query}&sort=updated&order=desc&per_page={min(limit, 20)}"
        )
        self.rate_limits.observe_headers(response.headers)
        data = response.data
        items = data.get("items", []) if isinstance(data, dict) else []
        candidates: list[Candidate] = []
        for raw in items:
            if not isinstance(raw, dict):
                continue
            full_name = str(raw.get("full_name", ""))
            if not full_name or "/" not in full_name:
                continue
            repo = self.api.get(f"/repos/{full_name}")
            self.rate_limits.observe_headers(repo.headers)
            meta = repo.data if isinstance(repo.data, dict) else {}
            branch = str(meta.get("default_branch") or "main")
            commit = self.api.get(
                f"/repos/{full_name}/commits/{urllib.parse.quote(branch, safe='')}"
            )
            self.rate_limits.observe_headers(commit.headers)
            commit_data = commit.data if isinstance(commit.data, dict) else {}
            sha = str(commit_data.get("sha", ""))
            if len(sha) < 12:
                continue

            release_tag: str | None = None
            try:
                release = self.api.get(f"/repos/{full_name}/releases/latest")
                self.rate_limits.observe_headers(release.headers)
                release_data = release.data if isinstance(release.data, dict) else {}
                if release_data.get("tag_name"):
                    release_tag = str(release_data["tag_name"])
            except GitHubApiError as exc:
                if exc.status != 404:
                    raise

            root_names: set[str] = set()
            try:
                contents = self.api.get(f"/repos/{full_name}/contents")
                self.rate_limits.observe_headers(contents.headers)
                if isinstance(contents.data, list):
                    root_names = {
                        str(item.get("name", "")).lower()
                        for item in contents.data
                        if isinstance(item, dict)
                    }
            except GitHubApiError as exc:
                if exc.status not in {403, 404}:
                    raise

            license_spdx: str | None = None
            license_url: str | None = None
            license_meta = meta.get("license")
            if isinstance(license_meta, dict):
                key = license_meta.get("spdx_id")
                license_spdx = None if key in {None, "NOASSERTION"} else str(key)
                license_url = (
                    None if license_meta.get("url") is None else str(license_meta["url"])
                )

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
                    name=str(meta.get("name") or full_name.split("/", 1)[1]),
                    commit_sha=sha,
                    release_tag=release_tag,
                    default_branch=branch,
                    acquired_at=utc_now(),
                    license_spdx=license_spdx,
                    license_file_url=license_url,
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
                        "tests_present": bool(
                            root_names.intersection({"test", "tests", "spec", "specs"})
                        ),
                        "ci_present": ".github" in root_names,
                        "readme_present": any(name.startswith("readme") for name in root_names),
                        "dependency_manifests": sorted(
                            root_names.intersection(
                                {
                                    "pyproject.toml",
                                    "requirements.txt",
                                    "package.json",
                                    "pubspec.yaml",
                                    "cargo.toml",
                                    "go.mod",
                                    "pom.xml",
                                    "build.gradle",
                                    "build.gradle.kts",
                                }
                            )
                        ),
                    },
                )
            )
        return candidates
