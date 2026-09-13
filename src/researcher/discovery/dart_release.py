from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass
from typing import Callable

from ..github_api import GitHubApi, GitHubApiError, GitHubResponse


_STABLE_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:\+\d+)?$")
_CHANGELOG_VERSION = re.compile(r"^#{1,6}\s+\[?(\d+\.\d+\.\d+(?:\+\d+)?)\]?\s*$")


@dataclass(frozen=True)
class DartSourceResolution:
    commit_sha: str
    source_version: str | None
    source_stable: bool | None
    manifest_path: str | None
    strategy: str
    latest_stable_version: str | None = None


class DartStableReleaseResolver:
    """Resolve a Dart package to a verifiable stable source commit when possible.

    The resolver is deliberately conservative. It never invents a tag and never
    treats an unstable branch-tip manifest as a stable release. For monorepos it
    prefers a pubspec whose package name matches the repository name, then verifies
    any historical commit by reading the same manifest at that immutable SHA.
    """

    def __init__(
        self,
        api: GitHubApi,
        observe: Callable[[GitHubResponse], None],
    ) -> None:
        self.api = api
        self.observe = observe

    @staticmethod
    def _basename(path: str) -> str:
        return path.rsplit("/", 1)[-1]

    @staticmethod
    def _parent_name(path: str) -> str:
        parts = path.split("/")
        return "" if len(parts) < 2 else parts[-2]

    @staticmethod
    def _scalar(text: str, key: str) -> str | None:
        prefix = f"{key}:"
        for raw in text.splitlines():
            if raw.startswith((" ", "\t", "#")):
                continue
            if not raw.startswith(prefix):
                continue
            value = raw[len(prefix) :].strip().strip("\"'")
            return value or None
        return None

    @staticmethod
    def _is_stable(version: str | None) -> bool:
        return bool(version and _STABLE_VERSION.fullmatch(version))

    @staticmethod
    def _latest_stable_from_changelog(text: str) -> str | None:
        for raw in text.splitlines():
            match = _CHANGELOG_VERSION.match(raw.strip())
            if match:
                return match.group(1)
        return None

    def _text_file(self, full_name: str, path: str, ref: str) -> str | None:
        encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        encoded_ref = urllib.parse.quote(ref, safe="")
        try:
            response = self.api.get(
                f"/repos/{full_name}/contents/{encoded_path}?ref={encoded_ref}"
            )
            self.observe(response)
        except GitHubApiError as exc:
            if exc.status in {403, 404, 422}:
                return None
            raise
        payload = response.data if isinstance(response.data, dict) else {}
        raw_content = payload.get("content")
        if raw_content is None:
            return None
        try:
            return base64.b64decode(str(raw_content).replace("\n", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def _select_manifest(
        self,
        full_name: str,
        repo_name: str,
        ref: str,
        manifest_paths: list[str],
    ) -> tuple[str, str, str] | None:
        repo_key = repo_name.lower().replace("-", "_")

        def rank(path: str) -> tuple[int, int, str]:
            parent = self._parent_name(path).lower().replace("-", "_")
            if path.lower() == "pubspec.yaml":
                return (0, len(path), path)
            if parent == repo_key:
                return (1, len(path), path)
            return (10, len(path), path)

        for path in sorted(manifest_paths, key=rank)[:12]:
            if self._basename(path).lower() != "pubspec.yaml":
                continue
            parent = self._parent_name(path).lower().replace("-", "_")
            if path.lower() != "pubspec.yaml" and parent != repo_key:
                continue
            text = self._text_file(full_name, path, ref)
            if text is None:
                continue
            package_name = self._scalar(text, "name")
            version = self._scalar(text, "version")
            if package_name and version:
                package_key = package_name.lower().replace("-", "_")
                if package_key == repo_key:
                    return path, package_name, version
        return None

    def _find_verified_stable_commit(
        self,
        full_name: str,
        manifest_path: str,
        package_name: str,
        stable_version: str,
    ) -> str | None:
        query = urllib.parse.quote(
            f'repo:{full_name} "{package_name}" "{stable_version}"',
            safe="",
        )
        try:
            response = self.api.get(
                f"/search/commits?q={query}&sort=committer-date&order=desc&per_page=10"
            )
            self.observe(response)
        except GitHubApiError as exc:
            if exc.status in {403, 404, 422}:
                return None
            raise
        data = response.data if isinstance(response.data, dict) else {}
        raw_items = data.get("items")
        items = raw_items if isinstance(raw_items, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            sha = str(item.get("sha", ""))
            if len(sha) < 12:
                continue
            manifest = self._text_file(full_name, manifest_path, sha)
            if manifest is None:
                continue
            if self._scalar(manifest, "name") != package_name:
                continue
            if self._scalar(manifest, "version") == stable_version:
                return sha
        return None

    def resolve(
        self,
        full_name: str,
        repo_name: str,
        branch_sha: str,
        dependency_manifests: list[str],
    ) -> DartSourceResolution:
        pubspecs = [
            path
            for path in dependency_manifests
            if self._basename(path).lower() == "pubspec.yaml"
        ]
        selected = self._select_manifest(full_name, repo_name, branch_sha, pubspecs)
        if selected is None:
            return DartSourceResolution(
                commit_sha=branch_sha,
                source_version=None,
                source_stable=None,
                manifest_path=None,
                strategy="repository_tip_no_matching_pubspec",
            )

        manifest_path, package_name, current_version = selected
        if self._is_stable(current_version):
            return DartSourceResolution(
                commit_sha=branch_sha,
                source_version=current_version,
                source_stable=True,
                manifest_path=manifest_path,
                strategy="dart_manifest_current_commit",
                latest_stable_version=current_version,
            )

        prefix = manifest_path.rsplit("/", 1)[0] if "/" in manifest_path else ""
        changelog_path = f"{prefix}/CHANGELOG.md" if prefix else "CHANGELOG.md"
        changelog = self._text_file(full_name, changelog_path, branch_sha)
        stable_version = (
            None if changelog is None else self._latest_stable_from_changelog(changelog)
        )
        if stable_version is None:
            return DartSourceResolution(
                commit_sha=branch_sha,
                source_version=current_version,
                source_stable=False,
                manifest_path=manifest_path,
                strategy="dart_manifest_unstable_no_stable_changelog",
            )

        stable_sha = self._find_verified_stable_commit(
            full_name,
            manifest_path,
            package_name,
            stable_version,
        )
        if stable_sha is None:
            return DartSourceResolution(
                commit_sha=branch_sha,
                source_version=current_version,
                source_stable=False,
                manifest_path=manifest_path,
                strategy="dart_manifest_unstable_stable_commit_unresolved",
                latest_stable_version=stable_version,
            )

        return DartSourceResolution(
            commit_sha=stable_sha,
            source_version=stable_version,
            source_stable=True,
            manifest_path=manifest_path,
            strategy="dart_changelog_verified_stable_commit",
            latest_stable_version=stable_version,
        )
