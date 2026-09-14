from __future__ import annotations

import json
import re
import tomllib
import urllib.parse
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from .github_api import GitHubApi, GitHubResponse
from .models import Candidate
from .pinned_admission import PinnedCandidateResolver, admit_pinned_candidate
from .rate_limit import RateLimitManager

if TYPE_CHECKING:
    from .app import App

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
_DEPENDENCY_MANIFESTS = {
    "build.gradle",
    "build.gradle.kts",
    "cargo.lock",
    "cargo.toml",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pom.xml",
    "pubspec.lock",
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


def normalize_component_path(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    raw = value.strip()
    if (
        raw.startswith(("/", ".", "~"))
        or raw.endswith("/")
        or "\\" in raw
        or "\x00" in raw
    ):
        raise ValueError("component path must be a safe relative repository path")
    segments = raw.split("/")
    if any(
        not segment
        or segment in {".", ".."}
        or not _SAFE_SEGMENT.fullmatch(segment)
        for segment in segments
    ):
        raise ValueError("component path contains an unsafe segment")
    return "/".join(segments)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _in_scope(path: str, component_path: str) -> bool:
    return path == component_path or path.startswith(component_path + "/")


def _decode_contents(response: GitHubResponse) -> str | None:
    payload = response.data if isinstance(response.data, dict) else {}
    if payload.get("encoding") != "base64" or not payload.get("content"):
        return None
    import base64
    import binascii

    encoded = str(payload["content"]).replace("\n", "")
    try:
        raw = base64.b64decode(encoded, validate=True)
        return raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _component_metadata(
    path: str,
    filename: str,
    content: str,
) -> tuple[str | None, str | None]:
    lower = filename.lower()
    if lower == "pubspec.yaml":
        name: str | None = None
        description: str | None = None
        for raw_line in content.splitlines():
            if raw_line.startswith("name:"):
                name = raw_line.split(":", 1)[1].strip().strip("'\"") or None
            elif raw_line.startswith("description:"):
                value = raw_line.split(":", 1)[1].strip().strip("'\"")
                if value and value not in {">", ">-", "|", "|-"}:
                    description = value
            if name and description:
                break
        return name, description
    if lower == "package.json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return None, None
        if not isinstance(payload, dict):
            return None, None
        raw_name = payload.get("name")
        raw_description = payload.get("description")
        return (
            str(raw_name) if isinstance(raw_name, str) and raw_name else None,
            (
                str(raw_description)
                if isinstance(raw_description, str) and raw_description
                else None
            ),
        )
    if lower in {"cargo.toml", "pyproject.toml"}:
        try:
            payload = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return None, None
        section = (
            payload.get("package")
            if lower == "cargo.toml"
            else payload.get("project")
        )
        if not isinstance(section, dict):
            return None, None
        raw_name = section.get("name")
        raw_description = section.get("description")
        return (
            str(raw_name) if isinstance(raw_name, str) and raw_name else None,
            (
                str(raw_description)
                if isinstance(raw_description, str) and raw_description
                else None
            ),
        )
    return None, None


class ComponentCandidateResolver:
    """Resolve an immutable candidate and optionally scope it to one monorepo component."""

    def __init__(self, api: GitHubApi, rate_limits: RateLimitManager) -> None:
        self.api = api
        self.rate_limits = rate_limits
        self.base = PinnedCandidateResolver(api, rate_limits)

    def _get(self, path: str) -> GitHubResponse:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            self.rate_limits.record_backoff(
                decision.retry_after_seconds,
                "component_candidate_rate_limit",
            )
            raise RuntimeError(
                f"GitHub rate limit exhausted; retry after {decision.retry_after_seconds}s"
            )
        response = self.api.get(path)
        self.rate_limits.observe_headers(response.headers)
        return response

    def _component_signals(
        self,
        candidate: Candidate,
        component_path: str,
    ) -> dict[str, Any]:
        tree_sha = str(candidate.extra.get("provenance_tree_sha") or "")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", tree_sha):
            raise RuntimeError("component candidate has no verified root tree SHA")
        repository_path = "/".join(
            urllib.parse.quote(part, safe="")
            for part in candidate.repository.split("/", 1)
        )
        tree_response = self._get(
            f"/repos/{repository_path}/git/trees/{tree_sha}?recursive=1"
        )
        tree_data = (
            tree_response.data
            if isinstance(tree_response.data, dict)
            else {}
        )
        if str(tree_data.get("sha") or "") != tree_sha:
            raise RuntimeError("component tree provenance mismatch")
        if bool(tree_data.get("truncated", False)):
            raise RuntimeError("component repository tree is truncated; fail closed")
        raw_entries = tree_data.get("tree")
        if not isinstance(raw_entries, list):
            raise RuntimeError("component repository tree response is invalid")
        entries = [
            item
            for item in raw_entries
            if isinstance(item, dict)
            and _in_scope(str(item.get("path") or ""), component_path)
        ]
        if not entries:
            raise ValueError("component path does not exist at the pinned commit")

        paths = [
            str(item.get("path") or "")
            for item in entries
            if item.get("path")
        ]
        lower_paths = [path.lower() for path in paths]
        manifests = sorted(
            path
            for path in paths
            if _basename(path.lower()) in _DEPENDENCY_MANIFESTS
        )[:100]
        local_licenses = sorted(
            path
            for path in paths
            if _basename(path.lower()) in _LICENSE_FILES
            and path.rsplit("/", 1)[0] == component_path
        )
        license_file_url = candidate.license_file_url
        if local_licenses:
            encoded = urllib.parse.quote(local_licenses[0], safe="/")
            license_file_url = (
                f"https://github.com/{candidate.repository}/blob/"
                f"{candidate.commit_sha}/{encoded}"
            )

        name = _basename(component_path)
        description: str | None = None
        preferred = [
            "pubspec.yaml",
            "package.json",
            "cargo.toml",
            "pyproject.toml",
        ]
        by_name = {_basename(path.lower()): path for path in manifests}
        for manifest_name in preferred:
            manifest_path = by_name.get(manifest_name)
            if manifest_path is None:
                continue
            encoded_path = urllib.parse.quote(manifest_path, safe="/")
            ref = urllib.parse.quote(candidate.commit_sha, safe="")
            response = self._get(
                f"/repos/{repository_path}/contents/{encoded_path}?ref={ref}"
            )
            content = _decode_contents(response)
            if content is None:
                continue
            manifest_name_value, manifest_description = _component_metadata(
                manifest_path,
                manifest_name,
                content,
            )
            if manifest_name_value:
                name = manifest_name_value
            if manifest_description:
                description = manifest_description
            break

        return {
            "name": name,
            "description": description,
            "license_file_url": license_file_url,
            "dependency_manifests": manifests,
            "tests_present": any(
                any(segment in _TEST_DIRS for segment in path.split("/"))
                or _basename(path).endswith("_test.dart")
                or _basename(path).startswith("test_")
                for path in lower_paths
            ),
            "readme_present": any(
                _basename(path).startswith("readme") for path in lower_paths
            ),
            "component_entry_count": len(entries),
            "component_local_license": bool(local_licenses),
        }

    def resolve(
        self,
        repository: str,
        commit_sha: str,
        *,
        release_tag: str | None = None,
        source_version: str | None = None,
        component_path: str | None = None,
    ) -> Candidate:
        candidate = self.base.resolve(
            repository,
            commit_sha,
            release_tag=release_tag,
            source_version=source_version,
        )
        normalized = normalize_component_path(component_path)
        if normalized is None:
            return candidate

        signals = self._component_signals(candidate, normalized)
        extra = dict(candidate.extra)
        extra.update(
            {
                "component_path": normalized,
                "dependency_manifests": list(signals["dependency_manifests"]),
                "tests_present": bool(signals["tests_present"]),
                "readme_present": bool(signals["readme_present"]),
                "component_entry_count": int(signals["component_entry_count"]),
                "component_local_license": bool(signals["component_local_license"]),
            }
        )
        return replace(
            candidate,
            name=str(signals["name"]),
            description=(
                candidate.description
                if signals["description"] is None
                else str(signals["description"])
            ),
            license_file_url=(
                None
                if signals["license_file_url"] is None
                else str(signals["license_file_url"])
            ),
            extra=extra,
        )


def resolve_and_admit_component_candidate(
    app: App,
    capability_id: str,
    repository: str,
    commit_sha: str,
    *,
    release_tag: str | None = None,
    source_version: str | None = None,
    component_path: str | None = None,
    rescan: bool = False,
) -> dict[str, Any]:
    api = GitHubApi(
        app.config.github_token,
        app.config.github_api_base,
        uploads_base_url=app.config.github_uploads_base,
    )
    resolver = ComponentCandidateResolver(api, RateLimitManager(app.state))
    candidate = resolver.resolve(
        repository,
        commit_sha,
        release_tag=release_tag,
        source_version=source_version,
        component_path=component_path,
    )
    return admit_pinned_candidate(
        app,
        candidate,
        capability_id,
        rescan=rescan,
    )
