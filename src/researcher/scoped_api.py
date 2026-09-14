from __future__ import annotations

from typing import Any

from .github_api import GitHubApi, GitHubResponse


class ScopedLibraryWriteApi(GitHubApi):
    """Route Library operations to the writer credential and upstream reads elsewhere.

    `GitHubIntakePrSubmissionClient` also fetches immutable upstream LICENSE content. This
    router prevents the Library writer credential from being sent to unrelated upstream
    repositories while preserving the client's existing GitHubApi interface.
    """

    def __init__(
        self,
        source_api: GitHubApi,
        library_api: GitHubApi,
        library_repository: str,
    ) -> None:
        if library_repository.count("/") != 1:
            raise ValueError("library repository must be owner/name")
        self._source_api = source_api
        self._library_api = library_api
        self._library_prefix = f"/repos/{library_repository}/"

    def _is_library_path(self, path: str) -> bool:
        return path.startswith(self._library_prefix)

    def _require_library_path(self, path: str) -> None:
        if not self._is_library_path(path):
            raise ValueError("Library writer credential cannot be used outside Library repo")

    def get(self, path: str) -> GitHubResponse:
        if self._is_library_path(path):
            return self._library_api.get(path)
        return self._source_api.get(path)

    def post(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self._require_library_path(path)
        return self._library_api.post(path, payload)

    def put(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self._require_library_path(path)
        return self._library_api.put(path, payload)

    def patch(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self._require_library_path(path)
        return self._library_api.patch(path, payload)

    def delete(self, path: str) -> GitHubResponse:
        self._require_library_path(path)
        return self._library_api.delete(path)
