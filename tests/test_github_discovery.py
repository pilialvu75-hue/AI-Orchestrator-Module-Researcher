from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from researcher.discovery.github import GitHubDiscoveryProvider
from researcher.github_api import GitHubResponse
from researcher.rate_limit import RateLimitManager
from researcher.state import SQLiteStateStore

from helpers import need


class FakeGitHubApi:
    def __init__(self, tag_sha: str) -> None:
        self.tag_sha = tag_sha
        self.calls: list[str] = []

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(path)
        headers = {"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "9999999999"}
        sha = "a" * 40
        if path.startswith("/search/repositories?"):
            return GitHubResponse({"items": [{"full_name": "owner/repo"}]}, headers)
        if path == "/repos/owner/repo":
            return GitHubResponse(
                {
                    "full_name": "owner/repo",
                    "html_url": "https://github.com/owner/repo",
                    "name": "repo",
                    "owner": {"login": "owner"},
                    "default_branch": "main",
                    "license": {"spdx_id": "MIT", "url": "https://api.github.com/licenses/mit"},
                    "stargazers_count": 10,
                    "forks_count": 2,
                    "open_issues_count": 1,
                    "pushed_at": "2026-09-11T00:00:00Z",
                    "archived": False,
                    "disabled": False,
                    "language": "Dart",
                    "topics": ["http"],
                    "description": "HTTP client",
                    "homepage": None,
                    "size": 100,
                    "has_issues": True,
                    "has_wiki": False,
                    "visibility": "public",
                    "fork": False,
                },
                headers,
            )
        if path == "/repos/owner/repo/commits/main":
            return GitHubResponse(
                {"sha": sha, "commit": {"tree": {"sha": "tree123"}}}, headers
            )
        if path == "/repos/owner/repo/releases/latest":
            return GitHubResponse({"tag_name": "v1.0.0"}, headers)
        if path == "/repos/owner/repo/commits/v1.0.0":
            return GitHubResponse({"sha": self.tag_sha}, headers)
        if path == "/repos/owner/repo/git/trees/tree123?recursive=1":
            return GitHubResponse(
                {
                    "truncated": False,
                    "tree": [
                        {"path": "README.md"},
                        {"path": "LICENSE"},
                        {"path": "SECURITY.md"},
                        {"path": ".github/dependabot.yml"},
                        {"path": ".github/workflows/codeql.yml"},
                        {"path": "packages/core/pubspec.yaml"},
                        {"path": "packages/core/test/client_test.dart"},
                    ],
                },
                headers,
            )
        raise AssertionError(f"unexpected path: {path}")


class GitHubDiscoveryTests(unittest.TestCase):
    def _discover(self, tag_sha: str) -> tuple[Any, FakeGitHubApi]:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeGitHubApi(tag_sha)
            provider = GitHubDiscoveryProvider(api, RateLimitManager(state))  # type: ignore[arg-type]
            candidates = provider.discover(need("network.http"), limit=1)
            self.assertEqual(len(candidates), 1)
            return candidates[0], api

    def test_pins_license_file_and_recursive_evidence(self) -> None:
        sha = "a" * 40
        candidate, api = self._discover(sha)
        self.assertEqual(candidate.release_tag, "v1.0.0")
        self.assertEqual(
            candidate.license_file_url,
            f"https://github.com/owner/repo/blob/{sha}/LICENSE",
        )
        self.assertTrue(candidate.extra["tests_present"])
        self.assertTrue(candidate.extra["ci_present"])
        self.assertTrue(candidate.extra["security_policy_present"])
        self.assertTrue(candidate.extra["dependabot_present"])
        self.assertTrue(candidate.extra["codeql_present"])
        self.assertEqual(candidate.extra["dependency_manifests"], ["packages/core/pubspec.yaml"])
        self.assertIn("/repos/owner/repo/git/trees/tree123?recursive=1", api.calls)

    def test_does_not_attach_unrelated_latest_release(self) -> None:
        candidate, _ = self._discover("b" * 40)
        self.assertIsNone(candidate.release_tag)
        self.assertFalse(candidate.extra["release_tag_verified"])


if __name__ == "__main__":
    unittest.main()
