from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from typing import Any

from researcher.discovery.github import GitHubDiscoveryProvider
from researcher.github_api import GitHubResponse
from researcher.rate_limit import RateLimitManager
from researcher.state import SQLiteStateStore

from helpers import need


def encoded(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


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


class FakeNoAssertionGitHubApi(FakeGitHubApi):
    def get(self, path: str) -> GitHubResponse:
        if path == "/repos/owner/repo/license":
            self.calls.append(path)
            headers = {"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "9999999999"}
            return GitHubResponse({"license": {"spdx_id": "NOASSERTION"}}, headers)
        response = super().get(path)
        if path == "/repos/owner/repo" and isinstance(response.data, dict):
            data = dict(response.data)
            data["license"] = {"spdx_id": "NOASSERTION"}
            return GitHubResponse(data, response.headers)
        return response


class FakeRecoveredLicenseGitHubApi(FakeNoAssertionGitHubApi):
    def get(self, path: str) -> GitHubResponse:
        if path == "/repos/owner/repo/license":
            self.calls.append(path)
            headers = {"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "9999999999"}
            return GitHubResponse({"license": {"spdx_id": "Apache-2.0"}}, headers)
        return super().get(path)



class FakeLicenseEndpointOnlyApi(FakeNoAssertionGitHubApi):
    def get(self, path: str) -> GitHubResponse:
        if path == "/repos/owner/repo/license":
            self.calls.append(path)
            headers = {"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "9999999999"}
            return GitHubResponse(
                {"path": "LICENSE.txt", "license": {"spdx_id": "MIT"}},
                headers,
            )
        response = super().get(path)
        if path == "/repos/owner/repo/git/trees/tree123?recursive=1" and isinstance(
            response.data, dict
        ):
            data = dict(response.data)
            data["tree"] = [
                entry
                for entry in data.get("tree", [])
                if entry.get("path") != "LICENSE"
            ]
            return GitHubResponse(data, response.headers)
        return response


class FakeDartMonorepoApi:
    def __init__(self, resolve_stable: bool = True) -> None:
        self.resolve_stable = resolve_stable
        self.calls: list[str] = []
        self.branch_sha = "a" * 40
        self.stable_sha = "b" * 40
        self.unrelated_tag_sha = "c" * 40

    @staticmethod
    def _meta() -> dict[str, Any]:
        return {
            "full_name": "dart-lang/http",
            "html_url": "https://github.com/dart-lang/http",
            "name": "http",
            "owner": {"login": "dart-lang"},
            "default_branch": "master",
            "license": {"spdx_id": "BSD-3-Clause"},
            "stargazers_count": 1000,
            "forks_count": 400,
            "open_issues_count": 100,
            "pushed_at": "2026-09-10T00:00:00Z",
            "archived": False,
            "disabled": False,
            "language": "Dart",
            "topics": ["dart", "flutter", "http"],
            "description": "A composable API for HTTP requests",
            "homepage": "https://pub.dev/packages/http",
            "size": 6400,
            "has_issues": True,
            "has_wiki": True,
            "visibility": "public",
            "fork": False,
        }

    @staticmethod
    def _tree(tree_sha: str) -> GitHubResponse:
        headers = {"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "9999999999"}
        return GitHubResponse(
            {
                "truncated": False,
                "sha": tree_sha,
                "tree": [
                    {"path": "LICENSE"},
                    {"path": "README.md"},
                    {"path": ".github/workflows/dart.yml"},
                    {"path": "pkgs/http/pubspec.yaml"},
                    {"path": "pkgs/http/CHANGELOG.md"},
                    {"path": "pkgs/http/test/client_test.dart"},
                ],
            },
            headers,
        )

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(path)
        headers = {"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "9999999999"}
        if path.startswith("/search/repositories?"):
            return GitHubResponse({"items": [{"full_name": "dart-lang/http"}]}, headers)
        if path == "/repos/dart-lang/http":
            return GitHubResponse(self._meta(), headers)
        if path == "/repos/dart-lang/http/commits/master":
            return GitHubResponse(
                {"sha": self.branch_sha, "commit": {"tree": {"sha": "tiptree"}}},
                headers,
            )
        if path == "/repos/dart-lang/http/git/trees/tiptree?recursive=1":
            return self._tree("tiptree")
        if path.startswith("/repos/dart-lang/http/contents/pkgs/http/pubspec.yaml?ref="):
            ref = path.rsplit("=", 1)[-1]
            version = "1.6.0" if ref == self.stable_sha else "1.7.0-wip"
            return GitHubResponse(
                {"content": encoded(f"name: http\nversion: {version}\n")}, headers
            )
        if path.startswith("/repos/dart-lang/http/contents/pkgs/http/CHANGELOG.md?ref="):
            return GitHubResponse(
                {"content": encoded("## 1.7.0-wip\n\n## 1.6.0\n\n## 1.5.0\n")},
                headers,
            )
        if path.startswith("/search/commits?"):
            items = [{"sha": self.stable_sha}] if self.resolve_stable else []
            return GitHubResponse({"items": items}, headers)
        if path == f"/repos/dart-lang/http/commits/{self.stable_sha}":
            return GitHubResponse(
                {"sha": self.stable_sha, "commit": {"tree": {"sha": "stabletree"}}},
                headers,
            )
        if path == "/repos/dart-lang/http/git/trees/stabletree?recursive=1":
            return self._tree("stabletree")
        if path == "/repos/dart-lang/http/releases/latest":
            return GitHubResponse({"tag_name": "web_socket-v3.0.3"}, headers)
        if path == "/repos/dart-lang/http/commits/web_socket-v3.0.3":
            return GitHubResponse({"sha": self.unrelated_tag_sha}, headers)
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

    def _discover_dart(self, resolve_stable: bool) -> tuple[Any, FakeDartMonorepoApi]:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeDartMonorepoApi(resolve_stable=resolve_stable)
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

    def test_preserves_github_noassertion_for_license_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeNoAssertionGitHubApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, RateLimitManager(state))  # type: ignore[arg-type]
            candidates = provider.discover(need("network.http"), limit=1)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].license_spdx, "NOASSERTION")

    def test_recovers_license_from_github_license_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeRecoveredLicenseGitHubApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, RateLimitManager(state))  # type: ignore[arg-type]
            candidates = provider.discover(need("network.http"), limit=1)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].license_spdx, "Apache-2.0")
            self.assertEqual(
                candidates[0].extra["license_detection_source"],
                "github_license_endpoint",
            )
            self.assertIn("/repos/owner/repo/license", api.calls)


    def test_recovers_license_even_when_tree_has_no_license_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeLicenseEndpointOnlyApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, RateLimitManager(state))  # type: ignore[arg-type]
            candidates = provider.discover(need("network.http"), limit=1)
            self.assertEqual(len(candidates), 1)
            item = candidates[0]
            self.assertEqual(item.license_spdx, "MIT")
            self.assertEqual(
                item.license_file_url,
                f"https://github.com/owner/repo/blob/{'a' * 40}/LICENSE.txt",
            )
            self.assertEqual(
                item.extra["license_detection_source"],
                "github_license_endpoint",
            )
            self.assertIn("/repos/owner/repo/license", api.calls)

    def test_does_not_attach_unrelated_latest_release(self) -> None:
        candidate, _ = self._discover("b" * 40)
        self.assertIsNone(candidate.release_tag)
        self.assertFalse(candidate.extra["release_tag_verified"])

    def test_resolves_unstable_dart_tip_to_verified_stable_commit(self) -> None:
        candidate, api = self._discover_dart(resolve_stable=True)
        self.assertEqual(candidate.commit_sha, api.stable_sha)
        self.assertEqual(candidate.extra["source_version"], "1.6.0")
        self.assertTrue(candidate.extra["source_stable"])
        self.assertEqual(
            candidate.extra["release_resolution_strategy"],
            "dart_changelog_verified_stable_commit",
        )
        self.assertEqual(candidate.extra["source_manifest_path"], "pkgs/http/pubspec.yaml")
        self.assertIsNone(candidate.release_tag)
        self.assertEqual(
            candidate.license_file_url,
            f"https://github.com/dart-lang/http/blob/{api.stable_sha}/LICENSE",
        )

    def test_marks_unresolved_dart_tip_unstable(self) -> None:
        candidate, api = self._discover_dart(resolve_stable=False)
        self.assertEqual(candidate.commit_sha, api.branch_sha)
        self.assertEqual(candidate.extra["source_version"], "1.7.0-wip")
        self.assertFalse(candidate.extra["source_stable"])
        self.assertEqual(candidate.extra["latest_stable_version"], "1.6.0")
        self.assertEqual(
            candidate.extra["release_resolution_strategy"],
            "dart_manifest_unstable_stable_commit_unresolved",
        )


    def test_query_fallback_relaxes_internal_capability_taxonomy(self) -> None:
        requested = need("ai.acceleration_backend")
        queries = GitHubDiscoveryProvider._queries(requested)
        self.assertGreaterEqual(len(queries), 2)
        self.assertIn("acceleration backend", queries[0])
        self.assertTrue(any("acceleration backend" in query for query in queries))
        self.assertTrue(all("archived:false" in query for query in queries))

if __name__ == "__main__":
    unittest.main()
