from __future__ import annotations

import base64
import tempfile
import urllib.parse
import unittest
from pathlib import Path
from typing import Any

from researcher.discovery.github import (
    GitHubDiscoveryProvider,
    _QuotaCheckedApi,
    _CoreQuotaExhausted,
    _SearchQuotaExhausted,
)
from researcher.github_api import GitHubApiError, GitHubResponse
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
        if path == "/repos/owner/repo/license?ref=" + "a" * 40:
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
        if path == "/repos/owner/repo/license?ref=" + "a" * 40:
            self.calls.append(path)
            headers = {"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "9999999999"}
            return GitHubResponse({"license": {"spdx_id": "Apache-2.0"}}, headers)
        return super().get(path)



class FakeLicenseEndpointOnlyApi(FakeNoAssertionGitHubApi):
    def get(self, path: str) -> GitHubResponse:
        if path == "/repos/owner/repo/license?ref=" + "a" * 40:
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
            self.assertIn("/repos/owner/repo/license?ref=" + "a" * 40, api.calls)


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
            self.assertIn("/repos/owner/repo/license?ref=" + "a" * 40, api.calls)

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
        self.assertGreaterEqual(len(queries), 3)
        self.assertTrue(queries[0].startswith("llama cpp vulkan "))
        self.assertTrue(queries[1].startswith("acceleration backend in:name"))
        self.assertTrue(any("acceleration backend" in query for query in queries[1:]))
        self.assertTrue(all("archived:false" in query for query in queries))
        # A concrete upstream vocabulary must not remove taxonomy fallbacks.
        self.assertTrue(any(
            query.startswith("acceleration backend in:name") for query in queries[1:]
        ))

    def test_technical_hints_apply_only_to_known_capabilities(self) -> None:
        examples = {
            "ai.local_inference": "llama cpp android",
            "storage.secrets": "flutter secure storage",
            "release.packaging": "github actions android release",
            "voice.stt": "flutter speech to text",
        }
        for capability, hint in examples.items():
            with self.subTest(capability=capability):
                queries = GitHubDiscoveryProvider._queries(need(capability))
                self.assertTrue(queries[0].startswith(hint + " "))
                self.assertTrue(all("archived:false" in query for query in queries))
                self.assertTrue(any(
                    " ".join(capability.replace(".", " ").replace("_", " ").split()[1:])
                    in query
                    for query in queries[1:]
                ))
        generic = GitHubDiscoveryProvider._queries(need("network.http"))
        self.assertFalse(generic[0].startswith("llama cpp"))

    def test_search_defaults_to_github_best_match_ranking(self) -> None:
        # "sort=updated" was returning recently edited but irrelevant READMEs,
        # pushing actual runtime/storage packages out of the bounded top hits.
        _, api = self._discover("a" * 40)
        searches = [
            path for path in api.calls if path.startswith("/search/repositories?")
        ]
        self.assertTrue(searches)
        self.assertTrue(all("sort=" not in path for path in searches))
        self.assertTrue(all("order=" not in path for path in searches))
        self.assertTrue(all("per_page=1" in path for path in searches))

    def test_precise_query_cannot_starve_capability_fallback(self) -> None:
        class FallbackApi(FakeGitHubApi):
            def get(self, path: str) -> GitHubResponse:
                if path.startswith("/search/repositories?"):
                    self.calls.append(path)
                    # The first, overly specific query contains enough results
                    # to fill the cap. We must still execute capability fallback.
                    precise = "speech-to-text" in urllib.parse.unquote(path).lower()
                    names = (
                        ["owner/repo", "owner/irrelevant"]
                        if precise else ["owner/broad"]
                    )
                    return GitHubResponse(
                        {"items": [{"full_name": name} for name in names]},
                        {"X-RateLimit-Resource": "search",
                         "X-RateLimit-Remaining": "20",
                         "X-RateLimit-Reset": "9999999999"},
                    )
                if path.startswith(("/repos/owner/broad", "/repos/owner/irrelevant")):
                    name = path.split("/")[3]
                    original = super().get(path.replace(f"/{name}", "/repo", 1))
                    if path == f"/repos/owner/{name}" and isinstance(original.data, dict):
                        meta = dict(original.data)
                        meta["full_name"] = f"owner/{name}"
                        meta["name"] = name
                        return GitHubResponse(meta, original.headers)
                    return original
                return super().get(path)

        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FallbackApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, RateLimitManager(state))  # type: ignore[arg-type]
            found = provider.discover(need("network.http"), limit=2)
            self.assertEqual(
                {candidate.repository for candidate in found},
                {"owner/repo", "owner/broad"},
            )
            self.assertEqual(provider.last_discovery_diagnostics["queries_attempted"], 2)
            self.assertEqual(provider.last_discovery_diagnostics["candidates_returned"], 2)


class GitHubDiscoveryDiagnosticsTests(unittest.TestCase):
    def test_search_quota_block_is_visible_without_api_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            rate = RateLimitManager(state)
            rate.observe_headers({
                "X-RateLimit-Resource": "search",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "9999999999",
            })
            api = FakeGitHubApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, rate)  # type: ignore[arg-type]
            self.assertEqual(provider.discover(need("network.http")), [])
            self.assertEqual(api.calls, [])
            self.assertEqual(
                provider.last_discovery_diagnostics["status"], "SEARCH_RATE_LIMITED"
            )
            self.assertEqual(
                provider.last_discovery_diagnostics["queries_attempted"], 0
            )

    def test_exhausted_core_quota_prevents_repository_resolution(self) -> None:
        class SearchBucketApi(FakeGitHubApi):
            def get(self, path: str) -> GitHubResponse:
                response = super().get(path)
                if path.startswith("/search/"):
                    return GitHubResponse(response.data, {
                        "X-RateLimit-Resource": "search",
                        "X-RateLimit-Remaining": "100",
                        "X-RateLimit-Reset": "9999999999",
                    })
                return response

        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            rate = RateLimitManager(state)
            rate.observe_headers({
                "X-RateLimit-Resource": "core",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "9999999999",
            })
            api = SearchBucketApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, rate)  # type: ignore[arg-type]
            self.assertEqual(provider.discover(need("network.http"), limit=1), [])
            self.assertTrue(api.calls)
            self.assertTrue(all(path.startswith("/search/") for path in api.calls))
            self.assertEqual(
                provider.last_discovery_diagnostics["status"], "CORE_RATE_LIMITED"
            )

    def test_search_http_403_quota_exhaustion_returns_diagnostics(self) -> None:
        class SearchExhaustedApi(FakeGitHubApi):
            def get(self, path: str) -> GitHubResponse:
                if path.startswith("/search/"):
                    self.calls.append(path)
                    raise GitHubApiError(403, "rate limit exceeded", {
                        "X-RateLimit-Resource": "search",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "9999999999",
                    })
                return super().get(path)

        with tempfile.TemporaryDirectory() as tmp:
            rate = RateLimitManager(SQLiteStateStore(Path(tmp) / "state.db"))
            api = SearchExhaustedApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, rate)  # type: ignore[arg-type]
            self.assertEqual(provider.discover(need("network.http")), [])
            self.assertEqual(
                provider.last_discovery_diagnostics["status"], "SEARCH_RATE_LIMITED"
            )
            self.assertEqual(
                provider.last_discovery_diagnostics["search_quota_exhausted"], 1
            )
            self.assertFalse(rate.decision(resource="search").allowed)
            self.assertEqual(len(api.calls), 1)

    def test_failed_core_request_persists_quota_and_blocks_followup(self) -> None:
        class ExhaustedApi(FakeGitHubApi):
            def get(self, path: str) -> GitHubResponse:
                self.calls.append(path)
                raise GitHubApiError(403, "rate limit exceeded", {
                    "X-RateLimit-Resource": "core",
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "9999999999",
                })

        with tempfile.TemporaryDirectory() as tmp:
            rate = RateLimitManager(SQLiteStateStore(Path(tmp) / "state.db"))
            api = ExhaustedApi("a" * 40)
            guarded = _QuotaCheckedApi(api, rate)  # type: ignore[arg-type]
            with self.assertRaises(_CoreQuotaExhausted):
                guarded.get("/repos/owner/repo")
            self.assertFalse(rate.decision(resource="core").allowed)
            with self.assertRaises(_CoreQuotaExhausted):
                guarded.get("/repos/owner/other")
            self.assertEqual(api.calls, ["/repos/owner/repo"])

    def test_nested_commit_search_is_blocked_by_exhausted_search_bucket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rate = RateLimitManager(SQLiteStateStore(Path(tmp) / "state.db"))
            rate.observe_headers({
                "X-RateLimit-Resource": "search",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "9999999999",
            })
            api = FakeGitHubApi("a" * 40)
            guarded = _QuotaCheckedApi(api, rate)  # type: ignore[arg-type]
            with self.assertRaises(_SearchQuotaExhausted):
                guarded.get("/search/commits?q=repo%3Aowner%2Frepo")
            self.assertEqual(api.calls, [])

    def test_search_quota_exhausted_does_not_prevent_valid_candidate_resolution(self) -> None:
        class LastSearchCallApi(FakeGitHubApi):
            def get(self, path: str) -> GitHubResponse:
                response = super().get(path)
                if path.startswith("/search/"):
                    return GitHubResponse(response.data, {
                        "X-RateLimit-Resource": "search",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "9999999999",
                    })
                return response

        with tempfile.TemporaryDirectory() as tmp:
            rate = RateLimitManager(SQLiteStateStore(Path(tmp) / "state.db"))
            api = LastSearchCallApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, rate)  # type: ignore[arg-type]
            provider.discover(need("network.http"), limit=1)
            self.assertEqual(
                sum(path.startswith("/search/") for path in api.calls), 1
            )
            self.assertEqual(
                provider.last_discovery_diagnostics["status"], "CANDIDATES_FOUND"
            )

    def test_core_quota_exhausted_after_repository_metadata(self) -> None:
        class OneCoreCallApi(FakeGitHubApi):
            def get(self, path: str) -> GitHubResponse:
                response = super().get(path)
                if path.startswith("/search/"):
                    return GitHubResponse(response.data, {
                        "X-RateLimit-Resource": "search",
                        "X-RateLimit-Remaining": "100",
                        "X-RateLimit-Reset": "9999999999",
                    })
                if path == "/repos/owner/repo":
                    return GitHubResponse(response.data, {
                        "X-RateLimit-Resource": "core",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "9999999999",
                    })
                return response

        with tempfile.TemporaryDirectory() as tmp:
            rate = RateLimitManager(SQLiteStateStore(Path(tmp) / "state.db"))
            api = OneCoreCallApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, rate)  # type: ignore[arg-type]
            self.assertEqual(provider.discover(need("network.http"), limit=1), [])
            self.assertIn("/repos/owner/repo", api.calls)
            self.assertFalse(any("/commits/" in path for path in api.calls))
            self.assertEqual(
                provider.last_discovery_diagnostics["status"], "CORE_RATE_LIMITED"
            )

    def test_empty_search_is_distinct_from_quota_block(self) -> None:
        class EmptySearchApi(FakeGitHubApi):
            def get(self, path: str) -> GitHubResponse:
                if path.startswith("/search/repositories?"):
                    self.calls.append(path)
                    return GitHubResponse(
                        {"items": []},
                        {"X-RateLimit-Resource": "search",
                         "X-RateLimit-Remaining": "10",
                         "X-RateLimit-Reset": "9999999999"},
                    )
                return super().get(path)

        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = EmptySearchApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, RateLimitManager(state))  # type: ignore[arg-type]
            self.assertEqual(provider.discover(need("network.http")), [])
            diagnostics = provider.last_discovery_diagnostics
            self.assertEqual(diagnostics["status"], "NO_SEARCH_HITS")
            self.assertGreater(int(diagnostics["queries_attempted"]), 0)
            self.assertEqual(diagnostics["search_hits"], 0)
            self.assertEqual(diagnostics["candidates_returned"], 0)

    def test_found_candidates_are_counted_without_raw_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeGitHubApi("a" * 40)
            provider = GitHubDiscoveryProvider(api, RateLimitManager(state))  # type: ignore[arg-type]
            self.assertEqual(len(provider.discover(need("network.http"), limit=1)), 1)
            diagnostics = provider.last_discovery_diagnostics
            self.assertEqual(diagnostics["status"], "CANDIDATES_FOUND")
            self.assertEqual(diagnostics["candidates_returned"], 1)
            self.assertEqual(diagnostics["unique_repository_hits"], 1)
            self.assertEqual(diagnostics["search_hits"], 1)
            self.assertNotIn("repository", diagnostics)
            self.assertNotIn("query", diagnostics)


if __name__ == "__main__":
    unittest.main()
