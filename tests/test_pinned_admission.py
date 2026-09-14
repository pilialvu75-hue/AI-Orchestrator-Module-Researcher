from __future__ import annotations

import unittest
from types import SimpleNamespace

from researcher.cli import _parser
from researcher.github_api import GitHubResponse
from researcher.pinned_admission import PinnedCandidateResolver


class FakeRateLimits:
    def decision(self) -> SimpleNamespace:
        return SimpleNamespace(allowed=True, retry_after_seconds=0)

    def observe_headers(self, _headers: dict[str, str]) -> None:
        return None

    def record_backoff(self, _seconds: int, _reason: str) -> None:
        raise AssertionError("backoff should not be used in this test")


class FakeApi:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.paths: list[str] = []

    def get(self, path: str) -> GitHubResponse:
        self.paths.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected GitHub path: {path}")
        return GitHubResponse(data=self.responses[path], headers={})


def _responses(commit_sha: str, tree_sha: str) -> dict[str, object]:
    return {
        "/repos/example/project": {
            "full_name": "example/project",
            "name": "project",
            "html_url": "https://github.com/example/project",
            "default_branch": "main",
            "license": {"spdx_id": "MIT"},
            "owner": {"login": "example"},
            "stargazers_count": 10,
            "forks_count": 2,
            "open_issues_count": 1,
            "pushed_at": "2026-09-14T00:00:00Z",
            "archived": False,
            "language": "Dart",
            "topics": ["http", "client"],
            "description": "HTTP client",
            "homepage": None,
            "size": 500,
            "has_issues": True,
            "has_wiki": False,
            "fork": False,
            "disabled": False,
            "visibility": "public",
        },
        f"/repos/example/project/commits/{commit_sha}": {
            "sha": commit_sha,
            "commit": {"tree": {"sha": tree_sha}},
        },
        f"/repos/example/project/git/trees/{tree_sha}?recursive=1": {
            "sha": tree_sha,
            "truncated": False,
            "tree": [
                {"path": "README.md", "type": "blob"},
                {"path": "LICENSE", "type": "blob"},
                {"path": "pubspec.yaml", "type": "blob"},
                {"path": "pubspec.lock", "type": "blob"},
                {"path": "test/client_test.dart", "type": "blob"},
                {"path": ".github/workflows/ci.yml", "type": "blob"},
            ],
        },
        "/repos/example/project/commits/v1.2.3": {"sha": commit_sha},
    }


class PinnedCandidateResolverTest(unittest.TestCase):
    def test_resolves_exact_commit_and_verified_tag_without_execution(self) -> None:
        commit_sha = "a" * 40
        tree_sha = "b" * 40
        api = FakeApi(_responses(commit_sha, tree_sha))
        resolver = PinnedCandidateResolver(api, FakeRateLimits())  # type: ignore[arg-type]

        candidate = resolver.resolve(
            "example/project",
            commit_sha,
            release_tag="v1.2.3",
            source_version="1.2.3",
        )

        self.assertEqual(candidate.repository, "example/project")
        self.assertEqual(candidate.commit_sha, commit_sha)
        self.assertEqual(candidate.release_tag, "v1.2.3")
        self.assertEqual(candidate.license_spdx, "MIT")
        self.assertTrue(candidate.extra["tests_present"])
        self.assertTrue(candidate.extra["ci_present"])
        self.assertEqual(
            candidate.extra["dependency_manifests"],
            ["pubspec.lock", "pubspec.yaml"],
        )
        self.assertEqual(candidate.extra["provenance_tree_sha"], tree_sha)
        self.assertTrue(candidate.extra["release_tag_verified"])
        self.assertTrue(candidate.extra["pinned_admission"])

    def test_rejects_tag_that_does_not_resolve_to_pinned_commit(self) -> None:
        commit_sha = "a" * 40
        tree_sha = "b" * 40
        responses = _responses(commit_sha, tree_sha)
        responses["/repos/example/project/commits/v1.2.3"] = {"sha": "c" * 40}
        resolver = PinnedCandidateResolver(
            FakeApi(responses),
            FakeRateLimits(),  # type: ignore[arg-type]
        )

        with self.assertRaisesRegex(ValueError, "does not resolve"):
            resolver.resolve(
                "example/project",
                commit_sha,
                release_tag="v1.2.3",
            )

    def test_rejects_non_exact_commit(self) -> None:
        resolver = PinnedCandidateResolver(
            FakeApi({}),
            FakeRateLimits(),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(ValueError, "40-character"):
            resolver.resolve("example/project", "abc123")

    def test_cli_exposes_explicit_pinned_admission(self) -> None:
        commit_sha = "d" * 40
        args = _parser().parse_args(
            [
                "admit-pinned",
                "--capability",
                "network.http",
                "--repository",
                "dart-lang/http",
                "--commit",
                commit_sha,
                "--source-version",
                "1.6.0",
            ]
        )
        self.assertEqual(args.command, "admit-pinned")
        self.assertEqual(args.capability_id, "network.http")
        self.assertEqual(args.repository, "dart-lang/http")
        self.assertEqual(args.commit_sha, commit_sha)
        self.assertEqual(args.source_version, "1.6.0")
        self.assertFalse(args.rescan)


if __name__ == "__main__":
    unittest.main()
