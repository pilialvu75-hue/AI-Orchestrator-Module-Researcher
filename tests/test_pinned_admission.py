from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from researcher.cli import _parser
from researcher.comparison import ComparisonEngine
from researcher.dossiers import DossierStore
from researcher.engine import ResearchEngine
from researcher.github_api import GitHubResponse
from researcher.models import ResearchMode
from researcher.observability import EventLogger
from researcher.pinned_admission import (
    PinnedCandidateResolver,
    admit_pinned_candidate,
)
from researcher.scoring import CandidateScorer
from researcher.state import SQLiteStateStore
from researcher.submission import DryRunSubmissionClient
from tests.helpers import (
    FakeDiscovery,
    FakeLibrary,
    FakeSecurityScanner,
    FakeVulnerabilityScanner,
    candidate,
    need,
)


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

        item = resolver.resolve(
            "example/project",
            commit_sha,
            release_tag="v1.2.3",
            source_version="1.2.3",
        )

        self.assertEqual(item.repository, "example/project")
        self.assertEqual(item.commit_sha, commit_sha)
        self.assertEqual(item.release_tag, "v1.2.3")
        self.assertEqual(item.license_spdx, "MIT")
        self.assertTrue(item.extra["tests_present"])
        self.assertTrue(item.extra["ci_present"])
        self.assertEqual(
            item.extra["dependency_manifests"],
            ["pubspec.lock", "pubspec.yaml"],
        )
        self.assertEqual(item.extra["provenance_tree_sha"], tree_sha)
        self.assertTrue(item.extra["release_tag_verified"])
        self.assertTrue(item.extra["source_stable"])
        self.assertTrue(item.extra["pinned_admission"])

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

    def test_rejects_truncated_tree_fail_closed(self) -> None:
        commit_sha = "a" * 40
        tree_sha = "b" * 40
        responses = _responses(commit_sha, tree_sha)
        tree_path = f"/repos/example/project/git/trees/{tree_sha}?recursive=1"
        tree = dict(responses[tree_path])  # type: ignore[arg-type]
        tree["truncated"] = True
        responses[tree_path] = tree
        resolver = PinnedCandidateResolver(
            FakeApi(responses),
            FakeRateLimits(),  # type: ignore[arg-type]
        )

        with self.assertRaisesRegex(RuntimeError, "truncated"):
            resolver.resolve("example/project", commit_sha)

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


class PinnedAdmissionDeliveryTest(unittest.TestCase):
    def test_clear_candidate_is_prepared_once_for_library_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = SQLiteStateStore(root / "researcher.db")
            dossiers = DossierStore(root)
            library = FakeLibrary([need("voice.stt")])
            engine = ResearchEngine(
                library,
                library,
                FakeDiscovery([]),
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(dossiers),
                ResearchMode.SEEDING,
                shortlist_threshold=0.40,
                security_scanner=FakeSecurityScanner(),
                vulnerability_scanner=FakeVulnerabilityScanner(),
            )
            app = SimpleNamespace(
                engine=engine,
                state=state,
                events=EventLogger(state, diagnostics_enabled=False),
            )
            item = candidate("speech-stt", "a" * 40)

            first = admit_pinned_candidate(  # type: ignore[arg-type]
                app,
                item,
                "voice.stt",
            )
            self.assertEqual(first["lifecycle"], "SHORTLISTED")
            self.assertTrue(first["admission_eligible"])
            self.assertTrue(first["dry_run_prepared"])
            self.assertFalse(first["submitted"])
            self.assertEqual(first["submission"]["state"], "DRY_RUN_PREPARED")
            self.assertEqual(state.count_completed_submissions("voice.stt"), 1)

            second = admit_pinned_candidate(  # type: ignore[arg-type]
                app,
                item,
                "voice.stt",
            )
            self.assertEqual(second["state"], "EXISTING")
            self.assertTrue(second["dry_run_prepared"])
            self.assertEqual(state.count_completed_submissions("voice.stt"), 1)


if __name__ == "__main__":
    unittest.main()
