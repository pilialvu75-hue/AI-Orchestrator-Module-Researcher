from __future__ import annotations

import base64
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from researcher.github_api import GitHubResponse
from researcher.rate_limit import RateLimitManager
from researcher.security_admission import GitHubFullTreeSecurityScanner
from researcher.security_gate import SecurityVerdict, SourceArtifact
from researcher.state import SQLiteStateStore
from researcher.supply_chain import SupplyChainVerdict, analyze_supply_chain

from helpers import candidate


class FakeApi:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected GitHub path: {path}")
        return GitHubResponse(data=self.responses[path], headers={})


def _blob(content: str) -> dict[str, object]:
    raw = content.encode("utf-8")
    return {
        "encoding": "base64",
        "content": base64.b64encode(raw).decode("ascii"),
    }


class CMakeSupplyChainTest(unittest.TestCase):
    def test_clean_cmake_project_is_analyzed_and_clear(self) -> None:
        report = analyze_supply_chain(
            (
                SourceArtifact(
                    path="CMakeLists.txt",
                    content=(
                        "cmake_minimum_required(VERSION 3.16)\n"
                        "project(native_demo LANGUAGES C)\n"
                        "add_library(native_demo src/demo.c)\n"
                    ),
                ),
            )
        )

        self.assertEqual(report.verdict, SupplyChainVerdict.CLEAR)
        self.assertEqual(report.manifests_analyzed, ("CMakeLists.txt",))
        self.assertEqual(report.dependencies, ())
        self.assertEqual(report.findings, ())

    def test_pinned_fetchcontent_git_dependency_still_requires_review(self) -> None:
        sha = "a" * 40
        report = analyze_supply_chain(
            (
                SourceArtifact(
                    path="CMakeLists.txt",
                    content=(
                        "include(FetchContent)\n"
                        "FetchContent_Declare(\n"
                        "  example\n"
                        "  GIT_REPOSITORY https://example.invalid/example.git\n"
                        f"  GIT_TAG {sha}\n"
                        ")\n"
                    ),
                ),
            )
        )

        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertEqual(len(report.dependencies), 1)
        dependency = report.dependencies[0]
        self.assertEqual(dependency.ecosystem, "cmake")
        self.assertEqual(dependency.name, "example")
        self.assertEqual(dependency.source, "git")
        self.assertTrue(dependency.immutable)
        rules = {item.rule_id for item in report.findings}
        self.assertIn("cmake_git_dependency_requires_review", rules)
        self.assertNotIn("cmake_git_dependency_unpinned", rules)

    def test_mutable_fetchcontent_tag_is_explicitly_unpinned(self) -> None:
        report = analyze_supply_chain(
            (
                SourceArtifact(
                    path="cmake/Dependencies.cmake",
                    content=(
                        "FetchContent_Declare(example\n"
                        "  GIT_REPOSITORY https://example.invalid/example.git\n"
                        "  GIT_TAG v1.2.3\n"
                        ")\n"
                    ),
                ),
            )
        )

        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertFalse(report.dependencies[0].immutable)
        rules = {item.rule_id for item in report.findings}
        self.assertIn("cmake_git_dependency_unpinned", rules)

    def test_system_find_package_remains_fail_closed(self) -> None:
        report = analyze_supply_chain(
            (
                SourceArtifact(
                    path="CMakeLists.txt",
                    content="find_package(ALSA REQUIRED)\n",
                ),
            )
        )

        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertEqual(report.dependencies[0].name, "ALSA")
        self.assertEqual(report.dependencies[0].source, "system")
        self.assertFalse(report.dependencies[0].immutable)
        self.assertEqual(
            report.findings[0].rule_id,
            "cmake_system_dependency_requires_review",
        )

    def test_commented_remote_dependency_is_not_counted(self) -> None:
        report = analyze_supply_chain(
            (
                SourceArtifact(
                    path="CMakeLists.txt",
                    content=(
                        "# FetchContent_Declare(bad GIT_REPOSITORY https://bad.invalid/x)\n"
                        "#[[\n"
                        "ExternalProject_Add(bad URL https://bad.invalid/archive.zip)\n"
                        "]]\n"
                        "project(clean_native LANGUAGES C)\n"
                    ),
                ),
            )
        )

        self.assertEqual(report.verdict, SupplyChainVerdict.CLEAR)
        self.assertEqual(report.dependencies, ())
        self.assertEqual(report.findings, ())

    def test_full_tree_scanner_reads_cmakelists_and_uses_native_gate(self) -> None:
        commit_sha = "b" * 40
        tree_sha = "c" * 40
        blob_sha = "d" * 40
        source = (
            "cmake_minimum_required(VERSION 3.16)\n"
            "project(native_demo LANGUAGES C)\n"
            "add_library(native_demo src/demo.c)\n"
        )
        responses: dict[str, object] = {
            f"/repos/example/native/commits/{commit_sha}": {
                "sha": commit_sha,
                "commit": {"tree": {"sha": tree_sha}},
            },
            f"/repos/example/native/git/trees/{tree_sha}?recursive=1": {
                "sha": tree_sha,
                "truncated": False,
                "tree": [
                    {
                        "path": "CMakeLists.txt",
                        "type": "blob",
                        "mode": "100644",
                        "sha": blob_sha,
                        "size": len(source.encode("utf-8")),
                    }
                ],
            },
            f"/repos/example/native/git/blobs/{blob_sha}": _blob(source),
        }
        item = candidate("native", commit_sha)
        item = replace(
            item,
            extra={**item.extra, "provenance_tree_sha": tree_sha},
        )

        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            scanner = GitHubFullTreeSecurityScanner(
                FakeApi(responses),  # type: ignore[arg-type]
                RateLimitManager(state),
            )
            report = scanner.scan(item)

        self.assertEqual(report.verdict, SecurityVerdict.CLEAR)
        self.assertTrue(report.complete)
        self.assertEqual(report.scanned_files, 1)
        self.assertIsNotNone(report.supply_chain)
        assert report.supply_chain is not None
        self.assertEqual(report.supply_chain.verdict, SupplyChainVerdict.CLEAR)
        self.assertEqual(
            report.supply_chain.manifests_analyzed,
            ("CMakeLists.txt",),
        )


if __name__ == "__main__":
    unittest.main()
