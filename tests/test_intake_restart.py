from __future__ import annotations

import base64
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

from researcher.analysis import (
    classify_license,
    integration_estimate,
    maintenance_evidence,
    security_evidence,
)
from researcher.dedup import candidate_fingerprint
from researcher.github_api import GitHubApiError, GitHubResponse
from researcher.models import Dossier, utc_now
from researcher.scoring import CandidateScorer
from researcher.state import SQLiteStateStore
from researcher.submission import GitHubIntakePrSubmissionClient

from helpers import candidate, contract, need


class FakeGitHubApi:
    def __init__(self) -> None:
        self.base_sha = "b" * 40
        self.branches: set[str] = set()
        self.files: dict[tuple[str, str], bytes] = {}
        self.pulls: list[dict[str, Any]] = []
        self.pr_creations = 0
        self.put_calls = 0
        self.fail_put_number: int | None = None
        self.license_bytes = b"MIT License\n"

    @staticmethod
    def _response(data: Any) -> GitHubResponse:
        return GitHubResponse(data=data, headers={})

    def get(self, path: str) -> GitHubResponse:
        if path.startswith("/repos/example/") and "/contents/LICENSE?ref=" in path:
            return self._response(
                {
                    "encoding": "base64",
                    "content": base64.b64encode(self.license_bytes).decode("ascii"),
                }
            )

        if "/git/ref/heads/" in path:
            encoded = path.split("/git/ref/heads/", 1)[1]
            branch = urllib.parse.unquote(encoded)
            if branch == "main":
                return self._response({"object": {"sha": self.base_sha}})
            if branch in self.branches:
                return self._response({"object": {"sha": "c" * 40}})
            raise GitHubApiError(404, "missing ref")

        if "/contents/" in path and "?ref=" in path:
            rest = path.split("/contents/", 1)[1]
            encoded_path, query = rest.split("?", 1)
            file_path = urllib.parse.unquote(encoded_path)
            branch = urllib.parse.unquote(urllib.parse.parse_qs(query)["ref"][0])
            content = self.files.get((branch, file_path))
            if content is None:
                raise GitHubApiError(404, "missing content")
            return self._response(
                {
                    "encoding": "base64",
                    "content": base64.b64encode(content).decode("ascii"),
                }
            )

        if "/pulls?" in path:
            return self._response(list(self.pulls))

        if "/compare/" in path:
            comparison = path.split("/compare/", 1)[1]
            _, encoded_head = comparison.split("...", 1)
            branch = urllib.parse.unquote(encoded_head)
            changed = sorted(
                file_path
                for (item_branch, file_path), _ in self.files.items()
                if item_branch == branch
            )
            return self._response(
                {
                    "files": [
                        {"filename": file_path, "status": "added"}
                        for file_path in changed
                    ]
                }
            )

        raise AssertionError(f"unexpected GET {path}")

    def post(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        if path.endswith("/git/refs"):
            ref = str(payload["ref"])
            self.branches.add(ref.removeprefix("refs/heads/"))
            return self._response({"ref": ref})
        if path.endswith("/pulls"):
            self.pr_creations += 1
            pr = {
                "html_url": f"https://github.com/library/repo/pull/{self.pr_creations}",
                "state": "open",
                "merged_at": None,
                "head": {"ref": payload["head"]},
            }
            self.pulls.insert(0, pr)
            return self._response(pr)
        raise AssertionError(f"unexpected POST {path}")

    def put(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self.put_calls += 1
        if self.fail_put_number == self.put_calls:
            raise GitHubApiError(503, "simulated interrupted write")
        rest = path.split("/contents/", 1)[1]
        file_path = urllib.parse.unquote(rest)
        branch = str(payload["branch"])
        self.files[(branch, file_path)] = base64.b64decode(str(payload["content"]))
        return self._response({"content": {"path": file_path}})


def dossier_for(name: str = "alpha") -> Dossier:
    n = need()
    c = candidate(name, "a" * 40)
    ctr = contract()
    score = CandidateScorer().score(n, c, ctr)
    return Dossier(
        1,
        n.capability_id,
        c,
        candidate_fingerprint(n.capability_id, c),
        score,
        "SHORTLISTED",
        (),
        integration_estimate(c, n),
        security_evidence(c),
        maintenance_evidence(c),
        classify_license(c.license_spdx),
        {"manifest_files_detected": ["pubspec.yaml"], "dependencies_enumerated": False},
        {"status": "PLANNED_NOT_EXECUTED"},
        utc_now(),
    )


class IntakeRestartTests(unittest.TestCase):
    def test_crash_after_remote_delivery_before_local_ack_is_recovered(self) -> None:
        n = need()
        ctr = contract()
        dossier = dossier_for()
        api = FakeGitHubApi()
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.db"
            first_state = SQLiteStateStore(db)
            first_client = GitHubIntakePrSubmissionClient(
                api, "library/repo", first_state, "main"
            )

            delivered = first_client.submit(n, ctr, "1.0.0", dossier)
            self.assertEqual(delivered["state"], "SUBMITTED")
            self.assertEqual(api.pr_creations, 1)
            interrupted = first_state.submission_row(dossier.fingerprint)
            self.assertIsNotNone(interrupted)
            assert interrupted is not None
            self.assertEqual(interrupted["state"], "DELIVERING")
            self.assertEqual(interrupted["attempts"], 1)

            restarted_state = SQLiteStateStore(db)
            restarted_client = GitHubIntakePrSubmissionClient(
                api, "library/repo", restarted_state, "main"
            )
            resumed = restarted_client.resume_pending()

            self.assertEqual(len(resumed), 1)
            self.assertEqual(api.pr_creations, 1)
            completed = restarted_state.submission_row(dossier.fingerprint)
            self.assertIsNotNone(completed)
            assert completed is not None
            self.assertEqual(completed["state"], "SUBMITTED")
            self.assertEqual(completed["attempts"], 2)
            self.assertEqual(
                completed["pull_request_url"],
                "https://github.com/library/repo/pull/1",
            )
            self.assertEqual(len(api.files), 3)
            self.assertEqual(restarted_client.resume_pending(), [])
            self.assertEqual(api.pr_creations, 1)

    def test_partial_remote_write_retries_without_duplicate_files_or_pr(self) -> None:
        n = need()
        ctr = contract()
        dossier = dossier_for("partial")
        api = FakeGitHubApi()
        api.fail_put_number = 2
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.db"
            first_state = SQLiteStateStore(db)
            first_client = GitHubIntakePrSubmissionClient(
                api, "library/repo", first_state, "main"
            )
            with self.assertRaises(GitHubApiError):
                first_client.submit(n, ctr, "1.0.0", dossier)
            retry_row = first_state.submission_row(dossier.fingerprint)
            self.assertIsNotNone(retry_row)
            assert retry_row is not None
            self.assertEqual(retry_row["state"], "RETRY")
            self.assertEqual(len(api.files), 1)
            self.assertEqual(api.pr_creations, 0)

            api.fail_put_number = None
            restarted_state = SQLiteStateStore(db)
            restarted_client = GitHubIntakePrSubmissionClient(
                api, "library/repo", restarted_state, "main"
            )
            resumed = restarted_client.resume_pending()
            self.assertEqual(len(resumed), 1)
            self.assertEqual(len(api.files), 3)
            self.assertEqual(api.pr_creations, 1)
            completed = restarted_state.submission_row(dossier.fingerprint)
            self.assertIsNotNone(completed)
            assert completed is not None
            self.assertEqual(completed["state"], "SUBMITTED")
            self.assertEqual(completed["attempts"], 2)

    def test_persisted_payload_is_immutable_across_retry(self) -> None:
        dossier = dossier_for("immutable")
        api = FakeGitHubApi()
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            client = GitHubIntakePrSubmissionClient(api, "library/repo", state, "main")
            client.submit(need(), contract(), "1.0.0", dossier)
            row = state.submission_row(dossier.fingerprint)
            self.assertIsNotNone(row)
            assert row is not None
            changed = dict(row["payload"])
            changed["target_path"] = "intake/other/0.1.0/manifest.json"
            with self.assertRaisesRegex(RuntimeError, "payload diverges"):
                state.reserve_submission(
                    dossier.fingerprint,
                    need().capability_id,
                    str(row["submission_id"]),
                    str(row["target_path"]),
                    changed,
                    branch=str(row["branch"]),
                )


if __name__ == "__main__":
    unittest.main()
