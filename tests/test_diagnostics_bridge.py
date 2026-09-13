from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from typing import Any

from researcher.diagnostics_bridge import GitHubDiagnosticsBridge
from researcher.github_api import GitHubApiError, GitHubResponse
from researcher.observability import EventLevel, EventLogger
from researcher.state import SQLiteStateStore


class FakeDiagnosticsApi:
    def __init__(self, *, fail_patch: bool = False) -> None:
        self.fail_patch = fail_patch
        self.calls: list[tuple[str, str, Any]] = []
        self.release_exists = False
        self.release: dict[str, Any] = {"id": 77, "body": ""}
        self.assets: list[dict[str, Any]] = []
        self.next_asset_id = 100

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(("GET", path, None))
        if "/releases/tags/" in path:
            if not self.release_exists:
                raise GitHubApiError(404, "missing")
            return GitHubResponse(data=dict(self.release), headers={})
        if "/assets?" in path:
            return GitHubResponse(data=[dict(asset) for asset in self.assets], headers={})
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self.calls.append(("POST", path, payload))
        if not path.endswith("/releases"):
            raise AssertionError(f"unexpected POST {path}")
        self.release_exists = True
        self.release = {"id": 77, "body": payload.get("body", "")}
        return GitHubResponse(data=dict(self.release), headers={})

    def patch(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self.calls.append(("PATCH", path, payload))
        if self.fail_patch:
            raise GitHubApiError(503, "temporary failure")
        self.release.update(payload)
        self.release["id"] = 77
        return GitHubResponse(data=dict(self.release), headers={})

    def delete(self, path: str) -> GitHubResponse:
        self.calls.append(("DELETE", path, None))
        asset_id = int(path.rsplit("/", 1)[-1])
        self.assets = [asset for asset in self.assets if int(asset["id"]) != asset_id]
        return GitHubResponse(data=None, headers={})

    def upload_release_asset(
        self,
        repository: str,
        release_id: int,
        asset_name: str,
        content: bytes,
        *,
        content_type: str = "application/x-ndjson; charset=utf-8",
    ) -> GitHubResponse:
        self.calls.append(
            ("UPLOAD", asset_name, {"repository": repository, "content_type": content_type})
        )
        digest = hashlib.sha256(content).hexdigest()
        asset = {
            "id": self.next_asset_id,
            "name": asset_name,
            "state": "uploaded",
            "size": len(content),
            "digest": f"sha256:{digest}",
            "created_at": f"2026-09-13T15:{self.next_asset_id % 60:02d}:00Z",
        }
        self.next_asset_id += 1
        self.assets.append(asset)
        return GitHubResponse(data=dict(asset), headers={})


class DiagnosticsBridgeTests(unittest.TestCase):
    def _state_with_event(self, tmp: str) -> tuple[SQLiteStateStore, int]:
        state = SQLiteStateStore(Path(tmp) / "state.db")
        event_id = EventLogger(state, diagnostics_enabled=True).emit(
            EventLevel.INFO,
            "research_engine",
            "candidate_evaluated",
            {
                "capability_id": "voice.stt",
                "lifecycle": "SHORTLISTED",
                "repository": "private-owner/private-repo",
                "token": "secret-value",
            },
        )
        return state, event_id

    def _bridge(
        self,
        api: FakeDiagnosticsApi,
        state: SQLiteStateStore,
    ) -> GitHubDiagnosticsBridge:
        return GitHubDiagnosticsBridge(  # type: ignore[arg-type]
            api,
            state,
            "pilialvu75-hue/Ai-orchestrator-diagnostics",
            instance_id="researcher-test-01",
            producer_version="0.1.0/testcommit",
            platform_name="linux",
            run_id="run:test-01",
        )

    def test_sync_uses_v2_namespace_assets_and_marks_event_sent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, event_id = self._state_with_event(tmp)
            api = FakeDiagnosticsApi()
            bridge = self._bridge(api, state)
            result = bridge.sync()

            self.assertEqual(result["state"], "SYNCED")
            self.assertEqual(result["sent"], 1)
            self.assertEqual(
                bridge.tag,
                "diagnostics-researcher-v1-researcher-test-01",
            )
            rows = state.recent_events()
            self.assertEqual(rows[0]["id"], event_id)
            self.assertEqual(rows[0]["diagnostics_state"], "SENT")

            names = {str(asset["name"]) for asset in api.assets}
            archive = next(name for name in names if name.startswith("researcher-diag-"))
            self.assertRegex(archive, r"^researcher-diag-[a-f0-9]{64}\.jsonl$")
            self.assertIn("researcher-latest.jsonl", names)
            self.assertNotIn("latest.txt", names)

            body = str(api.release["body"])
            self.assertIn('"schema":"ai-orchestrator.diagnostics.event.v2"', body)
            self.assertIn('"producer":"researcher"', body)
            self.assertIn('"producer_version":"0.1.0/testcommit"', body)
            self.assertIn('"platform":"linux"', body)
            self.assertIn('"instance":"researcher-test-01"', body)
            self.assertIn('"run":"run:test-01"', body)
            self.assertIn('"event":"CANDIDATE_EVALUATED"', body)
            self.assertIn('"severity":"info"', body)
            self.assertIn('"capability_id":"voice.stt"', body)
            self.assertNotIn("private-owner", body)
            self.assertNotIn("secret-value", body)

    def test_patch_failure_keeps_event_pending_with_backoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, event_id = self._state_with_event(tmp)
            api = FakeDiagnosticsApi(fail_patch=True)
            bridge = self._bridge(api, state)
            result = bridge.sync()

            self.assertEqual(result["state"], "BACKOFF")
            rows = state.recent_events()
            self.assertEqual(rows[0]["id"], event_id)
            self.assertEqual(rows[0]["diagnostics_state"], "PENDING")
            self.assertEqual(rows[0]["diagnostics_attempts"], 1)
            self.assertIsNotNone(rows[0]["diagnostics_next_attempt_at"])
            self.assertTrue(any(asset["name"].startswith("researcher-diag-") for asset in api.assets))
            status = state.get_json("diagnostics_status")
            self.assertEqual(status["error_type"], "GitHubApiError")
            self.assertNotIn("temporary failure", str(status))

    def test_rotation_never_deletes_foreign_or_app_named_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, _ = self._state_with_event(tmp)
            api = FakeDiagnosticsApi()
            api.release_exists = True
            api.assets = [
                {
                    "id": 1,
                    "name": "latest.txt",
                    "state": "uploaded",
                    "size": 512,
                    "created_at": "2026-09-01T00:00:00Z",
                },
                {
                    "id": 2,
                    "name": "diag-crash-" + "a" * 64 + ".txt",
                    "state": "uploaded",
                    "size": 4096,
                    "created_at": "2026-09-01T00:00:01Z",
                },
                {
                    "id": 3,
                    "name": "library-diag-" + "b" * 64 + ".jsonl",
                    "state": "uploaded",
                    "size": 4096,
                    "created_at": "2026-09-01T00:00:02Z",
                },
                {
                    "id": 4,
                    "name": "researcher-diag-" + "c" * 64 + ".jsonl",
                    "state": "uploaded",
                    "size": 20 * 1024 * 1024,
                    "created_at": "2026-09-01T00:00:03Z",
                },
            ]
            bridge = self._bridge(api, state)
            result = bridge.sync()

            self.assertEqual(result["state"], "SYNCED")
            remaining_ids = {int(asset["id"]) for asset in api.assets}
            self.assertIn(1, remaining_ids)
            self.assertIn(2, remaining_ids)
            self.assertIn(3, remaining_ids)
            self.assertNotIn(4, remaining_ids)
            deleted_paths = [path for method, path, _ in api.calls if method == "DELETE"]
            self.assertTrue(any(path.endswith("/4") for path in deleted_paths))
            self.assertFalse(any(path.endswith("/1") for path in deleted_paths))
            self.assertFalse(any(path.endswith("/2") for path in deleted_paths))
            self.assertFalse(any(path.endswith("/3") for path in deleted_paths))

    def test_archive_retry_is_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, _ = self._state_with_event(tmp)
            api = FakeDiagnosticsApi()
            bridge = self._bridge(api, state)
            rows = state.pending_diagnostics()
            content, _, _ = bridge._batch(rows)
            api.release_exists = True
            assets = api.assets
            first_name, digest = bridge._ensure_archive(77, assets, content)
            upload_count = sum(1 for method, _, _ in api.calls if method == "UPLOAD")
            second_name, second_digest = bridge._ensure_archive(77, assets, content)
            second_upload_count = sum(1 for method, _, _ in api.calls if method == "UPLOAD")
            self.assertEqual(first_name, second_name)
            self.assertEqual(digest, second_digest)
            self.assertEqual(upload_count, second_upload_count)


if __name__ == "__main__":
    unittest.main()
