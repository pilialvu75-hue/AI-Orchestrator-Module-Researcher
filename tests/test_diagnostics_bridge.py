from __future__ import annotations

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
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.release_exists = False

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(("GET", path, None))
        if not self.release_exists:
            raise GitHubApiError(404, "missing")
        return GitHubResponse(data={"id": 77, "body": ""}, headers={})

    def post(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self.calls.append(("POST", path, payload))
        self.release_exists = True
        return GitHubResponse(data={"id": 77, "body": payload.get("body", "")}, headers={})

    def patch(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        self.calls.append(("PATCH", path, payload))
        if self.fail_patch:
            raise GitHubApiError(503, "temporary failure")
        return GitHubResponse(data={"id": 77, "body": payload.get("body", "")}, headers={})


class DiagnosticsBridgeTests(unittest.TestCase):
    def _state_with_event(self, tmp: str) -> tuple[SQLiteStateStore, int]:
        state = SQLiteStateStore(Path(tmp) / "state.db")
        event_id = EventLogger(state).emit(
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

    def test_sync_creates_release_and_marks_events_sent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, event_id = self._state_with_event(tmp)
            api = FakeDiagnosticsApi()
            bridge = GitHubDiagnosticsBridge(  # type: ignore[arg-type]
                api,
                state,
                "pilialvu75-hue/Ai-orchestrator-diagnostics",
            )
            result = bridge.sync()
            self.assertEqual(result["state"], "SYNCED")
            self.assertEqual(result["sent"], 1)
            rows = state.recent_events()
            self.assertEqual(rows[0]["id"], event_id)
            self.assertEqual(rows[0]["diagnostics_state"], "SENT")
            patch_payloads = [payload for method, _, payload in api.calls if method == "PATCH"]
            self.assertEqual(len(patch_payloads), 1)
            body = str(patch_payloads[0]["body"])
            self.assertIn("voice.stt", body)
            self.assertIn("SHORTLISTED", body)
            self.assertNotIn("private-owner", body)
            self.assertNotIn("secret-value", body)

    def test_failure_keeps_event_pending_and_schedules_backoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, event_id = self._state_with_event(tmp)
            api = FakeDiagnosticsApi(fail_patch=True)
            bridge = GitHubDiagnosticsBridge(  # type: ignore[arg-type]
                api,
                state,
                "pilialvu75-hue/Ai-orchestrator-diagnostics",
            )
            result = bridge.sync()
            self.assertEqual(result["state"], "BACKOFF")
            rows = state.recent_events()
            self.assertEqual(rows[0]["id"], event_id)
            self.assertEqual(rows[0]["diagnostics_state"], "PENDING")
            self.assertEqual(rows[0]["diagnostics_attempts"], 1)
            self.assertIsNotNone(rows[0]["diagnostics_next_attempt_at"])
            status = state.get_json("diagnostics_status")
            self.assertEqual(status["error_type"], "GitHubApiError")
            self.assertNotIn("temporary failure", str(status))


if __name__ == "__main__":
    unittest.main()
