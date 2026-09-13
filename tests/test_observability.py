from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from researcher.observability import EventLevel, EventLogger, public_projection, sanitize_payload
from researcher.state import SQLiteStateStore


class ObservabilityTests(unittest.TestCase):
    def test_redacts_secret_keys_bearer_tokens_and_url_queries(self) -> None:
        clean = sanitize_payload(
            {
                "token": "should-not-survive",
                "message": "Authorization Bearer abcdefghijklmnopqrstuvwxyz",
                "endpoint": "https://example.invalid/path?secret=one#fragment",
                "nested": {"password": "also-secret"},
            }
        )
        self.assertEqual(clean["token"], "[REDACTED]")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", clean["message"])
        self.assertEqual(clean["endpoint"], "https://example.invalid/path")
        self.assertEqual(clean["nested"]["password"], "[REDACTED]")

    def test_public_projection_is_allowlist_only(self) -> None:
        projected = public_projection(
            {
                "capability_id": "voice.stt",
                "lifecycle": "SECURITY_REVIEW",
                "repository": "private-owner/private-repo",
                "message": "local-only details",
                "path": "/home/user/project",
            }
        )
        self.assertEqual(
            projected,
            {"capability_id": "voice.stt", "lifecycle": "SECURITY_REVIEW"},
        )

    def test_event_logger_persists_local_and_public_views(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            logger = EventLogger(state)
            event_id = logger.emit(
                EventLevel.ERROR,
                "research_engine",
                "cycle_failed",
                {
                    "capability_id": "voice.stt",
                    "error_type": "RuntimeError",
                    "message": "Bearer abcdefghijklmnopqrstuvwxyz",
                    "api_key": "hidden",
                },
            )
            rows = state.recent_events()
            self.assertEqual(rows[0]["id"], event_id)
            self.assertEqual(rows[0]["payload"]["api_key"], "[REDACTED]")
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz", rows[0]["payload"]["message"])
            self.assertEqual(
                rows[0]["public_payload"],
                {"capability_id": "voice.stt", "error_type": "RuntimeError"},
            )
            pending = state.pending_diagnostics()
            self.assertEqual([row["id"] for row in pending], [event_id])

    def test_non_public_event_is_not_queued_for_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            EventLogger(state).emit(
                EventLevel.DEBUG,
                "internal",
                "detail",
                {"message": "local only"},
            )
            self.assertEqual(state.pending_diagnostics(), [])
            self.assertEqual(state.recent_events()[0]["diagnostics_state"], "SKIPPED")


if __name__ == "__main__":
    unittest.main()
