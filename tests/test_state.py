from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from researcher.state import SQLiteStateStore


class StateTests(unittest.TestCase):
    def test_restart_resume_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            first = SQLiteStateStore(path)
            created = first.upsert_candidate(
                "fp", "voice.stt", "a/b", "abc", "SHORTLISTED", 0.8, "dossier.json"
            )
            self.assertTrue(created)
            first.set_json("current_capability", "voice.stt")

            second = SQLiteStateStore(path)
            self.assertTrue(second.is_known_candidate("fp"))
            self.assertEqual(second.get_json("current_capability"), "voice.stt")
            created_again = second.upsert_candidate(
                "fp", "voice.stt", "a/b", "abc", "SHORTLISTED", 0.82, "dossier.json"
            )
            self.assertFalse(created_again)
            self.assertEqual(second.count_qualified("voice.stt"), 1)

    def test_submission_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteStateStore(Path(tmp) / "state.db")
            self.assertTrue(
                store.mark_submission(
                    "fp",
                    "voice.stt",
                    "sub1",
                    "DRY_RUN_PREPARED",
                    "intake/x",
                )
            )
            self.assertFalse(
                store.mark_submission(
                    "fp",
                    "voice.stt",
                    "sub2",
                    "DRY_RUN_PREPARED",
                    "intake/x",
                )
            )

    def test_legacy_submission_table_is_migrated_without_losing_ack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            with sqlite3.connect(path) as conn:
                conn.execute(
                    """
                    CREATE TABLE submissions (
                        fingerprint TEXT PRIMARY KEY,
                        capability_id TEXT NOT NULL,
                        submission_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        target_path TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO submissions(
                        fingerprint, capability_id, submission_id,
                        state, target_path, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-fp",
                        "voice.stt",
                        "legacy-sub",
                        "DRY_RUN_PREPARED",
                        "intake/legacy/manifest.json",
                        "2026-09-01T00:00:00+00:00",
                    ),
                )

            store = SQLiteStateStore(path)
            row = store.submission_row("legacy-fp")
            self.assertIsNotNone(row)
            assert row is not None
            self.assertEqual(row["state"], "DRY_RUN_PREPARED")
            self.assertEqual(row["payload"], {})
            self.assertEqual(row["attempts"], 0)
            self.assertEqual(row["updated_at"], "2026-09-01T00:00:00+00:00")
            self.assertEqual(store.pending_submissions(), [])
            status = store.status()
            self.assertEqual(status["submitted"], 1)
            self.assertEqual(status["submissions_pending"], 0)

            with sqlite3.connect(path) as conn:
                columns = {
                    str(item[1])
                    for item in conn.execute("PRAGMA table_info(submissions)").fetchall()
                }
            self.assertTrue(
                {
                    "payload_json",
                    "branch",
                    "pull_request_url",
                    "attempts",
                    "last_error",
                    "updated_at",
                }.issubset(columns)
            )


    def test_capability_knowledge_accumulates_only_compact_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteStateStore(Path(tmp) / "state.db")
            first = store.record_research_source(
                source_id="a",
                capability_id="network.http",
                repository="owner/a",
                commit_sha="a" * 40,
                direct_reuse=True,
                research_use=True,
                signals=("language:dart", "topic:http"),
            )
            second = store.record_research_source(
                source_id="b",
                capability_id="network.http",
                repository="owner/b",
                commit_sha="b" * 40,
                direct_reuse=False,
                research_use=True,
                signals=("topic:http", "topic:retry"),
            )
            self.assertEqual(first, ("language:dart", "topic:http"))
            self.assertEqual(second, ("topic:retry",))
            knowledge = store.capability_knowledge("network.http")
            self.assertEqual(knowledge["source_count"], 2)
            self.assertEqual(knowledge["direct_reuse_source_count"], 1)
            self.assertEqual(
                knowledge["signals"],
                ["language:dart", "topic:http", "topic:retry"],
            )



    def test_improvement_proposal_queue_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteStateStore(Path(tmp) / "state.db")
            kwargs = {
                "proposal_id": "proposal-1",
                "capability_id": "voice.tts",
                "novelty": ("topic:streaming",),
                "acceptance_gates": ("implementation_tests_pass",),
            }
            self.assertTrue(store.record_improvement_proposal(**kwargs))
            self.assertFalse(store.record_improvement_proposal(**kwargs))


if __name__ == "__main__":
    unittest.main()
