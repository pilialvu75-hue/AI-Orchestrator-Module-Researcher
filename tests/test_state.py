from __future__ import annotations

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
            self.assertFalse(second.is_known_candidate("fp"))
            self.assertEqual(second.get_json("current_capability"), "voice.stt")
            self.assertEqual(second.count_qualified("voice.stt"), 0)

            self.assertTrue(
                second.mark_submission(
                    "fp",
                    "voice.stt",
                    "sub1",
                    "DRY_RUN_PREPARED",
                    "intake/x",
                )
            )
            self.assertTrue(second.is_known_candidate("fp"))
            self.assertEqual(second.count_qualified("voice.stt"), 1)

            created_again = second.upsert_candidate(
                "fp", "voice.stt", "a/b", "abc", "SHORTLISTED", 0.82, "dossier.json"
            )
            self.assertFalse(created_again)
            self.assertEqual(second.count_qualified("voice.stt"), 1)

    def test_submission_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteStateStore(Path(tmp) / "state.db")
            store.upsert_candidate(
                "fp", "voice.stt", "a/b", "abc", "SHORTLISTED", 0.8, "dossier.json"
            )
            self.assertTrue(
                store.mark_submission("fp", "voice.stt", "sub1", "SUBMITTED", "intake/x")
            )
            self.assertFalse(
                store.mark_submission("fp", "voice.stt", "sub2", "SUBMITTED", "intake/x")
            )
            rows = store.candidate_rows("voice.stt")
            self.assertEqual(rows[0]["lifecycle"], "SUBMITTED")
            self.assertEqual(store.count_qualified("voice.stt"), 1)


if __name__ == "__main__":
    unittest.main()
