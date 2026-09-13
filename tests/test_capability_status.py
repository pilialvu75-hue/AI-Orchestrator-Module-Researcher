from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from researcher.capability_status import status_payload
from researcher.state import SQLiteStateStore


class CapabilityStatusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.state = SQLiteStateStore(Path(self.temp.name) / "researcher.db")
        self.state.set_json(
            "library_snapshot",
            {
                "updated_at": "2026-09-13T20:00:00Z",
                "used_cache": False,
                "loaded_at": "2026-09-13T20:01:00Z",
                "items": [
                    {
                        "capability_id": "voice.stt",
                        "title": "Speech-to-text integration bundle",
                        "priority": "high",
                        "desired_candidates": 2,
                        "status": "needed",
                        "targets": ["android", "desktop"],
                    },
                    {
                        "capability_id": "voice.tts",
                        "title": "Text-to-speech integration bundle",
                        "priority": "high",
                        "desired_candidates": 2,
                        "status": "needed",
                        "targets": ["android", "desktop"],
                    },
                ],
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exposes_per_capability_research_progress(self) -> None:
        self.state.set_json("current_capability", "voice.stt")
        self.state.upsert_candidate(
            "candidate-a",
            "voice.stt",
            "example/repo-a",
            "0123456789abcdef0123456789abcdef01234567",
            "SHORTLISTED",
            0.91,
            "dossiers/a.json",
        )
        self.state.upsert_candidate(
            "candidate-b",
            "voice.stt",
            "example/repo-b",
            "89abcdef0123456789abcdef0123456789abcdef",
            "SECURITY_REVIEW",
            0.82,
            "dossiers/b.json",
        )
        self.state.update_scan("voice.stt", success=True)

        payload = status_payload(self.state)
        rows = {item["capability_id"]: item for item in payload["capabilities"]}

        stt = rows["voice.stt"]
        self.assertEqual("SEARCHING", stt["research_state"])
        self.assertTrue(stt["current"])
        self.assertEqual(2, stt["candidate_count"])
        self.assertEqual(1, stt["qualified_candidates"])
        self.assertEqual(1, stt["shortlisted"])
        self.assertEqual(1, stt["security_review"])
        self.assertIsNotNone(stt["last_scan"])
        self.assertEqual(2, stt["desired_candidates"])

        tts = rows["voice.tts"]
        self.assertEqual("PENDING", tts["research_state"])
        self.assertFalse(tts["current"])
        self.assertEqual(0, tts["candidate_count"])

    def test_submitted_candidate_is_reported_without_claiming_certification(self) -> None:
        self.state.upsert_candidate(
            "candidate-c",
            "voice.tts",
            "example/repo-c",
            "fedcba9876543210fedcba9876543210fedcba98",
            "SUBMITTED",
            0.95,
            "dossiers/c.json",
        )

        payload = status_payload(self.state)
        row = next(
            item for item in payload["capabilities"]
            if item["capability_id"] == "voice.tts"
        )
        self.assertEqual("SUBMITTED", row["research_state"])
        self.assertEqual(1, row["submitted"])
        self.assertEqual(1, row["qualified_candidates"])
        self.assertNotIn("certified", row)
        self.assertNotIn("available", row)


if __name__ == "__main__":
    unittest.main()
