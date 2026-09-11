from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from researcher.comparison import ComparisonEngine
from researcher.dossiers import DossierStore
from researcher.engine import ResearchEngine
from researcher.models import ResearchMode
from researcher.scoring import CandidateScorer
from researcher.state import SQLiteStateStore
from researcher.submission import DryRunSubmissionClient

from helpers import FakeDiscovery, FakeLibrary, candidate, need


class E2ETests(unittest.TestCase):
    def test_need_to_two_dry_run_intake_submissions(self) -> None:
        n = need()
        library = FakeLibrary([n])
        discovery = FakeDiscovery(
            [
                candidate("alpha-stt", "a" * 40),
                candidate("beta-stt", "b" * 40, "Apache-2.0"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            dossiers = DossierStore(data)
            engine = ResearchEngine(
                library,
                library,
                discovery,
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(dossiers),
                ResearchMode.SEEDING,
                shortlist_threshold=0.40,
            )
            result = engine.run_cycle()
            self.assertEqual(result["state"], "COMPLETED")
            self.assertEqual(len(result["prepared_submissions"]), 2)
            self.assertEqual(state.count_qualified("voice.stt"), 2)
            pending = list((data / "submissions" / "pending").glob("*.json"))
            self.assertEqual(len(pending), 2)
            for path in pending:
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertTrue(payload["target_path"].startswith("intake/"))
                self.assertEqual(payload["manifest"]["status"], "discovered")
                self.assertNotIn("modules/", payload["target_path"])

            second = engine.run_cycle()
            self.assertEqual(second["state"], "IDLE")
            self.assertEqual(second["mode"], "MAINTENANCE")
            self.assertEqual(len(list((data / "submissions" / "pending").glob("*.json"))), 2)

    def test_missing_contract_creates_gap_and_no_submission(self) -> None:
        n = need("custom.future_capability")
        library = FakeLibrary([n], contracts={})
        discovery = FakeDiscovery([candidate("future", "c" * 40)])
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            dossiers = DossierStore(data)
            engine = ResearchEngine(
                library,
                library,
                discovery,
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(dossiers),
                ResearchMode.SEEDING,
            )
            result = engine.run_cycle()
            self.assertEqual(result["state"], "BLOCKED")
            self.assertTrue((data / "contract_gaps" / "custom.future_capability.json").exists())
            self.assertFalse((data / "submissions").exists())


if __name__ == "__main__":
    unittest.main()
