from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from dataclasses import replace

from researcher.comparison import ComparisonEngine
from researcher.dossiers import DossierStore
from researcher.engine import ResearchEngine
from researcher.models import ResearchMode
from researcher.observability import EventLogger
from researcher.scoring import CandidateScorer
from researcher.state import SQLiteStateStore
from researcher.submission import DryRunSubmissionClient

from helpers import (
    FakeDiscovery,
    FakeLibrary,
    FakeSecurityScanner,
    FakeVulnerabilityScanner,
    candidate,
    need,
)


class EngineObservabilityTests(unittest.TestCase):
    def test_cycle_emits_need_candidate_and_completion_events(self) -> None:
        n = need()
        library = FakeLibrary([n])
        discovery = FakeDiscovery([candidate("alpha-stt", "a" * 40)])
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            dossiers = DossierStore(data)
            logger = EventLogger(state)
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
                security_scanner=FakeSecurityScanner(),
                vulnerability_scanner=FakeVulnerabilityScanner(),
                event_logger=logger,
            )
            result = engine.run_cycle()
            self.assertEqual(result["state"], "COMPLETED")
            event_names = [row["event"] for row in reversed(state.recent_events())]
            self.assertIn("cycle_started", event_names)
            self.assertIn("need_selected", event_names)
            self.assertIn("candidate_evaluated", event_names)
            self.assertIn("cycle_completed", event_names)
            candidate_event = next(
                row for row in state.recent_events() if row["event"] == "candidate_evaluated"
            )
            self.assertNotIn("repository", candidate_event["public_payload"])
            self.assertEqual(candidate_event["public_payload"]["capability_id"], "voice.stt")

    def test_rejection_reason_distinguishes_prescreen_gates(self) -> None:
        c = candidate("alpha-stt", "a" * 40)
        security = FakeSecurityScanner().scan(c)
        vulnerability = FakeVulnerabilityScanner().scan(c, security)

        c.extra["source_stable"] = False
        self.assertEqual(
            ResearchEngine._rejection_reason("REJECTED", c, security, vulnerability),
            "unstable_source_ref",
        )
        c.extra["source_stable"] = True
        archived = replace(candidate("archived-stt", "b" * 40), archived=True)
        archived_security = FakeSecurityScanner().scan(archived)
        archived_vulnerability = FakeVulnerabilityScanner().scan(
            archived, archived_security
        )
        self.assertEqual(
            ResearchEngine._rejection_reason(
                "REJECTED", archived, archived_security, archived_vulnerability
            ),
            "pre_screen:archived",
        )


if __name__ == "__main__":
    unittest.main()
