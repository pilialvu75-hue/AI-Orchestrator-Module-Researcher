from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from researcher.comparison import ComparisonEngine
from researcher.dossiers import DossierStore
from researcher.models import ResearchMode
from researcher.scoring import CandidateScorer
from researcher.state import SQLiteStateStore
from researcher.submission import DryRunSubmissionClient
from researcher.target_engine import TargetAwareResearchEngine
from researcher.target_submission import TargetScopedSubmissionClient

from helpers import (
    FakeDiscovery,
    FakeLibrary,
    FakeSecurityScanner,
    FakeVulnerabilityScanner,
    candidate,
    need,
)


def _target_candidate(name: str, sha_char: str, *targets: str):
    item = candidate(name, sha_char * 40)
    return replace(
        item,
        extra={**item.extra, "research_targets": list(targets)},
    )


class TargetAwareEngineTests(unittest.TestCase):
    def test_split_candidates_continue_until_two_per_target(self) -> None:
        requested = need()
        candidates = [
            _target_candidate("android-one", "1", "android"),
            _target_candidate("desktop-one", "2", "desktop"),
            _target_candidate("android-two", "3", "android"),
            _target_candidate("desktop-two", "4", "desktop"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = SQLiteStateStore(root / "state.db")
            dossiers = DossierStore(root)
            engine = TargetAwareResearchEngine(
                FakeLibrary([requested]),
                FakeLibrary([requested]),
                FakeDiscovery(candidates),
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                TargetScopedSubmissionClient(DryRunSubmissionClient(dossiers)),
                ResearchMode.SEEDING,
                security_scanner=FakeSecurityScanner(),
                vulnerability_scanner=FakeVulnerabilityScanner(),
            )

            result = engine.run_cycle()

            self.assertEqual(len(result["prepared_submissions"]), 4)
            coverage = result["target_coverage"]
            self.assertTrue(coverage["complete"])
            self.assertEqual(coverage["counts"], {"android": 2, "desktop": 2})
            self.assertEqual(state.count_completed_submissions("voice.stt"), 4)

    def test_two_cross_platform_candidates_are_enough(self) -> None:
        requested = need()
        candidates = [
            _target_candidate("both-one", "5", "android", "desktop"),
            _target_candidate("both-two", "6", "android", "desktop"),
            _target_candidate("extra", "7", "android"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = SQLiteStateStore(root / "state.db")
            dossiers = DossierStore(root)
            engine = TargetAwareResearchEngine(
                FakeLibrary([requested]),
                FakeLibrary([requested]),
                FakeDiscovery(candidates),
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                TargetScopedSubmissionClient(DryRunSubmissionClient(dossiers)),
                ResearchMode.SEEDING,
                security_scanner=FakeSecurityScanner(),
                vulnerability_scanner=FakeVulnerabilityScanner(),
            )

            result = engine.run_cycle()

            self.assertEqual(len(result["prepared_submissions"]), 2)
            self.assertTrue(result["target_coverage"]["complete"])
            self.assertEqual(state.count_completed_submissions("voice.stt"), 2)


if __name__ == "__main__":
    unittest.main()
