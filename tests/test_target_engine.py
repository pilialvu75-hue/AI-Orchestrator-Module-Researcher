from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from researcher.comparison import ComparisonEngine
from researcher.dedup import candidate_fingerprint
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


    def test_target_seeding_retries_recoverable_license_rejections_only_when_due(self) -> None:
        requested = need()
        recovered = _target_candidate("license-recovered", "8", "android")
        too_early = _target_candidate("license-too-early", "9", "android")
        incompatible = _target_candidate("license-incompatible", "a", "android")
        candidates = [recovered, too_early, incompatible]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = SQLiteStateStore(root / "state.db")
            dossiers = DossierStore(root)
            for item, reason in (
                (recovered, "pre_screen:license_noassertion"),
                (too_early, "pre_screen:license_unknown"),
                (incompatible, "pre_screen:license_agpl"),
            ):
                state.upsert_candidate(
                    candidate_fingerprint(requested.capability_id, item),
                    requested.capability_id,
                    item.repository,
                    item.commit_sha,
                    "REJECTED",
                    0.1,
                    "old-dossier.json",
                    reason,
                )
            with state._connect() as conn:
                for item in (recovered, incompatible):
                    conn.execute(
                        "UPDATE candidates SET updated_at=datetime('now', '-7 hours') "
                        "WHERE fingerprint=?",
                        (candidate_fingerprint(requested.capability_id, item),),
                    )
            security = FakeSecurityScanner()
            vulnerability = FakeVulnerabilityScanner()
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
                security_scanner=security,
                vulnerability_scanner=vulnerability,
            )

            result = engine.run_cycle()

            self.assertEqual(1, result["new_analyzed"])
            self.assertEqual(2, result["known_candidates_skipped"])
            self.assertEqual(1, len(result["prepared_submissions"]))
            self.assertEqual(1, security.calls)
            self.assertEqual(1, vulnerability.calls)
            self.assertFalse(state.rejected_candidate_retry_due(
                candidate_fingerprint(requested.capability_id, recovered)
            ))


if __name__ == "__main__":
    unittest.main()
