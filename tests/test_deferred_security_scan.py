from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from researcher.comparison import ComparisonEngine
from researcher.dossiers import DossierStore
from researcher.models import ResearchMode
from researcher.scoring import CandidateScorer
from researcher.security_admission import SecurityScanDeferred
from researcher.state import SQLiteStateStore
from researcher.submission import DryRunSubmissionClient
from researcher.target_engine import TargetAwareResearchEngine
from researcher.target_submission import TargetScopedSubmissionClient

from helpers import FakeDiscovery, FakeLibrary, FakeVulnerabilityScanner, candidate, need


class DeferredScanner:
    def scan(self, candidate):
        raise SecurityScanDeferred("GitHub rate limit exhausted; retry after 60s")


class DeferredSecurityScanTests(unittest.TestCase):
    def test_deferred_scan_keeps_candidate_retryable(self):
        requested = need()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = SQLiteStateStore(root / "state.db")
            dossiers = DossierStore(root)
            engine = TargetAwareResearchEngine(
                FakeLibrary([requested]),
                FakeLibrary([requested]),
                FakeDiscovery([candidate("retryable", "a" * 40)]),
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                TargetScopedSubmissionClient(DryRunSubmissionClient(dossiers)),
                ResearchMode.SEEDING,
                security_scanner=DeferredScanner(),
                vulnerability_scanner=FakeVulnerabilityScanner(),
            )
            first = engine.run_cycle()
            self.assertEqual(first["state"], "BACKOFF")
            self.assertEqual(first["reason"], "security_scan_deferred")
            self.assertEqual(first["discovered"], 1)
            self.assertEqual(first["new_analyzed"], 0)
            self.assertEqual(first["capability_id"], requested.capability_id)
            self.assertEqual(state.get_json("engine_state"), "BACKOFF")
            second = engine.run_cycle()
            self.assertEqual(second["state"], "BACKOFF")
            self.assertEqual(second["reason"], "security_scan_deferred")
            self.assertEqual(state.count_completed_submissions(requested.capability_id), 0)


class SecurityReviewRetryTests(unittest.TestCase):
    def test_only_stale_security_reviews_can_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            for fingerprint, lifecycle in [
                ("review", "SECURITY_REVIEW"),
                ("blocked", "SECURITY_BLOCKED"),
                ("submitted", "SUBMITTED"),
            ]:
                state.upsert_candidate(
                    fingerprint, "test.capability", "example/repo",
                    "a" * 40, lifecycle, 0.5, "dossier.json",
                )
            self.assertFalse(state.security_review_retry_due("review"))
            with state._connect() as conn:
                conn.execute(
                    "UPDATE candidates SET updated_at='2020-01-01T00:00:00Z'"
                )
            self.assertTrue(state.security_review_retry_due("review"))
            self.assertFalse(state.security_review_retry_due("blocked"))
            self.assertFalse(state.security_review_retry_due("submitted"))


if __name__ == "__main__":
    unittest.main()
