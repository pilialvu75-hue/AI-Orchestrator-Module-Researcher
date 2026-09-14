from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from researcher.comparison import ComparisonEngine
from researcher.dossiers import DossierStore
from researcher.engine import ResearchEngine
from researcher.models import Contract, Dossier, Need, ResearchMode
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


class CrashBeforeSubmissionClient:
    def submit(
        self,
        need: Need,
        contract: Contract,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any]:
        raise RuntimeError("simulated crash before durable submission intent")


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
        scanner = FakeSecurityScanner()
        vulnerability_scanner = FakeVulnerabilityScanner()
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
                security_scanner=scanner,
                vulnerability_scanner=vulnerability_scanner,
            )
            result = engine.run_cycle()
            self.assertEqual(result["state"], "COMPLETED")
            self.assertEqual(len(result["prepared_submissions"]), 2)
            self.assertEqual(result["security_review"], 0)
            self.assertEqual(result["security_blocked"], 0)
            self.assertEqual(scanner.calls, 2)
            self.assertEqual(vulnerability_scanner.calls, 2)
            self.assertEqual(state.count_qualified("voice.stt"), 2)
            self.assertEqual(state.count_completed_submissions("voice.stt"), 2)
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

    def test_shortlists_orphaned_before_submission_are_recovered_after_restart(self) -> None:
        n = need()
        library = FakeLibrary([n])
        first_discovery = FakeDiscovery(
            [
                candidate("orphan-alpha", "1" * 40),
                candidate("orphan-beta", "2" * 40, "Apache-2.0"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            db = data / "state.db"
            first_state = SQLiteStateStore(db)
            first_dossiers = DossierStore(data)
            first_engine = ResearchEngine(
                library,
                library,
                first_discovery,
                first_state,
                first_dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                CrashBeforeSubmissionClient(),
                ResearchMode.SEEDING,
                shortlist_threshold=0.40,
                security_scanner=FakeSecurityScanner(),
                vulnerability_scanner=FakeVulnerabilityScanner(),
            )

            with self.assertRaisesRegex(RuntimeError, "before durable submission"):
                first_engine.run_cycle()
            self.assertEqual(first_state.count_qualified("voice.stt"), 2)
            self.assertEqual(first_state.count_completed_submissions("voice.stt"), 0)
            self.assertEqual(len(first_state.orphan_shortlist_rows("voice.stt")), 2)

            restarted_state = SQLiteStateStore(db)
            restarted_dossiers = DossierStore(data)
            restarted_discovery = FakeDiscovery([])
            restarted_scanner = FakeSecurityScanner()
            restarted_vulnerability = FakeVulnerabilityScanner()
            restarted_engine = ResearchEngine(
                library,
                library,
                restarted_discovery,
                restarted_state,
                restarted_dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(restarted_dossiers),
                ResearchMode.SEEDING,
                shortlist_threshold=0.40,
                security_scanner=restarted_scanner,
                vulnerability_scanner=restarted_vulnerability,
            )

            recovered = restarted_engine.run_cycle()
            self.assertEqual(recovered["state"], "COMPLETED")
            self.assertEqual(len(recovered["recovered_submissions"]), 2)
            self.assertEqual(len(recovered["prepared_submissions"]), 2)
            self.assertEqual(recovered["discovered"], 0)
            self.assertEqual(restarted_discovery.calls, 0)
            self.assertEqual(restarted_scanner.calls, 0)
            self.assertEqual(restarted_vulnerability.calls, 0)
            self.assertEqual(restarted_state.count_completed_submissions("voice.stt"), 2)
            self.assertEqual(restarted_state.orphan_shortlist_rows("voice.stt"), [])
            self.assertEqual(
                len(list((data / "submissions" / "pending").glob("*.json"))),
                2,
            )

            idle = restarted_engine.run_cycle()
            self.assertEqual(idle["state"], "IDLE")
            self.assertEqual(idle["mode"], "MAINTENANCE")

    def test_missing_security_scanner_fails_closed_before_submission(self) -> None:
        n = need()
        library = FakeLibrary([n])
        discovery = FakeDiscovery([candidate("unscanned", "e" * 40)])
        vulnerability_scanner = FakeVulnerabilityScanner()
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
                vulnerability_scanner=vulnerability_scanner,
            )
            result = engine.run_cycle()
            self.assertEqual(result["shortlisted"], 0)
            self.assertEqual(result["security_review"], 1)
            self.assertEqual(result["prepared_submissions"], [])
            self.assertEqual(vulnerability_scanner.calls, 0)
            self.assertEqual(state.count_qualified("voice.stt"), 0)
            rows = state.candidate_rows("voice.stt")
            self.assertEqual(rows[0]["lifecycle"], "SECURITY_REVIEW")
            self.assertEqual(rows[0]["rejection_reason"], "security_review:not_scanned")
            self.assertFalse((data / "submissions").exists())

    def test_missing_vulnerability_scanner_fails_closed_before_submission(self) -> None:
        n = need()
        library = FakeLibrary([n])
        discovery = FakeDiscovery([candidate("unverified-vulns", "f" * 40)])
        scanner = FakeSecurityScanner()
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
                security_scanner=scanner,
            )
            result = engine.run_cycle()
            self.assertEqual(result["shortlisted"], 0)
            self.assertEqual(result["security_review"], 1)
            self.assertEqual(result["prepared_submissions"], [])
            self.assertEqual(scanner.calls, 1)
            rows = state.candidate_rows("voice.stt")
            self.assertEqual(rows[0]["lifecycle"], "SECURITY_REVIEW")
            self.assertEqual(
                rows[0]["rejection_reason"],
                "vulnerability_review:not_analyzed",
            )
            self.assertFalse((data / "submissions").exists())

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

    def test_unresolved_unstable_source_is_not_shortlisted(self) -> None:
        n = need()
        library = FakeLibrary([n])
        unstable = candidate("unstable-stt", "d" * 40)
        unstable.extra["source_stable"] = False
        unstable.extra["source_version"] = "2.0.0-wip"
        discovery = FakeDiscovery([unstable])
        scanner = FakeSecurityScanner()
        vulnerability_scanner = FakeVulnerabilityScanner()
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
                security_scanner=scanner,
                vulnerability_scanner=vulnerability_scanner,
            )
            result = engine.run_cycle()
            self.assertEqual(result["state"], "COMPLETED")
            self.assertEqual(result["shortlisted"], 0)
            self.assertEqual(result["prepared_submissions"], [])
            self.assertEqual(scanner.calls, 0)
            self.assertEqual(vulnerability_scanner.calls, 0)
            self.assertEqual(state.count_qualified("voice.stt"), 0)
            rows = state.candidate_rows("voice.stt")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["lifecycle"], "REJECTED")
            self.assertEqual(rows[0]["rejection_reason"], "unstable_source_ref")


if __name__ == "__main__":
    unittest.main()
