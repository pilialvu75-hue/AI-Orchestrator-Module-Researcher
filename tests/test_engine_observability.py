from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from dataclasses import replace

from researcher.comparison import ComparisonEngine
from researcher.dossiers import DossierStore
from researcher.dedup import candidate_fingerprint
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

    def test_research_only_candidate_produces_actionable_handoff(self) -> None:
        n = need("ai.acceleration_backend")
        library = FakeLibrary([n])
        research_only = replace(
            candidate("gpu-backend", "e" * 40),
            license_spdx=None,
            language="C++",
            topics=("vulkan", "gpu", "acceleration"),
            description="Vulkan GPU acceleration backend with CPU fallback scheduling",
        )
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            dossiers = DossierStore(data)
            engine = ResearchEngine(
                library,
                library,
                FakeDiscovery([research_only]),
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(dossiers),
                ResearchMode.SEEDING,
                event_logger=EventLogger(state),
            )
            result = engine.run_cycle()
            self.assertEqual(result["state"], "COMPLETED")
            handoffs = state.pending_implementation_requests()
            self.assertEqual(len(handoffs), 1)
            self.assertEqual(handoffs[0]["capability_id"], "ai.acceleration_backend")
            self.assertEqual(
                handoffs[0]["mutation_policy"],
                "isolated_candidate_no_library_mutation",
            )
            self.assertTrue(handoffs[0]["knowledge_delta"])
            self.assertFalse(
                any(
                    research_only.repository in signal
                    or research_only.upstream_url in signal
                    for signal in handoffs[0]["knowledge_delta"]
                )
            )

    def test_known_candidate_backfills_v2_knowledge_and_handoff(self) -> None:
        n = need("ai.acceleration_backend")
        library = FakeLibrary([n])
        known = replace(
            candidate("legacy-gpu-backend", "f" * 40),
            license_spdx=None,
            language="C++",
            topics=("vulkan", "gpu", "acceleration"),
            description="Vulkan GPU acceleration backend with CPU fallback scheduling",
        )
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            dossiers = DossierStore(data)
            fingerprint = candidate_fingerprint(n.capability_id, known)
            state.upsert_candidate(
                fingerprint,
                n.capability_id,
                known.repository,
                known.commit_sha,
                "REJECTED",
                0.1,
                str(data / "legacy.json"),
                "pre_screen:license_unknown",
            )
            engine = ResearchEngine(
                library,
                library,
                FakeDiscovery([known]),
                state,
                dossiers,
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(dossiers),
                ResearchMode.SEEDING,
                event_logger=EventLogger(state),
            )
            result = engine.run_cycle()
            self.assertEqual(result["state"], "COMPLETED")
            handoffs = state.pending_implementation_requests()
            self.assertEqual(len(handoffs), 1)
            self.assertEqual(handoffs[0]["capability_id"], n.capability_id)
            self.assertTrue(handoffs[0]["knowledge_delta"])

    def test_stale_security_review_is_reassessed(self) -> None:
        n = need()
        c = candidate("stale-review", "b" * 40)
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            fingerprint = candidate_fingerprint(n.capability_id, c)
            state.upsert_candidate(
                fingerprint, n.capability_id, c.repository, c.commit_sha,
                "SECURITY_REVIEW", 0.1, str(data / "old.json"), "pending_review",
            )
            with state._connect() as conn:
                conn.execute(
                    "UPDATE candidates SET updated_at=datetime('now', '-25 hours') "
                    "WHERE fingerprint=?", (fingerprint,),
                )
            dossiers = DossierStore(data)
            engine = ResearchEngine(
                FakeLibrary([n]), FakeLibrary([n]), FakeDiscovery([c]),
                state, dossiers, CandidateScorer(), ComparisonEngine(),
                DryRunSubmissionClient(dossiers), ResearchMode.SEEDING,
                shortlist_threshold=0.40,
                security_scanner=FakeSecurityScanner(),
                vulnerability_scanner=FakeVulnerabilityScanner(),
            )
            engine.run_cycle()
            rows = state.candidate_rows(n.capability_id)
            self.assertEqual(len(rows), 1)
            self.assertNotEqual(rows[0]["lifecycle"], "SECURITY_REVIEW")

    def test_rank_needs_gives_unscanned_capabilities_a_first_pass(self) -> None:
        first = need()
        second = replace(first, capability_id="network.http", title="HTTP")
        library = FakeLibrary([first, second])
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            engine = ResearchEngine(
                library,
                library,
                FakeDiscovery([]),
                state,
                DossierStore(data),
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(DossierStore(data)),
                ResearchMode.SEEDING,
            )
            state.update_scan(first.capability_id, success=True)
            ranked = engine._rank_needs([first, second])
            self.assertEqual(ranked[0].capability_id, second.capability_id)

    def test_consecutive_cycles_rotate_across_unscanned_needs(self) -> None:
        first = need()
        second = replace(first, capability_id="network.http", title="HTTP")
        third = replace(first, capability_id="storage.local_db", title="Database")
        library = FakeLibrary([first, second, third])
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            state = SQLiteStateStore(data / "state.db")
            engine = ResearchEngine(
                library,
                library,
                FakeDiscovery([]),
                state,
                DossierStore(data),
                CandidateScorer(),
                ComparisonEngine(),
                DryRunSubmissionClient(DossierStore(data)),
                ResearchMode.SEEDING,
            )
            selected = []
            for _ in range(3):
                result = engine.run_cycle()
                selected.append(result["capability_id"])
            self.assertEqual(len(set(selected)), 3)

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

        unknown = replace(candidate("unknown-license", "c" * 40), license_spdx=None)
        unknown_security = FakeSecurityScanner().scan(unknown)
        unknown_vulnerability = FakeVulnerabilityScanner().scan(
            unknown, unknown_security
        )
        self.assertEqual(
            ResearchEngine._rejection_reason(
                "REJECTED", unknown, unknown_security, unknown_vulnerability
            ),
            "pre_screen:license_unknown",
        )

        noassertion = replace(
            candidate("noassertion-license", "d" * 40), license_spdx="NOASSERTION"
        )
        noassertion_security = FakeSecurityScanner().scan(noassertion)
        noassertion_vulnerability = FakeVulnerabilityScanner().scan(
            noassertion, noassertion_security
        )
        self.assertEqual(
            ResearchEngine._rejection_reason(
                "REJECTED",
                noassertion,
                noassertion_security,
                noassertion_vulnerability,
            ),
            "pre_screen:license_noassertion",
        )


if __name__ == "__main__":
    unittest.main()
