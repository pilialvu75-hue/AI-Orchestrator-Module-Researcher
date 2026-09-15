from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from researcher.models import Dossier, ScoreCard, utc_now
from researcher.state import SQLiteStateStore
from researcher.target_coverage import (
    candidate_research_targets,
    load_target_coverage,
    record_target_coverage,
    select_for_target_gaps,
)

from helpers import candidate, need


def _dossier(name: str, sha: str, targets: tuple[str, ...], score: float) -> Dossier:
    item = candidate(name, sha)
    item = replace(item, extra={**item.extra, "research_targets": list(targets)})
    scores = ScoreCard(
        functional_fit=0.8,
        contract_fit=0.8,
        maintenance=0.8,
        security=0.8,
        license_fit=1.0,
        platform_fit=0.8,
        test_quality=0.8,
        integration_cost=0.8,
        performance=0.5,
        footprint=0.8,
        documentation=0.8,
        recommendation=score,
        reasons=(),
    )
    return Dossier(
        schema_version=1,
        capability_id="voice.stt",
        candidate=item,
        fingerprint=f"fp-{name}",
        scores=scores,
        lifecycle="SHORTLISTED",
        warnings=(),
        integration_estimate={},
        security_evidence={},
        maintenance_evidence={},
        license_evidence={},
        dependency_evidence={},
        benchmark_plan={},
        created_at=utc_now(),
    )


class TargetCoverageTests(unittest.TestCase):
    def test_two_cross_platform_candidates_satisfy_two_per_target(self) -> None:
        requested = need()
        first = _dossier("one", "1" * 40, ("android", "desktop"), 0.9)
        second = _dossier("two", "2" * 40, ("android", "desktop"), 0.8)
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            record_target_coverage(state, requested, first.fingerprint, first.candidate)
            snapshot = record_target_coverage(
                state,
                requested,
                second.fingerprint,
                second.candidate,
            )
        self.assertTrue(snapshot.complete)
        self.assertEqual(snapshot.counts, {"android": 2, "desktop": 2})
        self.assertEqual(snapshot.tracked_candidates, 2)

    def test_two_total_candidates_do_not_satisfy_split_platform_coverage(self) -> None:
        requested = need()
        first = _dossier("android", "3" * 40, ("android",), 0.9)
        second = _dossier("desktop", "4" * 40, ("desktop",), 0.8)
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            record_target_coverage(state, requested, first.fingerprint, first.candidate)
            snapshot = record_target_coverage(
                state,
                requested,
                second.fingerprint,
                second.candidate,
            )
        self.assertFalse(snapshot.complete)
        self.assertEqual(snapshot.gaps, {"android": 1, "desktop": 1})

    def test_unknown_or_unrequested_targets_never_count(self) -> None:
        requested = need()
        item = _dossier("web-only", "5" * 40, ("web",), 0.9)
        self.assertEqual(candidate_research_targets(requested, item.candidate), ())
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            snapshot = record_target_coverage(
                state,
                requested,
                item.fingerprint,
                item.candidate,
            )
            loaded = load_target_coverage(state, requested)
        self.assertFalse(snapshot.tracked)
        self.assertEqual(loaded.tracked_candidates, 0)

    def test_greedy_selection_prefers_candidate_covering_multiple_gaps(self) -> None:
        requested = need()
        both = _dossier("both", "6" * 40, ("android", "desktop"), 0.75)
        android = _dossier("android", "7" * 40, ("android",), 0.95)
        desktop = _dossier("desktop", "8" * 40, ("desktop",), 0.94)
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            snapshot = load_target_coverage(state, requested)
        selected = select_for_target_gaps(
            requested,
            snapshot,
            [android, desktop, both],
        )
        self.assertEqual(selected[0].fingerprint, both.fingerprint)
        self.assertEqual(len(selected), 3)

    def test_policy_depth_follows_library_desired_candidates(self) -> None:
        requested = replace(need(), desired_candidates=1)
        item = _dossier("both", "9" * 40, ("android", "desktop"), 0.8)
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            snapshot = record_target_coverage(
                state,
                requested,
                item.fingerprint,
                item.candidate,
            )
        self.assertTrue(snapshot.complete)
        self.assertEqual(snapshot.desired_per_target, 1)


if __name__ == "__main__":
    unittest.main()
