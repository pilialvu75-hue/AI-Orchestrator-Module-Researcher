from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from researcher.dossiers import DossierStore
from researcher.models import Dossier, ScoreCard, utc_now
from researcher.submission import DryRunSubmissionClient
from researcher.target_submission import TargetScopedSubmissionClient

from helpers import candidate, contract, need


def _dossier(targets: tuple[str, ...]) -> Dossier:
    item = candidate("targeted", "a" * 40)
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
        recommendation=0.8,
        reasons=(),
    )
    return Dossier(
        schema_version=1,
        capability_id="voice.stt",
        candidate=item,
        fingerprint="f" * 64,
        scores=scores,
        lifecycle="SHORTLISTED",
        warnings=(),
        integration_estimate={"effort": "low", "reasons": []},
        security_evidence={},
        maintenance_evidence={},
        license_evidence={},
        dependency_evidence={},
        benchmark_plan={},
        created_at=utc_now(),
    )


class TargetScopedSubmissionTests(unittest.TestCase):
    def test_manifest_contains_only_researched_required_targets(self) -> None:
        requested = need()
        dossier = _dossier(("android",))
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = TargetScopedSubmissionClient(
                DryRunSubmissionClient(DossierStore(Path(tmp)))
            )
            result = wrapper.submit(
                requested,
                contract(),
                "1.0.0",
                dossier,
            )
        self.assertEqual(result["manifest"]["platforms"], ["android"])
        self.assertEqual(result["manifest"]["validation"]["validated_on"], [])

    def test_legacy_candidate_keeps_legacy_need_targets(self) -> None:
        requested = need()
        dossier = _dossier(())
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = TargetScopedSubmissionClient(
                DryRunSubmissionClient(DossierStore(Path(tmp)))
            )
            result = wrapper.submit(
                requested,
                contract(),
                "1.0.0",
                dossier,
            )
        self.assertEqual(result["manifest"]["platforms"], list(requested.targets))


if __name__ == "__main__":
    unittest.main()
