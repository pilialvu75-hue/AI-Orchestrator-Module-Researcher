from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from researcher.analysis import (
    classify_license,
    integration_estimate,
    maintenance_evidence,
    security_evidence,
)
from researcher.dedup import candidate_fingerprint
from researcher.dossiers import DossierStore
from researcher.models import Dossier, utc_now
from researcher.scoring import CandidateScorer
from researcher.submission import DryRunSubmissionClient

from helpers import candidate, contract, need


class SubmissionTests(unittest.TestCase):
    def test_dry_run_manifest_matches_library_contract_shape(self) -> None:
        n = need()
        original = candidate("alpha", "a" * 40)
        c = replace(
            original,
            license_file_url=(
                f"https://github.com/{original.repository}/blob/"
                f"{original.commit_sha}/LICENSE"
            ),
        )
        ctr = contract()
        score = CandidateScorer().score(n, c, ctr)
        dossier = Dossier(
            1,
            n.capability_id,
            c,
            candidate_fingerprint(n.capability_id, c),
            score,
            "SHORTLISTED",
            (),
            integration_estimate(c, n),
            security_evidence(c),
            maintenance_evidence(c),
            classify_license(c.license_spdx),
            {"manifest_files_detected": ["pubspec.yaml"], "dependencies_enumerated": False},
            {"status": "PLANNED_NOT_EXECUTED"},
            utc_now(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = DryRunSubmissionClient(DossierStore(Path(tmp))).submit(
                n, ctr, "1.0.0", dossier
            )
            manifest = result["manifest"]
            self.assertTrue(str(result["target_path"]).startswith("intake/"))
            self.assertEqual(manifest["connector"]["standard"], "ai-orchestrator-lego")
            self.assertEqual(manifest["connector"]["standard_version"], "1.0.0")
            self.assertEqual(
                manifest["connector"]["provides"][0]["contract_id"], "voice.stt.v1"
            )
            self.assertEqual(manifest["status"], "discovered")
            self.assertFalse(manifest["validation"]["tests_passed"])
            self.assertNotIn("known_vulnerabilities", manifest["security"])
            self.assertEqual(manifest["provenance"]["license_file"], "provenance/LICENSE")

    def test_dry_run_rejects_mutable_license_endpoint(self) -> None:
        n = need()
        c = candidate("mutable-license", "b" * 40)
        ctr = contract()
        score = CandidateScorer().score(n, c, ctr)
        dossier = Dossier(
            1,
            n.capability_id,
            c,
            candidate_fingerprint(n.capability_id, c),
            score,
            "SHORTLISTED",
            (),
            integration_estimate(c, n),
            security_evidence(c),
            maintenance_evidence(c),
            classify_license(c.license_spdx),
            {"manifest_files_detected": [], "dependencies_enumerated": False},
            {"status": "PLANNED_NOT_EXECUTED"},
            utc_now(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "immutable"):
                DryRunSubmissionClient(DossierStore(Path(tmp))).submit(
                    n, ctr, "1.0.0", dossier
                )


if __name__ == "__main__":
    unittest.main()
