from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "platform.filesystem"


def _load(name: str) -> dict[str, object]:
    return json.loads((PROOF / name).read_text(encoding="utf-8"))


class PlatformFilesystemProofTest(unittest.TestCase):
    def test_need_remains_staged_and_contract_remains_draft(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(
            comparison["need_source"],
            "catalog/needs.platform-extension.json",
        )
        self.assertEqual(comparison["need_status"], "needed")
        contract = comparison["contract"]
        assert isinstance(contract, dict)
        self.assertEqual(contract["contract_id"], "platform.filesystem.v1")
        self.assertEqual(contract["status"], "draft")
        decision = comparison["decision"]
        assert isinstance(decision, dict)
        self.assertFalse(decision["submission_ready"])
        self.assertFalse(decision["certification_asserted"])

    def test_required_targets_and_two_independent_candidates_are_explicit(self) -> None:
        comparison = _load("comparison.json")
        self.assertEqual(comparison["desired_candidates"], 2)
        self.assertEqual(
            set(comparison["required_targets"]),
            {"android", "windows", "linux", "macos", "ios", "raspberry_pi"},
        )
        candidates = comparison["candidates"]
        assert isinstance(candidates, list)
        self.assertEqual(len(candidates), 2)
        repositories = {str(item["id"]).split(":", 1)[0] for item in candidates}
        self.assertEqual(repositories, {"dart-lang/tools", "whuppi/cellar_flutter"})

    def test_live_security_results_fail_closed_without_overclaiming(self) -> None:
        live = _load("live-security-preflights-2026-09-15.json")
        self.assertFalse(live["certification_asserted"])
        self.assertFalse(live["functional_or_contract_fit_asserted"])
        self.assertFalse(live["library_accessed"])
        self.assertFalse(live["library_write_attempted"])
        self.assertFalse(live["executed_untrusted_code"])

        results = live["results"]
        assert isinstance(results, list)
        by_candidate = {item["candidate"]: item for item in results}

        file_result = by_candidate["dart-lang/tools:pkgs/file"]
        self.assertEqual(file_result["state"], "REVIEW")
        self.assertEqual(file_result["security"]["verdict"], "CLEAR")
        self.assertEqual(file_result["supply_chain"]["verdict"], "CLEAR")
        self.assertEqual(file_result["vulnerability"]["verdict"], "REVIEW")
        self.assertFalse(file_result["vulnerability"]["database_checked"])
        self.assertEqual(len(file_result["vulnerability"]["unresolved"]), 2)

        cellar_result = by_candidate["whuppi/cellar_flutter"]
        self.assertEqual(cellar_result["state"], "CLEAR")
        self.assertEqual(cellar_result["security"]["verdict"], "CLEAR")
        self.assertEqual(cellar_result["supply_chain"]["verdict"], "CLEAR")
        self.assertEqual(cellar_result["vulnerability"]["verdict"], "CLEAR")
        self.assertTrue(cellar_result["vulnerability"]["database_checked"])
        self.assertEqual(cellar_result["vulnerability"]["queried_components"], 48)
        self.assertEqual(cellar_result["vulnerability"]["hits"], [])

    def test_raspberry_pi_and_chroot_security_are_not_overclaimed(self) -> None:
        file_dossier = _load("dart-lang-tools-file.dossier.json")
        cellar_dossier = _load("whuppi-cellar-flutter.dossier.json")

        file_evidence = file_dossier["evidence"]
        assert isinstance(file_evidence, dict)
        self.assertFalse(file_evidence["chroot_is_os_security_boundary"])
        self.assertFalse(file_evidence["atomic_replace_semantics_verified"])
        self.assertFalse(file_evidence["raspberry_pi_explicitly_verified_upstream"])

        cellar_evidence = cellar_dossier["evidence"]
        assert isinstance(cellar_evidence, dict)
        self.assertTrue(cellar_evidence["atomic_writes_documented"])
        self.assertFalse(cellar_evidence["general_filesystem_interface"])
        self.assertFalse(cellar_evidence["raspberry_pi_explicitly_verified_upstream"])


if __name__ == "__main__":
    unittest.main()
