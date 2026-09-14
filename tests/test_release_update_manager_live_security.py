from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs" / "controlled-scans" / "release.update_manager"
LIVE = PROOF / "live-security-preflights-2026-09-14.json"


class ReleaseUpdateManagerLiveSecurityTest(unittest.TestCase):
    @staticmethod
    def _payload() -> dict:
        return json.loads(LIVE.read_text(encoding="utf-8"))

    def test_live_preflight_never_asserts_certification_or_execution(self) -> None:
        payload = self._payload()
        self.assertEqual(payload["capability_id"], "release.update_manager")
        self.assertFalse(payload["certification_asserted"])
        self.assertFalse(payload["library_accessed"])
        self.assertFalse(payload["library_write_attempted"])
        self.assertFalse(payload["executed_untrusted_code"])
        self.assertEqual(len(payload["results"]), 3)
        self.assertTrue(payload["decision"]["contract_detail_gap_remains"])
        self.assertFalse(
            payload["decision"]["complete_cross_platform_update_manager_found"]
        )

    def test_background_downloader_keeps_real_security_review_findings(self) -> None:
        payload = self._payload()
        background = payload["results"][0]

        self.assertEqual(background["candidate"], "781flyingdutchman/background_downloader")
        self.assertEqual(background["state"], "REVIEW")
        self.assertEqual(background["security"]["verdict"], "REVIEW")
        self.assertFalse(background["security"]["complete"])
        self.assertEqual(background["supply_chain"]["verdict"], "CLEAR")
        self.assertEqual(
            background["supply_chain"]["manifests_analyzed"],
            ["pubspec.yaml"],
        )
        rules = {finding["rule_id"] for finding in background["security"]["findings"]}
        self.assertIn("tls_certificate_validation_bypass", rules)
        self.assertIn("opaque_or_precompiled_artifact", rules)
        self.assertIn("suspicious_obfuscation", rules)
        self.assertIn(
            "example/assets/5MB-test.ZIP",
            background["security"]["opaque_artifacts"],
        )
        self.assertEqual(background["vulnerability"]["verdict"], "NOT_ANALYZED")

    def test_app_updater_exposes_true_unresolved_runtime_versions(self) -> None:
        payload = self._payload()
        updater = payload["results"][1]

        self.assertEqual(updater["candidate"], "mantreshkhurana/app_updater")
        self.assertEqual(updater["state"], "REVIEW")
        self.assertEqual(updater["security"]["verdict"], "CLEAR")
        self.assertTrue(updater["security"]["complete"])
        self.assertEqual(updater["supply_chain"]["verdict"], "CLEAR")
        self.assertEqual(updater["supply_chain"]["lockfiles_present"], [])
        self.assertEqual(updater["vulnerability"]["verdict"], "REVIEW")
        self.assertFalse(updater["vulnerability"]["database_checked"])
        self.assertEqual(
            set(updater["vulnerability"]["unresolved"]),
            {
                "version_unresolved:Pub:http:^1.6.0",
                "version_unresolved:Pub:package_info_plus:^9.0.0",
                "version_unresolved:Pub:shared_preferences:^2.5.4",
                "version_unresolved:Pub:url_launcher:^6.3.2",
                "version_unresolved:Pub:xml:^6.6.1",
            },
        )

    def test_updat_process_execution_review_is_not_downgraded(self) -> None:
        payload = self._payload()
        updat = payload["results"][2]

        self.assertEqual(updat["candidate"], "aguilaair/updat")
        self.assertEqual(updat["state"], "REVIEW")
        self.assertEqual(updat["security"]["verdict"], "REVIEW")
        self.assertEqual(updat["supply_chain"]["verdict"], "CLEAR")
        self.assertEqual(updat["vulnerability"]["verdict"], "NOT_ANALYZED")
        self.assertEqual(
            [finding["rule_id"] for finding in updat["security"]["findings"]],
            ["process_execution"],
        )
        self.assertEqual(
            updat["security"]["findings"][0]["path"],
            "lib/utils/open_link.dart",
        )


if __name__ == "__main__":
    unittest.main()
