from __future__ import annotations

import unittest

from researcher.models import Need
from tools.discovery_probe import probe_need


class QuotaBlockedProvider:
    last_discovery_diagnostics = {"status": "CORE_RATE_LIMITED"}

    def discover(self, need: Need, *, limit: int = 2) -> list:
        return []


class DiscoveryProbeTests(unittest.TestCase):
    def test_quota_blocked_discovery_is_not_reported_as_no_candidates(self) -> None:
        need = Need(
            capability_id="storage.secrets",
            title="Secrets",
            priority="high",
            desired_candidates=2,
            status="needed",
            targets=("android",),
        )
        result = probe_need(QuotaBlockedProvider(), need)  # type: ignore[arg-type]
        self.assertEqual(result["status"], "QUOTA_BLOCKED")
        self.assertEqual(result["diagnostics"]["status"], "CORE_RATE_LIMITED")


if __name__ == "__main__":
    unittest.main()
