from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from researcher.models import ResearchMode
from researcher.rate_limit import RateLimitManager
from researcher.scheduler import Scheduler
from researcher.state import SQLiteStateStore


class RateLimitTests(unittest.TestCase):
    def test_zero_remaining_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            manager = RateLimitManager(state)
            manager.observe_headers(
                {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + 120),
                }
            )
            decision = manager.decision()
            self.assertFalse(decision.allowed)
            self.assertGreaterEqual(decision.retry_after_seconds, 60)
            manager.record_backoff(decision.retry_after_seconds, "github_rate_limit")
            scheduler = Scheduler(
                state,
                lambda: ResearchMode.SEEDING,
                60,
                60,
                60,
            )
            self.assertGreaterEqual(scheduler.delay_seconds(), 100)


    def test_expired_reset_reopens_discovery_after_restored_zero(self) -> None:
        # A cached SQLite state must not persist a rate-limit block forever.
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            manager = RateLimitManager(state)
            manager.observe_headers(
                {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) - 60),
                }
            )
            manager.record_backoff(3600, "github_rate_limit")
            decision = manager.decision()
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.retry_after_seconds, 0)
            self.assertIsNone(state.get_json("backoff"))
            # Until a response refreshes the cached headers, the attempt is
            # allowed; this does not claim the quota actually renewed.
            self.assertTrue(manager.decision().allowed)

    def test_future_reset_still_blocks_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            manager = RateLimitManager(state)
            manager.observe_headers(
                {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + 300),
                }
            )
            decision = manager.decision()
            self.assertFalse(decision.allowed)
            self.assertGreaterEqual(decision.retry_after_seconds, 60)


if __name__ == "__main__":
    unittest.main()
