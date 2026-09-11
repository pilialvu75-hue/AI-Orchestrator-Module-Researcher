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


if __name__ == "__main__":
    unittest.main()
