from __future__ import annotations

import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Callable

from .models import ResearchMode
from .state import SQLiteStateStore


class Scheduler:
    def __init__(
        self,
        state: SQLiteStateStore,
        mode_provider: Callable[[], ResearchMode],
        seeding_interval: int,
        maintenance_interval: int,
        improvement_interval: int,
    ) -> None:
        self.state = state
        self.mode_provider = mode_provider
        self.intervals = {
            ResearchMode.SEEDING: seeding_interval,
            ResearchMode.MAINTENANCE: maintenance_interval,
            ResearchMode.IMPROVEMENT: improvement_interval,
        }

    def delay_seconds(self) -> int:
        mode = self.mode_provider()
        base = max(60, self.intervals[mode])
        jitter = secrets.randbelow(max(2, base // 10 + 1))
        delay = base + jitter
        backoff = self.state.get_json("backoff")
        if isinstance(backoff, dict) and backoff.get("until"):
            try:
                until = datetime.fromisoformat(str(backoff["until"]).replace("Z", "+00:00"))
                remaining = int((until - datetime.now(UTC)).total_seconds())
                delay = max(delay, remaining)
            except ValueError:
                pass
        return max(60, delay)

    def sleep(self) -> None:
        delay = self.delay_seconds()
        next_at = datetime.now(UTC) + timedelta(seconds=delay)
        self.state.set_json("next_cycle", next_at.isoformat().replace("+00:00", "Z"))
        time.sleep(delay)
