from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Mapping

from .models import utc_now
from .state import SQLiteStateStore


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


class RateLimitManager:
    def __init__(self, state: SQLiteStateStore) -> None:
        self.state = state

    def observe_headers(self, headers: Mapping[str, str]) -> None:
        remaining = headers.get("X-RateLimit-Remaining")
        reset = headers.get("X-RateLimit-Reset")
        if remaining is None and reset is None:
            return
        self.state.set_json(
            "rate_limit",
            {
                "remaining": None if remaining is None else int(remaining),
                "reset_epoch": None if reset is None else int(reset),
                "observed_at": utc_now(),
            },
        )

    def decision(self) -> RateLimitDecision:
        info = self.state.get_json("rate_limit", {})
        if not isinstance(info, dict):
            return RateLimitDecision(True, 0)
        remaining = info.get("remaining")
        reset = info.get("reset_epoch")
        if remaining is None or int(remaining) > 0:
            self.state.set_json("backoff", None)
            return RateLimitDecision(True, 0)
        if reset is None:
            return RateLimitDecision(False, 3600)
        now = int(datetime.now(UTC).timestamp())
        # The SQLite state survives GitHub Actions runs, but the GitHub rate
        # window does not. A persisted zero must never disable discovery after
        # its reset time has passed: the next request refreshes the headers.
        if int(reset) <= now:
            self.state.set_json("backoff", None)
            return RateLimitDecision(True, 0)
        return RateLimitDecision(False, max(60, int(reset) - now + 5))

    def record_backoff(self, seconds: int, reason: str) -> None:
        until = datetime.now(UTC) + timedelta(seconds=max(1, seconds))
        self.state.set_json(
            "backoff",
            {"until": until.isoformat().replace("+00:00", "Z"), "reason": reason},
        )

    @staticmethod
    def retry_after(headers: Mapping[str, str]) -> int:
        raw = headers.get("Retry-After")
        if raw:
            try:
                return max(1, int(raw))
            except ValueError:
                try:
                    when = parsedate_to_datetime(raw)
                    return max(1, int((when - datetime.now(UTC)).total_seconds()))
                except (TypeError, ValueError):
                    pass
        return 60
