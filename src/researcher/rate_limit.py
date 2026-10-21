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
        # Search and core have independent GitHub rate-limit buckets.
        normalized = {key.lower(): value for key, value in headers.items()}
        remaining = normalized.get("x-ratelimit-remaining")
        reset = normalized.get("x-ratelimit-reset")
        if remaining is None and reset is None:
            return
        resource = str(normalized.get("x-ratelimit-resource") or "core").lower()
        if resource not in {"core", "search"}:
            # The Researcher currently uses only the REST core and search APIs.
            # Unknown resources must not poison either known quota bucket.
            return
        info = {
            "remaining": None if remaining is None else int(remaining),
            "reset_epoch": None if reset is None else int(reset),
            "observed_at": utc_now(),
        }
        all_quotas = self.state.get_json("github_rate_limits_by_resource", {})
        if not isinstance(all_quotas, dict):
            all_quotas = {}
        self.state.set_json(
            "github_rate_limits_by_resource", {**all_quotas, resource: info}
        )
        if resource == "core":
            # Backwards-compatible status and migration key. Search responses
            # must not overwrite core's last known quota.
            self.state.set_json("rate_limit", info)

    def _clear_matching_backoff(self, resource: str) -> None:
        backoff = self.state.get_json("backoff")
        if isinstance(backoff, dict):
            reason = str(backoff.get("reason") or "")
            if resource == "search" and reason != "github_search_rate_limit":
                return
            if resource == "core" and reason == "github_search_rate_limit":
                return
        self.state.set_json("backoff", None)

    def decision(self, resource: str = "core") -> RateLimitDecision:
        if resource not in {"core", "search"}:
            raise ValueError("Unsupported GitHub rate-limit resource")
        all_quotas = self.state.get_json("github_rate_limits_by_resource", {})
        quotas = all_quotas if isinstance(all_quotas, dict) else {}
        info = quotas.get(resource)
        if info is None and resource == "core":
            # Existing durable SQLite databases predate the bucket split.
            info = self.state.get_json("rate_limit", {})
        if not isinstance(info, dict):
            return RateLimitDecision(True, 0)
        remaining = info.get("remaining")
        reset = info.get("reset_epoch")
        if remaining is None or int(remaining) > 0:
            self._clear_matching_backoff(resource)
            return RateLimitDecision(True, 0)
        if reset is None:
            return RateLimitDecision(False, 3600)
        now = int(datetime.now(UTC).timestamp())
        # A persisted quota exhaustion is valid only until its reset epoch.
        if int(reset) <= now:
            self._clear_matching_backoff(resource)
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
