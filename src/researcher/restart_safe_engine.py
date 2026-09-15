from __future__ import annotations

from typing import Any

from .models import utc_now
from .observability import EventLevel, sanitize_payload
from .target_engine import TargetAwareResearchEngine


class RestartSafeResearchEngine(TargetAwareResearchEngine):
    """Target-aware engine variant that reconciles interrupted Library intake first."""

    def run_cycle(self) -> dict[str, Any]:
        resume = getattr(self.submission, "resume_pending", None)
        resumed: list[dict[str, Any]] = []
        if callable(resume):
            try:
                value = resume()
                if isinstance(value, list):
                    resumed = [item for item in value if isinstance(item, dict)]
                if resumed:
                    self._emit(
                        EventLevel.INFO,
                        "submission_resume_completed",
                        {"submitted": len(resumed), "result": "COMPLETED"},
                    )
            except Exception as exc:
                safe_message = sanitize_payload(str(exc))
                self.state.set_json(
                    "last_error",
                    {
                        "at": utc_now(),
                        "type": type(exc).__name__,
                        "message": safe_message,
                    },
                )
                self.state.set_json("engine_state", "BACKOFF")
                self._emit(
                    EventLevel.ERROR,
                    "submission_resume_failed",
                    {"error_type": type(exc).__name__, "message": safe_message},
                )
                raise

        result = super().run_cycle()
        if resumed:
            result = dict(result)
            result["resumed_submissions"] = [
                {
                    "submission_id": item.get("submission_id"),
                    "state": item.get("state"),
                    "target_path": item.get("target_path"),
                }
                for item in resumed
            ]
            self.state.set_json("last_cycle", {"at": utc_now(), **result})
        return result
