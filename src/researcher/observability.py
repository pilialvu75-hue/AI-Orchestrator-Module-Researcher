from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from .state import SQLiteStateStore


class EventLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


_SECRET_KEY = re.compile(
    r"(?:token|secret|password|passwd|authorization|credential|cookie|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_LONG_SECRETISH = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b")
_PUBLIC_FIELDS = {
    "capability_id",
    "mode",
    "phase",
    "result",
    "lifecycle",
    "provider",
    "status_code",
    "retry_after_seconds",
    "security_verdict",
    "supply_chain_verdict",
    "vulnerability_verdict",
    "shortlisted",
    "security_review",
    "security_blocked",
    "prepared_submissions",
    "error_type",
}


def _sanitize_string(value: str) -> str:
    text = _BEARER.sub("Bearer [REDACTED]", value)
    text = _LONG_SECRETISH.sub("[REDACTED]", text)
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        # Public diagnostics never needs URL credentials, query strings or fragments.
        hostname = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path[:240]
        text = urllib.parse.urlunsplit((parsed.scheme, hostname + port, path, "", ""))
    return text[:500]


def sanitize_payload(value: Any, *, key: str | None = None) -> Any:
    if key is not None and _SECRET_KEY.search(key):
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): sanitize_payload(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_payload(item) for item in value]
    return _sanitize_string(str(value))


def public_projection(payload: Mapping[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for key in sorted(_PUBLIC_FIELDS):
        if key in payload:
            projected[key] = sanitize_payload(payload[key], key=key)
    return projected


@dataclass(frozen=True)
class EventRecord:
    id: int
    created_at: str
    level: str
    component: str
    event: str
    payload: dict[str, Any]
    public_payload: dict[str, Any]


class EventLogger:
    """Durable structured event logger. Local storage is authoritative."""

    def __init__(self, state: SQLiteStateStore) -> None:
        self.state = state

    def emit(
        self,
        level: EventLevel | str,
        component: str,
        event: str,
        payload: Mapping[str, Any] | None = None,
    ) -> int:
        clean_payload = sanitize_payload(dict(payload or {}))
        public_payload = public_projection(clean_payload)
        return self.state.append_event(
            level=str(level),
            component=component[:80],
            event=event[:120],
            payload=clean_payload,
            public_payload=public_payload,
        )
