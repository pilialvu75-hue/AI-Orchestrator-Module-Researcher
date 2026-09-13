from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .models import ResearchMode, utc_now


class SQLiteStateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS candidates (
                    fingerprint TEXT PRIMARY KEY,
                    capability_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    lifecycle TEXT NOT NULL,
                    score REAL NOT NULL,
                    rejection_reason TEXT,
                    dossier_path TEXT,
                    first_seen_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS submissions (
                    fingerprint TEXT PRIMARY KEY,
                    capability_id TEXT NOT NULL,
                    submission_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    capability_id TEXT PRIMARY KEY,
                    last_scan_at TEXT,
                    last_success_at TEXT,
                    next_scan_at TEXT,
                    error_state TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    level TEXT NOT NULL,
                    component TEXT NOT NULL,
                    event TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    public_payload_json TEXT NOT NULL,
                    diagnostics_state TEXT NOT NULL,
                    diagnostics_attempts INTEGER NOT NULL DEFAULT 0,
                    diagnostics_next_attempt_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_events_diagnostics
                    ON events(diagnostics_state, diagnostics_next_attempt_at, id);
                """
            )

    def set_json(self, key: str, value: Any) -> None:
        now = utc_now()
        encoded = json.dumps(value, sort_keys=True)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kv(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, encoded, now),
            )

    def get_json(self, key: str, default: Any = None) -> Any:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return default if row is None else json.loads(str(row["value"]))

    def append_event(
        self,
        *,
        level: str,
        component: str,
        event: str,
        payload: Any,
        public_payload: Any,
        retention: int = 5000,
    ) -> int:
        now = utc_now()
        public_json = json.dumps(public_payload, sort_keys=True, separators=(",", ":"))
        diagnostics_state = "PENDING" if public_payload else "SKIPPED"
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events(
                    created_at, level, component, event, payload_json, public_payload_json,
                    diagnostics_state, diagnostics_attempts, diagnostics_next_attempt_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)
                """,
                (
                    now,
                    level,
                    component,
                    event,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    public_json,
                    diagnostics_state,
                ),
            )
            event_id = int(cursor.lastrowid)
            if retention > 0:
                conn.execute(
                    """
                    DELETE FROM events
                    WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)
                    """,
                    (retention,),
                )
        return event_id

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 1000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, level, component, event, payload_json,
                       public_payload_json, diagnostics_state, diagnostics_attempts,
                       diagnostics_next_attempt_at
                FROM events ORDER BY id DESC LIMIT ?
                """,
                (bounded,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(str(item.pop("payload_json")))
            item["public_payload"] = json.loads(str(item.pop("public_payload_json")))
            result.append(item)
        return result

    def pending_diagnostics(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 500))
        now = utc_now()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, level, component, event, public_payload_json,
                       diagnostics_attempts
                FROM events
                WHERE diagnostics_state='PENDING'
                  AND (diagnostics_next_attempt_at IS NULL OR diagnostics_next_attempt_at<=?)
                ORDER BY id ASC LIMIT ?
                """,
                (now, bounded),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["public_payload"] = json.loads(str(item.pop("public_payload_json")))
            result.append(item)
        return result

    def mark_diagnostics_sent(self, event_ids: list[int]) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE events SET diagnostics_state='SENT', diagnostics_next_attempt_at=NULL
                WHERE id IN ({placeholders})
                """,
                tuple(event_ids),
            )

    def mark_diagnostics_retry(self, event_ids: list[int], next_attempt_at: str) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE events
                SET diagnostics_attempts=diagnostics_attempts+1,
                    diagnostics_next_attempt_at=?
                WHERE id IN ({placeholders}) AND diagnostics_state='PENDING'
                """,
                (next_attempt_at, *event_ids),
            )

    def upsert_candidate(
        self,
        fingerprint: str,
        capability_id: str,
        repository: str,
        commit_sha: str,
        lifecycle: str,
        score: float,
        dossier_path: str,
        rejection_reason: str | None = None,
    ) -> bool:
        now = utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT fingerprint FROM candidates WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            conn.execute(
                """
                INSERT INTO candidates(
                    fingerprint, capability_id, repository, commit_sha, lifecycle, score,
                    rejection_reason, dossier_path, first_seen_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    lifecycle=excluded.lifecycle,
                    score=excluded.score,
                    rejection_reason=excluded.rejection_reason,
                    dossier_path=excluded.dossier_path,
                    updated_at=excluded.updated_at
                """,
                (
                    fingerprint,
                    capability_id,
                    repository,
                    commit_sha,
                    lifecycle,
                    score,
                    rejection_reason,
                    dossier_path,
                    now,
                    now,
                ),
            )
        return existing is None

    def is_known_candidate(self, fingerprint: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM candidates WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
        return row is not None

    def count_qualified(self, capability_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c FROM candidates
                WHERE capability_id=? AND lifecycle IN ('SHORTLISTED', 'SUBMITTED')
                """,
                (capability_id,),
            ).fetchone()
        return int(row["c"]) if row else 0

    def candidate_rows(self, capability_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM candidates WHERE capability_id=? ORDER BY score DESC",
                (capability_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_submission(
        self,
        fingerprint: str,
        capability_id: str,
        submission_id: str,
        state: str,
        target_path: str,
    ) -> bool:
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT fingerprint FROM submissions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if existing:
                return False
            conn.execute(
                """
                INSERT INTO submissions(
                    fingerprint, capability_id, submission_id, state, target_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (fingerprint, capability_id, submission_id, state, target_path, utc_now()),
            )
        return True

    def update_scan(
        self,
        capability_id: str,
        *,
        success: bool,
        next_scan_at: str | None = None,
        error_state: str | None = None,
    ) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans(
                    capability_id, last_scan_at, last_success_at, next_scan_at, error_state
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(capability_id) DO UPDATE SET
                    last_scan_at=excluded.last_scan_at,
                    last_success_at=CASE
                        WHEN excluded.last_success_at IS NOT NULL
                        THEN excluded.last_success_at
                        ELSE scans.last_success_at
                    END,
                    next_scan_at=excluded.next_scan_at,
                    error_state=excluded.error_state
                """,
                (
                    capability_id,
                    now,
                    now if success else None,
                    next_scan_at,
                    error_state,
                ),
            )

    def last_scan(self, capability_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT last_scan_at FROM scans WHERE capability_id=?", (capability_id,)
            ).fetchone()
        return None if row is None else row["last_scan_at"]

    def set_mode(self, mode: ResearchMode) -> None:
        self.set_json("mode", mode.value)

    def status(self) -> dict[str, Any]:
        with self._connect() as conn:
            totals = conn.execute(
                """
                SELECT
                  COUNT(*) AS candidates,
                  SUM(CASE WHEN lifecycle='SHORTLISTED' THEN 1 ELSE 0 END) AS shortlisted,
                  SUM(CASE WHEN lifecycle='REJECTED' THEN 1 ELSE 0 END) AS rejected,
                  SUM(CASE WHEN lifecycle='SECURITY_REVIEW' THEN 1 ELSE 0 END)
                    AS security_review,
                  SUM(CASE WHEN lifecycle='SECURITY_BLOCKED' THEN 1 ELSE 0 END)
                    AS security_blocked
                FROM candidates
                """
            ).fetchone()
            submitted = conn.execute("SELECT COUNT(*) AS c FROM submissions").fetchone()
            event_counts = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN diagnostics_state='PENDING' THEN 1 ELSE 0 END) AS pending
                FROM events
                """
            ).fetchone()
        return {
            "mode": self.get_json("mode", ResearchMode.SEEDING.value),
            "engine_state": self.get_json("engine_state", "IDLE"),
            "current_capability": self.get_json("current_capability"),
            "last_cycle": self.get_json("last_cycle"),
            "next_cycle": self.get_json("next_cycle"),
            "library": self.get_json("library_snapshot", {}),
            "rate_limit": self.get_json("rate_limit", {}),
            "last_error": self.get_json("last_error"),
            "needs_total": self.get_json("needs_total", 0),
            "needs_incomplete": self.get_json("needs_incomplete", 0),
            "candidates": int(totals["candidates"] or 0),
            "shortlisted": int(totals["shortlisted"] or 0),
            "rejected": int(totals["rejected"] or 0),
            "security_review": int(totals["security_review"] or 0),
            "security_blocked": int(totals["security_blocked"] or 0),
            "submitted": int(submitted["c"] or 0),
            "events": int(event_counts["total"] or 0),
            "diagnostics_pending": int(event_counts["pending"] or 0),
        }
