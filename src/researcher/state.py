from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .models import ResearchMode, utc_now


_PENDING_SUBMISSION_STATES = {"PREPARED", "DELIVERING", "RETRY"}
_TERMINAL_SUBMISSION_STATES = {"SUBMITTED", "DRY_RUN_PREPARED", "MERGED"}


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

    @staticmethod
    def _submission_columns(conn: sqlite3.Connection) -> set[str]:
        return {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(submissions)").fetchall()
        }

    def _migrate_submissions(self, conn: sqlite3.Connection) -> None:
        columns = self._submission_columns(conn)
        migrations = {
            "payload_json": "payload_json TEXT NOT NULL DEFAULT '{}'",
            "branch": "branch TEXT",
            "pull_request_url": "pull_request_url TEXT",
            "attempts": "attempts INTEGER NOT NULL DEFAULT 0",
            "last_error": "last_error TEXT",
            "updated_at": "updated_at TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in migrations.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE submissions ADD COLUMN {declaration}")
        conn.execute(
            """
            UPDATE submissions
            SET updated_at=created_at
            WHERE updated_at IS NULL OR updated_at=''
            """
        )

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
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    branch TEXT,
                    pull_request_url TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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
            self._migrate_submissions(conn)
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_submissions_state
                ON submissions(state, updated_at)
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
        queue_diagnostics: bool,
        retention: int = 5000,
    ) -> int:
        now = utc_now()
        public_json = json.dumps(public_payload, sort_keys=True, separators=(",", ":"))
        diagnostics_state = "PENDING" if public_payload and queue_diagnostics else "SKIPPED"
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
            event_id = cursor.lastrowid
            if event_id is None:
                raise RuntimeError("SQLite did not return an event id")
            if retention > 0:
                conn.execute(
                    """
                    DELETE FROM events
                    WHERE diagnostics_state!='PENDING'
                      AND id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)
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
        with self._connect() as conn:
            conn.executemany(
                """
                UPDATE events
                SET diagnostics_state='SENT', diagnostics_next_attempt_at=NULL
                WHERE id=?
                """,
                ((event_id,) for event_id in event_ids),
            )

    def mark_diagnostics_retry(self, event_ids: list[int], next_attempt_at: str) -> None:
        if not event_ids:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                UPDATE events
                SET diagnostics_attempts=diagnostics_attempts+1,
                    diagnostics_next_attempt_at=?
                WHERE id=? AND diagnostics_state='PENDING'
                """,
                ((next_attempt_at, event_id) for event_id in event_ids),
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

    @staticmethod
    def _encode_submission_payload(payload: dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def reserve_submission(
        self,
        fingerprint: str,
        capability_id: str,
        submission_id: str,
        target_path: str,
        payload: dict[str, Any],
        *,
        branch: str | None = None,
    ) -> bool:
        """Durably record an immutable delivery intent before any remote side effect."""

        encoded = self._encode_submission_payload(payload)
        now = utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM submissions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["capability_id"]) != capability_id
                    or str(existing["submission_id"]) != submission_id
                    or str(existing["target_path"]) != target_path
                ):
                    raise RuntimeError("Stored submission identity diverges from retry intent")
                stored_payload = str(existing["payload_json"] or "{}")
                if stored_payload not in {"", "{}"} and stored_payload != encoded:
                    raise RuntimeError("Stored submission payload diverges from retry intent")
                if stored_payload in {"", "{}"}:
                    if str(existing["state"]) in _PENDING_SUBMISSION_STATES:
                        raise RuntimeError("Legacy pending submission has no recoverable payload")
                    return False
                if branch and existing["branch"] not in {None, "", branch}:
                    raise RuntimeError("Stored submission branch diverges from retry intent")
                return False
            conn.execute(
                """
                INSERT INTO submissions(
                    fingerprint, capability_id, submission_id, state, target_path,
                    payload_json, branch, pull_request_url, attempts, last_error,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 'PREPARED', ?, ?, ?, NULL, 0, NULL, ?, ?)
                """,
                (
                    fingerprint,
                    capability_id,
                    submission_id,
                    target_path,
                    encoded,
                    branch,
                    now,
                    now,
                ),
            )
        return True

    def mark_submission_attempt(self, fingerprint: str) -> bool:
        now = utc_now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state FROM submissions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row is None:
                raise RuntimeError("Submission attempt has no durable intent")
            if str(row["state"]) in _TERMINAL_SUBMISSION_STATES:
                return False
            conn.execute(
                """
                UPDATE submissions
                SET state='DELIVERING', attempts=attempts+1, last_error=NULL, updated_at=?
                WHERE fingerprint=?
                """,
                (now, fingerprint),
            )
        return True

    def mark_submission_retry(self, fingerprint: str, error: str) -> None:
        message = str(error).replace("\x00", "")[:1000]
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state FROM submissions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row is None:
                raise RuntimeError("Submission retry has no durable intent")
            if str(row["state"]) in _TERMINAL_SUBMISSION_STATES:
                return
            conn.execute(
                """
                UPDATE submissions
                SET state='RETRY', last_error=?, updated_at=?
                WHERE fingerprint=?
                """,
                (message, utc_now(), fingerprint),
            )

    def complete_submission(
        self,
        fingerprint: str,
        state: str,
        *,
        branch: str | None = None,
        pull_request_url: str | None = None,
    ) -> None:
        if state not in _TERMINAL_SUBMISSION_STATES:
            raise ValueError(f"Invalid terminal submission state: {state}")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM submissions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row is None:
                raise RuntimeError("Submission completion has no durable intent")
            conn.execute(
                """
                UPDATE submissions
                SET state=?,
                    branch=COALESCE(?, branch),
                    pull_request_url=COALESCE(?, pull_request_url),
                    last_error=NULL,
                    updated_at=?
                WHERE fingerprint=?
                """,
                (state, branch, pull_request_url, utc_now(), fingerprint),
            )

    def pending_submissions(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 500))
        placeholders = ",".join("?" for _ in _PENDING_SUBMISSION_STATES)
        states = tuple(sorted(_PENDING_SUBMISSION_STATES))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM submissions
                WHERE state IN ({placeholders})
                ORDER BY created_at ASC LIMIT ?
                """,
                (*states, bounded),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw = str(item.pop("payload_json") or "{}")
            payload = json.loads(raw)
            if not isinstance(payload, dict) or not payload:
                raise RuntimeError(
                    f"Pending submission {item['submission_id']} has no recoverable payload"
                )
            item["payload"] = payload
            result.append(item)
        return result

    def submission_row(self, fingerprint: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM submissions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        raw = str(item.pop("payload_json") or "{}")
        item["payload"] = json.loads(raw)
        return item

    def mark_submission(
        self,
        fingerprint: str,
        capability_id: str,
        submission_id: str,
        state: str,
        target_path: str,
    ) -> bool:
        """Compatibility acknowledgement used by the engine after submit() returns."""

        with self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM submissions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
        if existing is not None:
            same_identity = (
                str(existing["capability_id"]) == capability_id
                and str(existing["submission_id"]) == submission_id
                and str(existing["target_path"]) == target_path
            )
            if not same_identity:
                return False
            current = str(existing["state"])
            if current in _PENDING_SUBMISSION_STATES and state in _TERMINAL_SUBMISSION_STATES:
                self.complete_submission(fingerprint, state)
                return True
            return False

        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO submissions(
                    fingerprint, capability_id, submission_id, state, target_path,
                    payload_json, branch, pull_request_url, attempts, last_error,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, '{}', NULL, NULL, 0, NULL, ?, ?)
                """,
                (fingerprint, capability_id, submission_id, state, target_path, now, now),
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
            submission_counts = conn.execute(
                """
                SELECT
                  SUM(CASE WHEN state IN ('SUBMITTED','DRY_RUN_PREPARED','MERGED')
                           THEN 1 ELSE 0 END) AS completed,
                  SUM(CASE WHEN state IN ('PREPARED','DELIVERING','RETRY')
                           THEN 1 ELSE 0 END) AS pending
                FROM submissions
                """
            ).fetchone()
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
            "diagnostics": self.get_json("diagnostics_status", {"state": "DISABLED"}),
            "needs_total": self.get_json("needs_total", 0),
            "needs_incomplete": self.get_json("needs_incomplete", 0),
            "candidates": int(totals["candidates"] or 0),
            "shortlisted": int(totals["shortlisted"] or 0),
            "rejected": int(totals["rejected"] or 0),
            "security_review": int(totals["security_review"] or 0),
            "security_blocked": int(totals["security_blocked"] or 0),
            "submitted": int(submission_counts["completed"] or 0),
            "submissions_pending": int(submission_counts["pending"] or 0),
            "events": int(event_counts["total"] or 0),
            "diagnostics_pending": int(event_counts["pending"] or 0),
        }
