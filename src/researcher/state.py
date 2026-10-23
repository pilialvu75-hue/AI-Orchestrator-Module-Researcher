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
                CREATE TABLE IF NOT EXISTS improvement_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    capability_id TEXT NOT NULL,
                    novelty_json TEXT NOT NULL,
                    acceptance_gates_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_improvement_proposals_capability
                    ON improvement_proposals(capability_id, updated_at);
                CREATE TABLE IF NOT EXISTS research_sources (
                    source_id TEXT PRIMARY KEY,
                    capability_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    direct_reuse INTEGER NOT NULL,
                    research_use INTEGER NOT NULL,
                    signals_json TEXT NOT NULL,
                    novelty_json TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_research_sources_capability
                    ON research_sources(capability_id, updated_at);
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

    def security_review_retry_due(self, fingerprint: str) -> bool:
        """Retry only stale review decisions; never bypass the security gates.

        SQLite evaluates the stored UTC timestamp so a repeated sweep cannot
        immediately rescan the same candidate and exhaust GitHub API quota.
        """
        with self._connect() as conn:
            row = conn.execute(
                """SELECT 1 FROM candidates
                   WHERE fingerprint=? AND lifecycle='SECURITY_REVIEW'
                     AND datetime(updated_at) <= datetime('now', '-24 hours')""",
                (fingerprint,),
            ).fetchone()
        return row is not None

    def is_known_candidate(self, fingerprint: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM candidates WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
        return row is not None

    def count_qualified(self, capability_id: str) -> int:
        """Count locally qualified candidates, regardless of delivery state.

        Kept for scoring/inspection compatibility. Seeding completion uses
        count_completed_submissions() so an orphan shortlist cannot masquerade as
        delivered Library coverage.
        """

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c FROM candidates
                WHERE capability_id=? AND lifecycle IN ('SHORTLISTED', 'SUBMITTED')
                """,
                (capability_id,),
            ).fetchone()
        return int(row["c"]) if row else 0

    def count_completed_submissions(self, capability_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c FROM submissions
                WHERE capability_id=?
                  AND state IN ('SUBMITTED', 'DRY_RUN_PREPARED', 'MERGED')
                """,
                (capability_id,),
            ).fetchone()
        return int(row["c"]) if row else 0

    def orphan_shortlist_rows(self, capability_id: str) -> list[dict[str, Any]]:
        """Return shortlisted candidates that never reached durable submission intent."""

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT c.*
                FROM candidates AS c
                LEFT JOIN submissions AS s ON s.fingerprint=c.fingerprint
                WHERE c.capability_id=?
                  AND c.lifecycle='SHORTLISTED'
                  AND s.fingerprint IS NULL
                ORDER BY c.score DESC, c.first_seen_at ASC
                """,
                (capability_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def candidate_rows(self, capability_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM candidates WHERE capability_id=? ORDER BY score DESC",
                (capability_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def candidate_recovery_queue(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Read-only review queue for previously screened candidates.

        A rejected candidate may provide research value, but it must never
        bypass a fresh admission decision or be promoted by this report.
        Security-blocked entries are deliberately excluded.
        """
        bounded = max(1, min(int(limit), 1000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT fingerprint, capability_id, repository, commit_sha,
                       lifecycle, rejection_reason, score, dossier_path
                FROM candidates
                WHERE lifecycle IN ('REJECTED', 'SECURITY_REVIEW')
                ORDER BY CASE lifecycle
                    WHEN 'REJECTED' THEN 0 ELSE 1 END,
                    updated_at ASC, fingerprint ASC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
        return [
            {
                **dict(row),
                "recovery_action": (
                    "review_scoring_and_policy_then_fresh_admission"
                    if row["lifecycle"] == "REJECTED"
                    else "repeat_security_review_with_current_evidence"
                ),
                "automatically_admitted": False,
            }
            for row in rows
        ]

    def candidates_missing_research_knowledge(
        self, capability_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Return persisted candidates not yet represented in Research V2 memory."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT c.*
                FROM candidates c
                LEFT JOIN research_sources r
                  ON r.capability_id = c.capability_id
                 AND r.repository = c.repository
                 AND r.commit_sha = c.commit_sha
                WHERE c.capability_id=? AND r.source_id IS NULL
                ORDER BY c.first_seen_at ASC
                LIMIT ?
                """,
                (capability_id, limit),
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
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM submissions
                WHERE state IN ('PREPARED', 'DELIVERING', 'RETRY')
                ORDER BY created_at ASC LIMIT ?
                """,
                (bounded,),
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

    def record_research_source(
        self,
        *,
        source_id: str,
        capability_id: str,
        repository: str,
        commit_sha: str,
        direct_reuse: bool,
        research_use: bool,
        signals: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Persist compact knowledge and return only signals new to this capability."""
        now = utc_now()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT signals_json FROM research_sources WHERE capability_id=?",
                (capability_id,),
            ).fetchall()
            known: set[str] = set()
            for row in rows:
                known.update(json.loads(str(row["signals_json"])))
            novelty = tuple(sorted(set(signals) - known))
            conn.execute(
                """
                INSERT INTO research_sources(
                    source_id, capability_id, repository, commit_sha, direct_reuse,
                    research_use, signals_json, novelty_json, first_seen_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    direct_reuse=excluded.direct_reuse,
                    research_use=excluded.research_use,
                    signals_json=excluded.signals_json,
                    novelty_json=excluded.novelty_json,
                    updated_at=excluded.updated_at
                """,
                (
                    source_id, capability_id, repository, commit_sha,
                    int(direct_reuse), int(research_use),
                    json.dumps(signals, sort_keys=True),
                    json.dumps(novelty, sort_keys=True),
                    now, now,
                ),
            )
        return novelty

    def record_improvement_proposal(
        self,
        *,
        proposal_id: str,
        capability_id: str,
        novelty: tuple[str, ...],
        acceptance_gates: tuple[str, ...],
    ) -> bool:
        """Queue a proposal once; execution remains a separate gated stage."""
        now = utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT 1 FROM improvement_proposals WHERE proposal_id=?",
                (proposal_id,),
            ).fetchone()
            if existing is not None:
                return False
            conn.execute(
                """
                INSERT INTO improvement_proposals(
                    proposal_id, capability_id, novelty_json,
                    acceptance_gates_json, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'PROPOSED', ?, ?)
                """,
                (
                    proposal_id,
                    capability_id,
                    json.dumps(novelty, sort_keys=True),
                    json.dumps(acceptance_gates, sort_keys=True),
                    now,
                    now,
                ),
            )
        return True

    def export_improvement_proposals(self, *, limit: int = 100) -> dict[str, Any]:
        """Read-only, deterministic handoff for Library planning; never approves work."""
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT proposal_id, capability_id, novelty_json,
                          acceptance_gates_json, created_at
                   FROM improvement_proposals
                   WHERE state='PROPOSED'
                   ORDER BY created_at, proposal_id LIMIT ?""",
                (limit,),
            ).fetchall()
        return {
            "schema_version": 1,
            "kind": "research_improvement_proposals",
            "proposals": [
                {
                    "proposal_id": str(row["proposal_id"]),
                    "capability_id": str(row["capability_id"]),
                    "novelty": json.loads(str(row["novelty_json"])),
                    "acceptance_gates": json.loads(str(row["acceptance_gates_json"])),
                    "created_at": str(row["created_at"]),
                    "status": "PROPOSED",
                }
                for row in rows
            ],
        }

    def transition_improvement_proposal(
        self,
        proposal_id: str,
        *,
        expected_state: str,
        new_state: str,
    ) -> bool:
        """Atomically move one proposal through the evolution lifecycle."""
        allowed = {
            "PROPOSED": {"QUEUED", "REJECTED"},
            # A dispatch failure may safely return an unconsumed claim to the queue.
            "QUEUED": {"PROPOSED", "VALIDATING", "REJECTED"},
            "VALIDATING": {"ACCEPTED", "REJECTED", "QUEUED"},
        }
        if new_state not in allowed.get(expected_state, set()):
            return False
        now = utc_now()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE improvement_proposals
                SET state=?, updated_at=?
                WHERE proposal_id=? AND state=?
                """,
                (new_state, now, proposal_id, expected_state),
            )
        return cursor.rowcount == 1

    def requeue_improvement_proposal(self, proposal_id: str) -> bool:
        """Return an unconsumed dispatch claim to PROPOSED for a later retry."""
        return self.transition_improvement_proposal(
            proposal_id,
            expected_state="QUEUED",
            new_state="PROPOSED",
        )

    def recover_queued_improvement_proposals(self, *, limit: int = 100) -> list[str]:
        """Recover legacy direct-Cantiere claims back to PROPOSED.

        The Researcher no longer dispatches evolution work directly to Cantiere.
        This migration helper is intentionally narrow: it only moves QUEUED
        proposals back to PROPOSED so the Library-gated path can own the next
        transition.
        """
        bounded = max(1, min(int(limit), 1000))
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT proposal_id
                FROM improvement_proposals
                WHERE state='QUEUED'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
            proposal_ids = [str(row["proposal_id"]) for row in rows]
            if proposal_ids:
                conn.executemany(
                    """
                    UPDATE improvement_proposals
                    SET state='PROPOSED', updated_at=?
                    WHERE proposal_id=? AND state='QUEUED'
                    """,
                    ((now, proposal_id) for proposal_id in proposal_ids),
                )
        return proposal_ids

    def claim_improvement_proposal(self) -> dict[str, Any] | None:
        """Claim the oldest proposal exactly once for isolated implementation."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT proposal_id FROM improvement_proposals
                WHERE state='PROPOSED'
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            proposal_id = str(row["proposal_id"])
            conn.execute(
                """
                UPDATE improvement_proposals
                SET state='QUEUED', updated_at=?
                WHERE proposal_id=? AND state='PROPOSED'
                """,
                (utc_now(), proposal_id),
            )
        requests = self.implementation_requests_for_state("QUEUED", proposal_id=proposal_id)
        return requests[0] if requests else None

    def implementation_requests_for_state(
        self,
        state: str,
        *,
        proposal_id: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT proposal_id, capability_id, novelty_json,
                   acceptance_gates_json, state, created_at
            FROM improvement_proposals
            WHERE state=?
        """
        params: list[Any] = [state]
        if proposal_id is not None:
            query += " AND proposal_id=?"
            params.append(proposal_id)
        query += " ORDER BY created_at ASC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            {
                "schema_version": 1,
                "request_type": "library_module_improvement",
                "proposal_id": str(row["proposal_id"]),
                "capability_id": str(row["capability_id"]),
                "objective": (
                    "Evaluate and implement only the useful capability delta; preserve "
                    "existing behavior unless tests justify a change."
                ),
                "knowledge_delta": tuple(json.loads(str(row["novelty_json"]))),
                "acceptance_gates": tuple(json.loads(str(row["acceptance_gates_json"]))),
                "mutation_policy": "isolated_candidate_no_library_mutation",
                "state": str(row["state"]),
            }
            for row in rows
        ]

    def pending_implementation_requests(self, limit: int = 20) -> list[dict[str, Any]]:
        """Expose proposed work without granting permission to mutate Library."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT proposal_id, capability_id, novelty_json,
                       acceptance_gates_json, state, created_at
                FROM improvement_proposals
                WHERE state='PROPOSED'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "schema_version": 1,
                "request_type": "library_module_improvement",
                "proposal_id": str(row["proposal_id"]),
                "capability_id": str(row["capability_id"]),
                "objective": (
                    "Evaluate and implement only the useful capability delta; preserve "
                    "existing behavior unless tests justify a change."
                ),
                "knowledge_delta": tuple(json.loads(str(row["novelty_json"]))),
                "acceptance_gates": tuple(
                    json.loads(str(row["acceptance_gates_json"]))
                ),
                "mutation_policy": "isolated_candidate_no_library_mutation",
                "state": str(row["state"]),
            }
            for row in rows
        ]

    def capabilities_missing_research_knowledge(self, *, limit: int = 100) -> list[str]:
        """Find persisted candidate capabilities that predate V2 research memory."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT c.capability_id
                FROM candidates c
                LEFT JOIN research_sources r ON r.capability_id = c.capability_id
                WHERE r.capability_id IS NULL
                ORDER BY c.capability_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [str(row["capability_id"]) for row in rows]

    def capability_knowledge(self, capability_id: str) -> dict[str, Any]:
        """Return a compact cumulative view; source code is intentionally excluded."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT source_id, direct_reuse, research_use, signals_json, novelty_json
                FROM research_sources
                WHERE capability_id=?
                ORDER BY first_seen_at ASC
                """,
                (capability_id,),
            ).fetchall()
        signals: set[str] = set()
        novel: set[str] = set()
        direct_reuse_sources = 0
        research_sources = 0
        for row in rows:
            signals.update(json.loads(str(row["signals_json"])))
            novel.update(json.loads(str(row["novelty_json"])))
            direct_reuse_sources += int(row["direct_reuse"])
            research_sources += int(row["research_use"])
        return {
            "schema_version": 1,
            "capability_id": capability_id,
            "source_count": len(rows),
            "research_source_count": research_sources,
            "direct_reuse_source_count": direct_reuse_sources,
            "signals": sorted(signals),
            "novel_signals": sorted(novel),
        }

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
