from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any

from .github_api import GitHubApi, GitHubApiError
from .state import SQLiteStateStore


class GitHubDiagnosticsBridge:
    """Publishes only the allowlisted public event projection to a GitHub release body."""

    def __init__(
        self,
        api: GitHubApi,
        state: SQLiteStateStore,
        repository: str,
        tag: str = "researcher-diagnostics-v1",
    ) -> None:
        owner_repo = repository.split("/", 1)
        if len(owner_repo) != 2 or not all(owner_repo):
            raise ValueError("diagnostics repository must be owner/name")
        self.api = api
        self.state = state
        self.repository = repository
        self.tag = tag

    @property
    def _repo_path(self) -> str:
        return "/".join(urllib.parse.quote(part, safe="") for part in self.repository.split("/"))

    @property
    def _tag_path(self) -> str:
        return urllib.parse.quote(self.tag, safe="")

    @staticmethod
    def _render_body(rows: list[dict[str, Any]]) -> str:
        header = (
            "# AI Orchestrator Researcher diagnostics\n\n"
            "Public projection only. No prompts, source text, local paths, tokens, credentials, "
            "or private repository names are intentionally included.\n\n"
            "```jsonl\n"
        )
        lines: list[str] = []
        total = len(header) + len("```\n")
        for row in rows:
            payload = {
                "schema": 1,
                "id": row["id"],
                "at": row["created_at"],
                "level": row["level"],
                "component": row["component"],
                "event": row["event"],
                "data": row["public_payload"],
            }
            line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if total + len(line) + 1 > 60_000:
                break
            lines.append(line)
            total += len(line) + 1
        return header + "\n".join(lines) + "\n```\n"

    def _get_or_create_release(self, body: str) -> dict[str, Any]:
        try:
            response = self.api.get(
                f"/repos/{self._repo_path}/releases/tags/{self._tag_path}"
            )
            if not isinstance(response.data, dict):
                raise RuntimeError("unexpected diagnostics release response")
            return response.data
        except GitHubApiError as exc:
            if exc.status != 404:
                raise
        response = self.api.post(
            f"/repos/{self._repo_path}/releases",
            {
                "tag_name": self.tag,
                "name": "Researcher diagnostics",
                "body": body,
                "draft": False,
                "prerelease": True,
            },
        )
        if not isinstance(response.data, dict):
            raise RuntimeError("unexpected diagnostics release creation response")
        return response.data

    def sync(self, limit: int = 100) -> dict[str, Any]:
        rows = self.state.pending_diagnostics(limit)
        if not rows:
            result = {"state": "IDLE", "sent": 0}
            self.state.set_json("diagnostics_status", result)
            return result

        event_ids = [int(row["id"]) for row in rows]
        body = self._render_body(rows)
        try:
            release = self._get_or_create_release(body)
            release_id = int(release["id"])
            self.api.patch(
                f"/repos/{self._repo_path}/releases/{release_id}",
                {
                    "name": "Researcher diagnostics",
                    "body": body,
                    "prerelease": True,
                },
            )
            self.state.mark_diagnostics_sent(event_ids)
            result = {
                "state": "SYNCED",
                "sent": len(event_ids),
                "last_event_id": max(event_ids),
            }
            self.state.set_json("diagnostics_status", result)
            return result
        except Exception as exc:
            attempts = max(int(row["diagnostics_attempts"]) for row in rows) + 1
            delay_minutes = min(2 ** min(attempts, 6), 60)
            next_attempt = datetime.now(UTC) + timedelta(minutes=delay_minutes)
            next_at = next_attempt.isoformat().replace("+00:00", "Z")
            self.state.mark_diagnostics_retry(event_ids, next_at)
            result = {
                "state": "BACKOFF",
                "sent": 0,
                "error_type": type(exc).__name__,
                "next_attempt_at": next_at,
            }
            self.state.set_json("diagnostics_status", result)
            return result
