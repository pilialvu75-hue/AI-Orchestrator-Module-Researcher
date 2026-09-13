from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .github_api import GitHubApi, GitHubApiError
from .state import SQLiteStateStore


_SCHEMA = "ai-orchestrator.diagnostics.event.v2"
_MAX_ASSET_BYTES = 1024 * 1024
_MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
_BODY_BUDGET = 48_000
_ARCHIVE = re.compile(r"^researcher-diag-([a-f0-9]{64})\.jsonl$")
_LATEST = "researcher-latest.jsonl"
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9._+/\-]{1,128}$")
_SAFE_FIELD = re.compile(r"^[a-z0-9._-]{1,64}$")
_SENSITIVE_FIELDS = {
    "token",
    "secret",
    "password",
    "authorization",
    "cookie",
    "prompt",
    "conversation",
    "raw_payload",
    "api_key",
    "private_key",
}
_SEVERITIES = {"debug", "info", "warning", "error", "critical"}


def _event_name(value: str) -> str:
    normalized = re.sub(r"[^A-Z0-9_.-]+", "_", value.upper()).strip("_.-")
    if not normalized or not normalized[0].isalnum():
        normalized = f"EVENT_{normalized}" if normalized else "EVENT"
    return normalized[:128]


def _scalar(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, str):
            return value[:512]
        return value
    return str(value)[:512]


class GitHubDiagnosticsBridge:
    """Shared Diagnostics producer for the Researcher v2 namespace."""

    def __init__(
        self,
        api: GitHubApi,
        state: SQLiteStateStore,
        repository: str,
        *,
        instance_id: str,
        producer_version: str,
        platform_name: str,
        run_id: str | None = None,
    ) -> None:
        owner_repo = repository.split("/", 1)
        if len(owner_repo) != 2 or not all(owner_repo):
            raise ValueError("diagnostics repository must be owner/name")
        if not _SAFE_ID.fullmatch(instance_id):
            raise ValueError("diagnostics instance id is invalid")
        if not _SAFE_VERSION.fullmatch(producer_version):
            raise ValueError("diagnostics producer version is invalid")
        if not _SAFE_ID.fullmatch(platform_name):
            raise ValueError("diagnostics platform is invalid")
        actual_run = run_id or str(uuid.uuid4())
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", actual_run):
            raise ValueError("diagnostics run id is invalid")
        self.api = api
        self.state = state
        self.repository = repository
        self.instance_id = instance_id
        self.producer_version = producer_version
        self.platform_name = platform_name
        self.run_id = actual_run
        self.tag = f"diagnostics-researcher-v1-{instance_id}"

    @property
    def _repo_path(self) -> str:
        return "/".join(
            urllib.parse.quote(part, safe="") for part in self.repository.split("/")
        )

    @property
    def _tag_path(self) -> str:
        return urllib.parse.quote(self.tag, safe="")

    def _event(self, row: dict[str, Any]) -> dict[str, Any]:
        severity = str(row["level"]).lower()
        if severity not in _SEVERITIES:
            severity = "info"
        fields: dict[str, str | int | float | bool | None] = {
            "component": str(row["component"])[:512]
        }
        public = row.get("public_payload")
        if isinstance(public, dict):
            for raw_key, raw_value in sorted(public.items()):
                key = str(raw_key).lower()
                if not _SAFE_FIELD.fullmatch(key) or key in _SENSITIVE_FIELDS:
                    continue
                fields[key] = _scalar(raw_value)
        return {
            "schema": _SCHEMA,
            "producer": "researcher",
            "producer_version": self.producer_version,
            "platform": self.platform_name,
            "instance": self.instance_id,
            "run": self.run_id,
            "timestamp": str(row["created_at"]),
            "event": _event_name(str(row["event"])),
            "severity": severity,
            "correlation_id": f"event:{int(row['id'])}",
            "fields": fields,
        }

    def _batch(
        self, rows: list[dict[str, Any]]
    ) -> tuple[bytes, list[dict[str, Any]], list[int]]:
        chunks: list[bytes] = []
        events: list[dict[str, Any]] = []
        event_ids: list[int] = []
        used = 0
        for row in rows:
            event = self._event(row)
            encoded = (
                json.dumps(
                    event,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("utf-8")
            if len(encoded) > _MAX_ASSET_BYTES:
                raise RuntimeError("single diagnostics event exceeds 1 MiB")
            if chunks and used + len(encoded) > _MAX_ASSET_BYTES:
                break
            chunks.append(encoded)
            events.append(event)
            event_ids.append(int(row["id"]))
            used += len(encoded)
        if not chunks:
            raise RuntimeError("diagnostics batch is empty")
        return b"".join(chunks), events, event_ids

    @staticmethod
    def _events_from_body(body: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for raw in body.splitlines():
            line = raw.strip()
            if not line.startswith("{"):
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and value.get("schema") == _SCHEMA:
                result.append(value)
        return result

    @classmethod
    def _render_body(cls, previous_body: str, current: list[dict[str, Any]]) -> str:
        records: dict[str, dict[str, Any]] = {}
        for event in [*cls._events_from_body(previous_body), *current]:
            canonical = json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            fallback = hashlib.sha256(canonical).hexdigest()
            key = str(event.get("correlation_id") or fallback)
            records[key] = event
        ordered = sorted(
            records.values(),
            key=lambda item: str(item.get("timestamp", "")),
        )
        selected: list[str] = []
        used = 0
        for event in reversed(ordered):
            line = json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            if len(line) + 1 + used > _BODY_BUDGET:
                continue
            selected.append(line)
            used += len(line) + 1
        selected.reverse()
        return (
            "# AI Orchestrator Researcher diagnostics\n\n"
            "Filtered public diagnostics. Archive assets are namespaced `researcher-*`; "
            "the body is a bounded recent view and is not the complete history.\n\n"
            "```jsonl\n"
            + "\n".join(selected)
            + "\n```\n"
        )

    def _get_or_create_release(self) -> dict[str, Any]:
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
                "name": f"Researcher diagnostics {self.instance_id}",
                "body": self._render_body("", []),
                "draft": False,
                "prerelease": True,
            },
        )
        if not isinstance(response.data, dict):
            raise RuntimeError("unexpected diagnostics release creation response")
        return response.data

    def _assets(self, release_id: int) -> list[dict[str, Any]]:
        assets: list[dict[str, Any]] = []
        page = 1
        while True:
            path = (
                f"/repos/{self._repo_path}/releases/{release_id}/assets"
                f"?per_page=100&page={page}"
            )
            response = self.api.get(path)
            if not isinstance(response.data, list):
                raise RuntimeError("unexpected diagnostics assets response")
            batch = [dict(item) for item in response.data if isinstance(item, dict)]
            assets.extend(batch)
            if len(batch) < 100:
                return assets
            page += 1

    @staticmethod
    def _uploaded(
        asset: dict[str, Any],
        *,
        size: int,
        digest: str | None = None,
    ) -> bool:
        if asset.get("state") != "uploaded" or int(asset.get("size", -1)) != size:
            return False
        remote_digest = asset.get("digest")
        return (
            digest is None
            or remote_digest is None
            or remote_digest == f"sha256:{digest}"
        )

    def _delete_asset(self, asset: dict[str, Any]) -> None:
        asset_id = int(asset["id"])
        self.api.delete(f"/repos/{self._repo_path}/releases/assets/{asset_id}")

    def _rotate_archives(
        self,
        assets: list[dict[str, Any]],
        *,
        incoming_name: str,
        incoming_bytes: int,
        already_uploaded: bool,
    ) -> None:
        owned = [
            asset
            for asset in assets
            if _ARCHIVE.fullmatch(str(asset.get("name", "")))
        ]
        total = sum(int(asset.get("size", 0)) for asset in owned)
        incoming = 0 if already_uploaded else incoming_bytes
        owned.sort(key=lambda asset: str(asset.get("created_at", "")))
        for asset in owned:
            if total + incoming <= _MAX_ARCHIVE_BYTES:
                break
            if asset.get("name") == incoming_name:
                continue
            self._delete_asset(asset)
            total -= int(asset.get("size", 0))
            assets.remove(asset)

    def _ensure_archive(
        self,
        release_id: int,
        assets: list[dict[str, Any]],
        content: bytes,
    ) -> tuple[str, str]:
        digest = hashlib.sha256(content).hexdigest()
        name = f"researcher-diag-{digest}.jsonl"
        matching = [asset for asset in assets if asset.get("name") == name]
        valid = next(
            (
                asset
                for asset in matching
                if self._uploaded(asset, size=len(content), digest=digest)
            ),
            None,
        )
        for asset in matching:
            if asset is not valid:
                self._delete_asset(asset)
                assets.remove(asset)
        self._rotate_archives(
            assets,
            incoming_name=name,
            incoming_bytes=len(content),
            already_uploaded=valid is not None,
        )
        if valid is None:
            uploaded = self.api.upload_release_asset(
                self.repository,
                release_id,
                name,
                content,
            )
            if not isinstance(uploaded.data, dict):
                raise RuntimeError("unexpected archive upload response")
            created = dict(uploaded.data)
            if not self._uploaded(created, size=len(content), digest=digest):
                raise RuntimeError("archive upload was not verified")
            assets.append(created)
        return name, digest

    def _ensure_latest(
        self,
        release_id: int,
        assets: list[dict[str, Any]],
        content: bytes,
        digest: str,
    ) -> None:
        matching = [asset for asset in assets if asset.get("name") == _LATEST]
        valid = next(
            (
                asset
                for asset in matching
                if self._uploaded(asset, size=len(content), digest=digest)
            ),
            None,
        )
        for asset in matching:
            if asset is not valid:
                self._delete_asset(asset)
                assets.remove(asset)
        if valid is None:
            uploaded = self.api.upload_release_asset(
                self.repository,
                release_id,
                _LATEST,
                content,
            )
            if not isinstance(uploaded.data, dict):
                raise RuntimeError("unexpected latest upload response")
            created = dict(uploaded.data)
            if not self._uploaded(created, size=len(content), digest=digest):
                raise RuntimeError("latest upload was not verified")
            assets.append(created)

    def sync(self, limit: int = 500) -> dict[str, Any]:
        rows = self.state.pending_diagnostics(limit)
        if not rows:
            result = {"state": "IDLE", "sent": 0, "tag": self.tag}
            self.state.set_json("diagnostics_status", result)
            return result

        content, events, published_ids = self._batch(rows)
        try:
            release = self._get_or_create_release()
            release_id = int(release["id"])
            assets = self._assets(release_id)
            archive_name, digest = self._ensure_archive(release_id, assets, content)
            self._ensure_latest(release_id, assets, content, digest)
            body = self._render_body(str(release.get("body") or ""), events)
            response = self.api.patch(
                f"/repos/{self._repo_path}/releases/{release_id}",
                {
                    "name": f"Researcher diagnostics {self.instance_id}",
                    "body": body,
                    "prerelease": True,
                },
            )
            verified = isinstance(response.data, dict) and int(
                response.data.get("id", -1)
            ) == release_id
            if not verified:
                raise RuntimeError("release summary update was not verified")
            self.state.mark_diagnostics_sent(published_ids)
            result = {
                "state": "SYNCED",
                "sent": len(published_ids),
                "last_event_id": max(published_ids),
                "remaining_in_batch": len(rows) - len(published_ids),
                "tag": self.tag,
                "archive": archive_name,
            }
            self.state.set_json("diagnostics_status", result)
            return result
        except Exception as exc:
            published_set = set(published_ids)
            attempts = max(
                int(row["diagnostics_attempts"])
                for row in rows
                if int(row["id"]) in published_set
            ) + 1
            delay_minutes = min(2 ** min(attempts, 6), 60)
            next_attempt = datetime.now(UTC) + timedelta(minutes=delay_minutes)
            next_at = next_attempt.isoformat().replace("+00:00", "Z")
            self.state.mark_diagnostics_retry(published_ids, next_at)
            result = {
                "state": "BACKOFF",
                "sent": 0,
                "error_type": type(exc).__name__,
                "next_attempt_at": next_at,
                "tag": self.tag,
            }
            self.state.set_json("diagnostics_status", result)
            return result
