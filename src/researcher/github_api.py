from __future__ import annotations

import base64
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class GitHubApiError(RuntimeError):
    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status
        self.headers = headers or {}


@dataclass
class GitHubResponse:
    data: Any
    headers: dict[str, str]


class GitHubApi:
    def __init__(
        self,
        token: str | None,
        base_url: str = "https://api.github.com",
        user_agent: str = "AI-Orchestrator-Module-Researcher/0.1.0",
        timeout_seconds: int = 20,
    ) -> None:
        self._token = token
        self._base = self._validated_base_url(base_url)
        self._user_agent = user_agent
        self._timeout = timeout_seconds

    @staticmethod
    def _validated_base_url(base_url: str) -> str:
        value = base_url.rstrip("/")
        parsed = urllib.parse.urlsplit(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("GitHub API base URL must not contain credentials, query or fragment")
        hostname = (parsed.hostname or "").lower()
        loopback = hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError(
                "GitHub API base URL must use HTTPS "
                "(HTTP allowed only for loopback mocks)"
            )
        if not hostname:
            raise ValueError("GitHub API base URL requires a hostname")
        return value

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        retries: int = 2,
    ) -> GitHubResponse:
        if not path.startswith("/"):
            raise ValueError("GitHub API path must be relative to the configured API base")
        url = f"{self._base}{path}"
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self._user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if body is not None:
            headers["Content-Type"] = "application/json"

        for attempt in range(retries + 1):
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(  # nosec B310 - validated HTTPS/loopback base
                    request, timeout=self._timeout
                ) as response:
                    raw = response.read().decode("utf-8")
                    data = json.loads(raw) if raw else None
                    return GitHubResponse(data=data, headers=dict(response.headers.items()))
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                retryable = exc.code in {429, 500, 502, 503, 504}
                if retryable and attempt < retries:
                    time.sleep(min(2**attempt, 4) + secrets.randbelow(1000) / 1000)
                    continue
                raise GitHubApiError(exc.code, raw, dict(exc.headers.items())) from exc
            except urllib.error.URLError as exc:
                if attempt < retries:
                    time.sleep(min(2**attempt, 4) + secrets.randbelow(1000) / 1000)
                    continue
                raise GitHubApiError(0, str(exc.reason)) from exc
        raise AssertionError("unreachable")

    def get(self, path: str) -> GitHubResponse:
        return self._request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        return self._request("POST", path, payload)

    def put(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        return self._request("PUT", path, payload)

    def patch(self, path: str, payload: dict[str, Any]) -> GitHubResponse:
        return self._request("PATCH", path, payload)

    def get_json_file(self, repository: str, path: str, ref: str = "main") -> dict[str, Any]:
        encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        response = self.get(
            f"/repos/{repository}/contents/{encoded_path}?ref={urllib.parse.quote(ref, safe='')}"
        )
        payload = response.data
        if not isinstance(payload, dict) or "content" not in payload:
            raise GitHubApiError(500, f"Unexpected contents response for {path}")
        raw = base64.b64decode(str(payload["content"]).replace("\n", "")).decode("utf-8")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise GitHubApiError(500, f"Expected JSON object in {path}")
        return decoded
