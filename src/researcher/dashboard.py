from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from . import __version__


def make_handler(status_provider: Callable[[], dict[str, Any]]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path not in {"/", "/health", "/status"}:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            status = status_provider()
            payload = {
                "service": "AI-Orchestrator-Module-Researcher",
                "version": __version__,
                "health": "ok" if status.get("engine_state") != "BACKOFF" else "degraded",
                **status,
            }
            if self.path == "/":
                pretty = json.dumps(payload, indent=2, sort_keys=True)
                html = (
                    "<!doctype html><meta charset='utf-8'>"
                    "<meta http-equiv='refresh' content='30'>"
                    "<title>AI Orchestrator Module Researcher</title>"
                    "<style>body{font-family:system-ui;max-width:1000px;margin:2rem auto;"
                    "padding:0 1rem}pre{white-space:pre-wrap;background:#111;color:#eee;"
                    "padding:1rem;border-radius:.5rem}</style>"
                    "<h1>AI Orchestrator Module Researcher</h1>"
                    "<p>Read-only operational dashboard. Refreshes every 30 seconds.</p>"
                    f"<pre>{pretty}</pre>"
                )
                body = html.encode("utf-8")
                content_type = "text/html; charset=utf-8"
            else:
                body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
                content_type = "application/json; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def serve(host: str, port: int, status_provider: Callable[[], dict[str, Any]]) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(status_provider))
    server.serve_forever()
