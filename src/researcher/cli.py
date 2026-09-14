from __future__ import annotations

import argparse
import json
import sys
import threading

from .app import App, build_app
from .capability_status import status_payload
from .config import Config
from .dashboard import serve
from .observability import EventLevel
from .pinned_admission import resolve_and_admit_pinned_candidate
from .scheduler import Scheduler


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="researcher")
    sub = parser.add_subparsers(dest="command", required=True)
    once = sub.add_parser("once", help="Run one research cycle")
    once.add_argument(
        "--dry-run",
        action="store_true",
        help="Compatibility flag; DRY_RUN is default",
    )
    sub.add_parser("worker", help="Run persistent worker")
    sub.add_parser("dashboard", help="Run health/status HTTP server")
    sub.add_parser("status", help="Print durable state")
    events = sub.add_parser("events", help="Print recent structured local events")
    events.add_argument("--limit", type=int, default=100)
    sub.add_parser("diagnostics-sync", help="Sync pending public diagnostics if enabled")
    pinned = sub.add_parser(
        "admit-pinned",
        help="Run V1 security admission for one exact pre-researched GitHub commit",
    )
    pinned.add_argument("--capability", required=True, dest="capability_id")
    pinned.add_argument("--repository", required=True, help="GitHub owner/name")
    pinned.add_argument(
        "--commit",
        required=True,
        dest="commit_sha",
        help="Exact 40-character Git commit SHA",
    )
    pinned.add_argument(
        "--release-tag",
        default=None,
        help="Optional tag; admission verifies it resolves to the exact commit",
    )
    pinned.add_argument(
        "--source-version",
        default=None,
        help="Optional human-readable upstream version recorded as evidence",
    )
    pinned.add_argument(
        "--rescan",
        action="store_true",
        help="Re-run gates even if this capability/repository/commit is already known",
    )
    return parser


def _queue_capability_status(app: App) -> None:
    if app.diagnostics is None:
        return
    payload = status_payload(app.state)
    rows = payload.get("capabilities", [])
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        capability_id = str(row.get("capability_id") or "").strip()
        if not capability_id:
            continue
        app.events.emit(
            EventLevel.INFO,
            "capability_status",
            "capability_status",
            {
                "capability_id": capability_id,
                "research_state": str(row.get("research_state") or "PENDING"),
                "candidate_count": int(row.get("candidate_count") or 0),
                "qualified_candidates": int(row.get("qualified_candidates") or 0),
                "shortlisted": int(row.get("shortlisted") or 0),
                "submitted": int(row.get("submitted") or 0),
                "security_review": int(row.get("security_review") or 0),
                "security_blocked": int(row.get("security_blocked") or 0),
                "desired_candidates": max(1, int(row.get("desired_candidates") or 1)),
            },
        )


def _sync_diagnostics(app: App) -> dict[str, object]:
    if app.diagnostics is None:
        return {"state": "DISABLED", "sent": 0}
    try:
        _queue_capability_status(app)
        return app.diagnostics.sync()
    except Exception as exc:
        app.events.emit(
            EventLevel.WARNING,
            "diagnostics",
            "diagnostics_sync_failed",
            {"result": "FAILED", "error_type": type(exc).__name__},
        )
        return {"state": "ERROR", "sent": 0, "error_type": type(exc).__name__}


def _status(app: App) -> dict[str, object]:
    return status_payload(app.state)


def main() -> None:
    args = _parser().parse_args()
    config = Config.from_env()
    app = build_app(config)

    if args.command == "once":
        result = app.engine.run_cycle()
        _sync_diagnostics(app)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.command == "admit-pinned":
        result = resolve_and_admit_pinned_candidate(
            app,
            args.capability_id,
            args.repository,
            args.commit_sha,
            release_tag=args.release_tag,
            source_version=args.source_version,
            rescan=args.rescan,
        )
        _sync_diagnostics(app)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.command == "status":
        print(json.dumps(_status(app), indent=2, sort_keys=True))
        return
    if args.command == "events":
        print(json.dumps(app.state.recent_events(args.limit), indent=2, sort_keys=True))
        return
    if args.command == "diagnostics-sync":
        print(json.dumps(_sync_diagnostics(app), indent=2, sort_keys=True))
        return
    if args.command == "dashboard":
        serve(config.dashboard_host, config.dashboard_port, lambda: _status(app))
        return
    if args.command == "worker":
        dashboard_thread = threading.Thread(
            target=serve,
            args=(config.dashboard_host, config.dashboard_port, lambda: _status(app)),
            daemon=True,
            name="researcher-dashboard",
        )
        dashboard_thread.start()
        scheduler = Scheduler(
            app.state,
            lambda: app.engine.mode,
            config.seeding_interval_seconds,
            config.maintenance_interval_seconds,
            config.improvement_interval_seconds,
        )
        while True:
            try:
                result = app.engine.run_cycle()
                _sync_diagnostics(app)
                print(json.dumps(result, sort_keys=True), flush=True)
            except Exception as exc:
                app.events.emit(
                    EventLevel.ERROR,
                    "worker",
                    "worker_cycle_failed",
                    {"error_type": type(exc).__name__},
                )
                _sync_diagnostics(app)
                print(
                    json.dumps({"state": "ERROR", "error_type": type(exc).__name__}),
                    file=sys.stderr,
                )
            scheduler.sleep()


if __name__ == "__main__":
    main()
