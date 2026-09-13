from __future__ import annotations

import argparse
import json
import sys
import threading

from .app import App, build_app
from .config import Config
from .dashboard import serve
from .observability import EventLevel
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
    return parser


def _sync_diagnostics(app: App) -> dict[str, object]:
    if app.diagnostics is None:
        return {"state": "DISABLED", "sent": 0}
    try:
        return app.diagnostics.sync()
    except Exception as exc:
        app.events.emit(
            EventLevel.WARNING,
            "diagnostics",
            "diagnostics_sync_failed",
            {"result": "FAILED", "error_type": type(exc).__name__},
        )
        return {"state": "ERROR", "sent": 0, "error_type": type(exc).__name__}


def main() -> None:
    args = _parser().parse_args()
    config = Config.from_env()
    app = build_app(config)

    if args.command == "once":
        result = app.engine.run_cycle()
        _sync_diagnostics(app)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.command == "status":
        print(json.dumps(app.state.status(), indent=2, sort_keys=True))
        return
    if args.command == "events":
        print(json.dumps(app.state.recent_events(args.limit), indent=2, sort_keys=True))
        return
    if args.command == "diagnostics-sync":
        print(json.dumps(_sync_diagnostics(app), indent=2, sort_keys=True))
        return
    if args.command == "dashboard":
        serve(config.dashboard_host, config.dashboard_port, app.state.status)
        return
    if args.command == "worker":
        dashboard_thread = threading.Thread(
            target=serve,
            args=(config.dashboard_host, config.dashboard_port, app.state.status),
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
