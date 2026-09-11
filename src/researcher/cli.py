from __future__ import annotations

import argparse
import json
import sys
import threading

from .app import build_app
from .config import Config
from .dashboard import serve
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
    return parser


def main() -> None:
    args = _parser().parse_args()
    config = Config.from_env()
    app = build_app(config)

    if args.command == "once":
        print(json.dumps(app.engine.run_cycle(), indent=2, sort_keys=True))
        return
    if args.command == "status":
        print(json.dumps(app.state.status(), indent=2, sort_keys=True))
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
                print(json.dumps(result, sort_keys=True), flush=True)
            except Exception as exc:
                print(json.dumps({"state": "ERROR", "message": str(exc)}), file=sys.stderr)
            scheduler.sleep()


if __name__ == "__main__":
    main()
