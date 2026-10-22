from __future__ import annotations

import argparse
import json
import sys
import threading

from .app import App, build_app
from .capability_status import status_payload
from .component_candidate import resolve_and_admit_component_candidate
from .config import Config
from .dashboard import serve
from .evolution import EvolutionWorker
from .first_party_mining import run_one_first_party_candidate
from .observability import EventLevel
from .scheduler import Scheduler
from .source_preflight import run_source_preflight
from .state import SQLiteStateStore


def _add_pinned_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True, help="GitHub owner/name")
    parser.add_argument(
        "--commit",
        required=True,
        dest="commit_sha",
        help="Exact 40-character Git commit SHA",
    )
    parser.add_argument(
        "--component-path",
        default=None,
        help="Optional safe repository subdirectory for a monorepo component",
    )
    parser.add_argument(
        "--release-tag",
        default=None,
        help="Optional tag; preflight verifies it resolves to the exact commit",
    )
    parser.add_argument(
        "--source-version",
        default=None,
        help="Optional human-readable upstream version recorded as evidence",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="researcher")
    sub = parser.add_subparsers(dest="command", required=True)
    once = sub.add_parser("once", help="Run one research cycle")
    once.add_argument(
        "--dry-run",
        action="store_true",
        help="Compatibility flag; DRY_RUN is default",
    )
    sweep = sub.add_parser("sweep", help="Run a bounded breadth-first research sweep")
    sweep.add_argument("--cycles", type=int, default=4)
    sub.add_parser("handoffs", help="Print pending implementation requests")
    export = sub.add_parser(
        "export-improvement-proposals",
        help="Export read-only Researcher proposals for trusted Library intake",
    )
    export.add_argument("--limit", type=int, default=100)
    backfill = sub.add_parser(
        "backfill-knowledge",
        help="Migrate persisted dossiers into Research V2 knowledge",
    )
    backfill.add_argument("--limit", type=int, default=100)
    evolve = sub.add_parser("evolve", help="Claim bounded module evolution work")
    evolve.add_argument("--limit", type=int, default=1)
    requeue = sub.add_parser("requeue-evolution", help="Return a failed dispatch claim to PROPOSED")
    requeue.add_argument("proposal_id")
    recover = sub.add_parser(
        "recover-evolution-queue",
        help="Recover legacy direct-Cantiere QUEUED proposals back to PROPOSED",
    )
    recover.add_argument("--limit", type=int, default=100)
    sub.add_parser("worker", help="Run persistent worker")
    sub.add_parser("dashboard", help="Run health/status HTTP server")
    sub.add_parser("status", help="Print durable state")
    events = sub.add_parser("events", help="Print recent structured local events")
    events.add_argument("--limit", type=int, default=100)
    sub.add_parser("diagnostics-sync", help="Sync pending public diagnostics if enabled")

    preflight = sub.add_parser(
        "preflight-pinned",
        help=(
            "Verify one exact upstream source with static security, supply-chain "
            "and OSV gates without accessing the Library"
        ),
    )
    _add_pinned_source_arguments(preflight)

    pinned = sub.add_parser(
        "admit-pinned",
        help="Run V1 security admission for one exact pre-researched GitHub commit",
    )
    pinned.add_argument("--capability", required=True, dest="capability_id")
    _add_pinned_source_arguments(pinned)
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

    if args.command == "export-improvement-proposals":
        # A read-only handoff must not initialize network clients or workers.
        config.data_dir.mkdir(parents=True, exist_ok=True)
        state = SQLiteStateStore(config.data_dir / "researcher.db")
        print(json.dumps(
            state.export_improvement_proposals(limit=args.limit),
            indent=2,
            sort_keys=True,
        ))
        return

    if args.command == "preflight-pinned":
        config.data_dir.mkdir(parents=True, exist_ok=True)
        state = SQLiteStateStore(config.data_dir / "researcher.db")
        result = run_source_preflight(
            config,
            state,
            args.repository,
            args.commit_sha,
            component_path=args.component_path,
            release_tag=args.release_tag,
            source_version=args.source_version,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    app = build_app(config)

    if args.command == "once":
        result = app.engine.run_cycle()
        _sync_diagnostics(app)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.command == "sweep":
        cycles = max(1, min(int(args.cycles), 24))
        first_party = run_one_first_party_candidate(app)
        results = []
        for _ in range(cycles):
            cycle_result = app.engine.run_cycle()
            results.append(cycle_result)
            if cycle_result.get("state") == "BACKOFF":
                break
        _sync_diagnostics(app)
        print(
            json.dumps(
                {
                    "state": "COMPLETE",
                    "cycles": cycles,
                    "first_party": first_party,
                    "results": results,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.command == "backfill-knowledge":
        limit = max(1, min(int(args.limit), 1000))
        result = app.engine.backfill_research_knowledge(limit=limit)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.command == "handoffs":
        print(
            json.dumps(
                app.state.pending_implementation_requests(),
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.command == "requeue-evolution":
        ok = app.state.requeue_improvement_proposal(args.proposal_id)
        print(json.dumps({"proposal_id": args.proposal_id, "requeued": ok}, sort_keys=True))
        if not ok:
            raise SystemExit(2)
        return
    if args.command == "recover-evolution-queue":
        limit = max(1, min(int(args.limit), 1000))
        recovered = app.state.recover_queued_improvement_proposals(limit=limit)
        print(
            json.dumps(
                {
                    "state": "RECOVERED" if recovered else "IDLE",
                    "recovered": recovered,
                    "routing_boundary": "library_only",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.command == "evolve":
        limit = max(1, min(int(args.limit), 8))
        worker = EvolutionWorker(app.state)
        claimed = []
        for _ in range(limit):
            item = worker.claim_next()
            if item is None:
                break
            claimed.append(item.as_dict())
        payload = {"state": "READY" if claimed else "IDLE", "claimed": claimed}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if args.command == "admit-pinned":
        result = resolve_and_admit_component_candidate(
            app,
            args.capability_id,
            args.repository,
            args.commit_sha,
            component_path=args.component_path,
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
