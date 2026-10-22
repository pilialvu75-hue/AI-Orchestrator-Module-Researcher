"""Summarize bounded Researcher seeding yield without asserting Library certification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def _count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Researcher count must be a non-negative integer")
    return value


def summarize(backfill: dict[str, Any], sweep: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(backfill, dict) or not isinstance(sweep, dict):
        raise ValueError("Expected Researcher JSON objects")
    results = sweep.get("results")
    if not isinstance(results, list) or not all(isinstance(row, dict) for row in results):
        raise ValueError("Researcher sweep must contain a results array")

    def total(key: str) -> int:
        return sum(_count(row.get(key, 0)) for row in results)

    def array_total(key: str) -> int:
        value = 0
        for row in results:
            items = row.get(key, [])
            if not isinstance(items, list):
                raise ValueError(f"Researcher {key} must be a list")
            value += len(items)
        return value

    def discovery_total(key: str) -> int:
        count = 0
        for row in results:
            evidence = row.get("discovery_diagnostics", {})
            if not isinstance(evidence, dict):
                raise ValueError("Invalid discovery diagnostics")
            count += _count(evidence.get(key, 0))
        return count

    discovery_statuses: dict[str, int] = {}
    for row in results:
        evidence = row.get("discovery_diagnostics", {})
        if not isinstance(evidence, dict):
            raise ValueError("Invalid discovery diagnostics")
        status = evidence.get("status")
        if status is not None:
            if status not in {
                "SEARCH_RATE_LIMITED", "CORE_RATE_LIMITED", "NO_SEARCH_HITS",
                "SEARCH_HITS_UNRESOLVED", "CANDIDATES_FOUND",
                "NO_REQUIRED_TARGETS", "NOT_RUN",
            }:
                raise ValueError("Unknown discovery status")
            discovery_statuses[status] = discovery_statuses.get(status, 0) + 1

    first_party = sweep.get("first_party", {})
    if not isinstance(first_party, dict):
        raise ValueError("Invalid first_party sweep result")
    first_party_state = str(first_party.get("state", "UNKNOWN"))
    first_party_submitted = 0
    first_party_dry_run_prepared = 0
    if first_party_state == "COMPLETE":
        candidate = first_party.get("candidate")
        if not isinstance(candidate, dict):
            raise ValueError("Completed first-party work requires a candidate object")
        submitted = candidate.get("submitted", False)
        dry_run_prepared = candidate.get("dry_run_prepared", False)
        if (
            not isinstance(submitted, bool)
            or not isinstance(dry_run_prepared, bool)
            or (submitted and dry_run_prepared)
        ):
            raise ValueError("Invalid first-party delivery flags")
        first_party_submitted = int(submitted)
        first_party_dry_run_prepared = int(dry_run_prepared)

    discovered = total("discovered")
    analyzed = total("new_analyzed")
    sweep_prepared = array_total("prepared_submissions")
    prepared = sweep_prepared + first_party_submitted + first_party_dry_run_prepared
    recovered = array_total("recovered_submissions")
    first_party_resumed = 0
    if first_party_state == "COMPLETE":
        resumed = first_party["candidate"].get("resumed_submissions", [])
        if not isinstance(resumed, list):
            raise ValueError("First-party resumed_submissions must be a list")
        first_party_resumed = len(resumed)
    # Engine sweep rows already include recovered deliveries in prepared_submissions.
    # Only first-party resumed deliveries require an additional contribution.
    prepared += first_party_resumed
    failures = sum(row.get("state") in {"ERROR", "BLOCKED", "BACKOFF"} for row in results)
    known_skipped = total("known_candidates_skipped")
    search_rate_limited = discovery_total("rate_limited_targets")
    core_rate_limited = discovery_total("core_rate_limited_targets")
    core_limited_cycles = sum(
        (
            row.get("discovery_diagnostics", {}).get("core_rate_limited_targets", 0) > 0
            or row.get("discovery_diagnostics", {}).get("status") == "CORE_RATE_LIMITED"
        )
        for row in results
    )
    if (
        failures or first_party_state in {"ERROR", "BLOCKED"}
        or ((search_rate_limited or core_rate_limited) and not prepared and not discovered)
    ):
        outcome = "BLOCKED"
    elif sweep_prepared or first_party_submitted or first_party_resumed:
        outcome = "CANDIDATES_PREPARED"
    elif first_party_dry_run_prepared:
        outcome = "CANDIDATES_DRY_RUN_PREPARED"
    elif discovered and known_skipped == discovered and not analyzed:
        outcome = "ONLY_KNOWN_CANDIDATES"
    elif discovered or first_party_state == "COMPLETE":
        outcome = "DISCOVERED_NO_SUBMISSIONS"
    else:
        outcome = "ZERO_DISCOVERY"

    return {
        "schema": "ai-orchestrator.researcher-seeding-health.v1",
        "outcome": outcome,
        "cycles": len(results),
        "discovered": discovered,
        "new_analyzed": analyzed,
        "known_candidates_skipped": known_skipped,
        "search_queries_attempted": discovery_total("queries_attempted"),
        "search_hits": discovery_total("search_hits"),
        "search_rate_limited_targets": search_rate_limited,
        "core_rate_limited_targets": core_rate_limited,
        "core_rate_limited_cycles": core_limited_cycles,
        "search_status_counts": dict(sorted(discovery_statuses.items())),
        "shortlisted": total("shortlisted"),
        "prepared_submissions": prepared,
        "sweep_prepared_submissions": sweep_prepared,
        "first_party_submitted": first_party_submitted,
        "first_party_dry_run_prepared": first_party_dry_run_prepared,
        "recovered_submissions": recovered + first_party_resumed,
        "first_party_resumed_submissions": first_party_resumed,
        "backfill_proposed": _count(backfill.get("proposed", 0)),
        "first_party_state": first_party_state,
        "first_party_reason": str(first_party.get("reason", "")),
        "library_certified_modules": None,
        "certification_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Produce Researcher run health evidence")
    parser.add_argument("--backfill", type=Path, required=True)
    parser.add_argument("--sweep", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = summarize(
        json.loads(args.backfill.read_text(encoding="utf-8")),
        json.loads(args.sweep.read_text(encoding="utf-8")),
    )
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary:
        lines = [
            "## Researcher discovery yield",
            "",
            f"Outcome: **{summary['outcome']}** (not a Library certification)",
            "",
            "| Metric | Count |",
            "| --- | ---: |",
            f"| Cycles | {summary['cycles']} |",
            f"| Discovered | {summary['discovered']} |",
            f"| Analyzed | {summary['new_analyzed']} |",
            f"| Already known skipped | {summary['known_candidates_skipped']} |",
            f"| GitHub search queries | {summary['search_queries_attempted']} |",
            f"| GitHub search hits | {summary['search_hits']} |",
            f"| Rate-limited target searches | {summary['search_rate_limited_targets']} |",
            f"| Shortlisted | {summary['shortlisted']} |",
            f"| Submissions prepared (all paths) | {summary['prepared_submissions']} |",
            f"| First-party submitted | {summary['first_party_submitted']} |",
            f"| First-party dry-run prepared | {summary['first_party_dry_run_prepared']} |",
            f"| Backfill proposals | {summary['backfill_proposed']} |",
            "",
            f"First-party source status: `{summary['first_party_state']}`",
            f"Discovery states: `{json.dumps(summary['search_status_counts'], sort_keys=True)}`",
            "",
            "Certified modules: **not determined by Researcher** (requires Library evidence).",
            "",
        ]
        if summary["outcome"] == "ZERO_DISCOVERY":
            lines.append("**Warning:** successful workflow execution produced zero new discoveries.")
        with Path(github_summary).open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
