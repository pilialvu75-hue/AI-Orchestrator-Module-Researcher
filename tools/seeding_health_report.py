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

    first_party = sweep.get("first_party", {})
    if not isinstance(first_party, dict):
        raise ValueError("Invalid first_party sweep result")
    discovered = total("discovered")
    analyzed = total("new_analyzed")
    prepared = array_total("prepared_submissions")
    recovered = array_total("recovered_submissions")
    failures = sum(row.get("state") in {"ERROR", "BLOCKED"} for row in results)
    if failures:
        outcome = "BLOCKED"
    elif prepared:
        outcome = "CANDIDATES_PREPARED"
    elif discovered:
        outcome = "DISCOVERED_NO_SUBMISSIONS"
    else:
        outcome = "ZERO_DISCOVERY"

    return {
        "schema": "ai-orchestrator.researcher-seeding-health.v1",
        "outcome": outcome,
        "cycles": len(results),
        "discovered": discovered,
        "new_analyzed": analyzed,
        "shortlisted": total("shortlisted"),
        "prepared_submissions": prepared,
        "recovered_submissions": recovered,
        "backfill_proposed": _count(backfill.get("proposed", 0)),
        "first_party_state": str(first_party.get("state", "UNKNOWN")),
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
            f"| Shortlisted | {summary['shortlisted']} |",
            f"| Submissions prepared | {summary['prepared_submissions']} |",
            f"| Backfill proposals | {summary['backfill_proposed']} |",
            "",
            f"First-party source status: `{summary['first_party_state']}`",
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
