#!/usr/bin/env python3
"""Choose the single existing Researcher -> Library proposal queue, if any.

Read `gh pr list --json number,headRefName,isCrossRepository` on stdin and
emit three GitHub Actions outputs on stdout. Never create a parallel PR when
there are multiple or ambiguous queue branches.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

_BRANCH = re.compile(r"researcher/proposal-handoff-[0-9]+")


def select_queue(pull_requests: Any) -> dict[str, str]:
    if not isinstance(pull_requests, list):
        raise ValueError("Expected a JSON array of Library pull requests")
    matches = []
    for pr in pull_requests:
        if not isinstance(pr, dict):
            raise ValueError("Unexpected Library pull request item")
        branch = pr.get("headRefName")
        if not isinstance(branch, str) or not _BRANCH.fullmatch(branch):
            continue
        if pr.get("isCrossRepository") is True:
            raise ValueError("Researcher queue PR unexpectedly comes from a fork")
        number = pr.get("number")
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
            raise ValueError("Researcher queue PR lacks a valid number")
        matches.append((number, branch))
    if len(matches) > 1:
        raise ValueError(
            f"Multiple Researcher queue PRs ({len(matches)}): "
            "consolidate existing proposals before resuming exports"
        )
    if not matches:
        return {"existing": "false", "number": "", "branch": ""}
    number, branch = matches[0]
    return {"existing": "true", "number": str(number), "branch": branch}


def main() -> int:
    try:
        result = select_queue(json.load(sys.stdin))
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"::error title=Researcher queue ambiguous::{exc}", file=sys.stderr)
        return 1
    for key in ("existing", "number", "branch"):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
