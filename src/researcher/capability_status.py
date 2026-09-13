from __future__ import annotations

from typing import Any

from .state import SQLiteStateStore


def status_payload(state: SQLiteStateStore) -> dict[str, Any]:
    """Return dashboard state enriched with per-capability research progress.

    Availability/certification is deliberately *not* decided here. The Researcher
    only reports its own progress. Ai-orchestrator and the Cantiere must still use
    the Module Library catalog as the authority for reusable/certified assets.
    """

    result = dict(state.status())
    library = result.get("library")
    raw_items = library.get("items", []) if isinstance(library, dict) else []
    current = str(result.get("current_capability") or "").strip()

    capabilities: list[dict[str, Any]] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        capability_id = str(raw.get("capability_id") or "").strip()
        if not capability_id:
            continue

        rows = state.candidate_rows(capability_id)
        lifecycle_counts: dict[str, int] = {}
        for row in rows:
            lifecycle = str(row.get("lifecycle") or "UNKNOWN").upper()
            lifecycle_counts[lifecycle] = lifecycle_counts.get(lifecycle, 0) + 1

        shortlisted = lifecycle_counts.get("SHORTLISTED", 0)
        submitted = lifecycle_counts.get("SUBMITTED", 0)
        security_review = lifecycle_counts.get("SECURITY_REVIEW", 0)
        security_blocked = lifecycle_counts.get("SECURITY_BLOCKED", 0)
        rejected = lifecycle_counts.get("REJECTED", 0)
        qualified = shortlisted + submitted
        last_scan = state.last_scan(capability_id)
        is_current = capability_id == current

        if is_current:
            research_state = "SEARCHING"
        elif security_review > 0:
            research_state = "SECURITY_REVIEW"
        elif submitted > 0:
            research_state = "SUBMITTED"
        elif shortlisted > 0:
            research_state = "CANDIDATES_FOUND"
        elif last_scan is not None or rows:
            research_state = "SEARCHED"
        else:
            research_state = "PENDING"

        capabilities.append(
            {
                "capability_id": capability_id,
                "title": str(raw.get("title") or capability_id),
                "priority": str(raw.get("priority") or "normal"),
                "desired_candidates": max(1, int(raw.get("desired_candidates") or 1)),
                "need_status": str(raw.get("status") or "needed"),
                "targets": [str(item) for item in raw.get("targets", [])],
                "research_state": research_state,
                "current": is_current,
                "candidate_count": len(rows),
                "qualified_candidates": qualified,
                "shortlisted": shortlisted,
                "submitted": submitted,
                "security_review": security_review,
                "security_blocked": security_blocked,
                "rejected": rejected,
                "last_scan": last_scan,
            }
        )

    result["capabilities"] = capabilities
    return result
