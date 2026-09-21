from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .models import Candidate, Need


PERMISSIVE = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "BSL-1.0",
}
STRONG_COPYLEFT = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-3.0",
    "GPL-3.0-only",
    "AGPL-3.0",
    "AGPL-3.0-only",
}
REVIEW_REQUIRED = STRONG_COPYLEFT | {"SSPL-1.0", "BUSL-1.1", "NOASSERTION"}


def classify_license(spdx: str | None) -> dict[str, Any]:
    if spdx is None:
        return {
            "classification": "unknown",
            "fit": 0.45,
            "warning": "license_unknown_direct_reuse_unverified",
            "direct_reuse": False,
            "research_use": True,
        }
    if spdx in PERMISSIVE:
        return {
            "classification": "permissive",
            "fit": 1.0,
            "warning": None,
            "direct_reuse": True,
            "research_use": True,
        }
    if spdx in REVIEW_REQUIRED:
        return {
            "classification": "review_required",
            "fit": 0.25,
            "warning": f"license_obligations:{spdx}",
            "direct_reuse": False,
            "research_use": True,
        }
    if spdx.startswith("LGPL") or spdx.startswith("MPL"):
        return {"classification": "conditional", "fit": 0.65, "warning": f"license_review:{spdx}", "direct_reuse": True, "research_use": True}
    return {"classification": "other", "fit": 0.45, "warning": f"license_review:{spdx}", "direct_reuse": False, "research_use": True}


def maintenance_evidence(candidate: Candidate) -> dict[str, Any]:
    age_days: int | None = None
    if candidate.pushed_at:
        try:
            pushed = datetime.fromisoformat(candidate.pushed_at.replace("Z", "+00:00"))
            age_days = (datetime.now(UTC) - pushed.astimezone(UTC)).days
        except ValueError:
            pass
    if candidate.archived:
        score = 0.0
    elif age_days is None:
        score = 0.35
    elif age_days <= 90:
        score = 1.0
    elif age_days <= 365:
        score = 0.8
    elif age_days <= 730:
        score = 0.55
    else:
        score = 0.25
    return {
        "score": score,
        "last_push_age_days": age_days,
        "archived": candidate.archived,
        "open_issues": candidate.open_issues,
        "stars_signal_only": candidate.stars,
        "forks_signal_only": candidate.forks,
    }


def integration_estimate(candidate: Candidate, need: Need) -> dict[str, Any]:
    language = (candidate.language or "").lower()
    target_set = set(need.targets)
    native_change = language in {"c", "c++", "rust", "swift", "kotlin", "java"}
    likely_adapter = True
    effort = "medium"
    score = 0.55
    reasons: list[str] = ["adapter_required_until_contract_validation"]
    if candidate.size_kb is not None and candidate.size_kb > 200_000:
        effort = "high"
        score -= 0.15
        reasons.append("large_repository")
    if native_change and ("android" in target_set or "desktop" in target_set):
        reasons.append("native_build_changes_possible")
        score -= 0.10
    if candidate.extra.get("fork"):
        reasons.append("fork_provenance_review")
        score -= 0.05
    score = max(0.0, min(1.0, score))
    return {
        "effort": effort,
        "score": score,
        "adapters": 1 if likely_adapter else 0,
        "native_build_changes_possible": native_change,
        "reasons": reasons,
    }


def security_evidence(candidate: Candidate) -> dict[str, Any]:
    warnings: list[str] = []
    score = 0.65
    if candidate.archived:
        warnings.append("archived_upstream")
        score -= 0.25
    if candidate.extra.get("disabled"):
        warnings.append("github_repository_disabled")
        score -= 0.30
    if candidate.license_spdx is None:
        warnings.append("license_missing")
        score -= 0.10
    return {
        "score": max(0.0, min(1.0, score)),
        "static_metadata_only": True,
        "untrusted_code_executed": False,
        "warnings": warnings,
    }
