from __future__ import annotations

from datetime import UTC, datetime
import re
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
    "0BSD",
    "MIT-0",
    "Unlicense",
    "CC0-1.0",
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


def _single_license(spdx: str | None) -> dict[str, Any]:
    """Distinguish permissive, conditional, copyleft and unknown evidence."""
    if spdx is None:
        return {
            "classification": "unknown",
            "fit": 0.45,
            "warning": "license_unknown_direct_reuse_unverified",
            "direct_reuse": False,
            "research_use": True,
        }
    normalized = next(
        (value for value in PERMISSIVE if value.lower() == spdx.lower()), None
    )
    if normalized is not None:
        return {
            "classification": "permissive",
            "fit": 1.0,
            "warning": None,
            "direct_reuse": True,
            "research_use": True,
        }
    upper = spdx.upper()
    if upper in {"NOASSERTION", "NONE"}:
        return {
            "classification": "review_required",
            "fit": 0.25,
            "warning": f"license_obligations:{spdx}",
            "direct_reuse": False,
            "research_use": True,
        }
    if upper.startswith(("GPL-", "AGPL-")) or upper in {
        "SSPL-1.0", "BUSL-1.1"
    }:
        return {
            "classification": "review_required",
            "fit": 0.25,
            "warning": f"license_obligations:{spdx}",
            "direct_reuse": False,
            "research_use": True,
        }
    if upper.startswith(("LGPL-", "MPL-")):
        return {
            "classification": "conditional",
            "fit": 0.65,
            "warning": f"license_review:{spdx}",
            "direct_reuse": True,
            "research_use": True,
        }
    return {
        "classification": "other",
        "fit": 0.45,
        "warning": f"license_review:{spdx}",
        "direct_reuse": False,
        "research_use": True,
    }


def _license_options(expression: str) -> list[frozenset[str]]:
    """Parse bounded SPDX AND/OR/WITH grammar, preserving license choices.

    OR is an alternative; AND requires compliance with *all* obligations.
    Unknown identifiers, exceptions and malformed expressions never acquire
    permission merely through parsing. No network or upstream execution.
    """
    if len(expression) > 240 or "\n" in expression:
        raise ValueError("license expression too long or multiline")
    tokens = re.findall(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+:-]*", expression)
    if len(tokens) > 40 or not tokens:
        raise ValueError("invalid or oversized SPDX expression")
    if re.sub(r"\s+", "", expression) != "".join(tokens):
        raise ValueError("unrecognized SPDX expression syntax")
    position = 0

    def atom(depth: int) -> list[frozenset[str]]:
        nonlocal position
        if depth > 10 or position >= len(tokens):
            raise ValueError("invalid SPDX expression depth")
        current = tokens[position]
        position += 1
        if current == "(":
            out = options(depth + 1)
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unbalanced SPDX expression")
            position += 1
            return out
        if current.upper() in {"AND", "OR", "WITH"} or current == ")":
            raise ValueError("missing SPDX license identifier")
        if position < len(tokens) and tokens[position].upper() == "WITH":
            position += 1
            if position >= len(tokens) or tokens[position] in {"(", ")"}:
                raise ValueError("missing SPDX exception")
            exception = tokens[position]
            if exception.upper() in {"AND", "OR", "WITH"}:
                raise ValueError("invalid SPDX exception")
            position += 1
            # Exception remains unverified: never automatically mark this
            # combination safe for direct reuse.
            current += " WITH " + exception
        return [frozenset((current,))]

    def conjunction(depth: int) -> list[frozenset[str]]:
        nonlocal position
        out = atom(depth)
        while position < len(tokens) and tokens[position].upper() == "AND":
            position += 1
            right = atom(depth)
            out = [a | b for a in out for b in right]
            if len(out) > 32:
                raise ValueError("too many SPDX alternatives")
        return out

    def options(depth: int) -> list[frozenset[str]]:
        nonlocal position
        out = conjunction(depth)
        while position < len(tokens) and tokens[position].upper() == "OR":
            position += 1
            out.extend(conjunction(depth))
            if len(out) > 32:
                raise ValueError("too many SPDX alternatives")
        return out

    result = options(0)
    if position != len(tokens):
        raise ValueError("trailing SPDX expression syntax")
    if len(result) > 1 and any(
        x.upper() in {"NONE", "NOASSERTION"} for items in result for x in items
    ):
        raise ValueError("SPDX NOASSERTION/NONE cannot be OR alternatives")
    return result


def classify_license(spdx: str | None) -> dict[str, Any]:
    """Evaluate SPDX alternatives instead of automatically rejecting all expressions.

    A usable permissive OR branch can be selected. An AND branch must satisfy
    all listed licenses. Strong copyleft, source-available terms, custom
    LicenseRef and WITH exceptions remain review-only, not auto-approved.
    """
    if spdx is None or not spdx.strip():
        return _single_license(None)
    spdx = spdx.strip()
    if not re.search(r"\b(?:AND|OR|WITH)\b|[()]", spdx, flags=re.IGNORECASE):
        return _single_license(spdx)
    try:
        alternatives = _license_options(spdx)
    except ValueError:
        return _single_license(spdx)
    ranked = []
    for licenses in alternatives:
        verdicts = [_single_license(item) for item in sorted(licenses)]
        direct = all(v["direct_reuse"] for v in verdicts)
        combined_fit = min(v["fit"] for v in verdicts)
        classification = (
            "permissive" if all(v["classification"] == "permissive" for v in verdicts)
            else "conditional" if direct else "review_required"
        )
        ranked.append((
            direct,
            combined_fit,
            sorted(licenses),
            classification,
        ))
    direct, fit, selected, classification = max(
        ranked, key=lambda item: (item[0], item[1], -len(item[2]))
    )
    return {
        "classification": classification,
        "fit": fit,
        "warning": (
            f"license_expression_option:{' AND '.join(selected)}"
            if direct else f"license_expression_review:{spdx}"
        ),
        "direct_reuse": direct,
        "research_use": True,
        "selected_license_option": " AND ".join(selected) if direct else None,
        "license_expression": spdx,
    }


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
