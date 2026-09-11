from __future__ import annotations

from typing import Any

from .models import Dossier, Need, utc_now


class ComparisonEngine:
    def compare(self, need: Need, dossiers: list[Dossier]) -> dict[str, Any]:
        ranked = sorted(
            dossiers,
            key=lambda dossier: dossier.scores.recommendation,
            reverse=True,
        )
        rows = []
        for dossier in ranked:
            rows.append(
                {
                    "fingerprint": dossier.fingerprint,
                    "repository": dossier.candidate.repository,
                    "commit_sha": dossier.candidate.commit_sha,
                    "license": dossier.candidate.license_spdx,
                    "platform_targets": list(need.targets),
                    "scores": dossier.scores.to_dict(),
                    "integration": dossier.integration_estimate,
                    "warnings": list(dossier.warnings),
                    "scenario_notes": [
                        "ranking is evidence-based, not an absolute winner",
                        "platform-specific validation can change the final Library decision",
                    ],
                }
            )
        return {
            "schema_version": 1,
            "capability_id": need.capability_id,
            "generated_at": utc_now(),
            "desired_candidates": need.desired_candidates,
            "candidates": rows,
        }
