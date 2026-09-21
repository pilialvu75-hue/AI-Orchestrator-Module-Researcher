from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Candidate, Dossier, ScoreCard


class DossierStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir

    @staticmethod
    def _safe(value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)

    def _dossier_path(self, capability_id: str, fingerprint: str) -> Path:
        folder = self.data_dir / "discoveries" / self._safe(capability_id)
        return folder / f"{self._safe(fingerprint)}.json"

    def save_dossier(self, dossier: Dossier) -> Path:
        path = self._dossier_path(dossier.capability_id, dossier.fingerprint)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(
                json.dumps(dossier.to_dict(), indent=2, sort_keys=True),
                encoding="utf-8",
            )
        return path

    def load_research_candidate(self, capability_id: str, fingerprint: str) -> Candidate:
        """Recover candidate metadata for Research V2 backfill from any saved dossier.

        Unlike submission recovery this does not require SHORTLISTED lifecycle: the
        candidate metadata is research evidence only and is never executed or promoted.
        Identity is still reconstructed from trusted identifiers and checked strictly.
        """
        path = self._dossier_path(capability_id, fingerprint)
        if not path.is_file():
            raise RuntimeError(
                f"Persisted dossier missing for {capability_id}:{fingerprint}"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            candidate_raw = dict(raw["candidate"])
            candidate_raw["topics"] = tuple(candidate_raw.get("topics", ()))
            candidate = Candidate(**candidate_raw)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Persisted research dossier unreadable for {capability_id}:{fingerprint}"
            ) from exc
        if str(raw.get("capability_id")) != capability_id or str(raw.get("fingerprint")) != fingerprint:
            raise RuntimeError("Persisted research dossier identity mismatch")
        return candidate

    def load_dossier(self, capability_id: str, fingerprint: str) -> Dossier:
        """Load a locally persisted dossier for restart recovery.

        The path is reconstructed from trusted identifiers rather than accepting an
        arbitrary persisted filesystem path. Any malformed or mismatched dossier
        fails closed instead of being submitted to the Library.
        """

        path = self._dossier_path(capability_id, fingerprint)
        if not path.is_file():
            raise RuntimeError(
                f"Persisted dossier missing for {capability_id}:{fingerprint}"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Persisted dossier unreadable for {capability_id}:{fingerprint}"
            ) from exc
        if not isinstance(raw, dict):
            raise RuntimeError("Persisted dossier is not a JSON object")

        try:
            candidate_raw = dict(raw["candidate"])
            candidate_raw["topics"] = tuple(candidate_raw.get("topics", ()))
            candidate = Candidate(**candidate_raw)

            scores_raw = dict(raw["scores"])
            scores_raw["reasons"] = tuple(scores_raw.get("reasons", ()))
            scores = ScoreCard(**scores_raw)

            dossier = Dossier(
                schema_version=int(raw["schema_version"]),
                capability_id=str(raw["capability_id"]),
                candidate=candidate,
                fingerprint=str(raw["fingerprint"]),
                scores=scores,
                lifecycle=str(raw["lifecycle"]),
                warnings=tuple(str(item) for item in raw.get("warnings", ())),
                integration_estimate=dict(raw["integration_estimate"]),
                security_evidence=dict(raw["security_evidence"]),
                maintenance_evidence=dict(raw["maintenance_evidence"]),
                license_evidence=dict(raw["license_evidence"]),
                dependency_evidence=dict(raw["dependency_evidence"]),
                benchmark_plan=dict(raw["benchmark_plan"]),
                created_at=str(raw["created_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Persisted dossier schema invalid for {capability_id}:{fingerprint}"
            ) from exc

        if dossier.schema_version != 1:
            raise RuntimeError("Unsupported persisted dossier schema version")
        if dossier.capability_id != capability_id or dossier.fingerprint != fingerprint:
            raise RuntimeError("Persisted dossier identity mismatch")
        if dossier.lifecycle != "SHORTLISTED":
            raise RuntimeError("Only persisted SHORTLISTED dossiers may be recovered")
        return dossier

    def save_comparison(self, capability_id: str, payload: dict[str, Any]) -> Path:
        folder = self.data_dir / "comparisons"
        folder.mkdir(parents=True, exist_ok=True)
        stem = self._safe(capability_id)
        path = folder / f"{stem}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        lines = [
            f"# Comparison — {capability_id}",
            "",
            "Machine scores are decision support, not legal or certification decisions.",
            "",
        ]
        candidates = payload.get("candidates", [])
        if not candidates:
            lines.append("No newly analyzed candidates in this cycle.")
        for index, candidate in enumerate(candidates, start=1):
            scores = candidate.get("scores", {})
            integration = candidate.get("integration", {})
            warnings = candidate.get("warnings", [])
            lines.extend(
                [
                    f"## {index}. {candidate.get('repository', 'unknown')}",
                    "",
                    f"- Commit: `{candidate.get('commit_sha', 'unknown')}`",
                    f"- License: `{candidate.get('license') or 'unknown'}`",
                    f"- Recommendation: `{scores.get('recommendation', 0):.3f}`",
                    f"- Integration effort: `{integration.get('effort', 'unknown')}`",
                    "- Warnings: "
                    + (", ".join(str(v) for v in warnings) if warnings else "none recorded"),
                    "- Score dimensions: "
                    + ", ".join(
                        f"{key}={value:.2f}"
                        for key, value in scores.items()
                        if key != "recommendation" and isinstance(value, (int, float))
                    ),
                    "",
                ]
            )
            for note in candidate.get("scenario_notes", []):
                lines.append(f"- {note}")
            lines.append("")
        markdown_path = folder / f"{stem}.md"
        markdown_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return path

    def save_shortlist(self, capability_id: str, payload: dict[str, Any]) -> Path:
        folder = self.data_dir / "shortlist"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{self._safe(capability_id)}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def save_contract_gap(self, capability_id: str, payload: dict[str, Any]) -> Path:
        folder = self.data_dir / "contract_gaps"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{self._safe(capability_id)}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def save_submission_payload(self, submission_id: str, payload: dict[str, Any]) -> Path:
        folder = self.data_dir / "submissions" / "pending"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{self._safe(submission_id)}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path
