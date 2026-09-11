from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Dossier


class DossierStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir

    @staticmethod
    def _safe(value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)

    def save_dossier(self, dossier: Dossier) -> Path:
        folder = self.data_dir / "discoveries" / self._safe(dossier.capability_id)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{dossier.fingerprint}.json"
        if not path.exists():
            path.write_text(
                json.dumps(dossier.to_dict(), indent=2, sort_keys=True),
                encoding="utf-8",
            )
        return path

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
