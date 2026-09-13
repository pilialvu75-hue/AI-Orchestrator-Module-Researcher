from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Protocol

from .github_api import GitHubApi, GitHubApiError
from .models import Contract, Dossier, Need, utc_now


class LibrarySubmissionClient(Protocol):
    def submit(
        self,
        need: Need,
        contract: Contract,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any]: ...


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-")


def build_manifest(
    need: Need,
    contract: Contract,
    standard_version: str,
    dossier: Dossier,
) -> dict[str, Any]:
    candidate = dossier.candidate
    asset_id = f"{need.capability_id}.{_slug(candidate.owner)}.{_slug(candidate.name)}"
    effort = str(dossier.integration_estimate["effort"])
    if effort not in {"trivial", "low", "medium", "high"}:
        effort = "medium"
    kind = (
        "integration_bundle"
        if need.capability_id.startswith(("ai.", "voice."))
        else "module"
    )
    return {
        "id": asset_id,
        "name": candidate.name,
        "version": "0.1.0",
        "kind": kind,
        "status": "discovered",
        "description": candidate.description or f"Research candidate for {need.title}",
        "tags": [need.capability_id, "researcher-candidate"],
        "capabilities": [need.capability_id],
        "platforms": list(need.targets),
        "languages": [] if candidate.language is None else [candidate.language.lower()],
        "frameworks": [],
        "entry_paths": [],
        "provenance": {
            "origin": "researcher",
            "source_repository": candidate.upstream_url,
            "source_commit": candidate.commit_sha,
            "source_tag": candidate.release_tag,
            "source_project_id": None,
            "source_task_id": dossier.fingerprint,
            "license": candidate.license_spdx,
            "license_file": candidate.license_file_url,
            "retrieved_at": candidate.acquired_at,
        },
        "validation": {
            "score": dossier.scores.recommendation,
            "tests_passed": False,
            "test_report": None,
            "validated_at": None,
            "validated_on": [],
        },
        "security": {
            "reviewed": False,
            "reviewed_at": None,
            "sbom": None,
            "notes": (
                "Metadata pre-screen only; external code has not been executed "
                "by Researcher V1."
            ),
        },
        "integration": {
            "estimated_effort": effort,
            "adaptation_allowed": True,
            "known_constraints": list(dossier.integration_estimate.get("reasons", [])),
            "adapter_notes": "Library normalization/test must validate adapter and contract fit.",
        },
        "connector": {
            "standard": "ai-orchestrator-lego",
            "standard_version": standard_version,
            "provides": [
                {
                    "capability_id": need.capability_id,
                    "contract_id": contract.contract_id,
                    "contract_version": contract.contract_version,
                }
            ],
            "requires": [],
            "integration_mode": "adapter",
            "adapters": [],
            "configuration_schema": None,
            "healthcheck": {"type": "none", "path": None},
        },
        "payload": {
            "type": "upstream_reference",
            "path": None,
            "sha256": None,
            "upstream_repository": candidate.upstream_url,
            "upstream_commit": candidate.commit_sha,
        },
        "quality": {
            "reuse_count": 0,
            "successful_integrations": 0,
            "failed_integrations": 0,
            "last_used_at": None,
        },
        "deprecation": {"reason": None, "replacement": None},
    }


@dataclass
class DryRunSubmissionClient:
    store: Any

    def submit(
        self,
        need: Need,
        contract: Contract,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any]:
        manifest = build_manifest(need, contract, standard_version, dossier)
        submission_id = f"{_slug(manifest['id'])}-{dossier.fingerprint[:12]}"
        target = f"intake/{manifest['id']}/{manifest['version']}/manifest.json"
        path = self.store.save_submission_payload(
            submission_id,
            {
                "submission_id": submission_id,
                "dry_run": True,
                "target_path": target,
                "manifest": manifest,
                "dossier": dossier.to_dict(),
                "prepared_at": utc_now(),
            },
        )
        return {
            "submission_id": submission_id,
            "state": "DRY_RUN_PREPARED",
            "target_path": target,
            "local_path": str(path),
            "manifest": manifest,
        }


class GitHubIntakePrSubmissionClient:
    """Restart-safe, immutable delivery into the Library intake boundary."""

    def __init__(self, api: GitHubApi, library_repository: str, base_ref: str = "main") -> None:
        self.api = api
        self.library_repository = library_repository
        self.base_ref = base_ref

    @property
    def _owner(self) -> str:
        owner_repo = self.library_repository.split("/", 1)
        if len(owner_repo) != 2 or not all(owner_repo):
            raise ValueError("library_repository must be owner/name")
        return owner_repo[0]

    @staticmethod
    def _quoted_path(path: str) -> str:
        return "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))

    def _branch_ref_path(self, branch: str) -> str:
        encoded = urllib.parse.quote(branch, safe="/")
        return f"/repos/{self.library_repository}/git/ref/heads/{encoded}"

    def _ensure_branch(self, branch: str) -> None:
        try:
            self.api.get(self._branch_ref_path(branch))
            return
        except GitHubApiError as exc:
            if exc.status != 404:
                raise

        base = self.api.get(
            f"/repos/{self.library_repository}/git/ref/heads/"
            f"{urllib.parse.quote(self.base_ref, safe='/')}"
        )
        base_data = base.data if isinstance(base.data, dict) else {}
        obj = base_data.get("object")
        if not isinstance(obj, dict) or not obj.get("sha"):
            raise RuntimeError("Unable to resolve Library base SHA")
        try:
            self.api.post(
                f"/repos/{self.library_repository}/git/refs",
                {"ref": f"refs/heads/{branch}", "sha": str(obj["sha"])},
            )
        except GitHubApiError as exc:
            if exc.status != 422:
                raise
            # Another retry/process may have created the deterministic branch.
            self.api.get(self._branch_ref_path(branch))

    def _ensure_immutable_json(
        self,
        path: str,
        payload: dict[str, Any],
        branch: str,
        submission_id: str,
    ) -> None:
        encoded_path = self._quoted_path(path)
        ref = urllib.parse.quote(branch, safe="")
        existing: dict[str, Any] | None = None
        try:
            response = self.api.get(
                f"/repos/{self.library_repository}/contents/{encoded_path}?ref={ref}"
            )
            if isinstance(response.data, dict):
                existing = response.data
        except GitHubApiError as exc:
            if exc.status != 404:
                raise

        if existing is not None:
            encoded = existing.get("content")
            if not isinstance(encoded, str):
                raise RuntimeError(f"Unexpected Library contents response for {path}")
            try:
                raw = base64.b64decode(encoded.replace("\n", "")).decode("utf-8")
                current = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as exc:
                raise RuntimeError(f"Existing intake payload is unreadable: {path}") from exc
            if current != payload:
                raise RuntimeError(
                    f"Immutable intake payload conflict for {path}; refusing overwrite"
                )
            return

        content = base64.b64encode(
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        ).decode("ascii")
        self.api.put(
            f"/repos/{self.library_repository}/contents/{encoded_path}",
            {
                "message": f"researcher: submit {submission_id}",
                "content": content,
                "branch": branch,
            },
        )

    def _find_open_pr(self, branch: str) -> dict[str, Any] | None:
        query = urllib.parse.urlencode(
            {
                "state": "open",
                "head": f"{self._owner}:{branch}",
                "base": self.base_ref,
                "per_page": 20,
            }
        )
        response = self.api.get(f"/repos/{self.library_repository}/pulls?{query}")
        if not isinstance(response.data, list):
            return None
        for item in response.data:
            if isinstance(item, dict):
                return item
        return None

    def submit(
        self,
        need: Need,
        contract: Contract,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any]:
        manifest = build_manifest(need, contract, standard_version, dossier)
        submission_id = f"{_slug(manifest['id'])}-{dossier.fingerprint[:12]}"
        branch = f"researcher/intake/{submission_id}"
        target = f"intake/{manifest['id']}/{manifest['version']}/manifest.json"
        dossier_target = (
            f"intake/{manifest['id']}/{manifest['version']}/provenance/researcher-dossier.json"
        )

        if not target.startswith("intake/") or not dossier_target.startswith("intake/"):
            raise RuntimeError("Fail-closed: Researcher may write only to Library intake/")

        self._ensure_branch(branch)
        self._ensure_immutable_json(target, manifest, branch, submission_id)
        self._ensure_immutable_json(
            dossier_target,
            dossier.to_dict(),
            branch,
            submission_id,
        )

        pr_data = self._find_open_pr(branch)
        if pr_data is None:
            pr = self.api.post(
                f"/repos/{self.library_repository}/pulls",
                {
                    "title": f"Researcher intake: {manifest['name']} for {need.capability_id}",
                    "head": branch,
                    "base": self.base_ref,
                    "body": (
                        "Automated Researcher candidate submission.\n\n"
                        "This PR writes only to Library intake. It is not certification."
                    ),
                },
            )
            pr_data = pr.data if isinstance(pr.data, dict) else {}

        return {
            "submission_id": submission_id,
            "state": "SUBMITTED",
            "target_path": target,
            "branch": branch,
            "pull_request_url": pr_data.get("html_url"),
            "manifest": manifest,
        }
