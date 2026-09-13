from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Protocol

from .github_api import GitHubApi, GitHubApiError
from .models import Candidate, Contract, Dossier, Need, utc_now


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


def _license_source_path(candidate: Candidate) -> str:
    """Resolve a license path pinned to the candidate's immutable commit.

    Discovery emits a GitHub blob URL containing repository + exact commit. We
    intentionally reject the mutable `/license` API shape here because Library
    provenance must remain reproducible after submission.
    """

    raw = str(candidate.license_file_url or "").strip()
    if not raw:
        raise RuntimeError("Researcher candidate has no immutable license evidence")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RuntimeError("Researcher license evidence must be an immutable GitHub blob URL")
    prefix = f"/{candidate.repository}/blob/{candidate.commit_sha}/"
    if not parsed.path.startswith(prefix):
        raise RuntimeError("Researcher license evidence is not pinned to candidate commit")
    path = urllib.parse.unquote(parsed.path[len(prefix) :]).strip("/")
    if not path or path.startswith("../") or "/../" in path or "\\" in path:
        raise RuntimeError("Researcher license path is unsafe")
    return path


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
    # Fail closed before preparing an intake that Library normalization could
    # never accept. The original immutable source is retained in the dossier;
    # the manifest points to the materialized copy inside this intake.
    _license_source_path(candidate)
    if not str(candidate.license_spdx or "").strip():
        raise RuntimeError("Researcher candidate has no identified license")
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
            "license_file": "provenance/LICENSE",
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


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _submission_paths(manifest: dict[str, Any]) -> tuple[str, str, str]:
    root = f"intake/{manifest['id']}/{manifest['version']}"
    return (
        f"{root}/manifest.json",
        f"{root}/provenance/researcher-dossier.json",
        f"{root}/provenance/LICENSE",
    )


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
        target, dossier_target, license_target = _submission_paths(manifest)
        path = self.store.save_submission_payload(
            submission_id,
            {
                "submission_id": submission_id,
                "dry_run": True,
                "target_path": target,
                "manifest": manifest,
                "dossier": dossier.to_dict(),
                "package": {
                    "manifest_path": target,
                    "dossier_path": dossier_target,
                    "license_path": license_target,
                    "license_source_repository": dossier.candidate.repository,
                    "license_source_commit": dossier.candidate.commit_sha,
                    "license_source_path": _license_source_path(dossier.candidate),
                },
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
    def __init__(self, api: GitHubApi, library_repository: str, base_ref: str = "main") -> None:
        self.api = api
        self.library_repository = library_repository
        self.base_ref = base_ref

    def _optional_get(self, path: str) -> Any | None:
        try:
            return self.api.get(path).data
        except GitHubApiError as exc:
            if exc.status == 404:
                return None
            raise

    def _license_bytes(self, candidate: Candidate) -> bytes:
        source_path = _license_source_path(candidate)
        encoded = urllib.parse.quote(source_path, safe="/")
        ref = urllib.parse.quote(candidate.commit_sha, safe="")
        response = self.api.get(
            f"/repos/{candidate.repository}/contents/{encoded}?ref={ref}"
        )
        data = response.data if isinstance(response.data, dict) else {}
        if str(data.get("encoding", "")).lower() != "base64":
            raise RuntimeError("Immutable license content is not base64 encoded")
        raw = str(data.get("content") or "").replace("\n", "")
        try:
            content = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise RuntimeError("Immutable license content is invalid") from exc
        if not content or len(content) > 1024 * 1024:
            raise RuntimeError("Immutable license content is empty or too large")
        return content

    @staticmethod
    def _remote_bytes(data: Any) -> bytes | None:
        if not isinstance(data, dict):
            return None
        raw = str(data.get("content") or "").replace("\n", "")
        if not raw:
            return None
        try:
            return base64.b64decode(raw, validate=True)
        except Exception:
            return None

    def _ensure_file(self, path: str, content: bytes, branch: str, submission_id: str) -> None:
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_branch = urllib.parse.quote(branch, safe="")
        existing = self._optional_get(
            f"/repos/{self.library_repository}/contents/{encoded_path}?ref={encoded_branch}"
        )
        if existing is not None:
            if self._remote_bytes(existing) == content:
                return
            raise RuntimeError(f"Immutable Researcher intake diverges at {path}")
        self.api.put(
            f"/repos/{self.library_repository}/contents/{encoded_path}",
            {
                "message": f"researcher: submit {submission_id}",
                "content": base64.b64encode(content).decode("ascii"),
                "branch": branch,
            },
        )

    def _ensure_branch(self, branch: str) -> None:
        encoded_branch = urllib.parse.quote(branch, safe="")
        existing = self._optional_get(
            f"/repos/{self.library_repository}/git/ref/heads/{encoded_branch}"
        )
        if existing is not None:
            return
        base = self.api.get(f"/repos/{self.library_repository}/git/ref/heads/{self.base_ref}")
        base_data = base.data if isinstance(base.data, dict) else {}
        obj = base_data.get("object")
        if not isinstance(obj, dict) or not obj.get("sha"):
            raise RuntimeError("Unable to resolve Library base SHA")
        self.api.post(
            f"/repos/{self.library_repository}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": str(obj["sha"])},
        )

    def _existing_open_pr(self, branch: str) -> dict[str, Any] | None:
        owner = self.library_repository.split("/", 1)[0]
        query = urllib.parse.urlencode(
            {
                "state": "open",
                "head": f"{owner}:{branch}",
                "base": self.base_ref,
                "per_page": "10",
            }
        )
        data = self.api.get(f"/repos/{self.library_repository}/pulls?{query}").data
        if not isinstance(data, list):
            raise RuntimeError("Library pull request lookup returned invalid data")
        for item in data:
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
        target, dossier_target, license_target = _submission_paths(manifest)
        license_bytes = self._license_bytes(dossier.candidate)

        self._ensure_branch(branch)
        self._ensure_file(target, _json_bytes(manifest), branch, submission_id)
        self._ensure_file(
            dossier_target,
            _json_bytes(dossier.to_dict()),
            branch,
            submission_id,
        )
        self._ensure_file(license_target, license_bytes, branch, submission_id)

        existing_pr = self._existing_open_pr(branch)
        if existing_pr is None:
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
        else:
            pr_data = existing_pr

        return {
            "submission_id": submission_id,
            "state": "SUBMITTED",
            "target_path": target,
            "license_path": license_target,
            "branch": branch,
            "pull_request_url": pr_data.get("html_url"),
            "manifest": manifest,
        }
