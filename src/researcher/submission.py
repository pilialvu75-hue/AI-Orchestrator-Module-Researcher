from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .github_api import GitHubApi
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
    def __init__(self, api: GitHubApi, library_repository: str, base_ref: str = "main") -> None:
        self.api = api
        self.library_repository = library_repository
        self.base_ref = base_ref

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
        base = self.api.get(f"/repos/{self.library_repository}/git/ref/heads/{self.base_ref}")
        base_data = base.data if isinstance(base.data, dict) else {}
        obj = base_data.get("object")
        if not isinstance(obj, dict) or not obj.get("sha"):
            raise RuntimeError("Unable to resolve Library base SHA")
        self.api.post(
            f"/repos/{self.library_repository}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": str(obj["sha"])},
        )

        target = f"intake/{manifest['id']}/{manifest['version']}/manifest.json"
        dossier_target = (
            f"intake/{manifest['id']}/{manifest['version']}/provenance/researcher-dossier.json"
        )
        for path, payload in ((target, manifest), (dossier_target, dossier.to_dict())):
            content = base64.b64encode(
                json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            ).decode("ascii")
            self.api.put(
                f"/repos/{self.library_repository}/contents/{path}",
                {
                    "message": f"researcher: submit {submission_id}",
                    "content": content,
                    "branch": branch,
                },
            )
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
