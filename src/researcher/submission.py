from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Protocol

from .github_api import GitHubApi, GitHubApiError
from .models import Candidate, Contract, Dossier, Need, utc_now
from .state import SQLiteStateStore


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
    """Resolve a license path pinned to the candidate's immutable commit."""

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
            "license_source_url": candidate.license_file_url,
            "license_detection_source": candidate.extra.get("license_detection_source"),
            "attribution": {
                "upstream_repository": candidate.upstream_url,
                "upstream_commit": candidate.commit_sha,
                "preserve_upstream_notices": True,
                "obligations_must_be_validated_before_promotion": True,
            },
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


def _submission_package(
    need: Need,
    contract: Contract,
    standard_version: str,
    dossier: Dossier,
) -> dict[str, Any]:
    manifest = build_manifest(need, contract, standard_version, dossier)
    submission_id = f"{_slug(manifest['id'])}-{dossier.fingerprint[:12]}"
    branch = f"researcher/intake/{submission_id}"
    target, dossier_target, license_target = _submission_paths(manifest)
    candidate = dossier.candidate
    return {
        "schema_version": 1,
        "submission_id": submission_id,
        "fingerprint": dossier.fingerprint,
        "capability_id": need.capability_id,
        "branch": branch,
        "target_path": target,
        "dossier_path": dossier_target,
        "license_path": license_target,
        "manifest": manifest,
        "dossier": dossier.to_dict(),
        "license_source": {
            "repository": candidate.repository,
            "commit": candidate.commit_sha,
            "path": _license_source_path(candidate),
        },
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
        package = _submission_package(need, contract, standard_version, dossier)
        submission_id = str(package["submission_id"])
        target = str(package["target_path"])
        payload = {
            **package,
            "dry_run": True,
            "prepared_at": utc_now(),
        }
        path = self.store.save_submission_payload(submission_id, payload)
        return {
            "submission_id": submission_id,
            "state": "DRY_RUN_PREPARED",
            "target_path": target,
            "local_path": str(path),
            "manifest": package["manifest"],
        }


class GitHubIntakePrSubmissionClient:
    """Restart-safe and idempotent Library intake delivery.

    The exact immutable package is persisted to SQLite before the first GitHub
    write. A retry therefore never rebuilds payload from mutable Library state:
    it reconciles the same branch, the same three intake files and the same PR.
    """

    def __init__(
        self,
        api: GitHubApi,
        library_repository: str,
        state: SQLiteStateStore,
        base_ref: str = "main",
    ) -> None:
        self.api = api
        self.library_repository = library_repository
        self.state = state
        self.base_ref = base_ref

    def _optional_get(self, path: str) -> Any | None:
        try:
            return self.api.get(path).data
        except GitHubApiError as exc:
            if exc.status == 404:
                return None
            raise

    @staticmethod
    def _validate_package(package: dict[str, Any]) -> None:
        if int(package.get("schema_version", 0)) != 1:
            raise RuntimeError("Unsupported durable submission package")
        submission_id = str(package.get("submission_id") or "")
        fingerprint = str(package.get("fingerprint") or "")
        branch = str(package.get("branch") or "")
        manifest = package.get("manifest")
        dossier = package.get("dossier")
        license_source = package.get("license_source")
        if not submission_id or not fingerprint or not isinstance(manifest, dict):
            raise RuntimeError("Durable submission package is incomplete")
        if not isinstance(dossier, dict) or not isinstance(license_source, dict):
            raise RuntimeError("Durable submission package provenance is incomplete")
        if branch != f"researcher/intake/{submission_id}":
            raise RuntimeError("Durable submission branch identity is invalid")
        if str(manifest.get("status")) != "discovered":
            raise RuntimeError("Researcher may submit only discovered intake candidates")
        provenance = manifest.get("provenance")
        if not isinstance(provenance, dict) or str(provenance.get("source_task_id")) != fingerprint:
            raise RuntimeError("Durable submission fingerprint does not match manifest")
        target, dossier_target, license_target = _submission_paths(manifest)
        if str(package.get("target_path")) != target:
            raise RuntimeError("Durable submission manifest path is invalid")
        if str(package.get("dossier_path")) != dossier_target:
            raise RuntimeError("Durable submission dossier path is invalid")
        if str(package.get("license_path")) != license_target:
            raise RuntimeError("Durable submission license path is invalid")
        for path in (target, dossier_target, license_target):
            if not path.startswith("intake/") or "/../" in path or "\\" in path:
                raise RuntimeError("Durable submission escaped Library intake")
        repository = str(license_source.get("repository") or "")
        commit = str(license_source.get("commit") or "")
        source_path = str(license_source.get("path") or "")
        if (
            repository.count("/") != 1
            or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or not source_path
            or source_path.startswith("../")
            or "/../" in source_path
            or "\\" in source_path
        ):
            raise RuntimeError("Durable submission license provenance is invalid")

    def _license_bytes_from_package(self, package: dict[str, Any]) -> bytes:
        source = package["license_source"]
        repository = str(source["repository"])
        source_path = str(source["path"])
        commit = str(source["commit"])
        encoded = urllib.parse.quote(source_path, safe="/")
        ref = urllib.parse.quote(commit, safe="")
        response = self.api.get(f"/repos/{repository}/contents/{encoded}?ref={ref}")
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
        encoded_base = urllib.parse.quote(self.base_ref, safe="")
        base = self.api.get(
            f"/repos/{self.library_repository}/git/ref/heads/{encoded_base}"
        )
        base_data = base.data if isinstance(base.data, dict) else {}
        obj = base_data.get("object")
        if not isinstance(obj, dict) or not obj.get("sha"):
            raise RuntimeError("Unable to resolve Library base SHA")
        self.api.post(
            f"/repos/{self.library_repository}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": str(obj["sha"])},
        )

    def _existing_pr(self, branch: str) -> dict[str, Any] | None:
        owner = self.library_repository.split("/", 1)[0]
        query = urllib.parse.urlencode(
            {
                "state": "all",
                "head": f"{owner}:{branch}",
                "base": self.base_ref,
                "per_page": "20",
            }
        )
        data = self.api.get(f"/repos/{self.library_repository}/pulls?{query}").data
        if not isinstance(data, list):
            raise RuntimeError("Library pull request lookup returned invalid data")
        candidates = [item for item in data if isinstance(item, dict)]
        for item in candidates:
            if str(item.get("state")) == "open":
                return item
        for item in candidates:
            if item.get("merged_at"):
                return item
        return candidates[0] if candidates else None

    def _assert_branch_scope(
        self,
        package: dict[str, Any],
        *,
        require_complete: bool,
    ) -> None:
        branch = str(package["branch"])
        encoded_base = urllib.parse.quote(self.base_ref, safe="")
        encoded_branch = urllib.parse.quote(branch, safe="")
        response = self.api.get(
            f"/repos/{self.library_repository}/compare/{encoded_base}...{encoded_branch}"
        )
        data = response.data if isinstance(response.data, dict) else {}
        files = data.get("files")
        if not isinstance(files, list):
            raise RuntimeError("Unable to verify Researcher intake branch scope")
        allowed = {
            str(package["target_path"]),
            str(package["dossier_path"]),
            str(package["license_path"]),
        }
        changed = {
            str(item.get("filename"))
            for item in files
            if isinstance(item, dict) and item.get("filename")
        }
        unexpected = changed - allowed
        if unexpected:
            raise RuntimeError(
                "Researcher intake branch contains unexpected changes: "
                + ", ".join(sorted(unexpected))
            )
        if require_complete and changed != allowed:
            raise RuntimeError("Researcher intake branch is missing expected intake files")
        for item in files:
            if isinstance(item, dict) and str(item.get("status")) == "removed":
                raise RuntimeError("Researcher intake branch must not delete Library files")

    @staticmethod
    def _result_from_pr(package: dict[str, Any], pr_data: dict[str, Any]) -> dict[str, Any]:
        merged = bool(pr_data.get("merged_at"))
        state = "MERGED" if merged else "SUBMITTED"
        return {
            "submission_id": package["submission_id"],
            "state": state,
            "target_path": package["target_path"],
            "license_path": package["license_path"],
            "branch": package["branch"],
            "pull_request_url": pr_data.get("html_url"),
            "manifest": package["manifest"],
        }

    def _deliver_package(self, package: dict[str, Any]) -> dict[str, Any]:
        self._validate_package(package)
        branch = str(package["branch"])
        existing_pr = self._existing_pr(branch)
        if existing_pr is not None and existing_pr.get("merged_at"):
            return self._result_from_pr(package, existing_pr)
        if existing_pr is not None and str(existing_pr.get("state")) == "closed":
            raise RuntimeError(
                "Existing Researcher intake PR is closed without merge; refusing duplicate PR"
            )

        self._ensure_branch(branch)
        self._assert_branch_scope(package, require_complete=False)
        license_bytes = self._license_bytes_from_package(package)
        self._ensure_file(
            str(package["target_path"]),
            _json_bytes(package["manifest"]),
            branch,
            str(package["submission_id"]),
        )
        self._ensure_file(
            str(package["dossier_path"]),
            _json_bytes(package["dossier"]),
            branch,
            str(package["submission_id"]),
        )
        self._ensure_file(
            str(package["license_path"]),
            license_bytes,
            branch,
            str(package["submission_id"]),
        )
        self._assert_branch_scope(package, require_complete=True)

        if existing_pr is None:
            pr = self.api.post(
                f"/repos/{self.library_repository}/pulls",
                {
                    "title": (
                        f"Researcher intake: {package['manifest']['name']} "
                        f"for {package['capability_id']}"
                    ),
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
        if not pr_data.get("html_url"):
            raise RuntimeError("Library intake PR was not confirmed by GitHub")
        return self._result_from_pr(package, pr_data)

    def submit(
        self,
        need: Need,
        contract: Contract,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any]:
        package = _submission_package(need, contract, standard_version, dossier)
        fingerprint = str(package["fingerprint"])
        self.state.reserve_submission(
            fingerprint,
            str(package["capability_id"]),
            str(package["submission_id"]),
            str(package["target_path"]),
            package,
            branch=str(package["branch"]),
        )
        if not self.state.mark_submission_attempt(fingerprint):
            row = self.state.submission_row(fingerprint)
            if row is None:
                raise RuntimeError("Terminal submission state disappeared")
            return {
                "submission_id": row["submission_id"],
                "state": row["state"],
                "target_path": row["target_path"],
                "branch": row.get("branch"),
                "pull_request_url": row.get("pull_request_url"),
                "manifest": package["manifest"],
            }
        try:
            return self._deliver_package(package)
        except Exception as exc:
            self.state.mark_submission_retry(fingerprint, str(exc))
            raise

    def resume_pending(self) -> list[dict[str, Any]]:
        """Reconcile every interrupted delivery using its persisted immutable package."""

        resumed: list[dict[str, Any]] = []
        for row in self.state.pending_submissions():
            fingerprint = str(row["fingerprint"])
            package = row["payload"]
            if not self.state.mark_submission_attempt(fingerprint):
                continue
            try:
                result = self._deliver_package(package)
                self.state.complete_submission(
                    fingerprint,
                    str(result["state"]),
                    branch=str(result.get("branch") or package["branch"]),
                    pull_request_url=(
                        None
                        if result.get("pull_request_url") is None
                        else str(result["pull_request_url"])
                    ),
                )
                resumed.append(result)
            except Exception as exc:
                self.state.mark_submission_retry(fingerprint, str(exc))
                raise
        return resumed
