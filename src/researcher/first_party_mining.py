from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .github_api import GitHubApi, GitHubApiError
from .models import utc_now
from .state import SQLiteStateStore


_REPOSITORY = re.compile(r"^pilialvu75-hue/[A-Za-z0-9._-]+$")
_CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9._-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_KINDS = {
    "module",
    "component",
    "integration_bundle",
    "architecture_pattern",
    "project_template",
    "policy_bundle",
}
_PRIORITY = {"high": 0, "medium": 1, "low": 2}
_FORBIDDEN_SEGMENTS = {
    ".git",
    ".dart_tool",
    "build",
    "node_modules",
}
_FORBIDDEN_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    "key.properties",
    "keystore.properties",
    "local.properties",
}
_FORBIDDEN_SUFFIXES = (
    ".jks",
    ".keystore",
    ".p12",
    ".pfx",
    ".pem",
    ".key",
)
_LICENSE_NAMES = {
    "copying",
    "copying.md",
    "copying.txt",
    "license",
    "license.md",
    "license.txt",
}


class FirstPartyMiningError(RuntimeError):
    pass


@dataclass(frozen=True)
class FirstPartyCandidateSpec:
    capability_id: str
    component_path: str
    kind: str


@dataclass(frozen=True)
class FirstPartySourceSpec:
    repository: str
    priority: str
    lifecycle: str
    purpose: str | None
    candidates: tuple[FirstPartyCandidateSpec, ...]


def _safe_component_path(value: str) -> bool:
    if (
        not value
        or value.startswith(("/", "~"))
        or "\\" in value
        or ":" in value
        or "\x00" in value
    ):
        return False
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    lowered = [part.lower() for part in parts]
    if any(part in _FORBIDDEN_SEGMENTS for part in lowered):
        return False
    final = lowered[-1]
    if final in _FORBIDDEN_FILES or final.endswith(_FORBIDDEN_SUFFIXES):
        return False
    return True


def _sensitive_path(path: str) -> bool:
    lowered = path.lower()
    parts = lowered.split("/")
    if any(part in _FORBIDDEN_SEGMENTS for part in parts):
        return True
    final = parts[-1] if parts else lowered
    return final in _FORBIDDEN_FILES or final.endswith(_FORBIDDEN_SUFFIXES)


def _parse_catalog(payload: dict[str, Any]) -> tuple[FirstPartySourceSpec, ...]:
    if int(payload.get("schema_version", 0)) != 1:
        raise FirstPartyMiningError("Unsupported first-party source catalog schema")
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        raise FirstPartyMiningError("First-party source catalog policy is missing")
    expected = {
        "access": "read_only",
        "execute_source": False,
        "fetch_arbitrary_file_contents": False,
        "submit_destination": "library_intake_only",
        "certification_required": True,
        "provenance_required": True,
        "secret_paths_forbidden": True,
    }
    for key, value in expected.items():
        if policy.get(key) != value:
            raise FirstPartyMiningError(
                f"Unsafe first-party source policy: {key}={policy.get(key)!r}"
            )

    raw_sources = payload.get("sources")
    if not isinstance(raw_sources, list):
        raise FirstPartyMiningError("First-party source catalog sources must be an array")

    sources: list[FirstPartySourceSpec] = []
    seen: set[str] = set()
    for raw in raw_sources:
        if not isinstance(raw, dict):
            raise FirstPartyMiningError("Invalid first-party source entry")
        repository = str(raw.get("repository") or "").strip()
        if not _REPOSITORY.fullmatch(repository):
            raise FirstPartyMiningError(f"Unsafe first-party repository: {repository!r}")
        if repository in seen:
            raise FirstPartyMiningError(f"Duplicate first-party repository: {repository}")
        seen.add(repository)

        priority = str(raw.get("priority") or "").strip().lower()
        if priority not in _PRIORITY:
            raise FirstPartyMiningError(
                f"Invalid first-party priority for {repository}: {priority!r}"
            )
        lifecycle = str(raw.get("lifecycle") or "").strip()
        if not lifecycle:
            raise FirstPartyMiningError(
                f"Missing first-party lifecycle for {repository}"
            )
        purpose_raw = raw.get("purpose")
        purpose = None if purpose_raw is None else str(purpose_raw).strip() or None

        candidate_specs: list[FirstPartyCandidateSpec] = []
        raw_candidates = raw.get("candidates", [])
        if not isinstance(raw_candidates, list):
            raise FirstPartyMiningError(
                f"Invalid candidate list for first-party source {repository}"
            )
        for candidate in raw_candidates:
            if not isinstance(candidate, dict):
                raise FirstPartyMiningError(
                    f"Invalid candidate entry for first-party source {repository}"
                )
            capability_id = str(candidate.get("capability_id") or "").strip()
            component_path = str(candidate.get("component_path") or "").strip()
            kind = str(candidate.get("kind") or "").strip()
            if not _CAPABILITY.fullmatch(capability_id):
                raise FirstPartyMiningError(
                    f"Unsafe capability in {repository}: {capability_id!r}"
                )
            if not _safe_component_path(component_path):
                raise FirstPartyMiningError(
                    f"Unsafe component path in {repository}: {component_path!r}"
                )
            if kind not in _ALLOWED_KINDS:
                raise FirstPartyMiningError(
                    f"Unsupported candidate kind in {repository}: {kind!r}"
                )
            candidate_specs.append(
                FirstPartyCandidateSpec(
                    capability_id=capability_id,
                    component_path=component_path,
                    kind=kind,
                )
            )
        sources.append(
            FirstPartySourceSpec(
                repository=repository,
                priority=priority,
                lifecycle=lifecycle,
                purpose=purpose,
                candidates=tuple(candidate_specs),
            )
        )
    return tuple(
        sorted(
            sources,
            key=lambda source: (_PRIORITY[source.priority], source.repository.lower()),
        )
    )


def _active_need_ids(payload: dict[str, Any]) -> set[str]:
    if int(payload.get("schema_version", 0)) < 1:
        raise FirstPartyMiningError("Unsupported Library needs schema")
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise FirstPartyMiningError("Library needs items must be an array")
    result: set[str] = set()
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        capability_id = str(raw.get("capability_id") or "").strip()
        status = str(raw.get("status") or "").strip().lower()
        if capability_id and status == "needed":
            result.add(capability_id)
    return result


def _tree_entries(api: GitHubApi, repository: str) -> tuple[str, list[dict[str, Any]]]:
    metadata = api.get(f"/repos/{repository}").data
    if not isinstance(metadata, dict):
        raise FirstPartyMiningError(f"Invalid repository metadata for {repository}")
    if str(metadata.get("full_name") or "") != repository:
        raise FirstPartyMiningError(f"Repository identity mismatch for {repository}")
    if metadata.get("private") is not True:
        raise FirstPartyMiningError(
            f"First-party source must remain private: {repository}"
        )
    default_branch = str(metadata.get("default_branch") or "main")
    branch = urllib.parse.quote(default_branch, safe="")
    commit_response = api.get(f"/repos/{repository}/commits/{branch}").data
    if not isinstance(commit_response, dict):
        raise FirstPartyMiningError(f"Invalid commit metadata for {repository}")
    commit_sha = str(commit_response.get("sha") or "").lower()
    if not _SHA.fullmatch(commit_sha):
        raise FirstPartyMiningError(f"Invalid immutable commit for {repository}")

    commit_meta = commit_response.get("commit")
    tree_meta = commit_meta.get("tree") if isinstance(commit_meta, dict) else None
    tree_sha = str(tree_meta.get("sha") or "") if isinstance(tree_meta, dict) else ""
    if not _SHA.fullmatch(tree_sha.lower()):
        raise FirstPartyMiningError(f"Invalid tree identity for {repository}")

    tree_response = api.get(
        f"/repos/{repository}/git/trees/{tree_sha}?recursive=1"
    ).data
    if not isinstance(tree_response, dict):
        raise FirstPartyMiningError(f"Invalid tree response for {repository}")
    if bool(tree_response.get("truncated", False)):
        raise FirstPartyMiningError(
            f"Repository tree is truncated; refusing incomplete mining: {repository}"
        )
    raw_tree = tree_response.get("tree")
    if not isinstance(raw_tree, list):
        raise FirstPartyMiningError(f"Repository tree missing for {repository}")
    entries = [entry for entry in raw_tree if isinstance(entry, dict)]
    return commit_sha, entries


def _path_in_scope(path: str, component_path: str) -> bool:
    return path == component_path or path.startswith(component_path.rstrip("/") + "/")


def _candidate_finding(
    source: FirstPartySourceSpec,
    spec: FirstPartyCandidateSpec,
    commit_sha: str,
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    scoped = [
        entry
        for entry in entries
        if _path_in_scope(str(entry.get("path") or ""), spec.component_path)
    ]
    blobs = [
        str(entry.get("path") or "")
        for entry in scoped
        if str(entry.get("type") or "") == "blob"
    ]
    if not scoped or not blobs:
        return {
            "repository": source.repository,
            "commit_sha": commit_sha,
            "capability_id": spec.capability_id,
            "component_path": spec.component_path,
            "kind": spec.kind,
            "state": "MISSING_COMPONENT",
            "reason": "allowlisted component path is absent at the pinned commit",
        }

    sensitive = sorted(path for path in blobs if _sensitive_path(path))
    repo_blob_paths = [
        str(entry.get("path") or "")
        for entry in entries
        if str(entry.get("type") or "") == "blob"
    ]
    license_paths = sorted(
        path
        for path in repo_blob_paths
        if path.rsplit("/", 1)[-1].lower() in _LICENSE_NAMES
    )
    tests_present = any(
        "/test/" in f"/{path.lower()}/"
        or "/tests/" in f"/{path.lower()}/"
        or path.lower().endswith("_test.dart")
        or path.lower().rsplit("/", 1)[-1].startswith("test_")
        for path in blobs
    )
    manifest_names = {
        "pubspec.yaml",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "build.gradle",
        "build.gradle.kts",
        "cargo.toml",
        "go.mod",
        "pom.xml",
    }
    dependency_manifests = sorted(
        path for path in blobs if path.lower().rsplit("/", 1)[-1] in manifest_names
    )

    if sensitive:
        state = "BLOCKED_SENSITIVE_PATH"
        reason = "candidate scope contains forbidden secret/credential-like paths"
    elif not license_paths:
        state = "REVIEW_LICENSE"
        reason = "owner-controlled source has no repository license evidence"
    else:
        state = "READY_FOR_STATIC_ADMISSION"
        reason = "bounded first-party component is ready for normal static admission"

    return {
        "repository": source.repository,
        "commit_sha": commit_sha,
        "capability_id": spec.capability_id,
        "component_path": spec.component_path,
        "kind": spec.kind,
        "state": state,
        "reason": reason,
        "provenance": {
            "owner_controlled": True,
            "source_repository": f"https://github.com/{source.repository}",
            "source_commit": commit_sha,
            "source_lifecycle": source.lifecycle,
        },
        "static_inventory": {
            "file_count": len(blobs),
            "sample_paths": sorted(blobs)[:20],
            "dependency_manifests": dependency_manifests[:20],
            "tests_present_in_scope": tests_present,
            "repository_license_paths": license_paths[:10],
            "sensitive_paths": sensitive[:10],
        },
        "safety": {
            "code_executed": False,
            "arbitrary_file_contents_fetched": False,
            "repository_write_attempted": False,
            "library_write_attempted": False,
        },
    }


def run_first_party_mining(
    config: Config,
    state: SQLiteStateStore,
    *,
    repository_limit: int = 7,
    finding_limit: int = 32,
) -> dict[str, Any]:
    if not config.library_github_token:
        raise FirstPartyMiningError(
            "LIBRARY_GITHUB_TOKEN is required for first-party mining catalog access"
        )
    if not config.first_party_github_token:
        raise FirstPartyMiningError(
            "FIRST_PARTY_GITHUB_TOKEN is required for private legacy repository reads"
        )

    library_api = GitHubApi(
        config.library_github_token,
        config.github_api_base,
        user_agent="AI-Orchestrator-Module-Researcher-FirstPartyCatalog/1.0",
        uploads_base_url=config.github_uploads_base,
    )
    source_api = GitHubApi(
        config.first_party_github_token,
        config.github_api_base,
        user_agent="AI-Orchestrator-Module-Researcher-FirstPartyMiner/1.0",
        uploads_base_url=config.github_uploads_base,
    )

    catalog = library_api.get_json_file(
        config.library_repository,
        config.first_party_source_catalog_path,
        config.library_ref,
    )
    needs = library_api.get_json_file(
        config.library_repository,
        "catalog/needs.json",
        config.library_ref,
    )
    sources = _parse_catalog(catalog)
    active_needs = _active_need_ids(needs)

    bounded_repositories = max(1, min(int(repository_limit), 50))
    bounded_findings = max(1, min(int(finding_limit), 200))
    findings: list[dict[str, Any]] = []
    source_results: list[dict[str, Any]] = []

    for source in sources[:bounded_repositories]:
        if len(findings) >= bounded_findings:
            break
        relevant = [
            spec
            for spec in source.candidates
            if spec.capability_id in active_needs
        ]
        if not relevant:
            source_results.append(
                {
                    "repository": source.repository,
                    "state": "NO_ACTIVE_NEED_MATCH",
                    "purpose": source.purpose,
                }
            )
            continue
        try:
            commit_sha, entries = _tree_entries(source_api, source.repository)
        except (GitHubApiError, FirstPartyMiningError) as exc:
            source_results.append(
                {
                    "repository": source.repository,
                    "state": "INACCESSIBLE_OR_INVALID",
                    "error_type": type(exc).__name__,
                }
            )
            continue

        before = len(findings)
        for spec in relevant:
            if len(findings) >= bounded_findings:
                break
            findings.append(
                _candidate_finding(source, spec, commit_sha, entries)
            )
        source_results.append(
            {
                "repository": source.repository,
                "state": "SCANNED",
                "commit_sha": commit_sha,
                "finding_count": len(findings) - before,
            }
        )

    summary = {
        "schema": "ai-orchestrator.researcher-first-party-mining.v1",
        "generated_at": utc_now(),
        "state": "COMPLETE",
        "active_need_count": len(active_needs),
        "source_count": len(source_results),
        "finding_count": len(findings),
        "ready_for_static_admission": sum(
            1 for item in findings if item.get("state") == "READY_FOR_STATIC_ADMISSION"
        ),
        "review_license": sum(
            1 for item in findings if item.get("state") == "REVIEW_LICENSE"
        ),
        "blocked_sensitive": sum(
            1 for item in findings if item.get("state") == "BLOCKED_SENSITIVE_PATH"
        ),
        "policy": {
            "read_only": True,
            "code_execution": False,
            "arbitrary_file_fetch": False,
            "library_write": False,
        },
        "sources": source_results,
        "findings": findings,
    }

    output_dir = config.data_dir / "first_party_mining"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "latest.json"
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    state.set_json(
        "first_party_mining_status",
        {
            "generated_at": summary["generated_at"],
            "state": summary["state"],
            "finding_count": summary["finding_count"],
            "ready_for_static_admission": summary["ready_for_static_admission"],
            "review_license": summary["review_license"],
            "blocked_sensitive": summary["blocked_sensitive"],
            "report_path": str(output),
        },
    )
    return summary
