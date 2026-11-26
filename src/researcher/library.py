from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .github_api import GitHubApi, GitHubApiError
from .models import Contract, Need, utc_now


class NeedSource(Protocol):
    def load_needs(self) -> tuple[list[Need], dict[str, Any]]: ...


class ContractSource(Protocol):
    def load_contracts(self) -> tuple[dict[str, Contract], str]: ...


@dataclass
class LibrarySnapshot:
    needs_updated_at: str | None
    used_cache: bool


class GitHubLibrarySource:
    # catalog/needs.json is the single authoritative queue. The Library's
    # deterministic reconciler folds staged platform extensions into it.
    _NEED_SOURCES = (
        ("catalog/needs.json", "needs.json", "authoritative"),
    )

    def __init__(
        self,
        api: GitHubApi,
        repository: str,
        ref: str,
        cache_dir: Path,
    ) -> None:
        self.api = api
        self.repository = repository
        self.ref = ref
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _fetch_with_cache(
        self,
        remote_path: str,
        cache_name: str,
    ) -> tuple[dict[str, Any], bool]:
        cache_path = self.cache_dir / cache_name
        try:
            payload = self.api.get_json_file(self.repository, remote_path, self.ref)
            cache_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            return payload, False
        except GitHubApiError:
            if not cache_path.exists():
                raise
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if not isinstance(cached, dict):
                raise ValueError(f"Invalid cached Library payload: {cache_name}")
            return cached, True

    @staticmethod
    def _parse_need_items(
        payload: dict[str, Any],
        source_kind: str,
    ) -> tuple[list[Need], list[dict[str, Any]]]:
        if not isinstance(payload.get("schema_version"), int) or payload["schema_version"] < 1:
            raise ValueError(f"Unsupported Library needs schema: {source_kind}")
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            raise ValueError(f"Library needs items must be an array: {source_kind}")

        needs: list[Need] = []
        status_items: list[dict[str, Any]] = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                raise ValueError(f"Invalid need entry: {source_kind}")
            targets = raw.get("targets")
            if not isinstance(targets, list) or not targets:
                raise ValueError(f"Invalid targets for {raw.get('capability_id')}")
            capability_id = str(raw["capability_id"])
            title = str(raw["title"])
            priority = str(raw["priority"])
            desired_candidates = int(raw["desired_candidates"])
            status = str(raw["status"])
            normalized_targets = tuple(str(item) for item in targets)
            notes = None if raw.get("notes") is None else str(raw["notes"])
            needs.append(
                Need(
                    capability_id=capability_id,
                    title=title,
                    priority=priority,
                    desired_candidates=desired_candidates,
                    status=status,
                    targets=normalized_targets,
                    notes=notes,
                )
            )
            status_items.append(
                {
                    "capability_id": capability_id,
                    "title": title,
                    "priority": priority,
                    "desired_candidates": desired_candidates,
                    "status": status,
                    "targets": list(normalized_targets),
                    "source_kind": source_kind,
                }
            )
        return needs, status_items

    def load_needs(self) -> tuple[list[Need], dict[str, Any]]:
        merged_needs: list[Need] = []
        merged_status: list[dict[str, Any]] = []
        seen: set[str] = set()
        used_cache = False
        updated_values: list[str] = []
        loaded_sources: list[str] = []

        for remote_path, cache_name, source_kind in self._NEED_SOURCES:
            try:
                payload, cached = self._fetch_with_cache(remote_path, cache_name)
            except GitHubApiError:
                if source_kind == "authoritative":
                    raise
                continue

            parsed_needs, parsed_status = self._parse_need_items(payload, source_kind)
            for need, status_item in zip(parsed_needs, parsed_status, strict=True):
                if need.capability_id in seen:
                    raise ValueError(
                        "Duplicate capability across Library need sources: "
                        f"{need.capability_id}"
                    )
                seen.add(need.capability_id)
                merged_needs.append(need)
                merged_status.append(status_item)

            used_cache = used_cache or cached
            loaded_sources.append(source_kind)
            updated_at = payload.get("updated_at")
            if isinstance(updated_at, str) and updated_at:
                updated_values.append(updated_at)

        return merged_needs, {
            "updated_at": max(updated_values) if updated_values else None,
            "used_cache": used_cache,
            "loaded_at": utc_now(),
            "sources": loaded_sources,
            "items": merged_status,
        }

    def load_development_feedback(self) -> dict[str, Any]:
        """Read development test receipts; never treat a submission as a pass."""
        index, cached = self._fetch_with_cache(
            "packages/development-index.json", "development-index.json"
        )
        entries = index.get("packages")
        if not isinstance(entries, list):
            raise ValueError("Invalid development package index")
        evidence, evidence_cached = self._fetch_with_cache(
            "packages/development-platform-evidence.json", "development-platform-evidence.json"
        )
        if evidence.get("schema") != "aivexus.development-platform-evidence.v1":
            raise ValueError("Invalid development platform evidence schema")
        records = evidence.get("records")
        if not isinstance(records, list):
            raise ValueError("Invalid development platform evidence records")
        packages = []
        for row in entries:
            if (row.get("development_qualified") is not True
                    or row.get("independent_export_consumer") != "PASS"):
                continue
            pin = row["pin"]
            digest = row["package_sha256"]
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Invalid development package digest")
            remote_path = row["path"]
            if not re.fullmatch(
                r"packages/experimental/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/package.json",
                remote_path,
            ) or ".." in remote_path.split("/"):
                raise ValueError("Invalid development package path")
            cache_name = f"development-package-{digest}.json"
            cache_path = self.cache_dir / cache_name
            envelope = None
            if cache_path.exists():
                try:
                    local = json.loads(cache_path.read_text(encoding="utf-8"))
                    local_package = local["package"]
                    local_digest = hashlib.sha256(json.dumps(
                        local_package, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False
                    ).encode("utf-8")).hexdigest()
                    if (local_digest == digest
                            and local.get("package_sha256") == digest
                            and local_package.get("pin") == pin):
                        envelope = local
                except (OSError, ValueError, KeyError, TypeError, AttributeError):
                    pass
            package_cached = False
            if envelope is None:
                envelope, package_cached = self._fetch_with_cache(
                    remote_path, cache_name
                )
            cached = cached or package_cached
            package = envelope["package"]
            actual = hashlib.sha256(json.dumps(
                package, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")).hexdigest()
            if actual != digest or envelope.get("package_sha256") != digest:
                raise ValueError("Development package integrity mismatch")
            if package.get("pin") != pin:
                raise ValueError("Development package identity mismatch")
            targets = set(row["validated_targets"])
            for record in records:
                if (record.get("pin") == row["pin"]
                        and record.get("package_sha256") == row["package_sha256"]
                        and record.get("target") in ("linux", "windows", "macos")
                        and type(record.get("run_id")) is int and record["run_id"] > 0
                        and type(record.get("job_id")) is int and record["job_id"] > 0):
                    targets.add(record["target"])
            packages.append({
                "pin": row["pin"], "package_sha256": row["package_sha256"],
                "validated_targets": sorted(targets),
                "capabilities": package["capabilities"],
                "contracts": package["contracts"],
                "source": package["source"],
            })
        return {"used_cache": cached or evidence_cached, "packages": packages}

    def load_first_party_previews(self) -> dict[str, Any]:
        """Discover extracted source packages without claiming functional parity."""
        payload, cached = self._fetch_with_cache(
            "catalog/first-party-preview.json", "first-party-preview.json"
        )
        if payload.get("schema") != "aivexus.first-party-preview.v1":
            raise ValueError("Invalid first-party preview schema")
        assets = payload.get("assets")
        if not isinstance(assets, list):
            raise ValueError("Invalid first-party preview assets")
        records: list[dict[str, Any]] = []
        for asset in assets:
            for key in ("source_commit", "package_commit"):
                if not re.fullmatch(r"[0-9a-f]{40}", str(asset[key])):
                    raise ValueError("Preview commit must be immutable")
            path = str(asset["path"])
            if not re.fullmatch(r"packages/[A-Za-z0-9_-]+", path):
                raise ValueError("Invalid preview package path")
            records.append({
                "id": asset["id"], "version": asset["version"],
                "path": path, "package_commit": asset["package_commit"],
                "source_commit": asset["source_commit"],
                "capabilities": asset["capabilities"],
                "physical_ota": asset.get("physical_ota", "unknown"),
                "functional_coverage": False,
            })
        return {"used_cache": cached, "packages": records}

    def load_first_party_sources(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        payload, used_cache = self._fetch_with_cache(
            ".airlab/first-party-sources.json",
            "first-party-sources.json",
        )
        if not isinstance(payload.get("schema_version"), int) or payload["schema_version"] < 1:
            raise ValueError("Unsupported first-party source catalog schema")
        raw_sources = payload.get("sources")
        if not isinstance(raw_sources, list):
            raise ValueError("First-party source catalog sources must be an array")

        sources: list[dict[str, Any]] = []
        for raw in raw_sources:
            if not isinstance(raw, dict):
                raise ValueError("Invalid first-party source catalog entry")
            repository = str(raw.get("repository") or "").strip()
            if not re.fullmatch(r"pilialvu75-hue/[A-Za-z0-9._-]+", repository):
                raise ValueError("First-party source repository is outside the trusted owner")
            source_commit = raw.get("source_commit")
            if source_commit is not None and not re.fullmatch(
                r"[0-9a-fA-F]{40}", str(source_commit)
            ):
                raise ValueError(f"First-party source commit is not immutable: {repository}")
            candidates = raw.get("candidates")
            if not isinstance(candidates, list):
                raise ValueError(f"First-party source candidates must be an array: {repository}")
            normalized_candidates: list[dict[str, str]] = []
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    raise ValueError(f"Invalid first-party candidate: {repository}")
                capability_id = str(candidate.get("capability_id") or "").strip()
                component_path = str(candidate.get("component_path") or "").strip()
                kind = str(candidate.get("kind") or "").strip()
                if not capability_id or not component_path or not kind:
                    raise ValueError(f"Incomplete first-party candidate: {repository}")
                normalized_candidates.append(
                    {
                        "capability_id": capability_id,
                        "component_path": component_path,
                        "kind": kind,
                    }
                )
            sources.append(
                {
                    "repository": repository,
                    "priority": str(raw.get("priority") or "medium"),
                    "lifecycle": str(raw.get("lifecycle") or "unknown"),
                    "source_commit": None if source_commit is None else str(source_commit).lower(),
                    "candidates": normalized_candidates,
                }
            )

        return sources, {
            "updated_at": payload.get("updated_at"),
            "used_cache": used_cache,
            "loaded_at": utc_now(),
            "source_path": ".airlab/first-party-sources.json",
        }

    def load_contracts(self) -> tuple[dict[str, Contract], str]:
        payload, _ = self._fetch_with_cache("contracts/index.json", "contracts.json")
        raw_contracts = payload.get("contracts")
        if not isinstance(raw_contracts, list):
            raise ValueError("Library contracts must be an array")
        contracts: dict[str, Contract] = {}
        for raw in raw_contracts:
            if not isinstance(raw, dict):
                continue
            contract = Contract(
                capability_id=str(raw["capability_id"]),
                contract_id=str(raw["contract_id"]),
                contract_version=str(raw["contract_version"]),
                status=str(raw["status"]),
            )
            contracts[contract.capability_id] = contract

        example, _ = self._fetch_with_cache(
            "examples/module.manifest.example.json", "module.manifest.example.json"
        )
        connector = example.get("connector", {})
        standard_version = (
            str(connector.get("standard_version", ""))
            if isinstance(connector, dict)
            else ""
        )
        if not re.fullmatch(r"\d+\.\d+\.\d+", standard_version):
            raise ValueError("Unable to resolve Library Lego standard version")
        return contracts, standard_version
