from __future__ import annotations

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

    def _fetch_with_cache(self, remote_path: str, cache_name: str) -> tuple[dict[str, Any], bool]:
        cache_path = self.cache_dir / cache_name
        try:
            payload = self.api.get_json_file(self.repository, remote_path, self.ref)
            cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            return payload, False
        except GitHubApiError:
            if not cache_path.exists():
                raise
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if not isinstance(cached, dict):
                raise ValueError(f"Invalid cached Library payload: {cache_name}")
            return cached, True

    def load_needs(self) -> tuple[list[Need], dict[str, Any]]:
        payload, cached = self._fetch_with_cache("catalog/needs.json", "needs.json")
        if not isinstance(payload.get("schema_version"), int) or payload["schema_version"] < 1:
            raise ValueError("Unsupported Library needs schema")
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            raise ValueError("Library needs items must be an array")
        needs: list[Need] = []
        status_items: list[dict[str, Any]] = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                raise ValueError("Invalid need entry")
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
                }
            )
        return needs, {
            "updated_at": payload.get("updated_at"),
            "used_cache": cached,
            "loaded_at": utc_now(),
            "items": status_items,
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
