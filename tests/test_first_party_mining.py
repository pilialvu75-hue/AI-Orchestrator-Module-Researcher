from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from researcher.config import Config
from researcher.first_party_mining import (
    FirstPartyMiningError,
    _candidate_finding,
    _parse_catalog,
    run_first_party_mining,
)
from researcher.models import ResearchMode
from researcher.state import SQLiteStateStore


class _Response:
    def __init__(self, data):
        self.data = data
        self.headers = {}


class _FakeLibraryApi:
    def __init__(self, catalog, needs):
        self.catalog = catalog
        self.needs = needs
        self.calls = []

    def get_json_file(self, repository, path, ref="main"):
        self.calls.append(("get_json_file", repository, path, ref))
        if path.endswith("first-party-sources.json"):
            return self.catalog
        if path == "catalog/needs.json":
            return self.needs
        raise AssertionError(path)


class _FakeSourceApi:
    def __init__(self, *, sensitive=False):
        self.sensitive = sensitive
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path == "/repos/pilialvu75-hue/Legacy":
            return _Response(
                {
                    "full_name": "pilialvu75-hue/Legacy",
                    "private": True,
                    "default_branch": "main",
                }
            )
        if path == "/repos/pilialvu75-hue/Legacy/commits/main":
            return _Response(
                {
                    "sha": "a" * 40,
                    "commit": {"tree": {"sha": "b" * 40}},
                }
            )
        if path == f"/repos/pilialvu75-hue/Legacy/git/trees/{'b' * 40}?recursive=1":
            tree = [
                {"path": "LICENSE", "type": "blob"},
                {"path": "lib/demo", "type": "tree"},
                {"path": "lib/demo/demo.dart", "type": "blob"},
                {"path": "lib/demo/pubspec.yaml", "type": "blob"},
                {"path": "lib/demo/test", "type": "tree"},
                {"path": "lib/demo/test/demo_test.dart", "type": "blob"},
            ]
            if self.sensitive:
                tree.append({"path": "lib/demo/.env", "type": "blob"})
            return _Response({"truncated": False, "tree": tree})
        raise AssertionError(f"Unexpected API call: {path}")


def _catalog():
    return {
        "schema_version": 1,
        "policy": {
            "access": "read_only",
            "execute_source": False,
            "fetch_arbitrary_file_contents": False,
            "submit_destination": "library_intake_only",
            "certification_required": True,
            "provenance_required": True,
            "secret_paths_forbidden": True,
        },
        "sources": [
            {
                "repository": "pilialvu75-hue/Legacy",
                "priority": "high",
                "lifecycle": "legacy_source",
                "candidates": [
                    {
                        "capability_id": "storage.local_db",
                        "component_path": "lib/demo",
                        "kind": "module",
                    }
                ],
            }
        ],
    }


def _needs():
    return {
        "schema_version": 1,
        "items": [
            {
                "capability_id": "storage.local_db",
                "status": "needed",
            }
        ],
    }


def _config(root: Path, *, first_party_token: str | None = "first-party-token"):
    return Config(
        mode=ResearchMode.SEEDING,
        dry_run=True,
        allow_library_write=False,
        github_token=None,
        library_repository="pilialvu75-hue/AI-Orchestrator-Module-Library",
        library_ref="main",
        data_dir=root,
        maintenance_interval_seconds=21600,
        seeding_interval_seconds=900,
        improvement_interval_seconds=86400,
        dashboard_host="127.0.0.1",
        dashboard_port=8080,
        library_github_token="library-token",
        first_party_github_token=first_party_token,
    )


class FirstPartyMiningTest(unittest.TestCase):
    def test_catalog_rejects_policy_that_allows_execution(self) -> None:
        catalog = _catalog()
        catalog["policy"]["execute_source"] = True
        with self.assertRaises(FirstPartyMiningError):
            _parse_catalog(catalog)

    def test_mining_requires_dedicated_private_source_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "researcher.db")
            with self.assertRaisesRegex(
                FirstPartyMiningError,
                "FIRST_PARTY_GITHUB_TOKEN",
            ):
                run_first_party_mining(
                    _config(Path(tmp), first_party_token=None),
                    state,
                )

    def test_mining_uses_metadata_tree_only_and_persists_bounded_report(self) -> None:
        library_api = _FakeLibraryApi(_catalog(), _needs())
        source_api = _FakeSourceApi()

        def api_factory(token, *args, **kwargs):
            del args, kwargs
            return library_api if token == "library-token" else source_api

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = SQLiteStateStore(root / "researcher.db")
            with patch("researcher.first_party_mining.GitHubApi", side_effect=api_factory):
                result = run_first_party_mining(_config(root), state)

            self.assertEqual(result["finding_count"], 1)
            self.assertEqual(result["ready_for_static_admission"], 1)
            finding = result["findings"][0]
            self.assertEqual(finding["state"], "READY_FOR_STATIC_ADMISSION")
            self.assertEqual(finding["commit_sha"], "a" * 40)
            self.assertFalse(finding["safety"]["code_executed"])
            self.assertFalse(finding["safety"]["arbitrary_file_contents_fetched"])
            self.assertTrue(
                (root / "first_party_mining" / "latest.json").is_file()
            )
            self.assertEqual(
                source_api.calls,
                [
                    "/repos/pilialvu75-hue/Legacy",
                    "/repos/pilialvu75-hue/Legacy/commits/main",
                    f"/repos/pilialvu75-hue/Legacy/git/trees/{'b' * 40}?recursive=1",
                ],
            )

    def test_sensitive_file_inside_component_blocks_candidate(self) -> None:
        source = _parse_catalog(_catalog())[0]
        api = _FakeSourceApi(sensitive=True)
        commit, entries = __import__(
            "researcher.first_party_mining",
            fromlist=["_tree_entries"],
        )._tree_entries(api, source.repository)
        finding = _candidate_finding(source, source.candidates[0], commit, entries)
        self.assertEqual(finding["state"], "BLOCKED_SENSITIVE_PATH")
        self.assertEqual(finding["static_inventory"]["sensitive_paths"], ["lib/demo/.env"])


if __name__ == "__main__":
    unittest.main()
