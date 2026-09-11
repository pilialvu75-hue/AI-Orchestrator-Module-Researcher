from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from researcher.library import GitHubLibrarySource


class FakeApi:
    def __init__(self, payloads: dict[str, dict[str, Any]], fail: bool = False) -> None:
        self.payloads = payloads
        self.fail = fail

    def get_json_file(self, repository: str, path: str, ref: str = "main") -> dict[str, Any]:
        if self.fail:
            from researcher.github_api import GitHubApiError
            raise GitHubApiError(503, "offline")
        return self.payloads[path]


class NeedsTests(unittest.TestCase):
    def test_parser_and_cache_fallback(self) -> None:
        needs_payload = {
            "schema_version": 1,
            "updated_at": "2026-09-11T20:45:00Z",
            "items": [
                {
                    "capability_id": "voice.stt",
                    "title": "STT",
                    "priority": "high",
                    "desired_candidates": 2,
                    "status": "needed",
                    "targets": ["android"],
                }
            ],
        }
        contracts_payload = {
            "schema_version": 1,
            "contracts": [
                {
                    "capability_id": "voice.stt",
                    "contract_id": "voice.stt.v1",
                    "contract_version": "1.0",
                    "status": "draft",
                }
            ],
        }
        manifest_example = {"connector": {"standard_version": "1.0.0"}}
        payloads = {
            "catalog/needs.json": needs_payload,
            "contracts/index.json": contracts_payload,
            "examples/module.manifest.example.json": manifest_example,
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = GitHubLibrarySource(FakeApi(payloads), "x/y", "main", Path(tmp))
            needs, meta = source.load_needs()
            contracts, standard = source.load_contracts()
            self.assertEqual(needs[0].capability_id, "voice.stt")
            self.assertEqual(contracts["voice.stt"].contract_id, "voice.stt.v1")
            self.assertEqual(standard, "1.0.0")
            self.assertFalse(meta["used_cache"])

            source.api = FakeApi(payloads, fail=True)
            cached, cached_meta = source.load_needs()
            self.assertEqual(cached[0].capability_id, "voice.stt")
            self.assertTrue(cached_meta["used_cache"])


if __name__ == "__main__":
    unittest.main()
