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
        if path not in self.payloads:
            from researcher.github_api import GitHubApiError
            raise GitHubApiError(404, "missing")
        return self.payloads[path]


class NeedsTests(unittest.TestCase):
    def test_parser_merges_authoritative_and_platform_extension_and_cache_fallback(self) -> None:
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
        platform_payload = {
            "schema_version": 1,
            "updated_at": "2026-09-14T20:00:00Z",
            "items": [
                {
                    "capability_id": "platform.audio_io",
                    "title": "Audio IO",
                    "priority": "high",
                    "desired_candidates": 2,
                    "status": "needed",
                    "targets": ["android", "windows", "linux", "macos", "ios", "web", "raspberry_pi"],
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
                },
                {
                    "capability_id": "platform.audio_io",
                    "contract_id": "platform.audio_io.v1",
                    "contract_version": "1.0",
                    "status": "draft",
                },
            ],
        }
        manifest_example = {"connector": {"standard_version": "1.0.0"}}
        payloads = {
            "catalog/needs.json": needs_payload,
            "catalog/needs.platform-extension.json": platform_payload,
            "contracts/index.json": contracts_payload,
            "examples/module.manifest.example.json": manifest_example,
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = GitHubLibrarySource(FakeApi(payloads), "x/y", "main", Path(tmp))
            needs, meta = source.load_needs()
            contracts, standard = source.load_contracts()
            self.assertEqual([need.capability_id for need in needs], ["voice.stt", "platform.audio_io"])
            self.assertEqual(contracts["voice.stt"].contract_id, "voice.stt.v1")
            self.assertEqual(contracts["platform.audio_io"].contract_id, "platform.audio_io.v1")
            self.assertEqual(standard, "1.0.0")
            self.assertFalse(meta["used_cache"])
            self.assertEqual(meta["sources"], ["authoritative", "staged-platform-extension"])
            self.assertEqual(meta["items"][1]["source_kind"], "staged-platform-extension")

            source.api = FakeApi(payloads, fail=True)
            cached, cached_meta = source.load_needs()
            self.assertEqual([need.capability_id for need in cached], ["voice.stt", "platform.audio_io"])
            self.assertTrue(cached_meta["used_cache"])

    def test_platform_extension_is_optional_but_authoritative_needs_are_not(self) -> None:
        payloads = {
            "catalog/needs.json": {
                "schema_version": 1,
                "updated_at": "2026-09-11T20:45:00Z",
                "items": [
                    {
                        "capability_id": "voice.tts",
                        "title": "TTS",
                        "priority": "high",
                        "desired_candidates": 2,
                        "status": "needed",
                        "targets": ["android"],
                    }
                ],
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = GitHubLibrarySource(FakeApi(payloads), "x/y", "main", Path(tmp))
            needs, meta = source.load_needs()
            self.assertEqual([need.capability_id for need in needs], ["voice.tts"])
            self.assertEqual(meta["sources"], ["authoritative"])

    def test_duplicate_capability_across_need_sources_fails_closed(self) -> None:
        duplicate = {
            "schema_version": 1,
            "updated_at": "2026-09-14T20:00:00Z",
            "items": [
                {
                    "capability_id": "voice.stt",
                    "title": "duplicate",
                    "priority": "high",
                    "desired_candidates": 2,
                    "status": "needed",
                    "targets": ["android"],
                }
            ],
        }
        payloads = {
            "catalog/needs.json": duplicate,
            "catalog/needs.platform-extension.json": duplicate,
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = GitHubLibrarySource(FakeApi(payloads), "x/y", "main", Path(tmp))
            with self.assertRaisesRegex(ValueError, "Duplicate capability"):
                source.load_needs()


if __name__ == "__main__":
    unittest.main()
