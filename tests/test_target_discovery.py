from __future__ import annotations

import unittest
from dataclasses import replace

from researcher.models import Candidate, Need
from researcher.target_discovery import TargetAwareDiscoveryProvider

from helpers import candidate, need


class RecordingDiscovery:
    name = "recording"

    def __init__(self) -> None:
        self.calls: list[Need] = []

    def discover(self, requested: Need, limit: int = 8) -> list[Candidate]:
        self.calls.append(requested)
        common = candidate("common", "a" * 40)
        specific = candidate(f"specific-{requested.targets[0]}", requested.targets[0][0] * 40)
        return [common, specific][:limit]


class TargetAwareDiscoveryTests(unittest.TestCase):
    def test_same_candidate_merges_target_search_evidence(self) -> None:
        base = RecordingDiscovery()
        provider = TargetAwareDiscoveryProvider(base)
        requested = need()

        found = provider.discover_for_targets(
            requested,
            ("android", "desktop"),
            limit=8,
        )

        common = next(item for item in found if item.name == "common")
        self.assertEqual(
            common.extra["research_targets"],
            ["android", "desktop"],
        )
        self.assertFalse(common.extra["target_support_certified"])
        self.assertEqual(len(base.calls), 2)

    def test_short_target_names_expand_to_searchable_terms(self) -> None:
        base = RecordingDiscovery()
        provider = TargetAwareDiscoveryProvider(base)
        requested = replace(need(), targets=("ios", "web", "raspberry_pi"))

        provider.discover(requested, limit=12)

        titles = {call.targets[0]: call.title.lower() for call in base.calls}
        self.assertIn("iphone", titles["ios"])
        self.assertIn("browser", titles["web"])
        self.assertIn("raspberry", titles["raspberry_pi"])

    def test_unrequested_target_is_never_queried(self) -> None:
        base = RecordingDiscovery()
        provider = TargetAwareDiscoveryProvider(base)
        requested = need()

        found = provider.discover_for_targets(
            requested,
            ("android", "web"),
            limit=8,
        )

        self.assertTrue(found)
        self.assertEqual([call.targets for call in base.calls], [("android",)])



class TargetSearchDiagnosticsTests(unittest.TestCase):
    def test_aggregates_rate_limited_targets_without_leaking_queries(self) -> None:
        class BlockedDiscovery:
            name = "blocked"

            def __init__(self) -> None:
                self.last_discovery_diagnostics: dict[str, str | int] = {}

            def discover(self, requested: Need, limit: int = 8) -> list[Candidate]:
                self.last_discovery_diagnostics = {
                    "status": "SEARCH_RATE_LIMITED",
                    "queries_attempted": 0,
                    "search_hits": 0,
                    "unique_repository_hits": 0,
                    "candidates_returned": 0,
                }
                return []

        provider = TargetAwareDiscoveryProvider(BlockedDiscovery())  # type: ignore[arg-type]
        requested = need()
        self.assertEqual(
            provider.discover_for_targets(requested, ("android", "desktop")), []
        )
        report = provider.last_discovery_diagnostics
        self.assertEqual(report["status"], "SEARCH_RATE_LIMITED")
        self.assertEqual(report["targets_requested"], 2)
        self.assertEqual(report["rate_limited_targets"], 2)
        self.assertEqual(report["queries_attempted"], 0)

    def test_aggregates_empty_hits_separately(self) -> None:
        class EmptyDiscovery:
            name = "empty"

            def __init__(self) -> None:
                self.last_discovery_diagnostics: dict[str, str | int] = {}

            def discover(self, requested: Need, limit: int = 8) -> list[Candidate]:
                self.last_discovery_diagnostics = {
                    "status": "NO_SEARCH_HITS",
                    "queries_attempted": 2,
                    "search_hits": 0,
                    "unique_repository_hits": 0,
                    "candidates_returned": 0,
                }
                return []

        provider = TargetAwareDiscoveryProvider(EmptyDiscovery())  # type: ignore[arg-type]
        self.assertEqual(provider.discover_for_targets(need(), ("android", "desktop")), [])
        report = provider.last_discovery_diagnostics
        self.assertEqual(report["status"], "NO_SEARCH_HITS")
        self.assertEqual(report["queries_attempted"], 4)
        self.assertEqual(report["rate_limited_targets"], 0)


if __name__ == "__main__":
    unittest.main()
