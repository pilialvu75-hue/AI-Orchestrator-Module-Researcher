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


if __name__ == "__main__":
    unittest.main()
