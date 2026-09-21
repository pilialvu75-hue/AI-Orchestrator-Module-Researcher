from __future__ import annotations

import unittest
from dataclasses import replace

from researcher.knowledge import (
    build_improvement_proposal,
    improvement_signal,
    novelty_delta,
    research_source,
)
from helpers import candidate


class KnowledgeTests(unittest.TestCase):
    def test_unknown_license_is_retained_for_research_not_direct_reuse(self) -> None:
        source = research_source(
            "voice.stt",
            replace(candidate("alpha", "a" * 40), license_spdx=None),
        )
        self.assertTrue(source.research_use)
        self.assertFalse(source.direct_reuse)

    def test_novelty_keeps_only_new_signals(self) -> None:
        c = replace(candidate("alpha", "a" * 40), topics=("vulkan", "gpu"))
        source = research_source("ai.acceleration_backend", c)
        delta = novelty_delta({"topic:vulkan"}, source)
        self.assertIn("topic:gpu", delta)
        self.assertNotIn("topic:vulkan", delta)


    def test_research_signals_capture_non_code_engineering_evidence(self) -> None:
        c = replace(
            candidate("alpha", "a" * 40),
            description="Fast Vulkan acceleration backend with fallback scheduling",
            release_tag="v1.2.3",
            license_file_url="https://example.invalid/LICENSE",
            extra={
                "dependency_manifests": ["native/CMakeLists.txt", "Cargo.toml"],
                "tests_present": True,
                "ci_present": True,
                "security_policy_present": True,
                "source_stable": True,
            },
        )
        source = research_source("ai.acceleration_backend", c)
        self.assertIn("practice:tests_present", source.signals)
        self.assertIn("practice:ci_present", source.signals)
        self.assertIn("practice:security_policy_present", source.signals)
        self.assertIn("source:stable", source.signals)
        self.assertIn("release:pinned", source.signals)
        self.assertIn("license:evidence_present", source.signals)
        self.assertIn("concept:vulkan", source.signals)
        self.assertIn("manifest_kind:cargo.toml", source.signals)

    def test_improvement_requires_actual_novelty(self) -> None:
        knowledge = {"source_count": 3}
        self.assertEqual(
            improvement_signal(knowledge, ())["action"],
            "NO_CHANGE",
        )
        signal = improvement_signal(knowledge, ("topic:retry",))
        self.assertEqual(signal["action"], "CONSIDER_IMPROVEMENT")
        self.assertEqual(signal["novelty_count"], 1)


    def test_improvement_proposal_is_gated_and_not_created_without_delta(self) -> None:
        knowledge = {"source_count": 4}
        self.assertIsNone(
            build_improvement_proposal("storage.local_db", knowledge, ())
        )
        proposal = build_improvement_proposal(
            "storage.local_db",
            knowledge,
            ("topic:migration",),
        )
        self.assertIsNotNone(proposal)
        assert proposal is not None
        self.assertEqual(proposal.action, "EVALUATE_IMPROVEMENT")
        self.assertIn("regression_tests_pass", proposal.acceptance_gates)
        self.assertIn("security_gates_pass", proposal.acceptance_gates)


if __name__ == "__main__":
    unittest.main()
