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
