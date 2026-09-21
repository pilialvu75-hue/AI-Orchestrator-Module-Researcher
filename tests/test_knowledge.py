from __future__ import annotations

import unittest
from dataclasses import replace

from researcher.knowledge import novelty_delta, research_source
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


if __name__ == "__main__":
    unittest.main()
