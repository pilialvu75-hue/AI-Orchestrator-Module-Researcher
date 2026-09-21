from __future__ import annotations

import unittest

from researcher.handoff import implementation_request
from researcher.knowledge import build_improvement_proposal


class HandoffTests(unittest.TestCase):
    def test_handoff_is_isolated_and_keeps_acceptance_gates(self) -> None:
        proposal = build_improvement_proposal(
            "platform.audio_io",
            {"source_count": 5},
            ("topic:backpressure",),
        )
        assert proposal is not None
        request = implementation_request(proposal)
        self.assertEqual(request.schema_version, 1)
        self.assertEqual(request.request_type, "library_module_improvement")
        self.assertEqual(
            request.mutation_policy,
            "isolated_candidate_no_library_mutation",
        )
        self.assertEqual(request.knowledge_delta, ("topic:backpressure",))
        self.assertEqual(request.acceptance_gates, proposal.acceptance_gates)


if __name__ == "__main__":
    unittest.main()
