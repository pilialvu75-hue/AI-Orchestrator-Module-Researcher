from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from researcher.first_party_mining import run_one_first_party_candidate


class Source:
    def load_first_party_sources(self):
        return (
            [
                {
                    "repository": "pilialvu75-hue/AI-Orchestrator-Core",
                    "source_commit": "a" * 40,
                    "candidates": [
                        {
                            "capability_id": "inactive.capability",
                            "component_path": "ignored",
                            "kind": "module",
                        },
                        {
                            "capability_id": "ai.local_inference",
                            "component_path": "lib/core/runtime/inference",
                            "kind": "integration_bundle",
                        },
                    ],
                }
            ],
            {"source_path": ".airlab/first-party-sources.json"},
        )

    def load_needs(self):
        return (
            [SimpleNamespace(capability_id="ai.local_inference", status="needed")],
            {},
        )


class FirstPartyMiningTest(unittest.TestCase):

    def test_missing_private_token_keeps_first_party_lane_idle(self) -> None:
        app = SimpleNamespace(
            config=SimpleNamespace(first_party_source_github_token=None),
            engine=SimpleNamespace(need_source=object()),
        )

        result = run_one_first_party_candidate(app)

        self.assertEqual("IDLE", result["state"])
        self.assertEqual(
            "first_party_source_credential_unavailable",
            result["reason"],
        )

    def test_sweep_selects_one_active_allowlisted_component(self) -> None:
        app = SimpleNamespace(engine=SimpleNamespace(need_source=Source()))
        with patch(
            "researcher.first_party_mining.resolve_and_admit_component_candidate"
        ) as admit:
            admit.return_value = {"state": "ADMISSION_COMPLETE"}
            result = run_one_first_party_candidate(app)

        self.assertEqual(result["state"], "COMPLETE")
        admit.assert_called_once_with(
            app,
            "ai.local_inference",
            "pilialvu75-hue/AI-Orchestrator-Core",
            "a" * 40,
            component_path="lib/core/runtime/inference",
        )


if __name__ == "__main__":
    unittest.main()
