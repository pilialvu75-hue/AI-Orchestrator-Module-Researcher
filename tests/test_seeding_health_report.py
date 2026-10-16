from __future__ import annotations

import unittest

from tools.seeding_health_report import summarize


class SeedingHealthTests(unittest.TestCase):
    def test_zero_discovery_does_not_look_like_certified_success(self) -> None:
        actual = summarize(
            {"proposed": 0},
            {
                "first_party": {
                    "state": "IDLE",
                    "reason": "first_party_source_credential_unavailable",
                },
                "results": [
                    {"state": "COMPLETED", "discovered": 0, "new_analyzed": 0,
                     "prepared_submissions": []},
                ],
            },
        )
        self.assertEqual(actual["outcome"], "ZERO_DISCOVERY")
        self.assertEqual(actual["prepared_submissions"], 0)
        self.assertFalse(actual["certification_verified"])
        self.assertIsNone(actual["library_certified_modules"])
        self.assertEqual(
            actual["first_party_reason"], "first_party_source_credential_unavailable"
        )

    def test_prepared_candidates_are_not_mislabeled_certified(self) -> None:
        actual = summarize(
            {"proposed": 1},
            {"results": [
                {"state": "COMPLETED", "discovered": 3, "new_analyzed": 2,
                 "shortlisted": 1, "prepared_submissions": [{"id": "one"}],
                 "recovered_submissions": []},
            ]},
        )
        self.assertEqual(actual["outcome"], "CANDIDATES_PREPARED")
        self.assertEqual(actual["discovered"], 3)
        self.assertEqual(actual["prepared_submissions"], 1)
        self.assertFalse(actual["certification_verified"])

    def test_blocked_cycle_does_not_count_as_productive(self) -> None:
        actual = summarize(
            {},
            {"results": [{"state": "BLOCKED", "discovered": 0}]},
        )
        self.assertEqual(actual["outcome"], "BLOCKED")

    def test_rejects_invalid_evidence(self) -> None:
        with self.assertRaises(ValueError):
            summarize({}, {"results": [{"discovered": -1}]})
        with self.assertRaises(ValueError):
            summarize({}, {"results": "none"})


if __name__ == "__main__":
    unittest.main()
