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


    def test_first_party_submitted_counts_as_productive(self) -> None:
        actual = summarize(
            {"proposed": 0},
            {
                "first_party": {
                    "state": "COMPLETE",
                    "candidate": {"submitted": True, "dry_run_prepared": False},
                },
                "results": [{"state": "COMPLETED", "discovered": 0}],
            },
        )
        self.assertEqual(actual["outcome"], "CANDIDATES_PREPARED")
        self.assertEqual(actual["prepared_submissions"], 1)
        self.assertEqual(actual["sweep_prepared_submissions"], 0)
        self.assertEqual(actual["first_party_submitted"], 1)
        self.assertEqual(actual["first_party_dry_run_prepared"], 0)
        self.assertFalse(actual["certification_verified"])

    def test_first_party_dry_run_is_not_a_real_delivery(self) -> None:
        actual = summarize(
            {},
            {
                "first_party": {
                    "state": "COMPLETE",
                    "candidate": {"submitted": False, "dry_run_prepared": True},
                },
                "results": [{"state": "COMPLETED", "discovered": 0}],
            },
        )
        self.assertEqual(actual["outcome"], "CANDIDATES_DRY_RUN_PREPARED")
        self.assertEqual(actual["prepared_submissions"], 1)
        self.assertEqual(actual["first_party_submitted"], 0)
        self.assertEqual(actual["first_party_dry_run_prepared"], 1)

    def test_first_party_admission_without_delivery_is_not_zero_discovery(self) -> None:
        actual = summarize(
            {},
            {
                "first_party": {
                    "state": "COMPLETE",
                    "candidate": {"submitted": False, "dry_run_prepared": False},
                },
                "results": [{"state": "COMPLETED", "discovered": 0}],
            },
        )
        self.assertEqual(actual["outcome"], "DISCOVERED_NO_SUBMISSIONS")
        self.assertEqual(actual["prepared_submissions"], 0)

    def test_invalid_first_party_delivery_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            summarize({}, {"first_party": {"state": "COMPLETE"}, "results": []})
        with self.assertRaises(ValueError):
            summarize(
                {},
                {
                    "first_party": {
                        "state": "COMPLETE",
                        "candidate": {"submitted": "true"},
                    },
                    "results": [],
                },
            )
        with self.assertRaises(ValueError):
            summarize(
                {},
                {
                    "first_party": {
                        "state": "COMPLETE",
                        "candidate": {"submitted": True, "dry_run_prepared": True},
                    },
                    "results": [],
                },
            )

    def test_first_party_blocked_preempts_other_results(self) -> None:
        actual = summarize(
            {},
            {
                "first_party": {"state": "BLOCKED"},
                "results": [
                    {"state": "COMPLETED", "prepared_submissions": [{"id": "one"}]},
                ],
            },
        )
        self.assertEqual(actual["outcome"], "BLOCKED")


    def test_zero_hit_is_not_confused_with_rate_limit(self) -> None:
        actual = summarize(
            {}, {"results": [{
                "state": "COMPLETED", "discovered": 0,
                "discovery_diagnostics": {
                    "status": "NO_SEARCH_HITS", "queries_attempted": 6,
                    "search_hits": 0, "rate_limited_targets": 0,
                },
            }]},
        )
        self.assertEqual(actual["outcome"], "ZERO_DISCOVERY")
        self.assertEqual(actual["search_queries_attempted"], 6)
        self.assertEqual(actual["search_hits"], 0)
        self.assertEqual(actual["search_status_counts"], {"NO_SEARCH_HITS": 1})

    def test_rate_limited_zero_yield_is_blocked_even_if_cycle_completed(self) -> None:
        actual = summarize(
            {}, {"results": [{
                "state": "COMPLETED", "discovered": 0,
                "discovery_diagnostics": {
                    "status": "SEARCH_RATE_LIMITED", "queries_attempted": 0,
                    "search_hits": 0, "rate_limited_targets": 2,
                },
            }]},
        )
        self.assertEqual(actual["outcome"], "BLOCKED")
        self.assertEqual(actual["search_rate_limited_targets"], 2)

    def test_all_known_candidates_have_distinct_outcome(self) -> None:
        actual = summarize(
            {}, {"results": [{
                "state": "COMPLETED", "discovered": 3, "new_analyzed": 0,
                "known_candidates_skipped": 3,
                "discovery_diagnostics": {
                    "status": "CANDIDATES_FOUND", "queries_attempted": 3,
                    "search_hits": 8, "rate_limited_targets": 0,
                },
            }]},
        )
        self.assertEqual(actual["outcome"], "ONLY_KNOWN_CANDIDATES")
        self.assertEqual(actual["known_candidates_skipped"], 3)
        self.assertEqual(actual["search_hits"], 8)

    def test_invalid_search_diagnostics_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            summarize({}, {"results": [{
                "discovery_diagnostics": {
                    "status": "SEARCH_RATE_LIMITED",
                    "rate_limited_targets": -1,
                },
            }]})
        with self.assertRaises(ValueError):
            summarize({}, {"results": [{
                "discovery_diagnostics": {"status": "arbitrary"},
            }]})


if __name__ == "__main__":
    unittest.main()
