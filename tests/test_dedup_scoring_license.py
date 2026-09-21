from __future__ import annotations

import unittest

from researcher.analysis import classify_license
from researcher.dedup import candidate_fingerprint
from researcher.scoring import CandidateScorer

from helpers import candidate, contract, need


class DecisionTests(unittest.TestCase):
    def test_dedup_fingerprint_stable_and_commit_sensitive(self) -> None:
        a = candidate("alpha", "a" * 40)
        b = candidate("alpha", "b" * 40)
        self.assertEqual(
            candidate_fingerprint("voice.stt", a),
            candidate_fingerprint("voice.stt", a),
        )
        self.assertNotEqual(
            candidate_fingerprint("voice.stt", a),
            candidate_fingerprint("voice.stt", b),
        )

    def test_license_classification(self) -> None:
        self.assertEqual(classify_license("MIT")["classification"], "permissive")
        self.assertEqual(classify_license("AGPL-3.0")["classification"], "review_required")
        self.assertEqual(classify_license(None)["classification"], "unknown")
        self.assertFalse(classify_license(None)["direct_reuse"])
        self.assertTrue(classify_license(None)["research_use"])
        self.assertTrue(classify_license("MIT")["direct_reuse"])
        self.assertTrue(classify_license("MIT")["research_use"])

    def test_scoring_is_explainable(self) -> None:
        score = CandidateScorer().score(
            need(), candidate("alpha", "a" * 40), contract()
        )
        self.assertGreater(score.functional_fit, 0)
        self.assertGreater(len(score.reasons), 2)
        self.assertGreater(score.recommendation, 0)
        self.assertLessEqual(score.recommendation, 1)


if __name__ == "__main__":
    unittest.main()
