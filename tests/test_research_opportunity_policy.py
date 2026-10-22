import unittest
from types import SimpleNamespace

from researcher.knowledge import classify_research_opportunity


class ResearchOpportunityPolicyTests(unittest.TestCase):
    def test_shortlisted_reusable_source(self):
        self.assertEqual(
            classify_research_opportunity("SHORTLISTED", SimpleNamespace(direct_reuse=True, research_use=True)),
            "DIRECT_REUSE_CANDIDATE",
        )

    def test_reusable_blocked_source_requires_remediation(self):
        for lifecycle in ("SECURITY_REVIEW", "SECURITY_BLOCKED", "REJECTED"):
            with self.subTest(lifecycle=lifecycle):
                self.assertEqual(
                    classify_research_opportunity(lifecycle, SimpleNamespace(direct_reuse=True, research_use=True)),
                    "REMEDIATION_CANDIDATE",
                )

    def test_research_only_source_is_not_reusable(self):
        self.assertEqual(
            classify_research_opportunity("REJECTED", SimpleNamespace(direct_reuse=False, research_use=True)),
            "INDEPENDENT_IMPLEMENTATION_RESEARCH",
        )

    def test_unlicensed_source_stays_evidence_only(self):
        self.assertEqual(
            classify_research_opportunity("SHORTLISTED", SimpleNamespace(direct_reuse=False, research_use=False)),
            "EVIDENCE_ONLY",
        )


if __name__ == "__main__":
    unittest.main()
