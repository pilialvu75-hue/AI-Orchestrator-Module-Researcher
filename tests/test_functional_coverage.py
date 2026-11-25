import unittest

from researcher.functional_coverage import functional_coverage
from researcher.models import Need


class FunctionalCoverageTests(unittest.TestCase):
    def test_contract_target_and_duplicate_filtering(self):
        need = Need("platform.clipboard", "Clipboard", "high", 2, "needed",
                    ("windows", "linux"))
        candidate = {
            "pin": "first@1", "capabilities": ["platform.clipboard"],
            "contracts": ["platform.clipboard.v1"], "validated_targets": ["windows"],
        }
        feedback = {"used_cache": False, "packages": [
            candidate, candidate,
            dict(candidate, pin="wrong@1", contracts=["wrong.v1"]),
            dict(candidate, pin="second@1", validated_targets=["linux"]),
        ]}
        result = functional_coverage(need, "platform.clipboard.v1", feedback)
        self.assertEqual(result["tested_candidates"],
                         {"windows": ["first@1"], "linux": ["second@1"]})
        self.assertEqual(result["candidate_gaps"], {"windows": 1, "linux": 1})
        self.assertFalse(result["independent_pair_verified"])
