from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "plan_proposal_queue.py"
spec = importlib.util.spec_from_file_location("plan_proposal_queue", SCRIPT)
assert spec is not None and spec.loader is not None
queue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(queue)


def _pr(number: int, *, branch: str | None = None, fork: bool = False):
    return {
        "number": number,
        "headRefName": branch or f"researcher/proposal-handoff-{number}",
        "isCrossRepository": fork,
    }


class ProposalQueuePlannerTests(unittest.TestCase):
    def test_first_export_creates_new_queue(self):
        self.assertEqual(
            queue.select_queue([_pr(32, branch="feature/other")]),
            {"existing": "false", "number": "", "branch": ""},
        )

    def test_one_existing_queue_is_reused_not_skipped(self):
        self.assertEqual(
            queue.select_queue([_pr(174), _pr(25, branch="feature/other")]),
            {"existing": "true", "number": "174",
             "branch": "researcher/proposal-handoff-174"},
        )

    def test_existing_queue_from_run_id_is_selected(self):
        self.assertEqual(
            queue.select_queue([_pr(174, branch="researcher/proposal-handoff-40508809689")]),
            {"existing": "true", "number": "174",
             "branch": "researcher/proposal-handoff-40508809689"},
        )

    def test_more_than_one_queue_requires_consolidation(self):
        with self.assertRaisesRegex(ValueError, "Multiple Researcher queue PRs"):
            queue.select_queue([_pr(174), _pr(175)])

    def test_fork_queue_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "fork"):
            queue.select_queue([_pr(174, fork=True)])

    def test_unexpected_item_and_pr_number_fail_closed(self):
        for items in ({"a": 1}, [42], [_pr(0)], [_pr(-1)]):
            with self.subTest(items=items), self.assertRaises(ValueError):
                queue.select_queue(items)

    def test_malformed_queue_prefixed_branch_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Malformed"):
            queue.select_queue([
                _pr(77, branch="researcher/proposal-handoff-x; rm -rf /")
            ])


if __name__ == "__main__":
    unittest.main()
