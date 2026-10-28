"""Policy regression: open licenses are not guilt-by-association rejected.

A successful license classifier result still must pass pinned provenance, full
security, dependency/vulnerability and independent Library certification gates.
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from researcher.analysis import classify_license
from researcher.dedup import candidate_fingerprint
from researcher.engine import ResearchEngine
from researcher.github_api import GitHubApiError
from researcher.pinned_admission import PinnedCandidateResolver
from researcher.state import SQLiteStateStore
from tests.helpers import candidate, need
from tests.test_pinned_admission import FakeApi, FakeRateLimits, _responses


class SpdxPolicyTests(unittest.TestCase):
    def test_common_permissive_identifiers_allow_screening(self):
        for license_id in ("MIT", "Apache-2.0", "BSD-3-Clause", "0BSD",
                           "MIT-0", "Unlicense", "CC0-1.0", "BSL-1.0"):
            with self.subTest(license=license_id):
                policy = classify_license(license_id)
                self.assertEqual(policy["classification"], "permissive")
                self.assertTrue(policy["direct_reuse"])

    def test_or_choice_selects_permissive_path_despite_other_option(self):
        for expression in ("MIT OR GPL-3.0-only",
                           "(AGPL-3.0-only OR Apache-2.0) AND MIT",
                           "LGPL-2.1-only OR BSD-3-Clause"):
            with self.subTest(expression=expression):
                decision = classify_license(expression)
                self.assertTrue(decision["direct_reuse"])
                self.assertEqual(decision["classification"], "permissive")
                self.assertTrue(decision["selected_license_option"])

    def test_and_requires_all_licenses_and_never_ignores_copyleft(self):
        policy = classify_license("MIT AND GPL-3.0-only")
        self.assertFalse(policy["direct_reuse"])
        self.assertEqual(policy["classification"], "review_required")
        self.assertIsNone(policy["selected_license_option"])

    def test_and_of_permissive_terms_can_continue_to_security_review(self):
        policy = classify_license("MIT AND Apache-2.0")
        self.assertTrue(policy["direct_reuse"])
        self.assertEqual(policy["classification"], "permissive")
        self.assertIn("MIT", policy["selected_license_option"])

    def test_weak_copyleft_remains_conditional(self):
        for expression in ("MPL-2.0", "LGPL-3.0-only", "MIT AND MPL-2.0"):
            with self.subTest(expression=expression):
                self.assertEqual(
                    classify_license(expression)["classification"], "conditional"
                )

    def test_unknown_source_available_and_strong_copyleft_not_auto_approved(self):
        for license_id in (None, "NOASSERTION", "NONE", "LicenseRef-custom",
                           "BUSL-1.1", "SSPL-1.0", "AGPL-3.0-or-later",
                           "GPL-3.0-only", "MIT WITH Unknown-exception",
                           "MIT AND NOASSERTION", "MIT OR NOASSERTION",
                           "MIT OR (", "MIT; DROP TABLE modules"):
            with self.subTest(license=license_id):
                self.assertFalse(classify_license(license_id)["direct_reuse"])

    def test_expression_pre_screen_never_skips_other_gates(self):
        c = replace(candidate("permissive-or", "c" * 40),
                    license_spdx="GPL-3.0-only OR MIT")
        dossier = SimpleNamespace(scores=SimpleNamespace(
            recommendation=0.8, license_fit=classify_license(c.license_spdx)["fit"]
        ))
        self.assertTrue(ResearchEngine._pre_screen_qualified(dossier, c, 0.58))
        self.assertFalse(
            ResearchEngine._pre_screen_qualified(
                dossier, replace(c, archived=True), 0.58
            )
        )
        self.assertFalse(
            ResearchEngine._pre_screen_qualified(
                dossier, replace(c, extra={**c.extra, "source_stable": False}), 0.58
            )
        )


class ImmutableLicenseEvidenceTests(unittest.TestCase):
    sha = "a" * 40
    tree = "b" * 40

    def _resolver(self, source_license, *, tree_match=True, detected_sha=True):
        responses = _responses(self.sha, self.tree)
        responses["/repos/example/project"] = {
            **responses["/repos/example/project"],
            "license": {"spdx_id": "NOASSERTION"},
        }
        tree_key = f"/repos/example/project/git/trees/{self.tree}?recursive=1"
        responses[tree_key] = {
            **responses[tree_key],
            "tree": [
                {
                    **item,
                    "type": "blob",
                    "sha": ("c" * 40) if item["path"] == "LICENSE" else "d" * 40,
                }
                for item in responses[tree_key]["tree"]
            ],
        }
        if source_license is not None:
            responses[f"/repos/example/project/license?ref={self.sha}"] = {
                "path": "LICENSE" if tree_match else "UNVERIFIED-LICENSE",
                "sha": "c" * 40 if detected_sha else "f" * 40,
                "license": {"spdx_id": source_license},
            }
        api = FakeApi(responses)
        return PinnedCandidateResolver(api, FakeRateLimits()), api

    def test_pinned_license_recovery_restores_mit_with_file_digest(self):
        resolver, api = self._resolver("MIT")
        result = resolver.resolve("example/project", self.sha)
        self.assertEqual(result.license_spdx, "MIT")
        self.assertEqual(result.extra["license_detection_source"],
                         "pinned_github_license_endpoint")
        self.assertIn(f"/repos/example/project/license?ref={self.sha}", api.paths)

    def test_wrong_file_path_or_digest_never_grants_permission(self):
        for kwargs in ({"tree_match": False}, {"detected_sha": False}):
            with self.subTest(kwargs=kwargs):
                resolver, _ = self._resolver("MIT", **kwargs)
                item = resolver.resolve("example/project", self.sha)
                self.assertIsNone(item.license_spdx)

    def test_noassertion_remains_unverified_even_at_pinned_commit(self):
        resolver, _ = self._resolver("NOASSERTION")
        result = resolver.resolve("example/project", self.sha)
        self.assertIsNone(result.license_spdx)

    def test_missing_license_endpoint_does_not_grant_permission(self):
        class MissingLicenseApi(FakeApi):
            def get(self, path):
                if "/license?ref=" in path:
                    raise GitHubApiError(404, "not found")
                return super().get(path)
        resolver, _ = self._resolver(None)
        api = MissingLicenseApi(_responses(self.sha, self.tree))
        responses = _responses(self.sha, self.tree)
        responses["/repos/example/project"]["license"] = {"spdx_id": "NOASSERTION"}
        api = MissingLicenseApi(responses)
        candidate_result = PinnedCandidateResolver(api, FakeRateLimits()).resolve(
            "example/project", self.sha
        )
        self.assertIsNone(candidate_result.license_spdx)

    def test_non_404_api_failure_is_not_silently_accepted(self):
        class BrokenApi(FakeApi):
            def get(self, path):
                if "/license?ref=" in path:
                    raise GitHubApiError(500, "server error")
                return super().get(path)
        responses = _responses(self.sha, self.tree)
        responses["/repos/example/project"]["license"] = {"spdx_id": "NOASSERTION"}
        with self.assertRaises(GitHubApiError):
            PinnedCandidateResolver(
                BrokenApi(responses), FakeRateLimits()
            ).resolve("example/project", self.sha)


class BoundedRescanTests(unittest.TestCase):
    def test_rechecks_uncertain_license_without_retrying_strong_copyleft(self):
        n, c = need(), candidate("recheck", "e" * 40)
        fp = candidate_fingerprint(n.capability_id, c)
        with tempfile.TemporaryDirectory() as root:
            state = SQLiteStateStore(Path(root) / "researcher.db")
            for reason in ("pre_screen:license_unknown",
                           "pre_screen:license_noassertion",
                           "pre_screen:license_other",
                           "pre_screen:license_review_required"):
                state.upsert_candidate(fp, n.capability_id, c.repository,
                                       c.commit_sha, "REJECTED", .1, "test.json", reason)
                self.assertFalse(state.rejected_candidate_retry_due(fp))
                with state._connect() as conn:
                    conn.execute(
                        "UPDATE candidates SET updated_at=datetime('now', '-7 hours') "
                        "WHERE fingerprint=?", (fp,)
                    )
                self.assertTrue(state.rejected_candidate_retry_due(fp))
            state.upsert_candidate(fp, n.capability_id, c.repository,
                                   c.commit_sha, "REJECTED", .1, "test.json",
                                   "pre_screen:license_agpl")
            with state._connect() as conn:
                conn.execute(
                    "UPDATE candidates SET updated_at=datetime('now', '-7 hours') "
                    "WHERE fingerprint=?", (fp,)
                )
            self.assertFalse(state.rejected_candidate_retry_due(fp))


if __name__ == "__main__":
    unittest.main()
