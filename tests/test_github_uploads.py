from __future__ import annotations

import unittest

from researcher.github_api import GitHubApi


class GitHubUploadsTests(unittest.TestCase):
    def test_production_upload_host_is_fixed(self) -> None:
        api = GitHubApi(None)
        self.assertIsNotNone(api)
        for invalid in (
            "https://example.com",
            "https://uploads.github.com.evil.invalid",
            "http://uploads.github.com",
            "https://user:pass@uploads.github.com",
            "https://uploads.github.com?redirect=evil",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    GitHubApi(None, uploads_base_url=invalid)

    def test_loopback_upload_host_is_allowed_for_tests_only(self) -> None:
        api = GitHubApi(
            None,
            base_url="http://127.0.0.1:8080",
            uploads_base_url="http://127.0.0.1:8081",
        )
        self.assertIsNotNone(api)

    def test_asset_name_cannot_escape_release_namespace(self) -> None:
        api = GitHubApi(None)
        for invalid in ("../latest.txt", "nested/file.jsonl", "nested\\file.jsonl", ""):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    api.upload_release_asset("owner/repo", 1, invalid, b"x")


if __name__ == "__main__":
    unittest.main()
