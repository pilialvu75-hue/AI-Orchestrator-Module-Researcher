from __future__ import annotations

import unittest

from researcher.component_security import _ComponentTreeApi
from researcher.github_api import GitHubResponse


class FakeApi:
    def __init__(self, response: GitHubResponse) -> None:
        self.response = response

    def get(self, _path: str) -> GitHubResponse:
        return self.response


class ComponentEmptyBlobTest(unittest.TestCase):
    def test_explicit_zero_byte_blob_is_not_sent_to_source_decoder(self) -> None:
        tree_sha = "b" * 40
        endpoint = f"/repos/example/mono/git/trees/{tree_sha}?recursive=1"
        delegate = FakeApi(
            GitHubResponse(
                data={
                    "sha": tree_sha,
                    "truncated": False,
                    "tree": [
                        {"path": "pkg", "type": "tree", "mode": "040000"},
                        {
                            "path": "pkg/empty.properties",
                            "type": "blob",
                            "mode": "100644",
                            "sha": "e" * 40,
                            "size": 0,
                        },
                        {
                            "path": "pkg/lib/main.dart",
                            "type": "blob",
                            "mode": "100644",
                            "sha": "c" * 40,
                            "size": 20,
                        },
                    ],
                },
                headers={},
            )
        )
        api = _ComponentTreeApi(  # type: ignore[arg-type]
            delegate,
            "example/mono",
            tree_sha,
            "pkg",
        )

        response = api.get(endpoint)
        entries = response.data["tree"]
        paths = {item["path"] for item in entries}

        self.assertNotIn("pkg/empty.properties", paths)
        self.assertIn("pkg/lib/main.dart", paths)


if __name__ == "__main__":
    unittest.main()
