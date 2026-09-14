from __future__ import annotations

import unittest
from typing import Any

from researcher.github_api import GitHubResponse
from researcher.scoped_api import ScopedLibraryWriteApi


class FakeApi:
    def __init__(self, label: str) -> None:
        self.label = label
        self.calls: list[tuple[str, str]] = []

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(("GET", path))
        return GitHubResponse(data={"api": self.label}, headers={})

    def post(self, path: str, _payload: dict[str, Any]) -> GitHubResponse:
        self.calls.append(("POST", path))
        return GitHubResponse(data={"api": self.label}, headers={})

    def put(self, path: str, _payload: dict[str, Any]) -> GitHubResponse:
        self.calls.append(("PUT", path))
        return GitHubResponse(data={"api": self.label}, headers={})

    def patch(self, path: str, _payload: dict[str, Any]) -> GitHubResponse:
        self.calls.append(("PATCH", path))
        return GitHubResponse(data={"api": self.label}, headers={})

    def delete(self, path: str) -> GitHubResponse:
        self.calls.append(("DELETE", path))
        return GitHubResponse(data={"api": self.label}, headers={})


class ScopedLibraryWriteApiTest(unittest.TestCase):
    def test_upstream_read_uses_source_api(self) -> None:
        source = FakeApi("source")
        library = FakeApi("library")
        api = ScopedLibraryWriteApi(
            source,  # type: ignore[arg-type]
            library,  # type: ignore[arg-type]
            "owner/library",
        )

        result = api.get("/repos/upstream/project/contents/LICENSE?ref=abc")

        self.assertEqual(result.data, {"api": "source"})
        self.assertEqual(source.calls, [("GET", "/repos/upstream/project/contents/LICENSE?ref=abc")])
        self.assertEqual(library.calls, [])

    def test_library_read_and_write_use_library_api(self) -> None:
        source = FakeApi("source")
        library = FakeApi("library")
        api = ScopedLibraryWriteApi(
            source,  # type: ignore[arg-type]
            library,  # type: ignore[arg-type]
            "owner/library",
        )
        path = "/repos/owner/library/git/refs"

        read = api.get("/repos/owner/library/pulls?state=all")
        write = api.post(path, {"ref": "refs/heads/test"})

        self.assertEqual(read.data, {"api": "library"})
        self.assertEqual(write.data, {"api": "library"})
        self.assertEqual(source.calls, [])
        self.assertEqual(library.calls[0][0], "GET")
        self.assertEqual(library.calls[1], ("POST", path))

    def test_writer_rejects_non_library_mutation(self) -> None:
        api = ScopedLibraryWriteApi(
            FakeApi("source"),  # type: ignore[arg-type]
            FakeApi("library"),  # type: ignore[arg-type]
            "owner/library",
        )

        with self.assertRaisesRegex(ValueError, "outside Library"):
            api.put("/repos/upstream/project/contents/file", {"content": "x"})


if __name__ == "__main__":
    unittest.main()
