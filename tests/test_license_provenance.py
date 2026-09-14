from __future__ import annotations

import base64
import unittest
from types import SimpleNamespace

from researcher.github_api import GitHubResponse
from researcher.license_provenance import (
    ImmutableLicenseEvidenceResolver,
    classify_license_text,
)

from helpers import candidate


class FakeRateLimits:
    def decision(self) -> SimpleNamespace:
        return SimpleNamespace(allowed=True, retry_after_seconds=0)

    def observe_headers(self, _headers: dict[str, str]) -> None:
        return None

    def record_backoff(self, _seconds: int, _reason: str) -> None:
        raise AssertionError("backoff should not be used")


class FakeApi:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected GitHub path: {path}")
        return GitHubResponse(data=self.responses[path], headers={})


def _encoded(content: str, sha: str = "b" * 40) -> dict[str, object]:
    raw = content.encode("utf-8")
    return {
        "type": "file",
        "size": len(raw),
        "sha": sha,
        "encoding": "base64",
        "content": base64.b64encode(raw).decode("ascii"),
    }


BSD3_WITH_BUNDLED_MIT = """Copyright 2022 Example

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice.
2. Redistributions in binary form must reproduce the above copyright notice.
3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS".

--- bundled notice ---
MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
THE SOFTWARE IS PROVIDED "AS IS".
"""


class LicenseProvenanceTests(unittest.TestCase):
    def test_primary_license_wins_over_later_bundled_notice(self) -> None:
        self.assertEqual(classify_license_text(BSD3_WITH_BUNDLED_MIT), "BSD-3-Clause")

    def test_metadata_spdx_remains_authoritative_without_extra_fetch(self) -> None:
        item = candidate("project", "a" * 40, "MIT")
        api = FakeApi({})
        resolver = ImmutableLicenseEvidenceResolver(
            api,  # type: ignore[arg-type]
            FakeRateLimits(),  # type: ignore[arg-type]
        )

        result = resolver.enrich(item)

        self.assertEqual(result.license_spdx, "MIT")
        self.assertEqual(result.extra["license_provenance"], "github_repository_metadata")
        self.assertEqual(api.calls, [])

    def test_missing_metadata_uses_exact_commit_license_file(self) -> None:
        sha = "a" * 40
        item = candidate("project", sha, None)
        endpoint = f"/repos/example/project/contents/LICENSE?ref={sha}"
        api = FakeApi({endpoint: _encoded(BSD3_WITH_BUNDLED_MIT)})
        resolver = ImmutableLicenseEvidenceResolver(
            api,  # type: ignore[arg-type]
            FakeRateLimits(),  # type: ignore[arg-type]
        )

        result = resolver.enrich(item)

        self.assertEqual(result.license_spdx, "BSD-3-Clause")
        self.assertEqual(result.extra["license_provenance"], "immutable_license_file")
        self.assertEqual(result.extra["license_file_path"], "LICENSE")
        self.assertEqual(result.extra["license_file_blob_sha"], "b" * 40)
        self.assertEqual(api.calls, [endpoint])

    def test_unknown_immutable_license_text_is_not_guessed(self) -> None:
        sha = "a" * 40
        item = candidate("project", sha, None)
        endpoint = f"/repos/example/project/contents/LICENSE?ref={sha}"
        api = FakeApi({endpoint: _encoded("Custom terms. Ask counsel before use.")})
        resolver = ImmutableLicenseEvidenceResolver(
            api,  # type: ignore[arg-type]
            FakeRateLimits(),  # type: ignore[arg-type]
        )

        result = resolver.enrich(item)

        self.assertIsNone(result.license_spdx)
        self.assertEqual(
            result.extra["license_provenance"],
            "immutable_license_file_unrecognized",
        )
        self.assertEqual(api.calls, [endpoint])

    def test_non_exact_license_url_is_not_followed(self) -> None:
        item = candidate("project", "a" * 40, None)
        item.license_file_url = "https://github.com/example/project/blob/main/LICENSE"
        api = FakeApi({})
        resolver = ImmutableLicenseEvidenceResolver(
            api,  # type: ignore[arg-type]
            FakeRateLimits(),  # type: ignore[arg-type]
        )

        result = resolver.enrich(item)

        self.assertIsNone(result.license_spdx)
        self.assertEqual(result.extra["license_provenance"], "unresolved")
        self.assertEqual(api.calls, [])


if __name__ == "__main__":
    unittest.main()
