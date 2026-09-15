from __future__ import annotations

import unittest

from researcher.security_gate import SecurityVerdict, SourceArtifact, scan_source_artifacts


class InstallHookPrecisionTests(unittest.TestCase):
    def test_c_prepare_assignment_is_not_npm_install_hook(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="src/vendor.h",
                    content=(
                        "typedef int (*prepare_fn)(void);\n"
                        "prepare_fn prepare;\n"
                        "prepare = callback;\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
        self.assertNotIn("install_hook", {item.rule_id for item in result.findings})

    def test_quoted_package_prepare_hook_still_requires_review(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="package.json",
                    content='{"scripts":{"prepare":"node build.js"}}',
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertIn("install_hook", {item.rule_id for item in result.findings})


if __name__ == "__main__":
    unittest.main()
