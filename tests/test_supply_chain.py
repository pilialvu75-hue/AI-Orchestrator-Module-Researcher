from __future__ import annotations

import unittest

from researcher.security_gate import SourceArtifact
from researcher.supply_chain import SupplyChainVerdict, analyze_supply_chain


class SupplyChainTests(unittest.TestCase):
    def test_registry_only_npm_manifest_is_clear(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="package.json",
                    content='{"dependencies":{"left-pad":"^1.3.0"}}',
                ),
                SourceArtifact(
                    path="package-lock.json",
                    content='{"lockfileVersion":3}',
                ),
            ]
        )
        self.assertEqual(report.verdict, SupplyChainVerdict.CLEAR)
        self.assertTrue(report.admission_eligible)
        self.assertEqual(report.lockfiles_present, ("package-lock.json",))
        self.assertEqual(report.dependencies[0].source, "registry")
        self.assertFalse(report.executed_untrusted_code)

    def test_npm_install_hook_requires_review(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="package.json",
                    content='{"scripts":{"postinstall":"node install.js"}}',
                )
            ]
        )
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn("npm_lifecycle_hook", {item.rule_id for item in report.findings})

    def test_unpinned_npm_git_dependency_requires_review(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="package.json",
                    content='{"dependencies":{"x":"git+https://example.invalid/x.git#main"}}',
                )
            ]
        )
        rules = {item.rule_id for item in report.findings}
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn("git_dependency_requires_review", rules)
        self.assertIn("git_dependency_unpinned", rules)
        self.assertFalse(report.dependencies[0].immutable)

    def test_pinned_npm_git_dependency_still_requires_dependency_review(self) -> None:
        sha = "a" * 40
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="package.json",
                    content=(
                        '{"dependencies":{"x":"git+https://example.invalid/x.git#'
                        + sha
                        + '"}}'
                    ),
                )
            ]
        )
        rules = {item.rule_id for item in report.findings}
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn("git_dependency_requires_review", rules)
        self.assertNotIn("git_dependency_unpinned", rules)
        self.assertTrue(report.dependencies[0].immutable)

    def test_pub_path_dependency_requires_review(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="pubspec.yaml",
                    content="dependencies:\n  local_auth:\n    path: ../local_auth\n",
                )
            ]
        )
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn(
            "path_dependency_requires_review",
            {item.rule_id for item in report.findings},
        )

    def test_pub_git_ref_must_be_exact_commit(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="pubspec.yaml",
                    content=(
                        "dependencies:\n"
                        "  custom:\n"
                        "    git: https://example.invalid/custom.git\n"
                        "    ref: main\n"
                    ),
                )
            ]
        )
        rules = {item.rule_id for item in report.findings}
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn("git_dependency_requires_review", rules)
        self.assertIn("git_dependency_unpinned", rules)

    def test_cargo_path_dependency_requires_review(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="Cargo.toml",
                    content='[dependencies]\nlocal = { path = "../local" }\n',
                )
            ]
        )
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn(
            "path_dependency_requires_review",
            {item.rule_id for item in report.findings},
        )

    def test_python_direct_url_requires_review(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="pyproject.toml",
                    content=(
                        "[project]\n"
                        'dependencies = ["demo @ git+https://example.invalid/demo.git@main"]\n'
                    ),
                )
            ]
        )
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn(
            "direct_url_dependency_requires_review",
            {item.rule_id for item in report.findings},
        )

    def test_go_replace_requires_review(self) -> None:
        report = analyze_supply_chain(
            [
                SourceArtifact(
                    path="go.mod",
                    content=(
                        "module example.test/app\n"
                        "go 1.23\n"
                        "require example.test/lib v1.2.3\n"
                        "replace example.test/lib => ../lib\n"
                    ),
                )
            ]
        )
        self.assertEqual(report.verdict, SupplyChainVerdict.REVIEW)
        self.assertIn(
            "go_replace_requires_review",
            {item.rule_id for item in report.findings},
        )

    def test_missing_supported_manifest_is_not_auto_admitted(self) -> None:
        report = analyze_supply_chain(
            [SourceArtifact(path="lib/main.dart", content="void main() {}")]
        )
        self.assertEqual(report.verdict, SupplyChainVerdict.NOT_ANALYZED)
        self.assertFalse(report.admission_eligible)
        self.assertIn(
            "no_supported_dependency_manifest",
            {item.rule_id for item in report.findings},
        )


if __name__ == "__main__":
    unittest.main()
