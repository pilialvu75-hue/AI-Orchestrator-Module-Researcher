from __future__ import annotations

import unittest

from researcher.dependency_scope import dependency_scope_map
from researcher.security_gate import SourceArtifact
from researcher.supply_chain import (
    DependencyReference,
    SupplyChainReport,
    SupplyChainVerdict,
)
from researcher.vulnerability_admission import GitHubVulnerabilityAdmissionScanner


class DependencyScopeTest(unittest.TestCase):
    def test_pub_runtime_and_dev_dependencies_are_distinct(self) -> None:
        manifest = SourceArtifact(
            path="pkgs/logging/pubspec.yaml",
            content=(
                "name: logging\n"
                "dependencies:\n"
                "  clock: ^1.1.0\n"
                "dev_dependencies:\n"
                "  test: ^1.25.0\n"
            ),
        )

        scopes = dependency_scope_map((manifest,))

        self.assertEqual(
            scopes[("pkgs/logging/pubspec.yaml", "clock")],
            "runtime",
        )
        self.assertEqual(
            scopes[("pkgs/logging/pubspec.yaml", "test")],
            "development",
        )

    def test_cargo_runtime_scope_wins_over_build_and_dev(self) -> None:
        manifest = SourceArtifact(
            path="crates/example/Cargo.toml",
            content=(
                "[dependencies]\n"
                'shared = "1"\n'
                '[build-dependencies]\n'
                'shared = "1"\n'
                'cc = "1"\n'
                '[dev-dependencies]\n'
                'shared = "1"\n'
                'tempfile = "3"\n'
            ),
        )

        scopes = dependency_scope_map((manifest,))

        self.assertEqual(scopes[(manifest.path, "shared")], "runtime")
        self.assertEqual(scopes[(manifest.path, "cc")], "build")
        self.assertEqual(scopes[(manifest.path, "tempfile")], "development")

    def test_runtime_sbom_excludes_build_and_development_dependencies(self) -> None:
        path = "crates/example/Cargo.toml"
        manifest = SourceArtifact(
            path=path,
            content=(
                "[dependencies]\n"
                'serde = "1.0.0"\n'
                '[build-dependencies]\n'
                'cc = "1.0.0"\n'
                '[dev-dependencies]\n'
                'tempfile = "3.0.0"\n'
            ),
        )
        supply_chain = SupplyChainReport(
            verdict=SupplyChainVerdict.CLEAR,
            manifests_analyzed=(path,),
            lockfiles_present=(),
            dependencies=(
                DependencyReference(
                    ecosystem="cargo",
                    name="serde",
                    constraint="1.0.0",
                    source="registry",
                    manifest_path=path,
                    immutable=True,
                ),
                DependencyReference(
                    ecosystem="cargo",
                    name="cc",
                    constraint="1.0.0",
                    source="registry",
                    manifest_path=path,
                    immutable=True,
                ),
                DependencyReference(
                    ecosystem="cargo",
                    name="tempfile",
                    constraint="3.0.0",
                    source="registry",
                    manifest_path=path,
                    immutable=True,
                ),
            ),
            findings=(),
        )

        runtime = GitHubVulnerabilityAdmissionScanner._sbom_supply_chain(
            supply_chain,
            (manifest,),
        )

        self.assertEqual([item.name for item in runtime.dependencies], ["serde"])
        self.assertEqual(runtime.findings, supply_chain.findings)
        self.assertEqual(runtime.verdict, SupplyChainVerdict.CLEAR)


if __name__ == "__main__":
    unittest.main()
