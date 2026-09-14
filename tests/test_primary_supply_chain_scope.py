from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from researcher.github_api import GitHubResponse
from researcher.primary_supply_chain_scope import PrimarySupplyChainScopeRefiner
from researcher.rate_limit import RateLimitManager
from researcher.security_admission import FullTreeSecurityReport
from researcher.security_gate import SecurityFinding, SecuritySeverity, SecurityVerdict
from researcher.state import SQLiteStateStore
from researcher.supply_chain import (
    SupplyChainFinding,
    SupplyChainReport,
    SupplyChainSeverity,
    SupplyChainVerdict,
)

from helpers import candidate


class FakeApi:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, path: str) -> GitHubResponse:
        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected path: {path}")
        return GitHubResponse(
            data=self.responses[path],
            headers={
                "X-RateLimit-Remaining": "4999",
                "X-RateLimit-Reset": "9999999999",
            },
        )


def _file(content: str) -> dict[str, object]:
    raw = content.encode("utf-8")
    return {
        "type": "file",
        "size": len(raw),
        "encoding": "base64",
        "content": base64.b64encode(raw).decode("ascii"),
    }


def _recursive_review(
    *,
    root: str = "",
    source_findings: tuple[SecurityFinding, ...] = (),
) -> FullTreeSecurityReport:
    prefix = f"{root}/" if root else ""
    primary = f"{prefix}pubspec.yaml"
    auxiliary = f"{prefix}example/pubspec.yaml"
    auxiliary_lock = f"{prefix}example/pubspec.lock"
    supply = SupplyChainReport(
        verdict=SupplyChainVerdict.REVIEW,
        manifests_analyzed=(primary, auxiliary),
        lockfiles_present=(auxiliary_lock,),
        dependencies=(),
        findings=(
            SupplyChainFinding(
                rule_id="path_dependency_requires_review",
                severity=SupplyChainSeverity.REVIEW,
                path=auxiliary,
                evidence="demo: path ../",
            ),
        ),
    )
    return FullTreeSecurityReport(
        repository="example/secure-candidate",
        commit_sha="a" * 40,
        tree_sha="b" * 40,
        verdict=SecurityVerdict.REVIEW,
        complete=True,
        findings=source_findings,
        total_entries=4,
        blobs_seen=3,
        relevant_blobs=3,
        scanned_files=3,
        scanned_bytes=128,
        skipped_assets=0,
        opaque_artifacts=(),
        submodules=(),
        symlinks=(),
        supply_chain=supply,
    )


def _primary_dev_dependency_review(path: str = "pubspec.yaml") -> FullTreeSecurityReport:
    supply = SupplyChainReport(
        verdict=SupplyChainVerdict.REVIEW,
        manifests_analyzed=(path,),
        lockfiles_present=(),
        dependencies=(),
        findings=(
            SupplyChainFinding(
                rule_id="path_dependency_requires_review",
                severity=SupplyChainSeverity.REVIEW,
                path=path,
                evidence="dev_helper: path ../dev_helper",
            ),
        ),
    )
    return FullTreeSecurityReport(
        repository="example/secure-candidate",
        commit_sha="a" * 40,
        tree_sha="b" * 40,
        verdict=SecurityVerdict.REVIEW,
        complete=True,
        findings=(),
        total_entries=2,
        blobs_seen=1,
        relevant_blobs=1,
        scanned_files=1,
        scanned_bytes=128,
        skipped_assets=0,
        opaque_artifacts=(),
        submodules=(),
        symlinks=(),
        supply_chain=supply,
    )


class PrimarySupplyChainScopeTests(unittest.TestCase):
    def _refine(self, item, report, path: str, content: str | None = None):
        endpoint = (
            f"/repos/example/secure-candidate/contents/{path}"
            f"?ref={'a' * 40}"
        )
        api = FakeApi(
            {
                endpoint: _file(
                    content
                    or (
                        "name: secure_candidate\n"
                        "dependencies:\n"
                        "  http: ^1.2.0\n"
                    )
                )
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            refiner = PrimarySupplyChainScopeRefiner(
                api,  # type: ignore[arg-type]
                RateLimitManager(state),
            )
            result = refiner.refine(item, report)
        return result, api.calls

    def test_root_manifest_excludes_nested_example_dependency_scope(self) -> None:
        item = candidate("secure-candidate", "a" * 40)
        result, calls = self._refine(item, _recursive_review(), "pubspec.yaml")

        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
        assert result.supply_chain is not None
        self.assertEqual(result.supply_chain.verdict, SupplyChainVerdict.CLEAR)
        self.assertEqual(result.supply_chain.manifests_analyzed, ("pubspec.yaml",))
        self.assertEqual(result.supply_chain.lockfiles_present, ())
        self.assertEqual(
            {item.name for item in result.supply_chain.dependencies},
            {"http"},
        )
        notices = {
            finding.path
            for finding in result.supply_chain.findings
            if finding.rule_id == "auxiliary_dependency_file_out_of_primary_scope"
        }
        self.assertEqual(
            notices,
            {"example/pubspec.yaml", "example/pubspec.lock"},
        )
        self.assertEqual(len(calls), 1)

    def test_component_root_uses_exact_component_manifest(self) -> None:
        item = candidate("secure-candidate", "a" * 40)
        item.extra["component_path"] = "pkgs/logging"
        result, _ = self._refine(
            item,
            _recursive_review(root="pkgs/logging"),
            "pkgs/logging/pubspec.yaml",
        )

        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
        assert result.supply_chain is not None
        self.assertEqual(
            result.supply_chain.manifests_analyzed,
            ("pkgs/logging/pubspec.yaml",),
        )

    def test_dev_path_dependency_does_not_contaminate_runtime_gate(self) -> None:
        item = candidate("secure-candidate", "a" * 40)
        content = (
            "name: secure_candidate\n"
            "dependencies:\n"
            "  http: ^1.2.0\n"
            "dev_dependencies:\n"
            "  dev_helper:\n"
            "    path: ../dev_helper\n"
        )
        result, _ = self._refine(
            item,
            _primary_dev_dependency_review(),
            "pubspec.yaml",
            content,
        )

        self.assertEqual(result.verdict, SecurityVerdict.CLEAR)
        assert result.supply_chain is not None
        self.assertEqual(result.supply_chain.verdict, SupplyChainVerdict.CLEAR)
        self.assertEqual(
            {dependency.name for dependency in result.supply_chain.dependencies},
            {"http"},
        )
        self.assertFalse(
            any(
                finding.rule_id == "path_dependency_requires_review"
                for finding in result.supply_chain.findings
            )
        )

    def test_missing_primary_manifest_preserves_recursive_review(self) -> None:
        item = candidate("secure-candidate", "a" * 40)
        report = _recursive_review(root="nested")
        api = FakeApi({})
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteStateStore(Path(tmp) / "state.db")
            refiner = PrimarySupplyChainScopeRefiner(
                api,  # type: ignore[arg-type]
                RateLimitManager(state),
            )
            result = refiner.refine(item, report)

        self.assertEqual(result, report)
        self.assertEqual(api.calls, [])
        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)

    def test_static_high_finding_cannot_be_cleared_by_dependency_scope(self) -> None:
        item = candidate("secure-candidate", "a" * 40)
        finding = SecurityFinding(
            rule_id="process_execution",
            severity=SecuritySeverity.HIGH,
            path="lib/runner.dart",
            evidence="Process.start(",
        )
        report = _recursive_review(source_findings=(finding,))
        result, _ = self._refine(item, report, "pubspec.yaml")

        self.assertEqual(result.verdict, SecurityVerdict.REVIEW)
        self.assertIn(finding, result.findings)
        self.assertFalse(result.admission_eligible)


if __name__ == "__main__":
    unittest.main()
