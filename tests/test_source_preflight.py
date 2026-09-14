from __future__ import annotations

import unittest

from researcher.cli import _parser
from researcher.security_gate import SecurityVerdict
from researcher.source_preflight import _preflight_state
from researcher.vulnerability import (
    ResearcherSbom,
    VulnerabilityReport,
    VulnerabilityVerdict,
)
from researcher.vulnerability_admission import VulnerabilityAdmissionResult


def _vulnerability_result(*, clear: bool) -> VulnerabilityAdmissionResult:
    sbom = ResearcherSbom(
        schema_version=1,
        components=(),
        unresolved=() if clear else ("unresolved",),
        source_files=("pubspec.yaml",),
    )
    report = VulnerabilityReport(
        verdict=(
            VulnerabilityVerdict.CLEAR
            if clear
            else VulnerabilityVerdict.NOT_ANALYZED
        ),
        database="OSV",
        database_checked=clear,
        sbom_fingerprint=sbom.fingerprint,
        queried_components=0,
        hits=(),
        unresolved=sbom.unresolved,
        error=None if clear else "not analyzed",
    )
    return VulnerabilityAdmissionResult(sbom=sbom, report=report)


class SourcePreflightTest(unittest.TestCase):
    def test_clear_requires_both_security_and_vulnerability_gates(self) -> None:
        clear = _vulnerability_result(clear=True)
        review = _vulnerability_result(clear=False)

        self.assertEqual(
            _preflight_state(SecurityVerdict.CLEAR, True, clear),
            "CLEAR",
        )
        self.assertEqual(
            _preflight_state(SecurityVerdict.CLEAR, True, review),
            "REVIEW",
        )
        self.assertEqual(
            _preflight_state(SecurityVerdict.REVIEW, False, clear),
            "REVIEW",
        )

    def test_blocked_static_security_is_never_downgraded(self) -> None:
        self.assertEqual(
            _preflight_state(
                SecurityVerdict.BLOCK,
                False,
                _vulnerability_result(clear=True),
            ),
            "BLOCKED",
        )

    def test_cli_exposes_library_independent_component_preflight(self) -> None:
        args = _parser().parse_args(
            [
                "preflight-pinned",
                "--repository",
                "dart-lang/core",
                "--commit",
                "a" * 40,
                "--component-path",
                "pkgs/logging",
                "--release-tag",
                "logging-v1.3.0",
                "--source-version",
                "1.3.0",
            ]
        )

        self.assertEqual(args.command, "preflight-pinned")
        self.assertEqual(args.repository, "dart-lang/core")
        self.assertEqual(args.component_path, "pkgs/logging")
        self.assertEqual(args.release_tag, "logging-v1.3.0")


if __name__ == "__main__":
    unittest.main()
