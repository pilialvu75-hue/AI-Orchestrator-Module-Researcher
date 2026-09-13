from __future__ import annotations

from typing import Any

from researcher.models import Candidate, Contract, Need, utc_now
from researcher.security_admission import FullTreeSecurityReport
from researcher.security_gate import SecurityFinding, SecuritySeverity, SecurityVerdict
from researcher.supply_chain import SupplyChainReport, SupplyChainVerdict
from researcher.vulnerability import (
    ResearcherSbom,
    VulnerabilityHit,
    VulnerabilityReport,
    VulnerabilityVerdict,
)
from researcher.vulnerability_admission import VulnerabilityAdmissionResult


def need(capability_id: str = "voice.stt") -> Need:
    return Need(
        capability_id=capability_id,
        title="Speech-to-text integration bundle",
        priority="high",
        desired_candidates=2,
        status="needed",
        targets=("android", "desktop"),
    )


def contract(capability_id: str = "voice.stt") -> Contract:
    return Contract(
        capability_id=capability_id,
        contract_id=f"{capability_id}.v1",
        contract_version="1.0",
        status="draft",
    )


def candidate(name: str, sha: str, license_spdx: str | None = "MIT") -> Candidate:
    return Candidate(
        provider="github",
        repository=f"example/{name}",
        upstream_url=f"https://github.com/example/{name}",
        owner="example",
        name=name,
        commit_sha=sha,
        release_tag="v1.2.3",
        default_branch="main",
        acquired_at=utc_now(),
        license_spdx=license_spdx,
        license_file_url=(
            f"https://github.com/example/{name}/blob/{sha}/LICENSE"
        ),
        stars=10,
        forks=2,
        open_issues=1,
        pushed_at=utc_now(),
        archived=False,
        language="Dart",
        topics=("speech", "stt", "voice"),
        description="speech to text voice stt integration",
        size_kb=5000,
        extra={
            "tests_present": True,
            "ci_present": True,
            "readme_present": True,
            "dependency_manifests": ["pubspec.yaml"],
        },
    )


class FakeLibrary:
    def __init__(self, needs: list[Need], contracts: dict[str, Contract] | None = None) -> None:
        self.needs = needs
        self.contracts = (
            {item.capability_id: contract(item.capability_id) for item in needs}
            if contracts is None
            else contracts
        )

    def load_needs(self) -> tuple[list[Need], dict[str, Any]]:
        return self.needs, {"updated_at": utc_now(), "used_cache": False}

    def load_contracts(self) -> tuple[dict[str, Contract], str]:
        return self.contracts, "1.0.0"


class FakeDiscovery:
    name = "fake"

    def __init__(self, candidates: list[Candidate]) -> None:
        self.candidates = candidates
        self.calls = 0

    def discover(self, need: Need, limit: int = 8) -> list[Candidate]:
        self.calls += 1
        return self.candidates[:limit]


class FakeSecurityScanner:
    def __init__(
        self,
        verdict: SecurityVerdict = SecurityVerdict.CLEAR,
        complete: bool = True,
        supply_chain_verdict: SupplyChainVerdict = SupplyChainVerdict.CLEAR,
    ) -> None:
        self.verdict = verdict
        self.complete = complete
        self.supply_chain_verdict = supply_chain_verdict
        self.calls = 0

    def scan(self, item: Candidate) -> FullTreeSecurityReport:
        self.calls += 1
        findings: tuple[SecurityFinding, ...] = ()
        if self.verdict != SecurityVerdict.CLEAR:
            findings = (
                SecurityFinding(
                    rule_id="fake_security_finding",
                    severity=(
                        SecuritySeverity.CRITICAL
                        if self.verdict == SecurityVerdict.BLOCK
                        else SecuritySeverity.REVIEW
                    ),
                    path="lib/example.dart",
                    evidence="test-only security finding",
                ),
            )
        supply_chain = SupplyChainReport(
            verdict=self.supply_chain_verdict,
            manifests_analyzed=("pubspec.yaml",),
            lockfiles_present=(),
            dependencies=(),
            findings=(),
        )
        return FullTreeSecurityReport(
            repository=item.repository,
            commit_sha=item.commit_sha,
            tree_sha="f" * 40,
            verdict=self.verdict,
            complete=self.complete,
            findings=findings,
            total_entries=1,
            blobs_seen=1,
            relevant_blobs=1,
            scanned_files=1,
            scanned_bytes=32,
            skipped_assets=0,
            opaque_artifacts=(),
            submodules=(),
            symlinks=(),
            supply_chain=supply_chain,
        )


class FakeVulnerabilityScanner:
    def __init__(
        self,
        verdict: VulnerabilityVerdict = VulnerabilityVerdict.CLEAR,
        database_checked: bool = True,
    ) -> None:
        self.verdict = verdict
        self.database_checked = database_checked
        self.calls = 0

    def scan(
        self,
        item: Candidate,
        security_report: FullTreeSecurityReport,
    ) -> VulnerabilityAdmissionResult:
        self.calls += 1
        sbom = ResearcherSbom(
            schema_version=1,
            components=(),
            unresolved=(),
            source_files=("pubspec.yaml",),
        )
        hits: tuple[VulnerabilityHit, ...] = ()
        if self.verdict == VulnerabilityVerdict.REVIEW:
            hits = (
                VulnerabilityHit(
                    vulnerability_id="OSV-TEST-1",
                    ecosystem="Pub",
                    package="example",
                    version="1.0.0",
                ),
            )
        report = VulnerabilityReport(
            verdict=self.verdict,
            database="OSV",
            database_checked=self.database_checked,
            sbom_fingerprint=sbom.fingerprint,
            queried_components=0,
            hits=hits,
            unresolved=(),
            error=(
                None
                if self.database_checked
                else "test-only vulnerability database unavailable"
            ),
        )
        return VulnerabilityAdmissionResult(sbom=sbom, report=report)
