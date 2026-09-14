from __future__ import annotations

import base64
import binascii
import urllib.parse
from dataclasses import replace

from .github_api import GitHubApi, GitHubApiError, GitHubResponse
from .models import Candidate
from .rate_limit import RateLimitManager
from .security_admission import FullTreeSecurityReport
from .security_gate import SecuritySeverity, SecurityVerdict, SourceArtifact
from .supply_chain import (
    SupplyChainFinding,
    SupplyChainReport,
    SupplyChainSeverity,
    SupplyChainVerdict,
    analyze_supply_chain,
)


class PrimarySupplyChainScopeRefiner:
    """Refine dependency scope without narrowing the full source security scan.

    The full immutable repository/component tree is still scanned by the normal
    security gate. When that tree contains a supported dependency manifest at
    the admitted package root, only dependency files at that same root define
    the candidate's primary SBOM/supply-chain scope. Nested example/test
    manifests remain visible as auxiliary evidence but cannot by themselves
    contaminate the primary package dependency verdict.

    If a primary root manifest cannot be proven or read, the original report is
    returned unchanged (fail closed).
    """

    def __init__(
        self,
        api: GitHubApi,
        rate_limits: RateLimitManager,
        *,
        max_dependency_file_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        self.api = api
        self.rate_limits = rate_limits
        self.max_dependency_file_bytes = max_dependency_file_bytes

    @staticmethod
    def _parent(path: str) -> str:
        return path.rsplit("/", 1)[0] if "/" in path else ""

    @staticmethod
    def _package_root(candidate: Candidate) -> str:
        value = str(candidate.extra.get("component_path") or "").strip().strip("/")
        return value

    @staticmethod
    def _repo_path(repository: str) -> str:
        parts = repository.split("/", 1)
        if len(parts) != 2 or not all(parts):
            raise ValueError(f"Invalid GitHub repository name: {repository}")
        return "/".join(urllib.parse.quote(part, safe="") for part in parts)

    def _get(self, path: str) -> GitHubResponse | None:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            return None
        response = self.api.get(path)
        self.rate_limits.observe_headers(response.headers)
        return response

    def _read_text(self, candidate: Candidate, path: str) -> SourceArtifact | None:
        repository_path = self._repo_path(candidate.repository)
        encoded_path = "/".join(
            urllib.parse.quote(part, safe="") for part in path.split("/")
        )
        ref = urllib.parse.quote(candidate.commit_sha, safe="")
        response = self._get(
            f"/repos/{repository_path}/contents/{encoded_path}?ref={ref}"
        )
        if response is None:
            return None
        payload = response.data if isinstance(response.data, dict) else {}
        if payload.get("type") not in {None, "file"}:
            return None
        size = int(payload.get("size") or 0)
        if size > self.max_dependency_file_bytes:
            return None
        if payload.get("encoding") != "base64" or not payload.get("content"):
            return None
        encoded = str(payload["content"]).replace("\n", "")
        try:
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > self.max_dependency_file_bytes:
                return None
            content = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        return SourceArtifact(path=path, content=content)

    @staticmethod
    def _security_verdict(
        report: FullTreeSecurityReport,
        supply_chain: SupplyChainReport,
    ) -> SecurityVerdict:
        severities = {item.severity for item in report.findings}
        if (
            SecuritySeverity.CRITICAL in severities
            or supply_chain.verdict == SupplyChainVerdict.BLOCK
        ):
            return SecurityVerdict.BLOCK
        if (
            SecuritySeverity.HIGH in severities
            or SecuritySeverity.REVIEW in severities
            or not report.complete
            or supply_chain.verdict != SupplyChainVerdict.CLEAR
        ):
            return SecurityVerdict.REVIEW
        return SecurityVerdict.CLEAR

    def refine(
        self,
        candidate: Candidate,
        report: FullTreeSecurityReport,
    ) -> FullTreeSecurityReport:
        supply_chain = report.supply_chain
        if supply_chain is None or candidate.provider != "github":
            return report
        if report.verdict == SecurityVerdict.NOT_SCANNED:
            return report

        package_root = self._package_root(candidate)
        primary_manifests = tuple(
            path
            for path in supply_chain.manifests_analyzed
            if self._parent(path) == package_root
        )
        if not primary_manifests:
            return report

        primary_lockfiles = tuple(
            path
            for path in supply_chain.lockfiles_present
            if self._parent(path) == package_root
        )
        primary_paths = tuple(dict.fromkeys(primary_manifests + primary_lockfiles))
        auxiliary_paths = tuple(
            sorted(
                set(supply_chain.manifests_analyzed + supply_chain.lockfiles_present)
                - set(primary_paths)
            )
        )
        if not auxiliary_paths:
            return report

        artifacts: list[SourceArtifact] = []
        try:
            for path in primary_paths:
                artifact = self._read_text(candidate, path)
                if artifact is None:
                    return report
                artifacts.append(artifact)
        except (GitHubApiError, ValueError):
            return report

        refined = analyze_supply_chain(tuple(artifacts))
        notices = tuple(
            SupplyChainFinding(
                rule_id="auxiliary_dependency_file_out_of_primary_scope",
                severity=SupplyChainSeverity.NOTICE,
                path=path,
                evidence=(
                    "scanned as repository source but excluded from the primary "
                    "package dependency/SBOM scope"
                ),
            )
            for path in auxiliary_paths
        )
        refined = SupplyChainReport(
            verdict=refined.verdict,
            manifests_analyzed=refined.manifests_analyzed,
            lockfiles_present=refined.lockfiles_present,
            dependencies=refined.dependencies,
            findings=refined.findings + notices,
            executed_untrusted_code=refined.executed_untrusted_code,
        )
        return replace(
            report,
            verdict=self._security_verdict(report, refined),
            supply_chain=refined,
        )
