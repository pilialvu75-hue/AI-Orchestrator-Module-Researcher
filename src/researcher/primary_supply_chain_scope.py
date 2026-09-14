from __future__ import annotations

import base64
import binascii
import urllib.parse
from dataclasses import replace

from .dependency_scope import dependency_scope_map
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

_DEPENDENCY_FINDING_RULES = {
    "git_dependency_requires_review",
    "git_dependency_unpinned",
    "non_registry_dependency_requires_review",
    "path_dependency_requires_review",
}
_NON_RUNTIME_SCOPES = {"development", "build"}


class PrimarySupplyChainScopeRefiner:
    """Refine package dependency scope without narrowing the source scan.

    The full immutable repository/component tree remains visible to the source
    security gate. Dependency admission is narrower: only dependency files at
    the admitted package root define the primary SBOM, and dependencies proven
    to belong only to development/build sections cannot contaminate the runtime
    supply-chain verdict. Auxiliary manifests remain visible as NOTICE evidence.

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

    @staticmethod
    def _runtime_supply_chain(
        supply_chain: SupplyChainReport,
        artifacts: tuple[SourceArtifact, ...],
    ) -> SupplyChainReport:
        """Drop only dependencies proven to be dev/build scoped.

        Unknown scopes remain in the report. Dependency-specific findings are
        removed only when the same manifest/name pair is explicitly classified
        as development/build by the manifest parser. Package-wide findings such
        as lifecycle hooks are never suppressed here.
        """
        scopes = dependency_scope_map(artifacts)
        excluded = {
            key for key, scope in scopes.items() if scope in _NON_RUNTIME_SCOPES
        }
        dependencies = tuple(
            item
            for item in supply_chain.dependencies
            if (item.manifest_path, item.name) not in excluded
        )

        def keep_finding(finding: SupplyChainFinding) -> bool:
            if finding.rule_id not in _DEPENDENCY_FINDING_RULES:
                return True
            for path, name in excluded:
                if finding.path == path and finding.evidence.startswith(f"{name}:"):
                    return False
            return True

        findings = tuple(item for item in supply_chain.findings if keep_finding(item))
        severities = {item.severity for item in findings}
        if SupplyChainSeverity.BLOCK in severities:
            verdict = SupplyChainVerdict.BLOCK
        elif SupplyChainSeverity.REVIEW in severities:
            verdict = SupplyChainVerdict.REVIEW
        else:
            verdict = SupplyChainVerdict.CLEAR
        return SupplyChainReport(
            verdict=verdict,
            manifests_analyzed=supply_chain.manifests_analyzed,
            lockfiles_present=supply_chain.lockfiles_present,
            dependencies=dependencies,
            findings=findings,
            executed_untrusted_code=supply_chain.executed_untrusted_code,
        )

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

        artifacts: list[SourceArtifact] = []
        try:
            for path in primary_paths:
                artifact = self._read_text(candidate, path)
                if artifact is None:
                    return report
                artifacts.append(artifact)
        except (GitHubApiError, ValueError):
            return report

        material = tuple(artifacts)
        refined = self._runtime_supply_chain(
            analyze_supply_chain(material),
            material,
        )
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
