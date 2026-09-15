from __future__ import annotations

import base64
import binascii
import posixpath
import urllib.parse
from dataclasses import dataclass
from typing import Any, Protocol

from .github_api import GitHubApi, GitHubResponse
from .models import Candidate
from .rate_limit import RateLimitManager
from .security_gate import (
    SecurityFinding,
    SecuritySeverity,
    SecurityVerdict,
    SourceArtifact,
    scan_source_artifacts,
)
from .supply_chain import SupplyChainReport, SupplyChainVerdict, analyze_supply_chain


_SOURCE_SUFFIXES = {
    ".bat",
    ".c",
    ".cc",
    ".cfg",
    ".cjs",
    ".cmake",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".dart",
    ".fs",
    ".fsx",
    ".go",
    ".gradle",
    ".groovy",
    ".h",
    ".hpp",
    ".htm",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".lock",
    ".lua",
    ".m",
    ".mk",
    ".mjs",
    ".mm",
    ".php",
    ".pl",
    ".podspec",
    ".properties",
    ".proto",
    ".ps1",
    ".py",
    ".r",
    ".rb",
    ".rs",
    ".scss",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}
_SOURCE_NAMES = {
    ".gitmodules",
    "cargo.lock",
    "cargo.toml",
    "dockerfile",
    "gemfile",
    "go.mod",
    "go.sum",
    "makefile",
    "package-lock.json",
    "package.json",
    "podfile",
    "pubspec.lock",
    "pubspec.yaml",
    "pyproject.toml",
    "rakefile",
    "requirements.txt",
}
_OPAQUE_RISK_SUFFIXES = {
    ".7z",
    ".a",
    ".aab",
    ".aar",
    ".apk",
    ".bin",
    ".class",
    ".dex",
    ".dll",
    ".dylib",
    ".exe",
    ".gz",
    ".jar",
    ".lib",
    ".msi",
    ".node",
    ".o",
    ".rar",
    ".so",
    ".tar",
    ".tgz",
    ".wasm",
    ".whl",
    ".xz",
    ".zip",
}


class CandidateSecurityScanner(Protocol):
    def scan(self, candidate: Candidate) -> FullTreeSecurityReport: ...


class SecurityScanDeferred(RuntimeError):
    """The scan did not start or finish; callers must retry rather than admit the candidate."""


@dataclass(frozen=True)
class FullTreeSecurityReport:
    repository: str
    commit_sha: str
    tree_sha: str | None
    verdict: SecurityVerdict
    complete: bool
    findings: tuple[SecurityFinding, ...]
    total_entries: int
    blobs_seen: int
    relevant_blobs: int
    scanned_files: int
    scanned_bytes: int
    skipped_assets: int
    opaque_artifacts: tuple[str, ...]
    submodules: tuple[str, ...]
    symlinks: tuple[str, ...]
    supply_chain: SupplyChainReport | None = None
    executed_untrusted_code: bool = False

    @property
    def admission_eligible(self) -> bool:
        return (
            self.complete
            and self.verdict == SecurityVerdict.CLEAR
            and self.supply_chain is not None
            and self.supply_chain.admission_eligible
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "tree_sha": self.tree_sha,
            "verdict": self.verdict.value,
            "complete": self.complete,
            "admission_eligible": self.admission_eligible,
            "findings": [
                {
                    "rule_id": item.rule_id,
                    "severity": item.severity.value,
                    "path": item.path,
                    "evidence": item.evidence,
                }
                for item in self.findings
            ],
            "total_entries": self.total_entries,
            "blobs_seen": self.blobs_seen,
            "relevant_blobs": self.relevant_blobs,
            "scanned_files": self.scanned_files,
            "scanned_bytes": self.scanned_bytes,
            "skipped_assets": self.skipped_assets,
            "opaque_artifacts": list(self.opaque_artifacts),
            "submodules": list(self.submodules),
            "symlinks": list(self.symlinks),
            "supply_chain": None if self.supply_chain is None else self.supply_chain.to_dict(),
            "executed_untrusted_code": self.executed_untrusted_code,
        }

    @classmethod
    def not_scanned(cls, candidate: Candidate, reason: str) -> FullTreeSecurityReport:
        return cls(
            repository=candidate.repository,
            commit_sha=candidate.commit_sha,
            tree_sha=None,
            verdict=SecurityVerdict.NOT_SCANNED,
            complete=False,
            findings=(
                SecurityFinding(
                    rule_id="security_scan_not_completed",
                    severity=SecuritySeverity.REVIEW,
                    path=".",
                    evidence=reason,
                ),
            ),
            total_entries=0,
            blobs_seen=0,
            relevant_blobs=0,
            scanned_files=0,
            scanned_bytes=0,
            skipped_assets=0,
            opaque_artifacts=(),
            submodules=(),
            symlinks=(),
        )


class GitHubFullTreeSecurityScanner:
    """Reads an immutable GitHub tree and source blobs without executing candidate code."""

    def __init__(
        self,
        api: GitHubApi,
        rate_limits: RateLimitManager,
        *,
        max_relevant_files: int = 800,
        max_blob_bytes: int = 512 * 1024,
        max_large_text_bytes: int = 8 * 1024 * 1024,
        max_total_bytes: int = 16 * 1024 * 1024,
        static_chunk_chars: int = 512 * 1024,
        static_chunk_overlap: int = 2048,
        max_symlink_bytes: int = 4096,
        max_symlink_depth: int = 16,
    ) -> None:
        self.api = api
        self.rate_limits = rate_limits
        self.max_relevant_files = max_relevant_files
        self.max_blob_bytes = max_blob_bytes
        self.max_large_text_bytes = max_large_text_bytes
        self.max_total_bytes = max_total_bytes
        self.static_chunk_chars = static_chunk_chars
        self.static_chunk_overlap = static_chunk_overlap
        self.max_symlink_bytes = max_symlink_bytes
        self.max_symlink_depth = max_symlink_depth
        if self.max_blob_bytes <= 0 or self.max_large_text_bytes < self.max_blob_bytes:
            raise ValueError("source byte limits must be positive and monotonic")
        if self.max_total_bytes < self.max_blob_bytes:
            raise ValueError("total scan budget must cover at least one normal source blob")
        if self.static_chunk_chars <= 0 or self.static_chunk_overlap < 0:
            raise ValueError("static chunk settings must be non-negative and usable")
        if self.max_symlink_bytes <= 0 or self.max_symlink_depth <= 0:
            raise ValueError("symlink limits must be positive")

    def _get(self, path: str) -> GitHubResponse:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            self.rate_limits.record_backoff(
                decision.retry_after_seconds,
                "security_scan_rate_limit",
            )
            raise SecurityScanDeferred(
                f"GitHub rate limit exhausted; retry after {decision.retry_after_seconds}s"
            )
        response = self.api.get(path)
        self.rate_limits.observe_headers(response.headers)
        return response

    @staticmethod
    def _repo_path(repository: str) -> str:
        parts = repository.split("/", 1)
        if len(parts) != 2 or not all(parts):
            raise ValueError(f"Invalid GitHub repository name: {repository}")
        return "/".join(urllib.parse.quote(part, safe="") for part in parts)

    @staticmethod
    def _suffix(path: str) -> str:
        name = path.rsplit("/", 1)[-1].lower()
        dot = name.rfind(".")
        return "" if dot < 0 else name[dot:]

    @classmethod
    def _is_relevant_source(cls, path: str, mode: str) -> bool:
        lower = path.lower()
        name = lower.rsplit("/", 1)[-1]
        return (
            mode == "100755"
            or name in _SOURCE_NAMES
            or cls._suffix(path) in _SOURCE_SUFFIXES
            or lower.startswith(".github/workflows/")
        )

    @classmethod
    def _is_opaque_risk(cls, path: str) -> bool:
        return cls._suffix(path) in _OPAQUE_RISK_SUFFIXES

    @staticmethod
    def _finding(
        rule_id: str,
        severity: SecuritySeverity,
        path: str,
        evidence: str,
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            severity=severity,
            path=path,
            evidence=evidence[:240],
        )

    @staticmethod
    def _dedupe_findings(
        findings: list[SecurityFinding],
    ) -> list[SecurityFinding]:
        seen: set[tuple[str, SecuritySeverity, str, str]] = set()
        result: list[SecurityFinding] = []
        for item in findings:
            key = (item.rule_id, item.severity, item.path, item.evidence)
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    def _decode_blob(self, repository_path: str, blob_sha: str) -> bytes:
        response = self._get(f"/repos/{repository_path}/git/blobs/{blob_sha}")
        payload = response.data if isinstance(response.data, dict) else {}
        if payload.get("encoding") != "base64" or not payload.get("content"):
            raise ValueError("GitHub blob response is not base64 content")
        encoded = str(payload["content"]).replace("\n", "")
        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Invalid base64 blob returned by GitHub") from exc

    @staticmethod
    def _normalize_symlink_target(link_path: str, target: str) -> str:
        if (
            not target
            or target != target.strip()
            or "\x00" in target
            or "\n" in target
            or "\r" in target
            or "\t" in target
            or "\\" in target
            or target.startswith("/")
        ):
            raise ValueError("unsafe symbolic link target syntax")
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(link_path), target)
        )
        if (
            resolved in {"", ".", ".."}
            or resolved.startswith("../")
            or resolved.startswith("/")
        ):
            raise ValueError("symbolic link escapes admitted repository scope")
        return resolved

    def _resolve_symlink(
        self,
        repository_path: str,
        link_path: str,
        entries_by_path: dict[str, dict[str, Any]],
        target_cache: dict[str, str],
    ) -> str:
        current_path = link_path
        visited: set[str] = set()
        for _depth in range(self.max_symlink_depth):
            if current_path in visited:
                raise ValueError("symbolic link cycle detected")
            visited.add(current_path)
            entry = entries_by_path.get(current_path)
            if entry is None:
                raise ValueError("symbolic link target is outside admitted tree or missing")
            if str(entry.get("mode") or "") != "120000":
                if str(entry.get("type") or "") != "blob":
                    raise ValueError("symbolic link does not resolve to a blob")
                return current_path

            sha = str(entry.get("sha") or "")
            size = int(entry.get("size") or 0)
            if not sha:
                raise ValueError("symbolic link entry has no blob SHA")
            if size > self.max_symlink_bytes:
                raise ValueError("symbolic link target exceeds size limit")
            target = target_cache.get(sha)
            if target is None:
                raw_target = self._decode_blob(repository_path, sha)
                if len(raw_target) > self.max_symlink_bytes:
                    raise ValueError("symbolic link target exceeds decoded size limit")
                try:
                    target = raw_target.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError("symbolic link target is not UTF-8") from exc
                target_cache[sha] = target
            current_path = self._normalize_symlink_target(current_path, target)
        raise ValueError("symbolic link chain exceeds depth limit")

    def _static_artifacts(self, path: str, content: str) -> list[SourceArtifact]:
        if len(content.encode("utf-8")) <= self.max_blob_bytes:
            return [SourceArtifact(path=path, content=content)]
        chunk_size = min(self.static_chunk_chars, self.max_blob_bytes)
        chunk_size = max(1, chunk_size)
        overlap = min(self.static_chunk_overlap, chunk_size // 2)
        step = max(1, chunk_size - overlap)
        chunks: list[SourceArtifact] = []
        start = 0
        while start < len(content):
            end = min(len(content), start + chunk_size)
            chunks.append(SourceArtifact(path=path, content=content[start:end]))
            if end >= len(content):
                break
            start += step
        return chunks

    def scan(self, candidate: Candidate) -> FullTreeSecurityReport:
        if candidate.provider != "github":
            return FullTreeSecurityReport.not_scanned(
                candidate,
                f"unsupported provider: {candidate.provider}",
            )

        repository_path = self._repo_path(candidate.repository)
        commit_ref = urllib.parse.quote(candidate.commit_sha, safe="")
        commit_response = self._get(f"/repos/{repository_path}/commits/{commit_ref}")
        commit_data = commit_response.data if isinstance(commit_response.data, dict) else {}
        resolved_sha = str(commit_data.get("sha", ""))
        findings: list[SecurityFinding] = []
        if resolved_sha != candidate.commit_sha:
            findings.append(
                self._finding(
                    "commit_provenance_mismatch",
                    SecuritySeverity.CRITICAL,
                    ".",
                    f"expected {candidate.commit_sha}; resolved {resolved_sha or 'missing'}",
                )
            )
            return FullTreeSecurityReport(
                repository=candidate.repository,
                commit_sha=candidate.commit_sha,
                tree_sha=None,
                verdict=SecurityVerdict.BLOCK,
                complete=False,
                findings=tuple(findings),
                total_entries=0,
                blobs_seen=0,
                relevant_blobs=0,
                scanned_files=0,
                scanned_bytes=0,
                skipped_assets=0,
                opaque_artifacts=(),
                submodules=(),
                symlinks=(),
            )

        commit_meta = commit_data.get("commit")
        tree_meta = commit_meta.get("tree") if isinstance(commit_meta, dict) else None
        tree_sha = str(tree_meta.get("sha", "")) if isinstance(tree_meta, dict) else ""
        if not tree_sha:
            return FullTreeSecurityReport.not_scanned(candidate, "commit has no tree SHA")

        expected_tree = str(candidate.extra.get("provenance_tree_sha") or "")
        if expected_tree and expected_tree != tree_sha:
            findings.append(
                self._finding(
                    "tree_provenance_mismatch",
                    SecuritySeverity.CRITICAL,
                    ".",
                    f"expected {expected_tree}; resolved {tree_sha}",
                )
            )

        tree_ref = urllib.parse.quote(tree_sha, safe="")
        tree_response = self._get(
            f"/repos/{repository_path}/git/trees/{tree_ref}?recursive=1"
        )
        tree_data = tree_response.data if isinstance(tree_response.data, dict) else {}
        raw_entries = tree_data.get("tree")
        entries = raw_entries if isinstance(raw_entries, list) else []
        tree_truncated = bool(tree_data.get("truncated", False))
        if tree_truncated:
            findings.append(
                self._finding(
                    "tree_truncated",
                    SecuritySeverity.HIGH,
                    ".",
                    "GitHub recursive tree response was truncated",
                )
            )

        entries_by_path: dict[str, dict[str, Any]] = {
            str(raw.get("path")): raw
            for raw in entries
            if isinstance(raw, dict)
            and raw.get("path")
            and str(raw.get("type") or "") == "blob"
        }
        forced_relevant_paths: set[str] = set()
        symlinks: list[str] = []
        unsafe_symlinks: set[str] = set()
        target_cache: dict[str, str] = {}
        for path, raw in entries_by_path.items():
            if str(raw.get("mode") or "") != "120000":
                continue
            symlinks.append(path)
            try:
                final_path = self._resolve_symlink(
                    repository_path,
                    path,
                    entries_by_path,
                    target_cache,
                )
            except ValueError as exc:
                unsafe_symlinks.add(path)
                findings.append(
                    self._finding(
                        "unsafe_or_unresolved_symlink",
                        SecuritySeverity.HIGH,
                        path,
                        str(exc),
                    )
                )
                continue
            final_entry = entries_by_path[final_path]
            if self._is_relevant_source(path, "100644"):
                forced_relevant_paths.add(final_path)
            if self._is_relevant_source(
                final_path,
                str(final_entry.get("mode") or ""),
            ):
                forced_relevant_paths.add(final_path)

        source_artifacts: list[SourceArtifact] = []
        static_artifacts: list[SourceArtifact] = []
        opaque_artifacts: list[str] = []
        submodules: list[str] = []
        blobs_seen = 0
        relevant_blobs = 0
        scanned_source_files = 0
        scanned_bytes = 0
        skipped_assets = 0
        budget_exceeded = False
        source_unreadable = False

        for raw in entries:
            if not isinstance(raw, dict):
                continue
            path = str(raw.get("path", ""))
            entry_type = str(raw.get("type", ""))
            mode = str(raw.get("mode", ""))
            sha = str(raw.get("sha", ""))
            if not path:
                continue

            if entry_type == "commit" or mode == "160000":
                submodules.append(path)
                findings.append(
                    self._finding(
                        "unscanned_submodule",
                        SecuritySeverity.HIGH,
                        path,
                        "submodule content is outside the scanned commit tree",
                    )
                )
                continue
            if entry_type != "blob":
                continue

            blobs_seen += 1
            if mode == "120000":
                continue
            if self._is_opaque_risk(path):
                opaque_artifacts.append(path)
                findings.append(
                    self._finding(
                        "opaque_or_precompiled_artifact",
                        SecuritySeverity.HIGH,
                        path,
                        "binary/archive artifact requires separate supply-chain review",
                    )
                )
                continue
            is_relevant = (
                self._is_relevant_source(path, mode)
                or path in forced_relevant_paths
            )
            if not is_relevant:
                skipped_assets += 1
                continue

            relevant_blobs += 1
            size = int(raw.get("size") or 0)
            if relevant_blobs > self.max_relevant_files:
                if not budget_exceeded:
                    findings.append(
                        self._finding(
                            "scan_file_budget_exceeded",
                            SecuritySeverity.HIGH,
                            path,
                            f"more than {self.max_relevant_files} relevant files",
                        )
                    )
                budget_exceeded = True
                continue
            if size > self.max_large_text_bytes:
                source_unreadable = True
                findings.append(
                    self._finding(
                        "source_blob_too_large",
                        SecuritySeverity.HIGH,
                        path,
                        (
                            f"{size} bytes exceeds bounded large-text scan limit "
                            f"{self.max_large_text_bytes}"
                        ),
                    )
                )
                continue
            if scanned_bytes + size > self.max_total_bytes:
                if not budget_exceeded:
                    findings.append(
                        self._finding(
                            "scan_byte_budget_exceeded",
                            SecuritySeverity.HIGH,
                            path,
                            f"source scan exceeds {self.max_total_bytes} bytes",
                        )
                    )
                budget_exceeded = True
                continue
            if not sha:
                source_unreadable = True
                findings.append(
                    self._finding(
                        "source_blob_missing_sha",
                        SecuritySeverity.HIGH,
                        path,
                        "tree entry has no blob SHA",
                    )
                )
                continue

            try:
                raw_content = self._decode_blob(repository_path, sha)
                if len(raw_content) > self.max_large_text_bytes:
                    raise ValueError("decoded source exceeds bounded large-text limit")
                if scanned_bytes + len(raw_content) > self.max_total_bytes:
                    budget_exceeded = True
                    findings.append(
                        self._finding(
                            "scan_byte_budget_exceeded",
                            SecuritySeverity.HIGH,
                            path,
                            f"source scan exceeds {self.max_total_bytes} bytes",
                        )
                    )
                    continue
                content = raw_content.decode("utf-8")
            except (UnicodeDecodeError, ValueError) as exc:
                source_unreadable = True
                findings.append(
                    self._finding(
                        "source_blob_unreadable",
                        SecuritySeverity.HIGH,
                        path,
                        type(exc).__name__,
                    )
                )
                continue

            artifact = SourceArtifact(path=path, content=content)
            source_artifacts.append(artifact)
            static_artifacts.extend(self._static_artifacts(path, content))
            scanned_source_files += 1
            scanned_bytes += len(raw_content)

        source_result = scan_source_artifacts(static_artifacts)
        supply_chain = analyze_supply_chain(source_artifacts)
        findings.extend(source_result.findings)
        findings = self._dedupe_findings(findings)
        severities = {item.severity for item in findings}
        complete = (
            not tree_truncated
            and not budget_exceeded
            and not source_unreadable
            and not submodules
            and not unsafe_symlinks
            and not opaque_artifacts
            and relevant_blobs == scanned_source_files
        )

        if (
            SecuritySeverity.CRITICAL in severities
            or supply_chain.verdict == SupplyChainVerdict.BLOCK
        ):
            verdict = SecurityVerdict.BLOCK
        elif (
            SecuritySeverity.HIGH in severities
            or SecuritySeverity.REVIEW in severities
            or not complete
            or supply_chain.verdict != SupplyChainVerdict.CLEAR
        ):
            verdict = SecurityVerdict.REVIEW
        elif source_result.verdict == SecurityVerdict.CLEAR:
            verdict = SecurityVerdict.CLEAR
        else:
            verdict = SecurityVerdict.NOT_SCANNED

        return FullTreeSecurityReport(
            repository=candidate.repository,
            commit_sha=candidate.commit_sha,
            tree_sha=tree_sha,
            verdict=verdict,
            complete=complete,
            findings=tuple(findings),
            total_entries=len(entries),
            blobs_seen=blobs_seen,
            relevant_blobs=relevant_blobs,
            scanned_files=scanned_source_files,
            scanned_bytes=scanned_bytes,
            skipped_assets=skipped_assets,
            opaque_artifacts=tuple(sorted(opaque_artifacts)),
            submodules=tuple(sorted(submodules)),
            symlinks=tuple(sorted(symlinks)),
            supply_chain=supply_chain,
        )
