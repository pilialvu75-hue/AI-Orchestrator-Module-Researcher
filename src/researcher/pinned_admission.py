from __future__ import annotations

import json
import re
import urllib.parse
from typing import TYPE_CHECKING, Any

from .dedup import candidate_fingerprint
from .github_api import GitHubApi, GitHubApiError, GitHubResponse
from .models import Candidate, Dossier, utc_now
from .rate_limit import RateLimitManager
from .security_admission import FullTreeSecurityReport
from .security_gate import SecurityVerdict

if TYPE_CHECKING:
    from .app import App

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
_DEPENDENCY_MANIFESTS = {
    "build.gradle",
    "build.gradle.kts",
    "cargo.lock",
    "cargo.toml",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pom.xml",
    "pubspec.lock",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
}
_LICENSE_FILES = {
    "copying",
    "copying.md",
    "copying.txt",
    "license",
    "license.md",
    "license.txt",
}
_TEST_DIRS = {"test", "tests", "spec", "specs"}
_TERMINAL_SUBMISSION_STATES = {"SUBMITTED", "DRY_RUN_PREPARED", "MERGED"}


class PinnedCandidateResolver:
    """Resolve one exact GitHub repository commit without executing upstream code."""

    def __init__(self, api: GitHubApi, rate_limits: RateLimitManager) -> None:
        self.api = api
        self.rate_limits = rate_limits

    def _get(self, path: str) -> GitHubResponse:
        decision = self.rate_limits.decision()
        if not decision.allowed:
            self.rate_limits.record_backoff(
                decision.retry_after_seconds,
                "pinned_candidate_rate_limit",
            )
            raise RuntimeError(
                f"GitHub rate limit exhausted; retry after {decision.retry_after_seconds}s"
            )
        response = self.api.get(path)
        self.rate_limits.observe_headers(response.headers)
        return response

    @staticmethod
    def _validate(repository: str, commit_sha: str) -> tuple[str, str]:
        repository = repository.strip()
        commit_sha = commit_sha.strip().lower()
        if not _REPOSITORY.fullmatch(repository):
            raise ValueError("repository must be owner/name")
        if not _SHA40.fullmatch(commit_sha):
            raise ValueError("commit must be an exact 40-character Git SHA")
        return repository, commit_sha

    @staticmethod
    def _tree_signals(
        repository: str,
        commit_sha: str,
        tree_sha: str,
        tree_data: dict[str, Any],
    ) -> dict[str, Any]:
        raw_entries = tree_data.get("tree")
        entries = raw_entries if isinstance(raw_entries, list) else []
        paths = [
            str(entry.get("path", ""))
            for entry in entries
            if isinstance(entry, dict) and entry.get("path")
        ]
        lower_paths = [path.lower() for path in paths]

        def basename(path: str) -> str:
            return path.rsplit("/", 1)[-1]

        dependency_manifests = sorted(
            path
            for path in paths
            if basename(path.lower()) in _DEPENDENCY_MANIFESTS
        )[:100]
        license_paths = sorted(
            path for path in paths if basename(path.lower()) in _LICENSE_FILES
        )
        license_file_url = None
        if license_paths:
            encoded = urllib.parse.quote(license_paths[0], safe="/")
            license_file_url = (
                f"https://github.com/{repository}/blob/{commit_sha}/{encoded}"
            )

        return {
            "tests_present": any(
                any(segment in _TEST_DIRS for segment in path.split("/"))
                or basename(path).endswith("_test.dart")
                or basename(path).startswith("test_")
                for path in lower_paths
            ),
            "ci_present": any(
                path.startswith(".github/workflows/") for path in lower_paths
            ),
            "readme_present": any(
                basename(path).startswith("readme") for path in lower_paths
            ),
            "dependency_manifests": dependency_manifests,
            "license_file_url": license_file_url,
            "tree_truncated": bool(tree_data.get("truncated", False)),
            "security_policy_present": any(
                basename(path) in {"security.md", "security.txt"}
                for path in lower_paths
            ),
            "dependabot_present": any(
                path in {".github/dependabot.yml", ".github/dependabot.yaml"}
                for path in lower_paths
            ),
            "codeql_present": any(
                path.startswith(".github/workflows/")
                and "codeql" in basename(path)
                for path in lower_paths
            ),
            "provenance_tree_sha": tree_sha,
        }

    def resolve(
        self,
        repository: str,
        commit_sha: str,
        *,
        release_tag: str | None = None,
        source_version: str | None = None,
    ) -> Candidate:
        repository, commit_sha = self._validate(repository, commit_sha)
        encoded_repo = "/".join(
            urllib.parse.quote(part, safe="") for part in repository.split("/")
        )
        repo_response = self._get(f"/repos/{encoded_repo}")
        meta = repo_response.data if isinstance(repo_response.data, dict) else {}
        if str(meta.get("full_name") or "") != repository:
            raise RuntimeError("resolved repository identity mismatch")

        commit_response = self._get(f"/repos/{encoded_repo}/commits/{commit_sha}")
        commit_data = (
            commit_response.data if isinstance(commit_response.data, dict) else {}
        )
        if str(commit_data.get("sha") or "").lower() != commit_sha:
            raise RuntimeError("resolved commit identity mismatch")
        commit_meta = commit_data.get("commit")
        tree_meta = commit_meta.get("tree") if isinstance(commit_meta, dict) else None
        tree_sha = str(tree_meta.get("sha") or "") if isinstance(tree_meta, dict) else ""
        if not _SHA40.fullmatch(tree_sha):
            raise RuntimeError("exact commit does not expose a valid tree SHA")

        tree_response = self._get(
            f"/repos/{encoded_repo}/git/trees/{tree_sha}?recursive=1"
        )
        tree_data = tree_response.data if isinstance(tree_response.data, dict) else {}
        if str(tree_data.get("sha") or "") != tree_sha:
            raise RuntimeError("resolved tree identity mismatch")
        if bool(tree_data.get("truncated", False)):
            raise RuntimeError("resolved tree is truncated; fail closed")
        signals = self._tree_signals(repository, commit_sha, tree_sha, tree_data)

        verified_tag: str | None = None
        if release_tag:
            tag = release_tag.strip()
            if not tag or len(tag) > 128:
                raise ValueError("release tag is invalid")
            encoded_tag = urllib.parse.quote(tag, safe="")
            tag_response = self._get(
                f"/repos/{encoded_repo}/commits/{encoded_tag}"
            )
            tag_data = tag_response.data if isinstance(tag_response.data, dict) else {}
            if str(tag_data.get("sha") or "").lower() != commit_sha:
                raise ValueError("release tag does not resolve to the pinned commit")
            verified_tag = tag

        license_spdx: str | None = None
        license_source = "repository_metadata"
        license_meta = meta.get("license")
        if isinstance(license_meta, dict):
            spdx = license_meta.get("spdx_id")
            if spdx not in {None, "NOASSERTION"}:
                license_spdx = str(spdx)

        # Repository license metadata describes the default branch, not
        # necessarily the exact candidate revision. If it is unrecognized,
        # use GitHub's LICENSE detector at the immutable commit and require
        # that the detected file really occurs in that commit's verified tree.
        # A missing/NOASSERTION response NEVER authorizes code reuse.
        if license_spdx is None and signals.get("license_file_url"):
            try:
                detected = self._get(
                    f"/repos/{encoded_repo}/license?ref={commit_sha}"
                )
            except GitHubApiError as exc:
                if exc.status not in {404, 422}:
                    raise
            else:
                license_data = (
                    detected.data if isinstance(detected.data, dict) else {}
                )
                matched = license_data.get("license")
                path = license_data.get("path")
                pinned_files = {
                    str(entry.get("path")): entry
                    for entry in tree_data.get("tree", [])
                    if isinstance(entry, dict) and entry.get("type") == "blob"
                }
                file_entry = pinned_files.get(path) if isinstance(path, str) else None
                if file_entry is not None and (
                    not license_data.get("sha")
                    or license_data["sha"] == file_entry.get("sha")
                ):
                    detected_spdx = (
                        matched.get("spdx_id")
                        if isinstance(matched, dict) else None
                    )
                    if isinstance(detected_spdx, str) and detected_spdx not in {
                        "", "NOASSERTION", "NONE"
                    }:
                        license_spdx = detected_spdx
                        license_source = "pinned_github_license_endpoint"

        owner_meta = meta.get("owner")
        owner = (
            str(owner_meta.get("login"))
            if isinstance(owner_meta, dict) and owner_meta.get("login")
            else repository.split("/", 1)[0]
        )
        topics_raw = meta.get("topics")
        topics = topics_raw if isinstance(topics_raw, list) else []
        name = str(meta.get("name") or repository.split("/", 1)[1])
        default_branch = str(meta.get("default_branch") or "main")
        source_stable: bool | None = None
        if source_version:
            lowered = source_version.lower()
            source_stable = not any(
                marker in lowered
                for marker in ("alpha", "beta", "-rc", ".dev", "snapshot", "wip")
            )

        return Candidate(
            provider="github",
            repository=repository,
            upstream_url=str(meta.get("html_url") or f"https://github.com/{repository}"),
            owner=owner,
            name=name,
            commit_sha=commit_sha,
            release_tag=verified_tag,
            default_branch=default_branch,
            acquired_at=utc_now(),
            license_spdx=license_spdx,
            license_file_url=(
                None
                if signals.get("license_file_url") is None
                else str(signals["license_file_url"])
            ),
            stars=int(meta.get("stargazers_count") or 0),
            forks=int(meta.get("forks_count") or 0),
            open_issues=int(meta.get("open_issues_count") or 0),
            pushed_at=None if meta.get("pushed_at") is None else str(meta["pushed_at"]),
            archived=bool(meta.get("archived", False)),
            language=None if meta.get("language") is None else str(meta["language"]),
            topics=tuple(str(topic) for topic in topics),
            description=None if meta.get("description") is None else str(meta["description"]),
            homepage=None if meta.get("homepage") is None else str(meta["homepage"]),
            size_kb=None if meta.get("size") is None else int(meta["size"]),
            has_issues=bool(meta.get("has_issues", True)),
            has_wiki=bool(meta.get("has_wiki", False)),
            extra={
                "license_detection_source": license_source,
                "fork": bool(meta.get("fork", False)),
                "disabled": bool(meta.get("disabled", False)),
                "visibility": meta.get("visibility"),
                "tests_present": bool(signals.get("tests_present")),
                "ci_present": bool(signals.get("ci_present")),
                "readme_present": bool(signals.get("readme_present")),
                "dependency_manifests": list(signals.get("dependency_manifests", [])),
                "tree_truncated": signals.get("tree_truncated"),
                "security_policy_present": bool(signals.get("security_policy_present")),
                "dependabot_present": bool(signals.get("dependabot_present")),
                "codeql_present": bool(signals.get("codeql_present")),
                "provenance_tree_sha": tree_sha,
                "release_tag_verified": verified_tag is not None,
                "source_version": source_version,
                "source_stable": source_stable,
                "pinned_admission": True,
            },
        )


def _existing_candidate(
    app: App,
    capability_id: str,
    fingerprint: str,
) -> dict[str, Any] | None:
    for row in app.state.candidate_rows(capability_id):
        if str(row.get("fingerprint") or "") == fingerprint:
            return row
    return None


def _submission_summary(app: App, fingerprint: str) -> dict[str, Any] | None:
    row = app.state.submission_row(fingerprint)
    if row is None:
        return None
    return {
        "submission_id": row.get("submission_id"),
        "state": row.get("state"),
        "target_path": row.get("target_path"),
        "branch": row.get("branch"),
        "pull_request_url": row.get("pull_request_url"),
    }


def _resume_pending(app: App) -> list[dict[str, Any]]:
    resume = getattr(app.engine.submission, "resume_pending", None)
    if not callable(resume):
        return []
    value = resume()
    if not isinstance(value, list):
        return []
    return [
        {
            "submission_id": item.get("submission_id"),
            "state": item.get("state"),
            "target_path": item.get("target_path"),
        }
        for item in value
        if isinstance(item, dict)
    ]


def _persist_dossier(app: App, dossier: Dossier, *, replace: bool) -> str:
    path = app.engine.dossiers.save_dossier(dossier)
    if replace:
        path.write_text(
            json.dumps(dossier.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return str(path)


def _delivery_flags(submission: dict[str, Any] | None) -> tuple[bool, bool]:
    if submission is None:
        return False, False
    state = str(submission.get("state") or "")
    return state in {"SUBMITTED", "MERGED"}, state == "DRY_RUN_PREPARED"


def admit_pinned_candidate(
    app: App,
    candidate: Candidate,
    capability_id: str,
    *,
    rescan: bool = False,
) -> dict[str, Any]:
    """Run V1 admission gates and deliver eligible candidates through intake safely."""

    engine = app.engine
    resumed = _resume_pending(app)
    needs, snapshot = engine.need_source.load_needs()
    need = next((item for item in needs if item.capability_id == capability_id), None)
    if need is None:
        raise ValueError(f"unknown Library capability: {capability_id}")
    contracts, standard_version = engine.contract_source.load_contracts()
    contract = contracts.get(capability_id)
    if contract is None:
        raise RuntimeError(f"Library contract gap for {capability_id}")

    app.state.set_json("library_snapshot", snapshot)
    fingerprint = candidate_fingerprint(capability_id, candidate)
    existing = _existing_candidate(app, capability_id, fingerprint)
    if existing is not None and not rescan:
        submission = _submission_summary(app, fingerprint)
        lifecycle = str(existing.get("lifecycle") or "UNKNOWN")
        if lifecycle == "SHORTLISTED" and submission is None:
            dossier = engine.dossiers.load_dossier(capability_id, fingerprint)
            engine._submit_dossier(need, contract, standard_version, dossier)
            submission = _submission_summary(app, fingerprint)
        submitted, dry_run_prepared = _delivery_flags(submission)
        return {
            "state": "EXISTING",
            "capability_id": capability_id,
            "fingerprint": fingerprint,
            "repository": candidate.repository,
            "commit_sha": candidate.commit_sha,
            "lifecycle": lifecycle,
            "dossier_path": existing.get("dossier_path"),
            "submission": submission,
            "submitted": submitted,
            "dry_run_prepared": dry_run_prepared,
            "resumed_submissions": resumed,
            "executed_untrusted_code": False,
        }

    preliminary = engine._dossier(need, candidate, contract, "SCREENED")
    if engine._pre_screen_qualified(
        preliminary,
        candidate,
        engine.shortlist_threshold,
    ):
        security_report = engine._scan_candidate(candidate)
        if security_report.admission_eligible:
            vulnerability_admission = engine._scan_vulnerabilities(
                candidate,
                security_report,
            )
            lifecycle = (
                "SHORTLISTED"
                if vulnerability_admission.admission_eligible
                else "SECURITY_REVIEW"
            )
        else:
            vulnerability_admission = engine._vulnerability_not_analyzed(
                "earlier security gate not clear"
            )
            lifecycle = (
                "SECURITY_BLOCKED"
                if security_report.verdict == SecurityVerdict.BLOCK
                else "SECURITY_REVIEW"
            )
    else:
        security_report = FullTreeSecurityReport.not_scanned(
            candidate,
            "candidate did not pass preliminary scoring/policy",
        )
        vulnerability_admission = engine._vulnerability_not_analyzed(
            "candidate did not pass preliminary scoring/policy"
        )
        lifecycle = "REJECTED"

    dossier = engine._dossier(
        need,
        candidate,
        contract,
        lifecycle,
        security_report,
        vulnerability_admission,
    )
    dossier_path = _persist_dossier(app, dossier, replace=rescan)
    rejection_reason = engine._rejection_reason(
        lifecycle,
        candidate,
        security_report,
        vulnerability_admission,
    )
    app.state.upsert_candidate(
        fingerprint,
        capability_id,
        candidate.repository,
        candidate.commit_sha,
        lifecycle,
        dossier.scores.recommendation,
        dossier_path,
        rejection_reason,
    )

    submission = None
    if lifecycle == "SHORTLISTED":
        engine._submit_dossier(need, contract, standard_version, dossier)
        submission = _submission_summary(app, fingerprint)

    supply_chain = security_report.supply_chain
    app.events.emit(
        "INFO",
        "pinned_admission",
        "pinned_candidate_evaluated",
        {
            "capability_id": capability_id,
            "provider": candidate.provider,
            "lifecycle": lifecycle,
            "security_verdict": security_report.verdict.value,
            "supply_chain_verdict": (
                None if supply_chain is None else supply_chain.verdict.value
            ),
            "vulnerability_verdict": vulnerability_admission.report.verdict.value,
            "delivery_state": (
                None if submission is None else submission.get("state")
            ),
        },
    )
    submitted, dry_run_prepared = _delivery_flags(submission)

    return {
        "state": "ADMISSION_COMPLETE",
        "capability_id": capability_id,
        "fingerprint": fingerprint,
        "repository": candidate.repository,
        "commit_sha": candidate.commit_sha,
        "release_tag": candidate.release_tag,
        "lifecycle": lifecycle,
        "admission_eligible": lifecycle == "SHORTLISTED",
        "recommendation_score": dossier.scores.recommendation,
        "security": security_report.to_dict(),
        "vulnerability": vulnerability_admission.to_dict(),
        "dossier_path": dossier_path,
        "submission": submission,
        "submitted": submitted,
        "dry_run_prepared": dry_run_prepared,
        "resumed_submissions": resumed,
        "executed_untrusted_code": False,
    }


def resolve_and_admit_pinned_candidate(
    app: App,
    capability_id: str,
    repository: str,
    commit_sha: str,
    *,
    release_tag: str | None = None,
    source_version: str | None = None,
    rescan: bool = False,
) -> dict[str, Any]:
    api = GitHubApi(
        app.config.github_token,
        app.config.github_api_base,
        uploads_base_url=app.config.github_uploads_base,
    )
    resolver = PinnedCandidateResolver(api, RateLimitManager(app.state))
    candidate = resolver.resolve(
        repository,
        commit_sha,
        release_tag=release_tag,
        source_version=source_version,
    )
    return admit_pinned_candidate(
        app,
        candidate,
        capability_id,
        rescan=rescan,
    )
