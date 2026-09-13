from __future__ import annotations

from typing import Any

from .analysis import (
    classify_license,
    integration_estimate,
    maintenance_evidence,
    security_evidence,
)
from .benchmark import BenchmarkCoordinator
from .comparison import ComparisonEngine
from .dedup import candidate_fingerprint
from .discovery.base import DiscoveryProvider
from .dossiers import DossierStore
from .library import ContractSource, NeedSource
from .models import Candidate, Dossier, Need, ResearchMode, utc_now
from .scoring import CandidateScorer
from .security_admission import CandidateSecurityScanner, FullTreeSecurityReport
from .security_gate import SecurityVerdict
from .state import SQLiteStateStore
from .submission import LibrarySubmissionClient


_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ResearchEngine:
    def __init__(
        self,
        need_source: NeedSource,
        contract_source: ContractSource,
        discovery: DiscoveryProvider,
        state: SQLiteStateStore,
        dossiers: DossierStore,
        scorer: CandidateScorer,
        comparisons: ComparisonEngine,
        submission: LibrarySubmissionClient,
        mode: ResearchMode,
        shortlist_threshold: float = 0.58,
        security_scanner: CandidateSecurityScanner | None = None,
    ) -> None:
        self.need_source = need_source
        self.contract_source = contract_source
        self.discovery = discovery
        self.state = state
        self.dossiers = dossiers
        self.scorer = scorer
        self.comparisons = comparisons
        self.benchmarks = BenchmarkCoordinator()
        self.submission = submission
        self.mode = mode
        self.shortlist_threshold = shortlist_threshold
        self.security_scanner = security_scanner
        self.state.set_mode(mode)

    def _rank_needs(self, needs: list[Need]) -> list[Need]:
        statuses = (
            {"needed", "researching", "satisfied"}
            if self.mode == ResearchMode.IMPROVEMENT
            else {"needed", "researching"}
        )
        active = [need for need in needs if need.status in statuses]
        if self.mode != ResearchMode.IMPROVEMENT:
            active = [
                need
                for need in active
                if self.state.count_qualified(need.capability_id) < need.desired_candidates
            ]

        def key(need: Need) -> tuple[int, int, str]:
            qualified = self.state.count_qualified(need.capability_id)
            shortage = max(0, need.desired_candidates - qualified)
            last_scan = self.state.last_scan(need.capability_id) or ""
            return (_PRIORITY.get(need.priority, 99), -shortage, last_scan)

        return sorted(active, key=key)

    def _warnings(self, candidate: Candidate) -> tuple[str, ...]:
        warnings: list[str] = []
        license_info = classify_license(candidate.license_spdx)
        if license_info["warning"]:
            warnings.append(str(license_info["warning"]))
        security = security_evidence(candidate)
        warnings.extend(str(item) for item in security["warnings"])
        if candidate.archived:
            warnings.append("upstream_archived")
        if candidate.extra.get("source_stable") is False:
            warnings.append("unstable_source_ref")
        return tuple(sorted(set(warnings)))

    def _dossier(
        self,
        need: Need,
        candidate: Candidate,
        contract: Any,
        lifecycle: str,
        security_report: FullTreeSecurityReport | None = None,
    ) -> Dossier:
        fingerprint = candidate_fingerprint(need.capability_id, candidate)
        scores = self.scorer.score(need, candidate, contract)
        security = security_evidence(candidate)
        security["admission_gate"] = (
            None if security_report is None else security_report.to_dict()
        )
        return Dossier(
            schema_version=1,
            capability_id=need.capability_id,
            candidate=candidate,
            fingerprint=fingerprint,
            scores=scores,
            lifecycle=lifecycle,
            warnings=self._warnings(candidate),
            integration_estimate=integration_estimate(candidate, need),
            security_evidence=security,
            maintenance_evidence=maintenance_evidence(candidate),
            license_evidence=classify_license(candidate.license_spdx),
            dependency_evidence={
                "manifest_files_detected": list(
                    candidate.extra.get("dependency_manifests", [])
                ),
                "dependencies_enumerated": False,
                "note": "Metadata pre-screen only; manifests are not executed.",
            },
            benchmark_plan=self.benchmarks.plan(need, candidate),
            created_at=utc_now(),
        )

    def _scan_candidate(self, candidate: Candidate) -> FullTreeSecurityReport:
        if self.security_scanner is None:
            return FullTreeSecurityReport.not_scanned(
                candidate,
                "no candidate security scanner configured",
            )
        return self.security_scanner.scan(candidate)

    @staticmethod
    def _pre_screen_qualified(
        dossier: Dossier,
        candidate: Candidate,
        shortlist_threshold: float,
    ) -> bool:
        return (
            dossier.scores.recommendation >= shortlist_threshold
            and dossier.scores.license_fit >= 0.45
            and not candidate.archived
            and candidate.extra.get("source_stable") is not False
        )

    @staticmethod
    def _rejection_reason(
        lifecycle: str,
        candidate: Candidate,
        security_report: FullTreeSecurityReport,
    ) -> str | None:
        if lifecycle == "SHORTLISTED":
            return None
        if lifecycle == "SECURITY_BLOCKED":
            return "security_gate_blocked"
        if lifecycle == "SECURITY_REVIEW":
            return f"security_review:{security_report.verdict.value.lower()}"
        if candidate.extra.get("source_stable") is False:
            return "unstable_source_ref"
        return "pre_screen_threshold_or_policy"

    def run_cycle(self) -> dict[str, Any]:
        self.state.set_json("engine_state", "RUNNING")
        self.state.set_json("last_error", None)
        result: dict[str, Any]
        try:
            needs, snapshot = self.need_source.load_needs()
            contracts, standard_version = self.contract_source.load_contracts()
            self.state.set_json("library_snapshot", snapshot)
            ranked = self._rank_needs(needs)
            self.state.set_json("needs_total", len(needs))
            self.state.set_json("needs_incomplete", len(ranked))

            if not ranked:
                if self.mode == ResearchMode.SEEDING:
                    self.mode = ResearchMode.MAINTENANCE
                    self.state.set_mode(self.mode)
                result = {
                    "state": "IDLE",
                    "reason": "no_active_needs",
                    "mode": self.mode.value,
                    "needs_total": len(needs),
                }
                self.state.set_json("last_cycle", {"at": utc_now(), **result})
                return result

            need = ranked[0]
            self.state.set_json("current_capability", need.capability_id)
            qualified_before = self.state.count_qualified(need.capability_id)
            contract = contracts.get(need.capability_id)
            if contract is None:
                gap = {
                    "schema_version": 1,
                    "capability_id": need.capability_id,
                    "title": need.title,
                    "reason": "No contract_id exists in current Library contracts index",
                    "observed_at": utc_now(),
                    "action": "CONTRACT_PROPOSAL_REQUIRED",
                }
                path = self.dossiers.save_contract_gap(need.capability_id, gap)
                self.state.update_scan(
                    need.capability_id,
                    success=False,
                    error_state=f"contract_gap:{path}",
                )
                return {
                    "state": "BLOCKED",
                    "capability_id": need.capability_id,
                    "contract_gap": str(path),
                }

            candidates = self.discovery.discover(
                need,
                limit=max(need.desired_candidates * 4, 6),
            )
            dossiers: list[Dossier] = []
            for candidate in candidates:
                fingerprint = candidate_fingerprint(need.capability_id, candidate)
                if self.state.is_known_candidate(fingerprint):
                    continue

                preliminary = self._dossier(need, candidate, contract, "SCREENED")
                pre_screen_qualified = self._pre_screen_qualified(
                    preliminary,
                    candidate,
                    self.shortlist_threshold,
                )
                if pre_screen_qualified:
                    security_report = self._scan_candidate(candidate)
                    if security_report.admission_eligible:
                        lifecycle = "SHORTLISTED"
                    elif security_report.verdict == SecurityVerdict.BLOCK:
                        lifecycle = "SECURITY_BLOCKED"
                    else:
                        lifecycle = "SECURITY_REVIEW"
                else:
                    security_report = FullTreeSecurityReport.not_scanned(
                        candidate,
                        "candidate did not pass preliminary scoring/policy",
                    )
                    lifecycle = "REJECTED"

                dossier = self._dossier(
                    need,
                    candidate,
                    contract,
                    lifecycle,
                    security_report,
                )
                dossier_path = self.dossiers.save_dossier(dossier)
                rejection_reason = self._rejection_reason(
                    lifecycle,
                    candidate,
                    security_report,
                )
                self.state.upsert_candidate(
                    fingerprint,
                    need.capability_id,
                    candidate.repository,
                    candidate.commit_sha,
                    lifecycle,
                    dossier.scores.recommendation,
                    str(dossier_path),
                    rejection_reason,
                )
                dossiers.append(dossier)

            all_rows = self.state.candidate_rows(need.capability_id)
            comparison_payload = self.comparisons.compare(
                need,
                [dossier for dossier in dossiers],
            )
            comparison_payload["known_candidates"] = all_rows
            comparison_path = self.dossiers.save_comparison(
                need.capability_id, comparison_payload
            )

            shortlisted = [d for d in dossiers if d.lifecycle == "SHORTLISTED"]
            security_review = [d for d in dossiers if d.lifecycle == "SECURITY_REVIEW"]
            security_blocked = [d for d in dossiers if d.lifecycle == "SECURITY_BLOCKED"]
            shortlist_payload = {
                "schema_version": 1,
                "capability_id": need.capability_id,
                "generated_at": utc_now(),
                "candidates": [
                    {
                        "fingerprint": dossier.fingerprint,
                        "repository": dossier.candidate.repository,
                        "score": dossier.scores.recommendation,
                    }
                    for dossier in shortlisted
                ],
            }
            self.dossiers.save_shortlist(need.capability_id, shortlist_payload)

            prepared: list[dict[str, Any]] = []
            slots = max(0, need.desired_candidates - qualified_before)
            for dossier in shortlisted[:slots]:
                submission_result = self.submission.submit(
                    need,
                    contract,
                    standard_version,
                    dossier,
                )
                if self.state.mark_submission(
                    dossier.fingerprint,
                    need.capability_id,
                    str(submission_result["submission_id"]),
                    str(submission_result["state"]),
                    str(submission_result["target_path"]),
                ):
                    prepared.append(
                        {
                            "submission_id": submission_result["submission_id"],
                            "state": submission_result["state"],
                            "target_path": submission_result["target_path"],
                        }
                    )

            self.state.update_scan(need.capability_id, success=True)
            result = {
                "state": "COMPLETED",
                "mode": self.mode.value,
                "capability_id": need.capability_id,
                "discovered": len(candidates),
                "new_analyzed": len(dossiers),
                "shortlisted": len(shortlisted),
                "security_review": len(security_review),
                "security_blocked": len(security_blocked),
                "prepared_submissions": prepared,
                "comparison": str(comparison_path),
            }
            self.state.set_json("last_cycle", {"at": utc_now(), **result})
            return result
        except Exception as exc:
            self.state.set_json("last_error", {"at": utc_now(), "message": str(exc)})
            self.state.set_json("engine_state", "BACKOFF")
            raise
        finally:
            if self.state.get_json("engine_state") != "BACKOFF":
                self.state.set_json("engine_state", "IDLE")
                self.state.set_json("current_capability", None)
