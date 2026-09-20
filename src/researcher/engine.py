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
from .observability import EventLevel, EventLogger, sanitize_payload
from .scoring import CandidateScorer
from .security_admission import CandidateSecurityScanner, FullTreeSecurityReport
from .security_gate import SecurityVerdict
from .state import SQLiteStateStore
from .submission import LibrarySubmissionClient
from .vulnerability import ResearcherSbom, VulnerabilityReport
from .vulnerability_admission import (
    CandidateVulnerabilityScanner,
    VulnerabilityAdmissionResult,
)


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
        vulnerability_scanner: CandidateVulnerabilityScanner | None = None,
        event_logger: EventLogger | None = None,
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
        self.vulnerability_scanner = vulnerability_scanner
        self.event_logger = event_logger
        self.state.set_mode(mode)

    def _emit(
        self,
        level: EventLevel | str,
        event: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        if self.event_logger is not None:
            self.event_logger.emit(level, "research_engine", event, payload)

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
                if self.state.count_completed_submissions(need.capability_id)
                < need.desired_candidates
            ]

        def key(need: Need) -> tuple[int, int, str]:
            completed = self.state.count_completed_submissions(need.capability_id)
            shortage = max(0, need.desired_candidates - completed)
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
        vulnerability_admission: VulnerabilityAdmissionResult | None = None,
    ) -> Dossier:
        fingerprint = candidate_fingerprint(need.capability_id, candidate)
        scores = self.scorer.score(need, candidate, contract)
        security = security_evidence(candidate)
        security["admission_gate"] = (
            None if security_report is None else security_report.to_dict()
        )
        security["vulnerability_gate"] = (
            None
            if vulnerability_admission is None
            else vulnerability_admission.to_dict()
        )
        supply_chain = None if security_report is None else security_report.supply_chain
        sbom = None if vulnerability_admission is None else vulnerability_admission.sbom
        vulnerability_report = (
            None if vulnerability_admission is None else vulnerability_admission.report
        )
        dependency_evidence = {
            "manifest_files_detected": list(candidate.extra.get("dependency_manifests", [])),
            "dependencies_enumerated": bool(
                supply_chain is not None and supply_chain.manifests_analyzed
            ),
            "dependency_count": 0 if supply_chain is None else len(supply_chain.dependencies),
            "supply_chain_verdict": (
                None if supply_chain is None else supply_chain.verdict.value
            ),
            "manifests_analyzed": (
                [] if supply_chain is None else list(supply_chain.manifests_analyzed)
            ),
            "lockfiles_present": (
                [] if supply_chain is None else list(supply_chain.lockfiles_present)
            ),
            "sbom_complete": None if sbom is None else sbom.complete,
            "sbom_component_count": 0 if sbom is None else len(sbom.components),
            "sbom_fingerprint": None if sbom is None else sbom.fingerprint,
            "vulnerability_database_checked": bool(
                vulnerability_report is not None
                and vulnerability_report.database_checked
            ),
            "vulnerability_verdict": (
                None
                if vulnerability_report is None
                else vulnerability_report.verdict.value
            ),
            "known_vulnerability_count": (
                0
                if vulnerability_report is None
                else len(vulnerability_report.hits)
            ),
            "note": (
                "Static source, dependency provenance, SBOM and vulnerability admission only; "
                "candidate/package-manager code was not executed."
            ),
        }
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
            dependency_evidence=dependency_evidence,
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
    def _vulnerability_not_analyzed(reason: str) -> VulnerabilityAdmissionResult:
        sbom = ResearcherSbom(
            schema_version=1,
            components=(),
            unresolved=(reason,),
            source_files=(),
        )
        return VulnerabilityAdmissionResult(
            sbom=sbom,
            report=VulnerabilityReport.not_analyzed(reason, sbom),
        )

    def _scan_vulnerabilities(
        self,
        candidate: Candidate,
        security_report: FullTreeSecurityReport,
    ) -> VulnerabilityAdmissionResult:
        if self.vulnerability_scanner is None:
            return self._vulnerability_not_analyzed(
                "no candidate vulnerability scanner configured"
            )
        return self.vulnerability_scanner.scan(candidate, security_report)

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
        vulnerability_admission: VulnerabilityAdmissionResult,
    ) -> str | None:
        if lifecycle == "SHORTLISTED":
            return None
        if lifecycle == "SECURITY_BLOCKED":
            return "security_gate_blocked"
        if lifecycle == "SECURITY_REVIEW":
            if security_report.admission_eligible:
                verdict = vulnerability_admission.report.verdict.value.lower()
                return f"vulnerability_review:{verdict}"
            return f"security_review:{security_report.verdict.value.lower()}"
        if candidate.extra.get("source_stable") is False:
            return "unstable_source_ref"
        if candidate.archived:
            return "pre_screen:archived"
        license_info = classify_license(candidate.license_spdx)
        if license_info["fit"] < 0.45:
            classification = str(license_info["classification"])
            spdx = candidate.license_spdx
            if spdx is None:
                return "pre_screen:license_unknown"
            if spdx == "NOASSERTION":
                return "pre_screen:license_noassertion"
            if spdx in {"SSPL-1.0", "BUSL-1.1"}:
                return "pre_screen:license_source_available"
            if spdx.startswith("AGPL"):
                return "pre_screen:license_agpl"
            if spdx.startswith("GPL"):
                return "pre_screen:license_gpl"
            return f"pre_screen:license_{classification}"
        return "pre_screen:recommendation_threshold"

    def _submit_dossier(
        self,
        need: Need,
        contract: Any,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any] | None:
        submission_result = self.submission.submit(
            need,
            contract,
            standard_version,
            dossier,
        )
        if not self.state.mark_submission(
            dossier.fingerprint,
            need.capability_id,
            str(submission_result["submission_id"]),
            str(submission_result["state"]),
            str(submission_result["target_path"]),
        ):
            return None
        return {
            "submission_id": submission_result["submission_id"],
            "state": submission_result["state"],
            "target_path": submission_result["target_path"],
        }

    def _recover_orphan_shortlists(
        self,
        need: Need,
        contract: Any,
        standard_version: str,
        slots: int,
    ) -> list[dict[str, Any]]:
        if slots <= 0:
            return []
        recovered: list[dict[str, Any]] = []
        rows = self.state.orphan_shortlist_rows(need.capability_id)
        for row in rows[:slots]:
            fingerprint = str(row["fingerprint"])
            dossier = self.dossiers.load_dossier(need.capability_id, fingerprint)
            if dossier.candidate.repository != str(row["repository"]):
                raise RuntimeError("Persisted orphan dossier repository mismatch")
            if dossier.candidate.commit_sha != str(row["commit_sha"]):
                raise RuntimeError("Persisted orphan dossier commit mismatch")
            summary = self._submit_dossier(
                need,
                contract,
                standard_version,
                dossier,
            )
            if summary is not None:
                recovered.append(summary)
        return recovered

    def run_cycle(self) -> dict[str, Any]:
        self.state.set_json("engine_state", "RUNNING")
        self.state.set_json("last_error", None)
        self._emit(EventLevel.INFO, "cycle_started", {"mode": self.mode.value})
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
                self._emit(EventLevel.INFO, "cycle_idle", {"mode": self.mode.value})
                return result

            need = ranked[0]
            self.state.set_json("current_capability", need.capability_id)
            self._emit(
                EventLevel.INFO,
                "need_selected",
                {"capability_id": need.capability_id, "mode": self.mode.value},
            )
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
                self._emit(
                    EventLevel.WARNING,
                    "contract_gap",
                    {"capability_id": need.capability_id, "phase": "contract"},
                )
                return {
                    "state": "BLOCKED",
                    "capability_id": need.capability_id,
                    "contract_gap": str(path),
                }

            completed_before = self.state.count_completed_submissions(need.capability_id)
            initial_slots = max(0, need.desired_candidates - completed_before)
            recovered = self._recover_orphan_shortlists(
                need,
                contract,
                standard_version,
                initial_slots,
            )
            if recovered:
                self._emit(
                    EventLevel.INFO,
                    "orphan_shortlists_recovered",
                    {
                        "capability_id": need.capability_id,
                        "recovered": len(recovered),
                        "result": "COMPLETED",
                    },
                )

            completed_after_recovery = self.state.count_completed_submissions(
                need.capability_id
            )
            if (
                self.mode != ResearchMode.IMPROVEMENT
                and completed_after_recovery >= need.desired_candidates
            ):
                self.state.update_scan(need.capability_id, success=True)
                result = {
                    "state": "COMPLETED",
                    "mode": self.mode.value,
                    "capability_id": need.capability_id,
                    "discovered": 0,
                    "new_analyzed": 0,
                    "shortlisted": 0,
                    "security_review": 0,
                    "security_blocked": 0,
                    "recovered_submissions": recovered,
                    "prepared_submissions": recovered,
                    "comparison": None,
                }
                self.state.set_json("last_cycle", {"at": utc_now(), **result})
                self._emit(
                    EventLevel.INFO,
                    "cycle_completed",
                    {
                        "capability_id": need.capability_id,
                        "mode": self.mode.value,
                        "result": "COMPLETED",
                        "shortlisted": 0,
                        "security_review": 0,
                        "security_blocked": 0,
                        "prepared_submissions": len(recovered),
                        "recovered_submissions": len(recovered),
                    },
                )
                return result

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
                        vulnerability_admission = self._scan_vulnerabilities(
                            candidate,
                            security_report,
                        )
                        lifecycle = (
                            "SHORTLISTED"
                            if vulnerability_admission.admission_eligible
                            else "SECURITY_REVIEW"
                        )
                    else:
                        vulnerability_admission = self._vulnerability_not_analyzed(
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
                    vulnerability_admission = self._vulnerability_not_analyzed(
                        "candidate did not pass preliminary scoring/policy"
                    )
                    lifecycle = "REJECTED"

                dossier = self._dossier(
                    need,
                    candidate,
                    contract,
                    lifecycle,
                    security_report,
                    vulnerability_admission,
                )
                dossier_path = self.dossiers.save_dossier(dossier)
                rejection_reason = self._rejection_reason(
                    lifecycle,
                    candidate,
                    security_report,
                    vulnerability_admission,
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
                supply_chain = security_report.supply_chain
                self._emit(
                    EventLevel.INFO,
                    "candidate_evaluated",
                    {
                        "capability_id": need.capability_id,
                        "provider": candidate.provider,
                        "lifecycle": lifecycle,
                        "security_verdict": security_report.verdict.value,
                        "supply_chain_verdict": (
                            None if supply_chain is None else supply_chain.verdict.value
                        ),
                        "vulnerability_verdict": vulnerability_admission.report.verdict.value,
                        "security_complete": security_report.complete,
                        "security_finding_rules": sorted(
                            {item.rule_id for item in security_report.findings}
                        ),
                        "security_opaque_artifact_count": len(
                            security_report.opaque_artifacts
                        ),
                        "security_submodule_count": len(security_report.submodules),
                        "supply_chain_reasons": (
                            []
                            if supply_chain is None
                            else list(supply_chain.reasons)
                        ),
                        "vulnerability_unresolved": list(
                            vulnerability_admission.sbom.unresolved
                        ),
                        "vulnerability_hit_count": len(
                            vulnerability_admission.report.hits
                        ),
                    },
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
            completed_now = self.state.count_completed_submissions(need.capability_id)
            slots = max(0, need.desired_candidates - completed_now)
            for dossier in shortlisted[:slots]:
                summary = self._submit_dossier(
                    need,
                    contract,
                    standard_version,
                    dossier,
                )
                if summary is not None:
                    prepared.append(summary)

            all_prepared = [*recovered, *prepared]
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
                "recovered_submissions": recovered,
                "prepared_submissions": all_prepared,
                "comparison": str(comparison_path),
            }
            self.state.set_json("last_cycle", {"at": utc_now(), **result})
            self._emit(
                EventLevel.INFO,
                "cycle_completed",
                {
                    "capability_id": need.capability_id,
                    "mode": self.mode.value,
                    "result": "COMPLETED",
                    "shortlisted": len(shortlisted),
                    "security_review": len(security_review),
                    "security_blocked": len(security_blocked),
                    "prepared_submissions": len(all_prepared),
                    "recovered_submissions": len(recovered),
                },
            )
            return result
        except Exception as exc:
            safe_message = sanitize_payload(str(exc))
            self.state.set_json(
                "last_error",
                {"at": utc_now(), "type": type(exc).__name__, "message": safe_message},
            )
            self.state.set_json("engine_state", "BACKOFF")
            self._emit(
                EventLevel.ERROR,
                "cycle_failed",
                {"error_type": type(exc).__name__, "message": safe_message},
            )
            raise
        finally:
            if self.state.get_json("engine_state") != "BACKOFF":
                self.state.set_json("engine_state", "IDLE")
                self.state.set_json("current_capability", None)
