from __future__ import annotations

from typing import Any

from .engine import ResearchEngine, _PRIORITY
from .models import Dossier, Need, ResearchMode, utc_now
from .observability import EventLevel, sanitize_payload
from .security_admission import FullTreeSecurityReport
from .security_gate import SecurityVerdict
from .target_coverage import (
    TargetCoverageSnapshot,
    candidate_research_targets,
    load_target_coverage,
    record_target_coverage,
    select_for_target_gaps,
)


class TargetAwareResearchEngine(ResearchEngine):
    """Research engine whose discovery depth is enforced per required target.

    Library `desired_candidates` remains the requested depth. Once target-aware
    evidence exists for a capability, that depth applies independently to every
    required target. A single cross-platform candidate may satisfy one slot on
    several targets. Research target evidence never asserts Library certification.
    """

    def _coverage(self, need: Need) -> TargetCoverageSnapshot:
        return load_target_coverage(self.state, need)

    def _need_complete(self, need: Need) -> bool:
        coverage = self._coverage(need)
        if coverage.tracked:
            return coverage.complete
        # Compatibility boundary: historical V1 submissions have no target-aware
        # research evidence. Do not silently reopen already completed legacy needs.
        return (
            self.state.count_completed_submissions(need.capability_id)
            >= need.desired_candidates
        )

    def _need_shortage(self, need: Need) -> int:
        coverage = self._coverage(need)
        if coverage.tracked:
            return coverage.total_gap
        completed = self.state.count_completed_submissions(need.capability_id)
        return max(0, need.desired_candidates - completed)

    def _rank_needs(self, needs: list[Need]) -> list[Need]:
        statuses = (
            {"needed", "researching", "satisfied"}
            if self.mode == ResearchMode.IMPROVEMENT
            else {"needed", "researching"}
        )
        active = [need for need in needs if need.status in statuses]
        if self.mode != ResearchMode.IMPROVEMENT:
            active = [need for need in active if not self._need_complete(need)]

        def key(need: Need) -> tuple[int, int, str]:
            shortage = self._need_shortage(need)
            last_scan = self.state.last_scan(need.capability_id) or ""
            return (_PRIORITY.get(need.priority, 99), -shortage, last_scan)

        return sorted(active, key=key)

    def _submit_dossier(
        self,
        need: Need,
        contract: Any,
        standard_version: str,
        dossier: Dossier,
    ) -> dict[str, Any] | None:
        summary = super()._submit_dossier(need, contract, standard_version, dossier)
        if summary is not None:
            coverage = record_target_coverage(
                self.state,
                need,
                dossier.fingerprint,
                dossier.candidate,
            )
            summary = dict(summary)
            summary["research_targets"] = list(
                candidate_research_targets(need, dossier.candidate)
            )
            summary["target_coverage"] = coverage.to_dict()
        return summary

    def _discover_for_gaps(
        self,
        need: Need,
        coverage: TargetCoverageSnapshot,
    ) -> list[Any]:
        missing_targets = tuple(
            target for target, gap in coverage.gaps.items() if gap > 0
        )
        if not missing_targets:
            missing_targets = need.targets
        limit = max(
            6,
            need.desired_candidates * max(2, len(missing_targets)) * 2,
        )
        targeted = getattr(self.discovery, "discover_for_targets", None)
        if callable(targeted):
            return list(targeted(need, missing_targets, limit=limit))
        return self.discovery.discover(need, limit=limit)

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
            coverage_before = self._coverage(need)
            self.state.set_json("current_capability", need.capability_id)
            self._emit(
                EventLevel.INFO,
                "need_selected",
                {
                    "capability_id": need.capability_id,
                    "mode": self.mode.value,
                    "target_coverage": coverage_before.to_dict(),
                },
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
                    "target_coverage": coverage_before.to_dict(),
                }

            # An orphan shortlist may cover several target gaps, so the upper bound
            # is the sum of all missing target slots. Duplicate target coverage is
            # harmless because record_target_coverage is fingerprint-idempotent.
            recovery_slots = max(need.desired_candidates, self._need_shortage(need))
            recovered = self._recover_orphan_shortlists(
                need,
                contract,
                standard_version,
                recovery_slots,
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

            coverage_after_recovery = self._coverage(need)
            if self.mode != ResearchMode.IMPROVEMENT and self._need_complete(need):
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
                    "target_coverage": coverage_after_recovery.to_dict(),
                }
                self.state.set_json("last_cycle", {"at": utc_now(), **result})
                self._emit(
                    EventLevel.INFO,
                    "cycle_completed",
                    {
                        "capability_id": need.capability_id,
                        "mode": self.mode.value,
                        "result": "COMPLETED",
                        "coverage_complete": coverage_after_recovery.complete,
                        "prepared_submissions": len(recovered),
                    },
                )
                return result

            candidates = self._discover_for_gaps(need, coverage_after_recovery)
            dossiers: list[Dossier] = []
            for candidate in candidates:
                from .dedup import candidate_fingerprint

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
                        "research_targets": list(
                            candidate_research_targets(need, candidate)
                        ),
                        "security_verdict": security_report.verdict.value,
                        "supply_chain_verdict": (
                            None if supply_chain is None else supply_chain.verdict.value
                        ),
                        "vulnerability_verdict": vulnerability_admission.report.verdict.value,
                    },
                )
                dossiers.append(dossier)

            all_rows = self.state.candidate_rows(need.capability_id)
            comparison_payload = self.comparisons.compare(need, dossiers)
            comparison_payload["known_candidates"] = all_rows
            comparison_payload["target_coverage_before"] = (
                coverage_after_recovery.to_dict()
            )
            comparison_path = self.dossiers.save_comparison(
                need.capability_id,
                comparison_payload,
            )

            shortlisted = [d for d in dossiers if d.lifecycle == "SHORTLISTED"]
            security_review = [d for d in dossiers if d.lifecycle == "SECURITY_REVIEW"]
            security_blocked = [d for d in dossiers if d.lifecycle == "SECURITY_BLOCKED"]
            review_reason_counts: dict[str, int] = {}
            for dossier in security_review:
                admission = dossier.security_evidence.get("admission_gate")
                vulnerability = dossier.security_evidence.get("vulnerability_gate")
                admission_eligible = bool(
                    isinstance(admission, dict) and admission.get("admission_eligible")
                )
                if admission_eligible and isinstance(vulnerability, dict):
                    report = vulnerability.get("vulnerability_report")
                    verdict = (
                        str(report.get("verdict", "unknown")).lower()
                        if isinstance(report, dict)
                        else "unknown"
                    )
                    reason = f"vulnerability_review:{verdict}"
                else:
                    verdict = (
                        str(admission.get("verdict", "unknown")).lower()
                        if isinstance(admission, dict)
                        else "unknown"
                    )
                    reason = f"security_review:{verdict}"
                review_reason_counts[reason] = review_reason_counts.get(reason, 0) + 1
            shortlist_payload = {
                "schema_version": 1,
                "capability_id": need.capability_id,
                "generated_at": utc_now(),
                "target_coverage_before": coverage_after_recovery.to_dict(),
                "candidates": [
                    {
                        "fingerprint": dossier.fingerprint,
                        "repository": dossier.candidate.repository,
                        "score": dossier.scores.recommendation,
                        "research_targets": list(
                            candidate_research_targets(need, dossier.candidate)
                        ),
                    }
                    for dossier in shortlisted
                ],
            }
            self.dossiers.save_shortlist(need.capability_id, shortlist_payload)

            prepared: list[dict[str, Any]] = []
            has_target_evidence = any(
                candidate_research_targets(need, dossier.candidate)
                for dossier in shortlisted
            )
            if coverage_after_recovery.tracked or has_target_evidence:
                selected = select_for_target_gaps(
                    need,
                    coverage_after_recovery,
                    shortlisted,
                )
            else:
                completed_now = self.state.count_completed_submissions(
                    need.capability_id
                )
                slots = max(0, need.desired_candidates - completed_now)
                selected = shortlisted[:slots]

            for dossier in selected:
                summary = self._submit_dossier(
                    need,
                    contract,
                    standard_version,
                    dossier,
                )
                if summary is not None:
                    prepared.append(summary)

            all_prepared = [*recovered, *prepared]
            coverage_after = self._coverage(need)
            comparison_payload["target_coverage_after"] = coverage_after.to_dict()
            self.dossiers.save_comparison(need.capability_id, comparison_payload)
            self.state.update_scan(need.capability_id, success=True)
            result = {
                "state": "COMPLETED",
                "mode": self.mode.value,
                "capability_id": need.capability_id,
                "discovered": len(candidates),
                "new_analyzed": len(dossiers),
                "shortlisted": len(shortlisted),
                "security_review": len(security_review),
                "security_review_reasons": dict(sorted(review_reason_counts.items())),
                "security_blocked": len(security_blocked),
                "recovered_submissions": recovered,
                "prepared_submissions": all_prepared,
                "comparison": str(comparison_path),
                "target_coverage": coverage_after.to_dict(),
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
                    "coverage_complete": coverage_after.complete,
                    "target_gap": coverage_after.total_gap,
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
