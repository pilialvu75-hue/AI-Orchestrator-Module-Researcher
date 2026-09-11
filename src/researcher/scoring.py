from __future__ import annotations

from .analysis import (
    classify_license,
    integration_estimate,
    maintenance_evidence,
    security_evidence,
)
from .models import Candidate, Contract, Need, ScoreCard


class CandidateScorer:
    def score(
        self,
        need: Need,
        candidate: Candidate,
        contract: Contract | None,
    ) -> ScoreCard:
        maintenance = maintenance_evidence(candidate)
        license_info = classify_license(candidate.license_spdx)
        security = security_evidence(candidate)
        integration = integration_estimate(candidate, need)

        text = " ".join(
            [
                candidate.name,
                candidate.description or "",
                " ".join(candidate.topics),
                candidate.repository,
            ]
        ).lower()
        capability_terms = [
            term for term in need.capability_id.replace(".", " ").split() if len(term) >= 2
        ]
        title_terms = [term.strip("(),/").lower() for term in need.title.split() if len(term) >= 4]
        matched = sum(1 for term in capability_terms + title_terms if term.lower() in text)
        denominator = max(1, len(capability_terms + title_terms))
        functional_fit = min(1.0, 0.35 + 1.6 * (matched / denominator))

        platform_fit = 0.45
        lang = (candidate.language or "").lower()
        if "android" in need.targets and lang in {"dart", "kotlin", "java", "c++", "c", "rust"}:
            platform_fit += 0.20
        if "web" in need.targets and lang in {"typescript", "javascript", "dart", "rust"}:
            platform_fit += 0.15
        if "desktop" in need.targets:
            platform_fit += 0.10
        platform_fit = min(1.0, platform_fit)

        contract_fit = 0.75 if contract is not None else 0.0
        test_quality = 0.75 if candidate.extra.get("tests_present") else 0.35
        if candidate.extra.get("ci_present"):
            test_quality = min(1.0, test_quality + 0.15)
        documentation = 0.45
        if candidate.extra.get("readme_present"):
            documentation += 0.25
        if candidate.has_wiki:
            documentation += 0.10
        documentation = min(1.0, documentation)
        performance = 0.5
        footprint = 0.65
        if candidate.size_kb is not None:
            if candidate.size_kb < 10_000:
                footprint = 0.9
            elif candidate.size_kb > 200_000:
                footprint = 0.35

        metrics = {
            "functional_fit": functional_fit,
            "contract_fit": contract_fit,
            "maintenance": float(maintenance["score"]),
            "security": float(security["score"]),
            "license_fit": float(license_info["fit"]),
            "platform_fit": platform_fit,
            "test_quality": test_quality,
            "integration_cost": float(integration["score"]),
            "performance": performance,
            "footprint": footprint,
            "documentation": documentation,
        }
        weights = {
            "functional_fit": 0.17,
            "contract_fit": 0.13,
            "maintenance": 0.10,
            "security": 0.12,
            "license_fit": 0.10,
            "platform_fit": 0.10,
            "test_quality": 0.06,
            "integration_cost": 0.10,
            "performance": 0.04,
            "footprint": 0.04,
            "documentation": 0.04,
        }
        recommendation = sum(metrics[name] * weight for name, weight in weights.items())

        reasons = [
            f"functional keywords matched: {matched}/{denominator}",
            f"maintenance score: {maintenance['score']:.2f}",
            f"license: {license_info['classification']}",
            f"integration effort: {integration['effort']}",
            f"contract present: {contract is not None}",
            f"tests present signal: {bool(candidate.extra.get('tests_present'))}",
            f"CI present signal: {bool(candidate.extra.get('ci_present'))}",
        ]
        return ScoreCard(
            functional_fit=functional_fit,
            contract_fit=contract_fit,
            maintenance=float(maintenance["score"]),
            security=float(security["score"]),
            license_fit=float(license_info["fit"]),
            platform_fit=platform_fit,
            test_quality=test_quality,
            integration_cost=float(integration["score"]),
            performance=performance,
            footprint=footprint,
            documentation=documentation,
            recommendation=round(recommendation, 4),
            reasons=tuple(reasons),
        )
