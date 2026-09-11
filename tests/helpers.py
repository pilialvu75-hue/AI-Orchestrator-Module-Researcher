from __future__ import annotations

from typing import Any

from researcher.models import Candidate, Contract, Need, utc_now


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
        license_file_url=f"https://api.github.com/repos/example/{name}/license",
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
