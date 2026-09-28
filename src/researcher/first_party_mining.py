from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .component_candidate import resolve_and_admit_component_candidate

if TYPE_CHECKING:
    from .app import App


def run_one_first_party_candidate(app: App) -> dict[str, Any]:
    if not app.config.first_party_source_github_token:
        return {
            "state": "IDLE",
            "reason": "first_party_source_credential_unavailable",
        }

    loader = getattr(app.engine.need_source, "load_first_party_sources", None)
    if not callable(loader):
        return {"state": "IDLE", "reason": "first_party_catalog_unavailable"}

    sources, metadata = loader()
    needs, _ = app.engine.need_source.load_needs()
    active = {
        need.capability_id
        for need in needs
        if need.status in {"needed", "researching", "satisfied"}
    }

    for source in sources:
        repository = str(source.get("repository") or "")
        commit_sha = source.get("source_commit")
        if not commit_sha:
            continue
        for item in source.get("candidates", []):
            if not isinstance(item, dict):
                continue
            capability_id = str(item.get("capability_id") or "")
            component_path = str(item.get("component_path") or "")
            if capability_id not in active or not component_path:
                continue
            result = resolve_and_admit_component_candidate(
                app,
                capability_id,
                repository,
                str(commit_sha),
                component_path=component_path,
            )
            if result.get("state") == "EXISTING":
                continue
            return {
                "state": "COMPLETE",
                "catalog": metadata,
                "candidate": result,
            }

    return {
        "state": "IDLE",
        "reason": "no_eligible_first_party_candidate",
        "catalog": metadata,
    }
