from __future__ import annotations

import json
import tomllib
from collections.abc import Iterable

from .security_gate import SourceArtifact

DependencyKey = tuple[str, str]


def _pub_scopes(artifact: SourceArtifact) -> dict[DependencyKey, str]:
    scopes: dict[DependencyKey, str] = {}
    section: str | None = None
    for raw_line in artifact.content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            section_name = stripped[:-1].strip()
            if section_name == "dependencies":
                section = "runtime"
            elif section_name == "dev_dependencies":
                section = "development"
            else:
                section = None
            continue
        if section is None or indent != 2 or ":" not in stripped:
            continue
        name = stripped.split(":", 1)[0].strip()
        if not name:
            continue
        dependency_key = (artifact.path, name)
        if section == "runtime" or dependency_key not in scopes:
            scopes[dependency_key] = section
    return scopes


def _npm_scopes(artifact: SourceArtifact) -> dict[DependencyKey, str]:
    try:
        payload = json.loads(artifact.content)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    scopes: dict[DependencyKey, str] = {}
    for section in ("dependencies", "optionalDependencies", "peerDependencies"):
        raw = payload.get(section)
        if not isinstance(raw, dict):
            continue
        for name in raw:
            if isinstance(name, str) and name:
                scopes[(artifact.path, name)] = "runtime"
    raw_dev = payload.get("devDependencies")
    if isinstance(raw_dev, dict):
        for name in raw_dev:
            if not isinstance(name, str) or not name:
                continue
            dependency_key = (artifact.path, name)
            if dependency_key not in scopes:
                scopes[dependency_key] = "development"
    return scopes


def _record_scope(
    scopes: dict[DependencyKey, str],
    dependency_key: DependencyKey,
    scope: str,
) -> None:
    current = scopes.get(dependency_key)
    if current == "runtime":
        return
    if scope == "runtime":
        scopes[dependency_key] = scope
        return
    if scope == "build" and current in {None, "development"}:
        scopes[dependency_key] = scope
        return
    if scope == "development" and current is None:
        scopes[dependency_key] = scope


def _cargo_table_scopes(
    table: object,
    artifact: SourceArtifact,
    scopes: dict[DependencyKey, str],
) -> None:
    if not isinstance(table, dict):
        return
    for section, scope in (
        ("dependencies", "runtime"),
        ("build-dependencies", "build"),
        ("dev-dependencies", "development"),
    ):
        raw = table.get(section)
        if not isinstance(raw, dict):
            continue
        for name in raw:
            if not isinstance(name, str) or not name:
                continue
            _record_scope(scopes, (artifact.path, name), scope)


def _cargo_scopes(artifact: SourceArtifact) -> dict[DependencyKey, str]:
    try:
        payload = tomllib.loads(artifact.content)
    except tomllib.TOMLDecodeError:
        return {}
    scopes: dict[DependencyKey, str] = {}
    _cargo_table_scopes(payload, artifact, scopes)
    targets = payload.get("target")
    if isinstance(targets, dict):
        for target_table in targets.values():
            _cargo_table_scopes(target_table, artifact, scopes)
    return scopes


def dependency_scope_map(
    artifacts: Iterable[SourceArtifact],
) -> dict[DependencyKey, str]:
    """Classify dependency sections without executing package-manager code.

    Unknown manifests intentionally produce no classification. Callers must then
    keep the dependency in the admission SBOM rather than assuming it is development-only.
    """

    scopes: dict[DependencyKey, str] = {}
    for artifact in artifacts:
        name = artifact.path.rsplit("/", 1)[-1].lower()
        if name == "pubspec.yaml":
            scopes.update(_pub_scopes(artifact))
        elif name == "package.json":
            scopes.update(_npm_scopes(artifact))
        elif name == "cargo.toml":
            scopes.update(_cargo_scopes(artifact))
    return scopes
