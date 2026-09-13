from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable

from .security_gate import SourceArtifact


class SupplyChainVerdict(StrEnum):
    CLEAR = "CLEAR"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    NOT_ANALYZED = "NOT_ANALYZED"


class SupplyChainSeverity(StrEnum):
    NOTICE = "NOTICE"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class SupplyChainFinding:
    rule_id: str
    severity: SupplyChainSeverity
    path: str
    evidence: str


@dataclass(frozen=True)
class DependencyReference:
    ecosystem: str
    name: str
    constraint: str
    source: str
    manifest_path: str
    immutable: bool


@dataclass(frozen=True)
class SupplyChainReport:
    verdict: SupplyChainVerdict
    manifests_analyzed: tuple[str, ...]
    lockfiles_present: tuple[str, ...]
    dependencies: tuple[DependencyReference, ...]
    findings: tuple[SupplyChainFinding, ...]
    executed_untrusted_code: bool = False

    @property
    def admission_eligible(self) -> bool:
        return self.verdict == SupplyChainVerdict.CLEAR

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "admission_eligible": self.admission_eligible,
            "manifests_analyzed": list(self.manifests_analyzed),
            "lockfiles_present": list(self.lockfiles_present),
            "dependencies": [
                {
                    "ecosystem": item.ecosystem,
                    "name": item.name,
                    "constraint": item.constraint,
                    "source": item.source,
                    "manifest_path": item.manifest_path,
                    "immutable": item.immutable,
                }
                for item in self.dependencies
            ],
            "findings": [
                {
                    "rule_id": item.rule_id,
                    "severity": item.severity.value,
                    "path": item.path,
                    "evidence": item.evidence,
                }
                for item in self.findings
            ],
            "executed_untrusted_code": self.executed_untrusted_code,
            "vulnerability_database_checked": False,
        }


_LOCKFILE_NAMES = {
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pubspec.lock",
    "yarn.lock",
}
_MANIFEST_NAMES = {
    "cargo.toml",
    "go.mod",
    "package.json",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
}
_GIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def _finding(
    rule_id: str,
    severity: SupplyChainSeverity,
    path: str,
    evidence: str,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        evidence=" ".join(evidence.split())[:240],
    )


def _dependency(
    ecosystem: str,
    name: str,
    constraint: str,
    source: str,
    manifest_path: str,
    *,
    immutable: bool,
) -> DependencyReference:
    return DependencyReference(
        ecosystem=ecosystem,
        name=name,
        constraint=constraint[:500],
        source=source,
        manifest_path=manifest_path,
        immutable=immutable,
    )


def _npm_dependency_source(value: str) -> tuple[str, bool]:
    lower = value.lower().strip()
    if lower.startswith(("file:", "link:", "workspace:")):
        return "local_or_workspace", False
    if lower.startswith(("git:", "git+", "github:", "gitlab:", "bitbucket:")):
        fragment = value.rsplit("#", 1)[1] if "#" in value else ""
        return "git", bool(_GIT_SHA.fullmatch(fragment))
    if lower.startswith(("http://", "https://")):
        return "remote_archive_or_url", False
    return "registry", True


def _analyze_package_json(
    artifact: SourceArtifact,
) -> tuple[list[DependencyReference], list[SupplyChainFinding]]:
    dependencies: list[DependencyReference] = []
    findings: list[SupplyChainFinding] = []
    try:
        payload = json.loads(artifact.content)
    except json.JSONDecodeError as exc:
        return [], [
            _finding(
                "manifest_parse_failed",
                SupplyChainSeverity.REVIEW,
                artifact.path,
                f"package.json parse error: {exc.msg}",
            )
        ]
    if not isinstance(payload, dict):
        return [], [
            _finding(
                "manifest_shape_invalid",
                SupplyChainSeverity.REVIEW,
                artifact.path,
                "package.json root is not an object",
            )
        ]

    scripts = payload.get("scripts")
    if isinstance(scripts, dict):
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
            command = scripts.get(hook)
            if isinstance(command, str) and command.strip():
                findings.append(
                    _finding(
                        "npm_lifecycle_hook",
                        SupplyChainSeverity.REVIEW,
                        artifact.path,
                        f"{hook}: {command}",
                    )
                )

    for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        raw = payload.get(section)
        if not isinstance(raw, dict):
            continue
        for name, value in raw.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            source, immutable = _npm_dependency_source(value)
            dependencies.append(
                _dependency("npm", name, value, source, artifact.path, immutable=immutable)
            )
            if source == "git":
                findings.append(
                    _finding(
                        "git_dependency_requires_review",
                        SupplyChainSeverity.REVIEW,
                        artifact.path,
                        f"{name}: {value}",
                    )
                )
                if not immutable:
                    findings.append(
                        _finding(
                            "git_dependency_unpinned",
                            SupplyChainSeverity.REVIEW,
                            artifact.path,
                            f"{name}: Git dependency is not pinned to a 40-character commit",
                        )
                    )
            elif source in {"local_or_workspace", "remote_archive_or_url"}:
                findings.append(
                    _finding(
                        "non_registry_dependency_requires_review",
                        SupplyChainSeverity.REVIEW,
                        artifact.path,
                        f"{name}: {value}",
                    )
                )
    return dependencies, findings


def _pubspec_sections(content: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    section: str | None = None
    current_dependency: str | None = None
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            key = stripped[:-1].strip()
            section = key if key in {"dependencies", "dev_dependencies"} else None
            current_dependency = None
            continue
        if section is None:
            continue
        if indent == 2 and ":" in stripped:
            name, value = stripped.split(":", 1)
            current_dependency = name.strip()
            rows.append((current_dependency, "constraint", value.strip()))
            continue
        if indent >= 4 and current_dependency and ":" in stripped:
            key, value = stripped.split(":", 1)
            rows.append((current_dependency, key.strip(), value.strip().strip("'\"")))
    return rows


def _analyze_pubspec(
    artifact: SourceArtifact,
) -> tuple[list[DependencyReference], list[SupplyChainFinding]]:
    dependencies: list[DependencyReference] = []
    findings: list[SupplyChainFinding] = []
    rows = _pubspec_sections(artifact.content)
    grouped: dict[str, dict[str, str]] = {}
    for name, key, value in rows:
        grouped.setdefault(name, {})[key] = value

    for name, fields in grouped.items():
        constraint = fields.get("constraint", "")
        if constraint and constraint not in {"null", "{}"}:
            dependencies.append(
                _dependency("pub", name, constraint, "hosted", artifact.path, immutable=True)
            )
            continue
        if "path" in fields:
            value = fields["path"]
            dependencies.append(
                _dependency("pub", name, value, "path", artifact.path, immutable=False)
            )
            findings.append(
                _finding(
                    "path_dependency_requires_review",
                    SupplyChainSeverity.REVIEW,
                    artifact.path,
                    f"{name}: path {value}",
                )
            )
            continue
        if "git" in fields or "url" in fields:
            url = fields.get("git") or fields.get("url") or "git"
            ref = fields.get("ref", "")
            immutable = bool(_GIT_SHA.fullmatch(ref))
            rendered = f"{url} ref={ref or '<mutable/default>'}"
            dependencies.append(
                _dependency("pub", name, rendered, "git", artifact.path, immutable=immutable)
            )
            findings.append(
                _finding(
                    "git_dependency_requires_review",
                    SupplyChainSeverity.REVIEW,
                    artifact.path,
                    f"{name}: {rendered}",
                )
            )
            if not immutable:
                findings.append(
                    _finding(
                        "git_dependency_unpinned",
                        SupplyChainSeverity.REVIEW,
                        artifact.path,
                        f"{name}: Git ref is not an exact 40-character commit",
                    )
                )
    return dependencies, findings


def _toml_dependency_table(
    payload: dict[str, Any],
    section: str,
) -> dict[str, Any]:
    current: Any = payload
    for part in section.split("."):
        if not isinstance(current, dict):
            return {}
        current = current.get(part)
    return current if isinstance(current, dict) else {}


def _analyze_cargo_toml(
    artifact: SourceArtifact,
) -> tuple[list[DependencyReference], list[SupplyChainFinding]]:
    dependencies: list[DependencyReference] = []
    findings: list[SupplyChainFinding] = []
    try:
        payload = tomllib.loads(artifact.content)
    except tomllib.TOMLDecodeError as exc:
        return [], [
            _finding(
                "manifest_parse_failed",
                SupplyChainSeverity.REVIEW,
                artifact.path,
                f"Cargo.toml parse error: {exc}",
            )
        ]
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        raw = _toml_dependency_table(payload, section)
        for name, value in raw.items():
            if isinstance(value, str):
                dependencies.append(
                    _dependency("cargo", name, value, "registry", artifact.path, immutable=True)
                )
                continue
            if not isinstance(value, dict):
                continue
            if isinstance(value.get("git"), str):
                ref = str(value.get("rev") or "")
                rendered = f"{value['git']} rev={ref or '<mutable/default>'}"
                immutable = bool(_GIT_SHA.fullmatch(ref))
                dependencies.append(
                    _dependency("cargo", name, rendered, "git", artifact.path, immutable=immutable)
                )
                findings.append(
                    _finding(
                        "git_dependency_requires_review",
                        SupplyChainSeverity.REVIEW,
                        artifact.path,
                        f"{name}: {rendered}",
                    )
                )
                if not immutable:
                    findings.append(
                        _finding(
                            "git_dependency_unpinned",
                            SupplyChainSeverity.REVIEW,
                            artifact.path,
                            f"{name}: Cargo git dependency has no exact rev commit",
                        )
                    )
            elif isinstance(value.get("path"), str):
                dependencies.append(
                    _dependency(
                        "cargo",
                        name,
                        str(value["path"]),
                        "path",
                        artifact.path,
                        immutable=False,
                    )
                )
                findings.append(
                    _finding(
                        "path_dependency_requires_review",
                        SupplyChainSeverity.REVIEW,
                        artifact.path,
                        f"{name}: path {value['path']}",
                    )
                )
            else:
                version = str(value.get("version") or "")
                dependencies.append(
                    _dependency("cargo", name, version, "registry", artifact.path, immutable=True)
                )
    return dependencies, findings


def _analyze_pyproject(
    artifact: SourceArtifact,
) -> tuple[list[DependencyReference], list[SupplyChainFinding]]:
    dependencies: list[DependencyReference] = []
    findings: list[SupplyChainFinding] = []
    try:
        payload = tomllib.loads(artifact.content)
    except tomllib.TOMLDecodeError as exc:
        return [], [
            _finding(
                "manifest_parse_failed",
                SupplyChainSeverity.REVIEW,
                artifact.path,
                f"pyproject.toml parse error: {exc}",
            )
        ]
    project = payload.get("project")
    raw_dependencies = project.get("dependencies") if isinstance(project, dict) else None
    if isinstance(raw_dependencies, list):
        for raw in raw_dependencies:
            if not isinstance(raw, str):
                continue
            source = "registry"
            immutable = True
            lower = raw.lower()
            if " @ " in raw and ("git+" in lower or "http://" in lower or "https://" in lower):
                source = "direct_url"
                immutable = bool(re.search(r"@[0-9a-fA-F]{40}(?:[#?]|$)", raw))
                findings.append(
                    _finding(
                        "direct_url_dependency_requires_review",
                        SupplyChainSeverity.REVIEW,
                        artifact.path,
                        raw,
                    )
                )
            name_match = re.match(r"\s*([A-Za-z0-9_.-]+)", raw)
            name = name_match.group(1) if name_match else raw[:80]
            dependencies.append(
                _dependency("pypi", name, raw, source, artifact.path, immutable=immutable)
            )
    return dependencies, findings


def _analyze_requirements(
    artifact: SourceArtifact,
) -> tuple[list[DependencyReference], list[SupplyChainFinding]]:
    dependencies: list[DependencyReference] = []
    findings: list[SupplyChainFinding] = []
    for raw_line in artifact.content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith(("-e ", "--editable ", "git+", "http://", "https://", "file:")):
            source = "direct_or_editable"
            immutable = bool(re.search(r"@[0-9a-fA-F]{40}(?:[#?]|$)", line))
            findings.append(
                _finding(
                    "direct_url_dependency_requires_review",
                    SupplyChainSeverity.REVIEW,
                    artifact.path,
                    line,
                )
            )
            name = line[:80]
        else:
            source = "registry"
            immutable = True
            name_match = re.match(r"([A-Za-z0-9_.-]+)", line)
            name = name_match.group(1) if name_match else line[:80]
        dependencies.append(
            _dependency("pypi", name, line, source, artifact.path, immutable=immutable)
        )
    return dependencies, findings


def _analyze_go_mod(
    artifact: SourceArtifact,
) -> tuple[list[DependencyReference], list[SupplyChainFinding]]:
    dependencies: list[DependencyReference] = []
    findings: list[SupplyChainFinding] = []
    in_require = False
    for raw_line in artifact.content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("replace ") or " => " in line:
            findings.append(
                _finding(
                    "go_replace_requires_review",
                    SupplyChainSeverity.REVIEW,
                    artifact.path,
                    line,
                )
            )
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_require:
            continue
        fields = line.split()
        if len(fields) >= 2:
            dependencies.append(
                _dependency(
                    "go",
                    fields[0],
                    fields[1],
                    "module_proxy",
                    artifact.path,
                    immutable=True,
                )
            )
    return dependencies, findings


def analyze_supply_chain(artifacts: Iterable[SourceArtifact]) -> SupplyChainReport:
    material = tuple(artifacts)
    if not material:
        return SupplyChainReport(
            verdict=SupplyChainVerdict.NOT_ANALYZED,
            manifests_analyzed=(),
            lockfiles_present=(),
            dependencies=(),
            findings=(
                _finding(
                    "supply_chain_not_analyzed",
                    SupplyChainSeverity.REVIEW,
                    ".",
                    "no source artifacts were available",
                ),
            ),
        )

    lockfiles = sorted(
        artifact.path
        for artifact in material
        if artifact.path.rsplit("/", 1)[-1].lower() in _LOCKFILE_NAMES
    )
    manifests: list[str] = []
    dependencies: list[DependencyReference] = []
    findings: list[SupplyChainFinding] = []

    for artifact in material:
        name = artifact.path.rsplit("/", 1)[-1].lower()
        if name not in _MANIFEST_NAMES:
            continue
        manifests.append(artifact.path)
        if name == "package.json":
            deps, issues = _analyze_package_json(artifact)
        elif name == "pubspec.yaml":
            deps, issues = _analyze_pubspec(artifact)
        elif name == "cargo.toml":
            deps, issues = _analyze_cargo_toml(artifact)
        elif name == "pyproject.toml":
            deps, issues = _analyze_pyproject(artifact)
        elif name == "requirements.txt":
            deps, issues = _analyze_requirements(artifact)
        elif name == "go.mod":
            deps, issues = _analyze_go_mod(artifact)
        else:
            deps, issues = [], []
        dependencies.extend(deps)
        findings.extend(issues)

    for dependency in dependencies:
        if not _PACKAGE_NAME.fullmatch(dependency.name) and dependency.source == "registry":
            findings.append(
                _finding(
                    "dependency_name_requires_review",
                    SupplyChainSeverity.REVIEW,
                    dependency.manifest_path,
                    dependency.name,
                )
            )

    severities = {item.severity for item in findings}
    if SupplyChainSeverity.BLOCK in severities:
        verdict = SupplyChainVerdict.BLOCK
    elif SupplyChainSeverity.REVIEW in severities:
        verdict = SupplyChainVerdict.REVIEW
    elif manifests:
        verdict = SupplyChainVerdict.CLEAR
    else:
        verdict = SupplyChainVerdict.NOT_ANALYZED
        findings.append(
            _finding(
                "no_supported_dependency_manifest",
                SupplyChainSeverity.REVIEW,
                ".",
                "no supported dependency manifest was present in scanned source",
            )
        )

    return SupplyChainReport(
        verdict=verdict,
        manifests_analyzed=tuple(sorted(manifests)),
        lockfiles_present=tuple(lockfiles),
        dependencies=tuple(dependencies),
        findings=tuple(findings),
    )
