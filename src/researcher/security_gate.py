from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class SecuritySeverity(StrEnum):
    REVIEW = "REVIEW"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityVerdict(StrEnum):
    CLEAR = "CLEAR"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    NOT_SCANNED = "NOT_SCANNED"


@dataclass(frozen=True)
class SourceArtifact:
    path: str
    content: str


@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    severity: SecuritySeverity
    path: str
    evidence: str


@dataclass(frozen=True)
class SecurityGateResult:
    verdict: SecurityVerdict
    findings: tuple[SecurityFinding, ...]
    scanned_files: int
    executed_untrusted_code: bool = False

    @property
    def certification_eligible(self) -> bool:
        return self.verdict == SecurityVerdict.CLEAR


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    severity: SecuritySeverity
    pattern: re.Pattern[str]


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "shell_download_execute",
        SecuritySeverity.CRITICAL,
        re.compile(
            r"(?:curl|wget)\b[^\n|;]*(?:\||&&|;)\s*(?:sh|bash|zsh|powershell|pwsh)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "credential_harvesting",
        SecuritySeverity.CRITICAL,
        re.compile(
            r"(?:GITHUB_TOKEN|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)"
            r".{0,120}(?:http|socket|upload|post|send)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    _Rule(
        "dynamic_remote_code",
        SecuritySeverity.CRITICAL,
        re.compile(
            r"(?:eval|exec)\s*\([^\n]{0,200}(?:http|https|base64|decode)",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "process_execution",
        SecuritySeverity.HIGH,
        re.compile(
            r"(?:subprocess\.|os\.system\(|Process\.start\(|Runtime\.getRuntime\(\)\.exec|child_process)",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "install_hook",
        SecuritySeverity.HIGH,
        re.compile(
            r"(?:postinstall|preinstall|prepare)\s*[\":=]",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "suspicious_obfuscation",
        SecuritySeverity.REVIEW,
        re.compile(
            r"(?:base64(?:decode|Decode)?|fromCharCode|String\.fromCharCodes)\s*\(",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "secret_environment_access",
        SecuritySeverity.REVIEW,
        re.compile(
            r"(?:os\.environ|Platform\.environment|process\.env|System\.getenv)",
            re.IGNORECASE,
        ),
    ),
)

_PUB_OVERRIDE = re.compile(
    r"(?m)^\s*dependency_overrides\s*:\s*(?:#.*)?$",
    re.IGNORECASE,
)


def _configuration_findings(artifact: SourceArtifact) -> list[SecurityFinding]:
    """Detect resolution controls that can pull code outside the admitted source scope."""
    name = artifact.path.rsplit("/", 1)[-1].lower()
    if name not in {"pubspec.yaml", "pubspec_overrides.yaml"}:
        return []
    match = _PUB_OVERRIDE.search(artifact.content)
    if match is None:
        return []
    return [
        SecurityFinding(
            rule_id="pub_dependency_override_requires_review",
            severity=SecuritySeverity.REVIEW,
            path=artifact.path,
            evidence="dependency_overrides changes package resolution and may reference code outside the admitted component",
        )
    ]


def scan_source_artifacts(artifacts: Iterable[SourceArtifact]) -> SecurityGateResult:
    """Static pre-screen only. Never executes candidate content."""
    material = tuple(artifacts)
    if not material:
        return SecurityGateResult(
            verdict=SecurityVerdict.NOT_SCANNED,
            findings=(),
            scanned_files=0,
        )

    findings: list[SecurityFinding] = []
    for artifact in material:
        findings.extend(_configuration_findings(artifact))
        for rule in _RULES:
            match = rule.pattern.search(artifact.content)
            if match is None:
                continue
            excerpt = " ".join(match.group(0).split())[:240]
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    path=artifact.path,
                    evidence=excerpt,
                )
            )

    severities = {finding.severity for finding in findings}
    if SecuritySeverity.CRITICAL in severities:
        verdict = SecurityVerdict.BLOCK
    elif SecuritySeverity.HIGH in severities or SecuritySeverity.REVIEW in severities:
        verdict = SecurityVerdict.REVIEW
    else:
        verdict = SecurityVerdict.CLEAR

    return SecurityGateResult(
        verdict=verdict,
        findings=tuple(findings),
        scanned_files=len(material),
    )
