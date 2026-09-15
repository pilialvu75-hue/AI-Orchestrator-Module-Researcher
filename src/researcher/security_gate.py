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


_SECRET_NAME = (  # nosec B105 - regex matches identifier names, not credential values
    r"(?:GITHUB_TOKEN|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)"
)
_EXFIL_SINK = (
    r"(?:requests\.(?:get|post|put|patch)|httpx\.(?:get|post|put|patch)|"
    r"urllib\.request\.(?:Request|urlopen)|socket\.(?:send|sendall)|"
    r"fetch\s*\(|axios\.(?:get|post|put|patch)|curl\b)"
)

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
            rf"{_EXFIL_SINK}.{{0,400}}{_SECRET_NAME}\b",
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
            r"(?:subprocess\.|os\.system\(|Process\.start\(|"
            r"Runtime\.getRuntime\(\)\.exec|child_process)",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "tls_certificate_validation_bypass",
        SecuritySeverity.HIGH,
        re.compile(
            r"(?:TrustAllX509TrustManager|acceptUntrustedCertificates|"
            r"Bypassing\s+TLS\s+certificate\s+validation|"
            r"badCertificateCallback\s*=|rejectUnauthorized\s*:\s*false|"
            r"verify\s*=\s*false|setDefaultSSLSocketFactory\s*\()",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "install_hook",
        SecuritySeverity.HIGH,
        re.compile(
            r"['\"](?:postinstall|preinstall|prepare)['\"]\s*:",
            re.IGNORECASE,
        ),
    ),
)

_PUB_OVERRIDE = re.compile(
    r"(?m)^\s*dependency_overrides\s*:\s*(?:#.*)?$",
    re.IGNORECASE,
)
_ENV_ACCESS = re.compile(
    r"(?:os\.environ\b|os\.getenv\b|Platform\.environment\b|process\.env\b|"
    r"System\.getenv\b)",
    re.IGNORECASE,
)
_SECRET_ENV_HINT = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|API[_-]?KEY|"
    r"CREDENTIAL|AWS_|GITHUB_|OPENAI_)",
    re.IGNORECASE,
)
_ENV_NAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"Platform\.environment\s*(?:\[\s*['\"]([^'\"]+)['\"]\s*\]|"
        r"\.containsKey\(\s*['\"]([^'\"]+)['\"]\s*\))",
        re.IGNORECASE,
    ),
    re.compile(
        r"os\.environ\s*(?:\[\s*['\"]([^'\"]+)['\"]\s*\]|"
        r"\.get\(\s*['\"]([^'\"]+)['\"])",
        re.IGNORECASE,
    ),
    re.compile(
        r"os\.getenv\s*\(\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    ),
    re.compile(
        r"process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|"
        r"\[\s*['\"]([^'\"]+)['\"]\s*\])",
        re.IGNORECASE,
    ),
    re.compile(
        r"System\.getenv\s*\(\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    ),
)
_NETWORK_SINK = re.compile(_EXFIL_SINK, re.IGNORECASE)
_ENCODING_PRIMITIVE = re.compile(
    r"(?:base64(?:decode|Decode)?|base64\.b64decode|fromCharCode|"
    r"String\.fromCharCodes)\s*\(",
    re.IGNORECASE,
)
_EXECUTION_OR_NETWORK_SINK = re.compile(
    rf"(?:{_EXFIL_SINK}|eval\s*\(|exec\s*\(|subprocess\.|os\.system\(|"
    r"Process\.start\(|Runtime\.getRuntime\(\)\.exec|child_process)",
    re.IGNORECASE,
)


def _context(content: str, match: re.Match[str], radius: int = 600) -> str:
    start = max(0, match.start() - radius)
    end = min(len(content), match.end() + radius)
    return content[start:end]


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
            evidence=(
                "dependency_overrides changes package resolution and may reference "
                "code outside the admitted component"
            ),
        )
    ]


def _direct_environment_names(content: str) -> tuple[str, ...]:
    names: list[str] = []
    for pattern in _ENV_NAME_PATTERNS:
        for match in pattern.finditer(content):
            value = next((group for group in match.groups() if group), None)
            if value:
                names.append(value)
    return tuple(names)


def _environment_findings(artifact: SourceArtifact) -> list[SecurityFinding]:
    """Review actual secret env keys or broad env access adjacent to outbound traffic."""
    findings: list[SecurityFinding] = []
    secret_name = next(
        (
            name
            for name in _direct_environment_names(artifact.content)
            if _SECRET_ENV_HINT.search(name)
        ),
        None,
    )
    if secret_name is not None:
        findings.append(
            SecurityFinding(
                rule_id="secret_environment_access",
                severity=SecuritySeverity.REVIEW,
                path=artifact.path,
                evidence=f"environment key resembles a secret: {secret_name[:120]}",
            )
        )

    for match in _ENV_ACCESS.finditer(artifact.content):
        nearby = _context(artifact.content, match)
        if _NETWORK_SINK.search(nearby) is None:
            continue
        findings.append(
            SecurityFinding(
                rule_id="environment_exfiltration_requires_review",
                severity=SecuritySeverity.HIGH,
                path=artifact.path,
                evidence="environment access near outbound network operation",
            )
        )
        break
    return findings


def _obfuscation_findings(artifact: SourceArtifact) -> list[SecurityFinding]:
    """Treat encoding primitives as suspicious only when coupled to a risky sink."""
    for match in _ENCODING_PRIMITIVE.finditer(artifact.content):
        nearby = _context(artifact.content, match)
        if _EXECUTION_OR_NETWORK_SINK.search(nearby) is None:
            continue
        excerpt = " ".join(match.group(0).split())[:240]
        return [
            SecurityFinding(
                rule_id="suspicious_obfuscation",
                severity=SecuritySeverity.REVIEW,
                path=artifact.path,
                evidence=excerpt,
            )
        ]
    return []


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
        findings.extend(_environment_findings(artifact))
        findings.extend(_obfuscation_findings(artifact))
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
