"""Narrow, audited first-party builder pilot; never runs arbitrary research code.

Only the in-repository diagnostics logging template is allowed. Docker runs with
no network, no secrets, an immutable image digest and read-only candidate mount.
The Library contract gate intentionally stays false until Library intake verifies it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Mapping

from .evolution import EvolutionWorkItem, EvolutionWorker
from .evolution_adapter import EvolutionAdapter
from .sandbox import DockerSandboxPlanner, SandboxInput

IMAGE = (
    "python@sha256:"
    "e8a38829209aea82774882e5157e1f7c3e8c8393ff53a697b3580896e57f345c"
)
GATES = (
    "implementation_tests_pass",
    "security_gates_pass",
    "regression_tests_pass",
    "library_contract_pass",
)
MODULE = '''"""First-party JSON diagnostics encoder. No network, disk or process access."""
import json


def encode_event(level: str, message: str) -> str:
    if level not in ("INFO", "WARN", "ERROR"):
        raise ValueError("unsupported log level")
    if not isinstance(message, str):
        raise TypeError("message must be text")
    return json.dumps({"level": level, "message": message},
                      ensure_ascii=False, sort_keys=True)
'''
IMPLEMENTATION_CHECK = '''import runpy
encoder = runpy.run_path("/candidate/eventlog.py")["encode_event"]
assert encoder("INFO", "ready") == '{"level": "INFO", "message": "ready"}'
assert encoder("WARN", "caffè") == '{"level": "WARN", "message": "caffè"}'
print("IMPLEMENTATION_OK")
'''
REGRESSION_CHECK = '''import runpy
encoder = runpy.run_path("/candidate/eventlog.py")["encode_event"]
for level in ("", "debug", "UNKNOWN"):
    try:
        encoder(level, "message")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid level accepted")
try:
    encoder("ERROR", None)
except TypeError:
    pass
else:
    raise AssertionError("invalid message accepted")
assert encoder("ERROR", "\\\\n") == '{"level": "ERROR", "message": "\\\\\\\\n"}'
print("REGRESSION_OK")
'''
_FILES = {
    "eventlog.py": MODULE,
    "implementation_check.py": IMPLEMENTATION_CHECK,
    "regression_check.py": REGRESSION_CHECK,
}
RunFunction = Callable[..., subprocess.CompletedProcess[str]]


def _validate_order(order: Mapping[str, Any]) -> EvolutionWorkItem:
    proposal = order.get("proposal_id")
    capability = order.get("capability_id")
    if not isinstance(proposal, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", proposal):
        raise ValueError("invalid builder proposal ID")
    if capability != "diagnostics.logging":
        raise ValueError("unsupported first-party builder capability")
    delta = order.get("knowledge_delta")
    if not isinstance(delta, list) or any(not isinstance(x, str) for x in delta):
        raise ValueError("invalid knowledge delta")
    if order.get("acceptance_gates") != list(GATES):
        raise ValueError("builder gates do not match the contract")
    work = EvolutionWorkItem(proposal, capability, tuple(delta), GATES)
    expected = EvolutionWorker.prepare_builder_request(work)
    for key in ("mutation_policy", "execution_boundary", "library_publish_allowed",
                "work_type", "required_output"):
        if order.get(key) != expected[key]:
            raise ValueError("builder request violates the isolated execution boundary")
    return work


class FirstPartyPilotBuilder:
    """Build a real Python candidate in an ephemeral stage; no Library writes."""

    def __init__(self, *, runner: RunFunction = subprocess.run) -> None:
        self.runner = runner

    def build(
        self, order: Mapping[str, Any], *, source_commit: str, output_dir: Path
    ) -> dict[str, Any]:
        work = _validate_order(order)
        if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
            raise ValueError("source commit must be a full SHA-1")
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        if output_dir.is_symlink():
            raise ValueError("output directory cannot be a symlink")

        results: dict[str, bool] = {gate: False for gate in GATES}
        traces: dict[str, str] = {}
        with tempfile.TemporaryDirectory(prefix="researcher-pilot-") as staging:
            stage = Path(staging)
            stage.chmod(0o755)  # The unprivileged Docker UID must read these files.
            for name, data in _FILES.items():
                path = stage / name
                path.write_text(data, encoding="utf-8")
                path.chmod(0o644)

            fingerprint = hashlib.sha256(
                b"".join(name.encode() + b"\0" + _FILES[name].encode()
                         for name in sorted(_FILES))
            ).hexdigest()
            source = SandboxInput(str(stage), fingerprint, source_commit, fingerprint)
            planner = DockerSandboxPlanner(IMAGE)
            checks = (
                ("implementation_tests_pass", "implementation_check.py", "IMPLEMENTATION_OK"),
                ("regression_tests_pass", "regression_check.py", "REGRESSION_OK"),
            )
            plans = [
                (gate, marker, planner.plan(source, ["python", "-I", "-B",
                                                      "/candidate/" + script]))
                for gate, script, marker in checks
            ]
            safe_plans = all(
                plan.network == "none"
                and plan.root_filesystem_read_only
                and plan.source_mount_read_only
                and plan.capabilities_dropped == ("ALL",)
                and plan.no_new_privileges
                and not plan.privileged
                and not plan.secrets_mounted
                and not plan.host_devices
                and plan.image == IMAGE
                for _, _, plan in plans
            )
            # Only the two checked-in verification scripts ever execute in Docker.
            # The generic sandbox planner remains non-executing for untrusted work.
            if safe_plans:
                for gate, marker, plan in plans:
                    try:
                        process = self.runner(
                            list(plan.argv), capture_output=True, text=True,
                            timeout=plan.limits.wall_clock_seconds, check=False,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        )
                        results[gate] = (
                            process.returncode == 0 and process.stdout.strip() == marker
                        )
                        traces[gate] = "pass" if results[gate] else "failed"
                    except (OSError, subprocess.TimeoutExpired):
                        traces[gate] = "sandbox unavailable or timed out"
                        results[gate] = False
            else:
                traces["security"] = "unsafe sandbox plan rejected"

            results["security_gates_pass"] = (
                safe_plans and all(results[gate] for gate, _, _ in plans)
                and all((stage / name).read_text(encoding="utf-8") == data
                        for name, data in _FILES.items())
            )
            # Only the Library's own separate admission can verify this gate.
            results["library_contract_pass"] = False
            candidate_ref = "artifact://researcher-pilot/" + fingerprint
            candidate = EvolutionAdapter().validate_result(
                work, candidate_ref=candidate_ref, gate_results=results
            )
            payload = candidate.as_dict()
            payload["library_intake_required"] = True
            payload["source_commit"] = source_commit
            payload["source_sha256"] = fingerprint
            payload["runtime_image"] = IMAGE
            payload["checks"] = traces
            payload["execution_started"] = bool(traces)
            archive = output_dir / ("candidate-" + fingerprint[:16] + ".zip")
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for name, data in sorted(_FILES.items()):
                    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    info.external_attr = 0o644 << 16
                    zf.writestr(info, data)
                info = zipfile.ZipInfo("candidate-manifest.json",
                                       (1980, 1, 1, 0, 0, 0))
                zf.writestr(info, json.dumps(payload, indent=2, sort_keys=True))
            payload["artifact_name"] = archive.name
            payload["artifact_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
            return payload
