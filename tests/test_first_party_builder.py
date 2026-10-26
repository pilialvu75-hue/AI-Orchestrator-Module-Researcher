from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from researcher.evolution import EvolutionWorkItem, EvolutionWorker
from researcher.first_party_builder import FirstPartyPilotBuilder, GATES


def _order(capability: str = "diagnostics.logging") -> dict:
    work = EvolutionWorkItem(
        "pilot-diagnostics-logging", capability, ("practice:stable-json",), GATES
    )
    return EvolutionWorker.prepare_builder_request(work)


class FirstPartyBuilderTests(unittest.TestCase):
    def test_real_candidate_files_and_checked_sandbox_argv(self) -> None:
        invoked: list[list[str]] = []

        def fake_docker(argv, **kwargs):
            invoked.append(argv)
            self.assertFalse(kwargs["check"])
            self.assertEqual(set(kwargs["env"]), {"PATH"})
            self.assertLessEqual(kwargs["timeout"], 120)
            self.assertIn("--network", argv)
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertIn("--read-only", argv)
            self.assertIn("no-new-privileges=true", argv)
            self.assertIn("--cap-drop", argv)
            self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
            self.assertNotIn("--privileged", argv)
            self.assertEqual(argv[argv.index("--pull") + 1], "never")
            marker = ("REGRESSION_OK" if "regression_check.py" in argv[-1]
                      else "IMPLEMENTATION_OK")
            return subprocess.CompletedProcess(argv, 0, marker + "\n", "")

        with tempfile.TemporaryDirectory() as root:
            result = FirstPartyPilotBuilder(runner=fake_docker).build(
                _order(), source_commit="a" * 40, output_dir=Path(root)
            )
            self.assertEqual(len(invoked), 2)
            self.assertTrue(result["evidence"]["implementation_tests_pass"])
            self.assertTrue(result["evidence"]["security_gates_pass"])
            self.assertTrue(result["evidence"]["regression_tests_pass"])
            self.assertFalse(result["evidence"]["library_contract_pass"])
            self.assertFalse(result["accepted"])
            self.assertTrue(result["library_intake_required"])
            archive = Path(root) / result["artifact_name"]
            self.assertTrue(archive.is_file())
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                             result["artifact_sha256"])
            with zipfile.ZipFile(archive) as zf:
                self.assertIn("eventlog.py", zf.namelist())
                self.assertIn("implementation_check.py", zf.namelist())
                manifest = json.loads(zf.read("candidate-manifest.json"))
                self.assertFalse(manifest["accepted"])
                self.assertNotIn("library_publish_allowed", manifest)

    def test_unsupported_capability_fails_before_execution(self) -> None:
        def should_not_run(*args, **kwargs):
            self.fail("untrusted capability was executed")

        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "unsupported"):
                FirstPartyPilotBuilder(runner=should_not_run).build(
                    _order("ai.local_inference"),
                    source_commit="a" * 40, output_dir=Path(root)
                )

    def test_rejects_publication_mutation_or_fake_gates(self) -> None:
        for patch in (
            {"library_publish_allowed": True},
            {"mutation_policy": "library_direct_write"},
            {"execution_boundary": "host"},
            {"acceptance_gates": list(GATES[:-1])},
            {"knowledge_delta": "not-a-list"},
            {"proposal_id": "../outside"},
        ):
            with self.subTest(patch=patch):
                with tempfile.TemporaryDirectory() as root:
                    order = {**_order(), **patch}
                    with self.assertRaises(ValueError):
                        FirstPartyPilotBuilder().build(
                            order, source_commit="a" * 40,
                            output_dir=Path(root)
                        )

    def test_failed_sandbox_never_self_certifies_candidate(self) -> None:
        def failed(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "failure")

        with tempfile.TemporaryDirectory() as root:
            result = FirstPartyPilotBuilder(runner=failed).build(
                _order(), source_commit="a" * 40, output_dir=Path(root)
            )
            self.assertFalse(result["accepted"])
            self.assertFalse(result["evidence"]["implementation_tests_pass"])
            self.assertFalse(result["evidence"]["security_gates_pass"])
            self.assertFalse(result["evidence"]["regression_tests_pass"])

    def test_unavailable_docker_is_not_a_pass(self) -> None:
        def unavailable(argv, **kwargs):
            raise FileNotFoundError("docker")

        with tempfile.TemporaryDirectory() as root:
            result = FirstPartyPilotBuilder(runner=unavailable).build(
                _order(), source_commit="a" * 40, output_dir=Path(root)
            )
            self.assertFalse(result["accepted"])
            self.assertFalse(result["execution_started"] is False)
            self.assertFalse(result["evidence"]["security_gates_pass"])

    def test_requires_real_source_commit(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "full SHA-1"):
                FirstPartyPilotBuilder().build(
                    _order(), source_commit="bad", output_dir=Path(root)
                )


if __name__ == "__main__":
    unittest.main()
