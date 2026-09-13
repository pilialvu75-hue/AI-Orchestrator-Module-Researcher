from __future__ import annotations

import unittest

from researcher.sandbox import (
    DockerSandboxPlanner,
    SandboxInput,
    SandboxLimits,
    SandboxPolicyError,
)


_IMAGE = "researcher-sandbox@sha256:" + "a" * 64


def _source(path: str = "/quarantine/candidate-001") -> SandboxInput:
    return SandboxInput(
        staged_source_path=path,
        candidate_fingerprint="b" * 64,
        commit_sha="c" * 40,
        content_sha256="d" * 64,
    )


class SandboxPlannerTests(unittest.TestCase):
    def test_hardened_plan_is_non_executing_and_network_denied(self) -> None:
        planner = DockerSandboxPlanner(_IMAGE)
        plan = planner.plan(_source(), ["/runner/benchmark", "--case", "smoke"])
        self.assertFalse(plan.execution_enabled)
        self.assertEqual(plan.network, "none")
        self.assertTrue(plan.root_filesystem_read_only)
        self.assertEqual(plan.capabilities_dropped, ("ALL",))
        self.assertTrue(plan.no_new_privileges)
        self.assertTrue(plan.source_mount_read_only)
        self.assertFalse(plan.privileged)
        self.assertEqual(plan.host_devices, ())
        self.assertFalse(plan.secrets_mounted)

        argv = list(plan.argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("no-new-privileges=true", argv)
        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--memory", argv)
        self.assertIn("--cpus", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--device", argv)
        self.assertNotIn("-v", argv)
        self.assertNotIn("--env", argv)
        self.assertNotIn("-e", argv)
        self.assertTrue(
            any(
                item.startswith("type=bind,src=/quarantine/candidate-001")
                and item.endswith("dst=/candidate,readonly")
                for item in argv
            )
        )

    def test_image_must_be_digest_pinned(self) -> None:
        for image in ("ubuntu:latest", "ubuntu:24.04", "researcher-sandbox"):
            with self.subTest(image=image):
                with self.assertRaises(SandboxPolicyError):
                    DockerSandboxPlanner(image)

    def test_project_and_docker_socket_mounts_are_rejected(self) -> None:
        planner = DockerSandboxPlanner(_IMAGE)
        paths = (
            "/workspace/AI-Orchestrator-Module-Researcher",
            "/workspace/AI-Orchestrator-Module-Library",
            "/workspace/Ai-orchestrator-riserva",
            "/var/run/docker.sock",
            "/quarantine/.git/objects",
        )
        for path in paths:
            with self.subTest(path=path):
                with self.assertRaises(SandboxPolicyError):
                    planner.plan(_source(path), ["true"])

    def test_parent_traversal_and_broad_mounts_are_rejected(self) -> None:
        planner = DockerSandboxPlanner(_IMAGE)
        for path in ("/", "/tmp", "/var", "/home", "/quarantine/../etc"):
            with self.subTest(path=path):
                with self.assertRaises(SandboxPolicyError):
                    planner.plan(_source(path), ["true"])

    def test_resource_limits_are_bounded(self) -> None:
        with self.assertRaises(SandboxPolicyError):
            DockerSandboxPlanner(_IMAGE, SandboxLimits(cpus=8))
        with self.assertRaises(SandboxPolicyError):
            DockerSandboxPlanner(_IMAGE, SandboxLimits(memory_mb=8192))
        with self.assertRaises(SandboxPolicyError):
            DockerSandboxPlanner(_IMAGE, SandboxLimits(pids=1024))
        with self.assertRaises(SandboxPolicyError):
            DockerSandboxPlanner(_IMAGE, SandboxLimits(wall_clock_seconds=3600))

    def test_command_must_be_explicit_and_valid(self) -> None:
        planner = DockerSandboxPlanner(_IMAGE)
        with self.assertRaises(SandboxPolicyError):
            planner.plan(_source(), [])
        with self.assertRaises(SandboxPolicyError):
            planner.plan(_source(), ["bad\x00arg"])


if __name__ == "__main__":
    unittest.main()
