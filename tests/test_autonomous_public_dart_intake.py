"""End-to-end offline tests for Researcher's automatic public-source acquisition."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from autonomous_public_dart_intake import acquire, discover, known, payload_digest  # noqa: E402


class AutonomousPublicDartTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.library = self.root / "library"
        (self.library / "catalog").mkdir(parents=True)
        (self.library / "catalog/needs.json").write_text(
            json.dumps({"items": [{"capability_id": "platform.filesystem",
                                   "status": "needed"}]}))
        self.repo = self.root / "source"
        self.repo.mkdir()
        def git(*parts):
            return subprocess.run(["git", *parts], cwd=self.repo,
                                  capture_output=True, check=True).stdout
        git("init", "-q")
        git("config", "user.email", "ci@example.invalid")
        git("config", "user.name", "Source Fixture")
        folder = self.repo / "pkgs/path"
        (folder / "lib").mkdir(parents=True)
        (folder / "pubspec.yaml").write_text(
            "name: path\nversion: 1.9.1\nenvironment:\n  sdk: ^3.4.0\n")
        (folder / "LICENSE").write_text(
            "Copyright source owner. Redistribution and use in source and binary forms\n"
            "Neither the name of the copyright holder nor contributors may be used.\n")
        (folder / "lib/path.dart").write_text("library path;\n")
        git("add", ".")
        git("commit", "-qm", "real public git fixture")

    def test_stable_tag_selection_skips_existing_and_unneeded(self):
        tags = (
            "a" * 40 + " refs/tags/path-v1.9.0\n" +
            "b" * 40 + " refs/tags/path-v1.9.1\n" +
            "c" * 40 + " refs/tags/characters-v1.4.0\n" +
            "d" * 40 + " refs/tags/path-v2.0.0-wip\n"
        ).encode()
        self.assertEqual(
            ("path", "path-v1.9.1", "1.9.1"),
            discover(tags, set(), {"platform.filesystem"})[0])
        self.assertEqual(
            [("characters", "characters-v1.4.0", "1.4.0")],
            discover(tags, {"path"}, {"platform.filesystem"}))
        self.assertEqual([], discover(tags, set(), {"voice.tts"}))

    def test_materializes_git_bytes_and_functional_adapter_unapproved(self):
        result = acquire(self.library, "path", "path-v1.9.1", "1.9.1", self.repo)
        self.assertEqual("NORMALIZED_NOT_TESTED", result["state"])
        self.assertTrue(result["source_materialized"])
        self.assertFalse(result["certification_authorized"])
        self.assertFalse(result["independent_security_reviewed"])
        stage = self.library / "sandbox/researcher_public_dart/path"
        source = stage / "payload/src"
        self.assertEqual((self.repo / "pkgs/path/lib/path.dart").read_bytes(),
                         (source / "vendor/path/lib/path.dart").read_bytes())
        self.assertEqual(result["payload_sha256"], payload_digest(source))
        self.assertIn("path", known(self.library))
        self.assertIn("real path functionality",
                      (source / "tool/self_test.dart").read_text())
        with self.assertRaises(ValueError):
            acquire(self.library, "path", "path-v1.9.1", "1.9.1", self.repo)

    def test_stable_version_mismatch_rejected_without_creating_a_module(self):
        with self.assertRaisesRegex(ValueError, "version"):
            acquire(self.library, "path", "path-v1.9.2", "1.9.2", self.repo)
        self.assertFalse((self.library / "sandbox").exists())

    def test_symlink_source_fails_closed(self):
        ln = self.repo / "pkgs/path/lib/escape.dart"
        ln.symlink_to("/tmp/unsafe")
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add symlink"], cwd=self.repo, check=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            acquire(self.library, "path", "path-v1.9.1", "1.9.1", self.repo)


if __name__ == "__main__":
    unittest.main()
