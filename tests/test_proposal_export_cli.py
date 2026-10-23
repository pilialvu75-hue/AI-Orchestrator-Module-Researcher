from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ProposalExportCliTests(unittest.TestCase):
    def test_export_reads_existing_database_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = root / "researcher.db"
            with sqlite3.connect(database) as conn:
                conn.execute(
                    "CREATE TABLE improvement_proposals ("
                    "proposal_id TEXT, capability_id TEXT, novelty_json TEXT, "
                    "acceptance_gates_json TEXT, created_at TEXT, state TEXT)"
                )
                conn.execute(
                    "INSERT INTO improvement_proposals VALUES (?, ?, ?, ?, ?, ?)",
                    ("a" * 64, "ai.local_inference", '["topic:quantization"]',
                     '["security_gates_pass"]', "2026-10-23T00:00:00Z", "PROPOSED"),
                )
            before = database.read_bytes()
            env = dict(os.environ)
            env["DATA_DIR"] = str(root)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            result = subprocess.run(
                [sys.executable, "-m", "researcher", "export-improvement-proposals"],
                env=env, capture_output=True, text=True, check=True, timeout=30,
            )
            payload = json.loads(result.stdout)
            self.assertEqual(payload["proposals"][0]["proposal_id"], "a" * 64)
            self.assertEqual(database.read_bytes(), before)

    def test_export_excludes_non_proposed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with sqlite3.connect(root / "researcher.db") as conn:
                conn.execute(
                    "CREATE TABLE improvement_proposals ("
                    "proposal_id TEXT, capability_id TEXT, novelty_json TEXT, "
                    "acceptance_gates_json TEXT, created_at TEXT, state TEXT)"
                )
                for identifier, state in (("a" * 64, "PROPOSED"),
                                          ("b" * 64, "QUEUED"),
                                          ("c" * 64, "REJECTED")):
                    conn.execute(
                        "INSERT INTO improvement_proposals VALUES (?, ?, ?, ?, ?, ?)",
                        (identifier, "ai.local_inference", '["topic:quantization"]',
                         '["security_gates_pass"]', "2026-10-23T00:00:00Z", state),
                    )
            env = dict(os.environ)
            env["DATA_DIR"] = str(root)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            result = subprocess.run(
                [sys.executable, "-m", "researcher", "export-improvement-proposals"],
                env=env, capture_output=True, text=True, check=True, timeout=30,
            )
            proposals = json.loads(result.stdout)["proposals"]
            self.assertEqual([p["proposal_id"] for p in proposals], ["a" * 64])

    def test_missing_database_does_not_create_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            env = dict(os.environ)
            env["DATA_DIR"] = str(root)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            result = subprocess.run(
                [sys.executable, "-m", "researcher", "export-improvement-proposals"],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "researcher.db").exists())


if __name__ == "__main__":
    unittest.main()
