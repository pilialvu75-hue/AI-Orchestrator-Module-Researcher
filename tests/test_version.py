from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from researcher import __version__
from researcher.github_api import GitHubApi


ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_package_metadata_matches_runtime_version(self) -> None:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(__version__, "1.0.0")
        self.assertEqual(pyproject["project"]["version"], __version__)

    def test_default_github_user_agent_uses_runtime_version(self) -> None:
        api = GitHubApi(None)
        self.assertEqual(
            api._headers()["User-Agent"],  # noqa: SLF001 - release consistency check
            f"AI-Orchestrator-Module-Researcher/{__version__}",
        )


if __name__ == "__main__":
    unittest.main()
