from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from researcher.app import build_app
from researcher.config import Config
from researcher.models import ResearchMode


class FailClosedTests(unittest.TestCase):
    @staticmethod
    def _config(tmp: str, *, allow_write: bool, library_token: str | None = None) -> Config:
        return Config(
            mode=ResearchMode.SEEDING,
            dry_run=False,
            allow_library_write=allow_write,
            github_token=None,
            library_repository="x/y",
            library_ref="main",
            data_dir=Path(tmp),
            maintenance_interval_seconds=3600,
            seeding_interval_seconds=900,
            improvement_interval_seconds=86400,
            dashboard_host="127.0.0.1",
            dashboard_port=8080,
            library_github_token=library_token,
        )

    def test_real_write_requires_second_switch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(tmp, allow_write=False)
            with self.assertRaisesRegex(RuntimeError, "Fail-closed"):
                build_app(config)

    def test_real_write_requires_dedicated_library_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(tmp, allow_write=True)
            with self.assertRaisesRegex(RuntimeError, "LIBRARY_GITHUB_TOKEN"):
                build_app(config)

    def test_real_write_accepts_dedicated_library_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(tmp, allow_write=True, library_token="test-library-token")
            app = build_app(config)
            self.assertIsNotNone(app.engine.submission)


if __name__ == "__main__":
    unittest.main()
