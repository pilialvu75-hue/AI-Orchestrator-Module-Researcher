import tempfile
import unittest
from pathlib import Path
from researcher.library import GitHubLibrarySource

class FeedbackTests(unittest.TestCase):
    def test_only_functional_passes(self):
        class Api:
            def get_json_file(self, repository, path, ref):
                assert path == "packages/development-index.json"
                base = dict(pin="module@0.1.0", package_sha256="a"*64,
                            validated_targets=["linux"])
                return {"packages": [
                    dict(base, development_qualified=True, independent_export_consumer="PASS"),
                    dict(base, pin="failed", development_qualified=True, independent_export_consumer="FAIL"),
                    dict(base, pin="pending", development_qualified=False, independent_export_consumer="PASS"),
                ]}
        with tempfile.TemporaryDirectory() as tmp:
            source = GitHubLibrarySource(Api(), "owner/library", "main", Path(tmp))
            result = source.load_development_feedback()
            self.assertFalse(result["used_cache"])
            self.assertEqual([p["pin"] for p in result["packages"]], ["module@0.1.0"])
