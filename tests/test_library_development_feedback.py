import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from researcher.library import GitHubLibrarySource

class FeedbackTests(unittest.TestCase):
    def test_only_functional_passes(self):
        package = {
            "pin": "module@0.1.0", "capabilities": ["platform.clipboard"],
            "contracts": ["platform.clipboard.v1"], "source": {"source_repository": "owner/repo"},
        }
        digest = hashlib.sha256(json.dumps(
            package, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()).hexdigest()
        package_path = "packages/experimental/module/0.1.0/package.json"

        class Api:
            package_calls = 0

            def get_json_file(self, repository, path, ref):
                if path == package_path:
                    self.package_calls += 1
                    return {"package": package, "package_sha256": digest}
                if path == "packages/development-platform-evidence.json":
                    return {
                        "schema": "aivexus.development-platform-evidence.v1",
                        "records": [
                            dict(pin="module@0.1.0", package_sha256=digest,
                                 target="windows", run_id=1, job_id=2),
                            dict(pin="module@0.1.0", package_sha256="b"*64,
                                 target="macos", run_id=1, job_id=3),
                        ],
                    }
                assert path == "packages/development-index.json"
                base = dict(pin="module@0.1.0", package_sha256=digest,
                            validated_targets=["linux"], path=package_path)
                return {"packages": [
                    dict(base, development_qualified=True,
                         independent_export_consumer="PASS"),
                    dict(base, pin="failed", development_qualified=True,
                         independent_export_consumer="FAIL"),
                    dict(base, pin="pending", development_qualified=False,
                         independent_export_consumer="PASS"),
                ]}
        with tempfile.TemporaryDirectory() as tmp:
            api = Api()
            source = GitHubLibrarySource(api, "owner/library", "main", Path(tmp))
            result = source.load_development_feedback()
            self.assertFalse(result["used_cache"])
            self.assertEqual([p["pin"] for p in result["packages"]], ["module@0.1.0"])
            self.assertEqual(result["packages"][0]["validated_targets"],
                             ["linux", "windows"])
            self.assertEqual(result["packages"][0]["capabilities"], ["platform.clipboard"])
            self.assertEqual(result["packages"][0]["contracts"], ["platform.clipboard.v1"])
            self.assertEqual(source.load_development_feedback(), result)
            self.assertEqual(api.package_calls, 1)
            cache = Path(tmp) / f"development-package-{digest}.json"
            cache.write_text("invalid JSON", encoding="utf-8")
            self.assertEqual(source.load_development_feedback(), result)
            self.assertEqual(api.package_calls, 2)
            cache.unlink()
            package["contracts"] = ["tampered"]
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                source.load_development_feedback()

    def test_preview_is_not_functional_coverage(self):
        asset = {
            "id": "release.update_manager.original", "version": "0.1.0-dev.1",
            "path": "packages/aivexus_original_updater",
            "source_commit": "a"*40, "package_commit": "b"*40,
            "capabilities": ["release.update_manager"], "physical_ota": "pending",
        }

        class Api:
            def get_json_file(self, repository, path, ref):
                assert path == "catalog/first-party-preview.json"
                return {"schema": "aivexus.first-party-preview.v1", "assets": [asset]}

        with tempfile.TemporaryDirectory() as tmp:
            source = GitHubLibrarySource(Api(), "owner/library", "main", Path(tmp))
            result = source.load_first_party_previews()
            self.assertFalse(result["packages"][0]["functional_coverage"])
            self.assertEqual(result["packages"][0]["physical_ota"], "pending")
            asset["package_commit"] = "main"
            with self.assertRaisesRegex(ValueError, "immutable"):
                source.load_first_party_previews()
