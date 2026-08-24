import json
import os
import tempfile
import unittest
from pathlib import Path

import evidence_manifest_v80 as manifest


class EvidenceManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "aggregate.json").write_text('{"accepted":true}\n', encoding="utf-8")
        reports = self.root / "reports"
        reports.mkdir()
        (reports / "process-1.json.gz").write_bytes(b"deterministic evidence")

    def tearDown(self):
        self.temporary.cleanup()

    def test_created_manifest_verifies(self):
        path = manifest.write_manifest(self.root)
        verified = manifest.verify_manifest(self.root)
        self.assertEqual(path.name, manifest.MANIFEST_NAME)
        self.assertEqual(verified["schema"], manifest.SCHEMA)
        self.assertEqual(
            [entry["path"] for entry in verified["files"]],
            ["aggregate.json", "reports/process-1.json.gz"],
        )

    def test_parent_manifest_binds_a_nested_manifest(self):
        child = self.root / "stack-1"
        child.mkdir()
        (child / "aggregate.json").write_text("{}\n", encoding="utf-8")
        manifest.write_manifest(child)
        manifest.write_manifest(self.root)
        verified = manifest.verify_manifest(self.root)
        self.assertIn(
            "stack-1/manifest.sha256.json",
            [entry["path"] for entry in verified["files"]],
        )

    def test_changed_and_additional_files_refuse(self):
        manifest.write_manifest(self.root)
        (self.root / "aggregate.json").write_text('{"accepted":false}\n', encoding="utf-8")
        with self.assertRaisesRegex(manifest.ManifestError, "does not match"):
            manifest.verify_manifest(self.root)
        (self.root / "aggregate.json").write_text('{"accepted":true}\n', encoding="utf-8")
        (self.root / "unexpected.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(manifest.ManifestError, "does not match"):
            manifest.verify_manifest(self.root)

    def test_non_canonical_and_duplicate_manifest_keys_refuse(self):
        path = manifest.write_manifest(self.root)
        value = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(manifest.ManifestError, "not canonical"):
            manifest.verify_manifest(self.root)
        path.write_text(
            '{"files":[],"files":[],"hash_algorithm":"sha256","schema":"ndabi-evidence-manifest-v1"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(manifest.ManifestError, "duplicate key"):
            manifest.verify_manifest(self.root)

    def test_secret_and_symbolic_link_evidence_refuse(self):
        (self.root / "capture.jwt").write_text("secret", encoding="utf-8")
        with self.assertRaisesRegex(manifest.ManifestError, "secret material"):
            manifest.build_manifest(self.root)
        (self.root / "capture.jwt").unlink()
        if hasattr(os, "symlink"):
            os.symlink(self.root / "aggregate.json", self.root / "alias.json")
            with self.assertRaisesRegex(manifest.ManifestError, "non-regular"):
                manifest.build_manifest(self.root)

    def test_forged_parent_path_refuses(self):
        path = manifest.write_manifest(self.root)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["files"][0]["path"] = "../outside.json"
        path.write_bytes(manifest._canonical_bytes(value))
        with self.assertRaisesRegex(manifest.ManifestError, "unsafe evidence path"):
            manifest.verify_manifest(self.root)


if __name__ == "__main__":
    unittest.main()
