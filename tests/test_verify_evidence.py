import importlib.util
import gzip
import hashlib
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_evidence", ROOT / "verify_evidence.py"
)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class VerifyEvidenceTests(unittest.TestCase):
    def test_every_retained_manifest_resolves(self):
        self.assertEqual(len(VERIFY.MANIFESTS), 27)
        for manifest in VERIFY.MANIFESTS:
            self.assertTrue(manifest.is_file())

    def test_declared_incomplete_custody_remains_incomplete(self):
        report = VERIFY.verify_manifest(ROOT / "evidence" / "v34-failed" / "manifest.json")
        self.assertFalse(report["custody_complete"])

    def test_evidence_paths_cannot_escape_the_repository(self):
        with self.assertRaises(RuntimeError):
            VERIFY.resolve_bounded(Path("/etc/passwd"), (ROOT,))

    def test_duplicate_json_keys_fail_closed(self):
        with self.assertRaises(RuntimeError):
            VERIFY.reject_duplicate_keys([("status", "accepted"), ("status", "failed")])

    def test_gzip_custody_hashes_the_original_bytes(self):
        payload = b"exact retained binary bytes"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "binary.gz"
            with archive.open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as destination:
                    destination.write(payload)
            self.assertEqual(
                VERIFY.sha256_artifact(archive, "gzip"),
                hashlib.sha256(payload).hexdigest(),
            )

    def test_unknown_evidence_encoding_fails_closed(self):
        with self.assertRaises(RuntimeError):
            VERIFY.sha256_artifact(ROOT / "Cargo.toml", "unknown")


if __name__ == "__main__":
    unittest.main()
