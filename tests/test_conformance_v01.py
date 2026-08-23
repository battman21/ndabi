"""Verify that the committed NDABI vectors match the Rust generator."""

from __future__ import annotations

import json
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "v0.1" / "vectors.json"


class ConformanceVectorTests(unittest.TestCase):
    def test_rust_generator_matches_committed_vectors(self) -> None:
        completed = subprocess.run(
            ["cargo", "run", "--quiet", "--bin", "ndabi_vectors_v01", "--locked"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        generated = json.loads(completed.stdout)
        committed = json.loads(VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(generated, committed)

    def test_manifest_has_cross_language_security_cases(self) -> None:
        manifest = json.loads(VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "ndabi-conformance-v0.1")
        self.assertEqual(len(manifest["valid"]), 2)
        self.assertEqual(len(manifest["invalid"]), 7)
        self.assertEqual(len(manifest["sequences"]), 2)


if __name__ == "__main__":
    unittest.main()
