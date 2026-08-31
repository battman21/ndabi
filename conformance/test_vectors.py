"""Verify that the committed NDABI vectors match the Rust generator."""

from __future__ import annotations

import json
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "v0.1" / "vectors.json"
TRANSPORT_VECTORS = ROOT / "conformance" / "v0.2" / "transport-vectors.json"


class ConformanceVectorTests(unittest.TestCase):
    def test_rust_generator_matches_committed_vectors(self) -> None:
        completed = subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "-p",
                "ndabi-protocol",
                "--example",
                "ndabi_vectors_v01",
                "--locked",
            ],
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
        self.assertEqual(manifest["integer_encoding"], "decimal-string-for-64-bit")
        self.assertIsInstance(manifest["authority"]["generation"], str)
        self.assertIsInstance(manifest["valid"][0]["decoded"]["operation"]["first"], str)
        self.assertEqual(len(manifest["valid"]), 2)
        self.assertEqual(len(manifest["invalid"]), 7)
        self.assertEqual(len(manifest["sequences"]), 2)

    def test_transport_generator_matches_committed_vectors(self) -> None:
        completed = subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "-p",
                "ndabi-protocol",
                "--example",
                "ndabi_transport_vectors_v02",
                "--locked",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        generated = json.loads(completed.stdout)
        committed = json.loads(TRANSPORT_VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(generated, committed)

    def test_transport_manifest_covers_every_message_kind(self) -> None:
        manifest = json.loads(TRANSPORT_VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "ndabi-transport-conformance-v0.2")
        self.assertEqual(
            [vector["id"] for vector in manifest["valid"]],
            [
                "hello",
                "accept",
                "result",
                "error",
                "cancel",
                "stream-start",
                "stream-chunk",
                "stream-end",
                "bundle-accepted",
                "bundle-removed",
            ],
        )
        self.assertEqual(len(manifest["invalid"]), 6)
        self.assertEqual(manifest["invalid"][-1]["id"], "result-reflected-direction")


if __name__ == "__main__":
    unittest.main()
