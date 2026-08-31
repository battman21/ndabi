from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "create_release_bundle.py"
SPEC = importlib.util.spec_from_file_location("create_release_bundle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "NDABI test")
        self.git("config", "user.email", "ndabi-test@example.invalid")
        for path, contents in {
            "Cargo.lock": "lock\n",
            "rust-toolchain.toml": "[toolchain]\nchannel = \"1.92\"\n",
            "LICENSE": "Apache-2.0 test fixture\n",
            "src/lib.rs": "pub const VALUE: u8 = 1;\n",
        }.items():
            destination = self.repository / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(contents, encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture")
        self.git("tag", "v0.2.0-beta.1")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.repository), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def create(self, output: Path) -> dict[str, object]:
        return MODULE.create_release_bundle(
            self.repository,
            output,
            "v0.2.0-beta.1",
            allow_unsigned=True,
        )

    def test_bundle_is_reproducible_and_contains_only_the_tagged_tree(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        first_manifest = self.create(first)
        second_manifest = self.create(second)
        for suffix in ("tar.gz", "manifest.json", "sha256"):
            name = f"ndabi-v0.2.0-beta.1.{suffix}"
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        archive = first / "ndabi-v0.2.0-beta.1.tar.gz"
        manifest_path = first / "ndabi-v0.2.0-beta.1.manifest.json"
        checksums = {
            name: digest
            for digest, name in (
                line.split("  ", 1)
                for line in (first / "ndabi-v0.2.0-beta.1.sha256")
                .read_text(encoding="utf-8")
                .splitlines()
            )
        }
        self.assertEqual(checksums[archive.name], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(
            checksums[manifest_path.name],
            hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["source_archive"]["sha256"], checksums[archive.name])
        with gzip.open(archive, "rb") as source:
            with tarfile.open(fileobj=source, mode="r:") as contents:
                names = contents.getnames()
        self.assertTrue(names)
        self.assertTrue(
            all(
                name == "ndabi-v0.2.0-beta.1"
                or name.startswith("ndabi-v0.2.0-beta.1/")
                for name in names
            )
        )
        self.assertFalse(any("/.git" in name for name in names))
        self.assertEqual(first_manifest, second_manifest)

    def test_bundle_refuses_a_dirty_checkout(self) -> None:
        (self.repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ReleaseError, "checkout is dirty"):
            self.create(self.root / "output")

    def test_bundle_requires_an_authorised_signer_without_the_test_override(self) -> None:
        with self.assertRaisesRegex(MODULE.ReleaseError, "signer fingerprint is required"):
            MODULE.create_release_bundle(
                self.repository,
                self.root / "output",
                "v0.2.0-beta.1",
            )

    def test_bundle_refuses_a_changed_existing_artefact(self) -> None:
        output = self.root / "output"
        self.create(output)
        archive = output / "ndabi-v0.2.0-beta.1.tar.gz"
        archive.write_bytes(b"changed")
        with self.assertRaisesRegex(MODULE.ReleaseError, "artefact differs"):
            self.create(output)

    def test_preflight_refusal_does_not_write_a_partial_release_set(self) -> None:
        output = self.root / "output"
        output.mkdir()
        manifest = output / "ndabi-v0.2.0-beta.1.manifest.json"
        manifest.write_bytes(b"changed")
        with self.assertRaisesRegex(MODULE.ReleaseError, "artefact differs"):
            self.create(output)
        self.assertFalse((output / "ndabi-v0.2.0-beta.1.tar.gz").exists())
        self.assertFalse((output / "ndabi-v0.2.0-beta.1.sha256").exists())


if __name__ == "__main__":
    unittest.main()
