#!/usr/bin/env python3
"""Create and verify a deterministic NDABI evidence manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath


MANIFEST_NAME = "manifest.sha256.json"
SCHEMA = "ndabi-evidence-manifest-v1"
MAX_FILES = 10_000
MAX_FILE_BYTES = 1_073_741_824
MAX_MANIFEST_BYTES = 16_777_216
FORBIDDEN_NAMES = {".env", "api_keys.env"}
FORBIDDEN_SUFFIXES = {".jwt", ".key", ".pem", ".p12", ".pfx"}


class ManifestError(ValueError):
    """Report invalid or changed evidence without exposing evidence content."""


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ManifestError("the manifest contains a duplicate key")
        value[key] = item
    return value


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _validate_root(root: Path) -> Path:
    try:
        metadata = root.lstat()
    except OSError as error:
        raise ManifestError("the evidence root cannot be inspected") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ManifestError("the evidence root is not a regular directory")
    return root.resolve(strict=True)


def _validate_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or value != path.as_posix():
        raise ManifestError("the manifest contains an invalid evidence path")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestError("the manifest contains an unsafe evidence path")
    if value == MANIFEST_NAME:
        raise ManifestError("the manifest cannot describe itself")
    if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ManifestError("the evidence path identifies forbidden secret material")
    return path


def _walk_files(root: Path) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in directory_names:
            candidate = directory_path / name
            if candidate.is_symlink():
                raise ManifestError("the evidence tree contains a symbolic-link directory")
        for name in file_names:
            candidate = directory_path / name
            relative = candidate.relative_to(root).as_posix()
            if relative == MANIFEST_NAME:
                continue
            _validate_relative_path(relative)
            try:
                metadata = candidate.lstat()
            except OSError as error:
                raise ManifestError("an evidence file cannot be inspected") from error
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ManifestError("the evidence tree contains a non-regular file")
            if metadata.st_size > MAX_FILE_BYTES:
                raise ManifestError("an evidence file exceeds the size limit")
            files.append((relative, candidate))
            if len(files) > MAX_FILES:
                raise ManifestError("the evidence tree exceeds the file-count limit")
    files.sort(key=lambda item: item[0])
    return files


def _digest_file(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ManifestError("an evidence file cannot be opened safely") from error
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise ManifestError("an evidence file is not a bounded regular file")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise ManifestError("an evidence file cannot be read") from error
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ManifestError("an evidence file changed during hashing")
    return before.st_size, digest.hexdigest()


def build_manifest(root: Path) -> dict[str, object]:
    """Build one deterministic manifest without writing it."""
    root = _validate_root(root)
    entries = []
    for relative, path in _walk_files(root):
        size, digest = _digest_file(path)
        entries.append({"bytes": size, "path": relative, "sha256": digest})
    if not entries:
        raise ManifestError("the evidence tree is empty")
    return {
        "files": entries,
        "hash_algorithm": "sha256",
        "schema": SCHEMA,
    }


def write_manifest(root: Path) -> Path:
    """Write one manifest atomically after all evidence files stabilise."""
    root = _validate_root(root)
    manifest = build_manifest(root)
    encoded = _canonical_bytes(manifest)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".manifest-", dir=root)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
        destination = root / MANIFEST_NAME
        if destination.exists() or destination.is_symlink():
            try:
                destination_metadata = destination.lstat()
            except OSError as error:
                raise ManifestError("the manifest path cannot be inspected") from error
            if stat.S_ISLNK(destination_metadata.st_mode) or not stat.S_ISREG(
                destination_metadata.st_mode
            ):
                raise ManifestError("the manifest path is not a regular file")
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary.exists():
            temporary.unlink()


def _load_manifest(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ManifestError("the evidence manifest is absent") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ManifestError("the evidence manifest is not a regular file")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise ManifestError("the evidence manifest exceeds the size limit")
    try:
        encoded = path.read_bytes()
        value = json.loads(encoded, object_pairs_hook=_object_without_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError("the evidence manifest cannot be decoded") from error
    if not isinstance(value, dict) or _canonical_bytes(value) != encoded:
        raise ManifestError("the evidence manifest is not canonical")
    return value, encoded


def verify_manifest(root: Path) -> dict[str, object]:
    """Verify the manifest and reject changed or unexpected evidence files."""
    root = _validate_root(root)
    manifest, _ = _load_manifest(root / MANIFEST_NAME)
    if set(manifest) != {"files", "hash_algorithm", "schema"}:
        raise ManifestError("the evidence manifest has an invalid shape")
    if manifest["schema"] != SCHEMA or manifest["hash_algorithm"] != "sha256":
        raise ManifestError("the evidence manifest has an unsupported identity")
    entries = manifest["files"]
    if not isinstance(entries, list) or not entries or len(entries) > MAX_FILES:
        raise ManifestError("the evidence manifest has an invalid file list")
    expected_paths = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"bytes", "path", "sha256"}:
            raise ManifestError("the evidence manifest has an invalid file entry")
        relative = entry["path"]
        if not isinstance(relative, str):
            raise ManifestError("the evidence manifest has an invalid file path")
        _validate_relative_path(relative)
        expected_paths.append(relative)
        if not isinstance(entry["bytes"], int) or not 0 <= entry["bytes"] <= MAX_FILE_BYTES:
            raise ManifestError("the evidence manifest has an invalid file size")
        digest = entry["sha256"]
        if not isinstance(digest, str) or len(digest) != 64:
            raise ManifestError("the evidence manifest has an invalid digest")
        try:
            bytes.fromhex(digest)
        except ValueError as error:
            raise ManifestError("the evidence manifest has an invalid digest") from error
    if expected_paths != sorted(set(expected_paths)):
        raise ManifestError("the evidence manifest paths are not unique and ordered")
    actual = build_manifest(root)
    if manifest != actual:
        raise ManifestError("the evidence tree does not match the manifest")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("create", "verify"))
    parser.add_argument("root", type=Path)
    arguments = parser.parse_args()
    if arguments.operation == "create":
        write_manifest(arguments.root)
    else:
        verify_manifest(arguments.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
