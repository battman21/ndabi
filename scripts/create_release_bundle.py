#!/usr/bin/env python3
"""Create a deterministic NDABI source release bundle from one signed Git tag."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Sequence


MANIFEST_SCHEMA = "ndabi-source-release-v1"
REPOSITORY_URL = "https://github.com/battman21/ndabi"
TAG_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
PINNED_INPUTS = ("Cargo.lock", "rust-toolchain.toml", "LICENSE")


class ReleaseError(RuntimeError):
    """Report a release refusal without a Python traceback."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(repository: Path, arguments: Sequence[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseError(error or f"git {' '.join(arguments)} failed")
    return result.stdout


def committed_file(repository: Path, commit: str, path: str) -> bytes:
    return run_git(repository, ["show", f"{commit}:{path}"])


def deterministic_gzip(data: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as archive:
        archive.write(data)
    return output.getvalue()


def write_expected(path: Path, data: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            raise ReleaseError(f"the existing release artefact differs: {path}")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_release_set(output_directory: Path, artefacts: dict[str, bytes]) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    for name, data in artefacts.items():
        path = output_directory / name
        if path.exists() and (not path.is_file() or path.read_bytes() != data):
            raise ReleaseError(f"the existing release artefact differs: {path}")
    for name, data in artefacts.items():
        write_expected(output_directory / name, data)


def create_release_bundle(
    repository: Path,
    output_directory: Path,
    tag: str,
    *,
    allow_unsigned: bool = False,
    signer_fingerprint: str | None = None,
) -> dict[str, object]:
    repository = repository.resolve()
    if TAG_PATTERN.fullmatch(tag) is None:
        raise ReleaseError("the release tag contains unsupported characters")
    run_git(repository, ["rev-parse", "--is-inside-work-tree"])
    if run_git(repository, ["status", "--porcelain", "--untracked-files=normal"]):
        raise ReleaseError("the release checkout is dirty")

    head = run_git(repository, ["rev-parse", "HEAD"]).decode().strip()
    tag_ref = f"refs/tags/{tag}^{{commit}}"
    tag_commit = run_git(repository, ["rev-parse", "--verify", tag_ref]).decode().strip()
    if tag_commit != head:
        raise ReleaseError("the release tag does not identify HEAD")
    if not allow_unsigned:
        if signer_fingerprint is None:
            raise ReleaseError("the authorised signer fingerprint is required")
        run_git(repository, ["verify-tag", tag])
        actual_signer = run_git(
            repository,
            [
                "for-each-ref",
                "--format=%(signature:fingerprint)",
                f"refs/tags/{tag}",
            ],
        ).decode().strip()
        if actual_signer != signer_fingerprint:
            raise ReleaseError("the release tag signer is not authorised")
    else:
        actual_signer = None

    prefix = f"ndabi-{tag}/"
    tar_bytes = run_git(
        repository,
        ["archive", "--format=tar", f"--prefix={prefix}", tag_commit],
    )
    archive_bytes = deterministic_gzip(tar_bytes)
    archive_name = f"ndabi-{tag}.tar.gz"
    manifest_name = f"ndabi-{tag}.manifest.json"
    checksum_name = f"ndabi-{tag}.sha256"
    tracked_files = run_git(
        repository, ["ls-tree", "-r", "--name-only", tag_commit]
    ).splitlines()
    pinned_inputs = {
        path: sha256(committed_file(repository, tag_commit, path)) for path in PINNED_INPUTS
    }
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "repository": REPOSITORY_URL,
        "release_kind": "source",
        "tag": tag,
        "tag_signature": "not-verified-local-only" if allow_unsigned else "verified",
        "signer_fingerprint": actual_signer,
        "commit": tag_commit,
        "tracked_file_count": len(tracked_files),
        "pinned_inputs": pinned_inputs,
        "source_archive": {
            "file": archive_name,
            "bytes": len(archive_bytes),
            "sha256": sha256(archive_bytes),
        },
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    checksum_bytes = (
        f"{sha256(archive_bytes)}  {archive_name}\n"
        f"{sha256(manifest_bytes)}  {manifest_name}\n"
    ).encode()

    write_release_set(
        output_directory,
        {
            archive_name: archive_bytes,
            manifest_name: manifest_bytes,
            checksum_name: checksum_bytes,
        },
    )
    return manifest


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path("target/release-bundles"))
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--signer-fingerprint",
        help="require this exact verified tag-signing fingerprint",
    )
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="permit an unsigned tag for local testing only",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        manifest = create_release_bundle(
            arguments.repository,
            arguments.output,
            arguments.tag,
            allow_unsigned=arguments.allow_unsigned,
            signer_fingerprint=arguments.signer_fingerprint,
        )
    except ReleaseError as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 1
    source = manifest["source_archive"]
    assert isinstance(source, dict)
    print(f"release commit: {manifest['commit']}")
    print(f"source SHA-256: {source['sha256']}")
    print(f"output: {arguments.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
