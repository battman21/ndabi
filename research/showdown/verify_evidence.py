#!/usr/bin/env python3
"""Verify retained NDABI sources, binaries, summaries, and raw evidence."""

from __future__ import annotations

import hashlib
import gzip
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent.parent
MANIFESTS = sorted((ROOT / "evidence").glob("*/manifest.json"))


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"The JSON object contains a duplicate key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def sha256_artifact(path: Path, encoding: str | None = None) -> str:
    if encoding is None or encoding == "identity":
        return sha256_file(path)
    if encoding != "gzip":
        raise RuntimeError(f"The evidence encoding is unsupported: {encoding}")
    hasher = hashlib.sha256()
    with gzip.open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def resolve_bounded(path: Path, roots: tuple[Path, ...]) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise RuntimeError(f"The evidence path is not a file: {path}")
    if not any(resolved.is_relative_to(root.resolve()) for root in roots):
        raise RuntimeError(f"The evidence path escapes its custody roots: {path}")
    return resolved


def resolve_source(name: str, archived_root: str | None) -> Path:
    candidates = []
    if archived_root is not None:
        candidates.append(ROOT / archived_root / name)
    candidates.extend([ROOT / name, REPOSITORY / name])
    for path in candidates:
        try:
            return resolve_bounded(path, (ROOT, REPOSITORY))
        except (FileNotFoundError, RuntimeError):
            continue
    raise RuntimeError(f"The evidence source is absent: {name}")


def resolve_artifact(manifest_path: Path, name: str) -> Path:
    candidates = [manifest_path.parent / name, ROOT / name, REPOSITORY / name]
    for path in candidates:
        try:
            return resolve_bounded(path, (manifest_path.parent, ROOT, REPOSITORY))
        except (FileNotFoundError, RuntimeError):
            continue
    raise RuntimeError(f"The evidence artifact is absent: {name}")


def verify_manifest(path: Path) -> dict[str, object]:
    manifest = load_json(path)
    if manifest.get("schema") == "ndabi-v11-failed-campaign-v0.1":
        return {
            "manifest": str(path.relative_to(ROOT)),
            "sources": 0,
            "raw_results": 0,
            "campaign_gate_passed": False,
            "custody_complete": False,
            "passed": True,
        }
    if "artifacts" in manifest:
        artifacts = list(manifest["artifacts"].values()) + manifest.get("raw_results", [])
        for artifact in artifacts:
            candidate = resolve_artifact(path, artifact["path"])
            if sha256_artifact(candidate, artifact.get("encoding")) != artifact["sha256"]:
                raise RuntimeError(f"The evidence artifact changed: {candidate}")
        return {
            "manifest": str(path.relative_to(ROOT)),
            "sources": sum("source" in name for name in manifest["artifacts"]),
            "raw_results": len(manifest.get("raw_results", [])),
            "campaign_gate_passed": manifest.get("status") == "accepted",
            "custody_complete": manifest.get("custody_complete", True),
            "passed": True,
        }
    for name, expected in manifest["source_sha256"].items():
        source = resolve_source(name, manifest.get("archived_source_root"))
        if sha256_file(source) != expected:
            raise RuntimeError(f"The accepted source changed: {name}")
    binary = ROOT / manifest["release_binary"]
    if not binary.is_file():
        raise RuntimeError(f"The accepted release binary is absent: {binary}")
    if sha256_artifact(binary, manifest.get("release_binary_encoding")) != manifest["release_binary_sha256"]:
        raise RuntimeError(f"The accepted release binary changed: {binary}")
    summary_path = ROOT / manifest["campaign_summary"]
    expected_summary_sha256 = manifest.get("campaign_summary_sha256")
    if expected_summary_sha256 is not None:
        if sha256_file(summary_path) != expected_summary_sha256:
            raise RuntimeError(f"The campaign summary changed: {summary_path}")
    summary = load_json(summary_path)
    evidence = summary.get("run_evidence", summary.get("raw_evidence", []))
    for item in evidence:
        raw = ROOT / item["path"]
        if sha256_file(raw) != item["sha256"]:
            raise RuntimeError(f"The raw evidence changed: {raw}")
    return {
        "manifest": str(path.relative_to(ROOT)),
        "sources": len(manifest["source_sha256"]),
        "raw_results": len(evidence),
        "campaign_gate_passed": summary.get("campaign_gate", {}).get("passed"),
        "custody_complete": True,
        "passed": True,
    }


def main() -> None:
    report = {
        "schema": "ndabi-evidence-verification-v0.1",
        "manifests": [verify_manifest(path) for path in MANIFESTS],
    }
    report["passed"] = all(item["passed"] for item in report["manifests"])
    report["custody_complete"] = all(
        item["custody_complete"] for item in report["manifests"]
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
