#!/usr/bin/env python3
"""Fail closed unless every external Libraries crate resolves from one exact Git revision."""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

REPOSITORY = "https://github.com/RecursiveIntell/Libraries.git"
CRATES = (
    "boundary-compiler",
    "stack-ids",
    "bitemporal-runtime",
    "claim-ledger",
    "llm-tool-runtime",
)
REVISION = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit(f"libraries-dependency-source: {message}")


def manifest_revision(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies = data.get("workspace", {}).get("dependencies", {})
    revisions: set[str] = set()
    for name in CRATES:
        spec = dependencies.get(name)
        if not isinstance(spec, dict):
            fail(f"{name} must be a structured workspace dependency")
        if "path" in spec:
            fail(f"{name} must not use a filesystem path")
        if spec.get("git") != REPOSITORY:
            fail(f"{name} must use {REPOSITORY}")
        revision = spec.get("rev")
        if not isinstance(revision, str) or not REVISION.fullmatch(revision):
            fail(f"{name} must pin one lowercase 40-hex rev")
        revisions.add(revision)
    if len(revisions) != 1:
        fail(f"Libraries crates disagree on revision: {sorted(revisions)}")
    bitemporal = dependencies["bitemporal-runtime"]
    if bitemporal.get("default-features") is not False:
        fail("bitemporal-runtime must preserve default-features = false")
    return next(iter(revisions))


def check_metadata(path: Path, revision: str) -> None:
    metadata = json.loads(path.read_text(encoding="utf-8"))
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        fail("Cargo metadata lacks packages")
    for name in CRATES:
        matching = [package for package in packages if package.get("name") == name]
        if len(matching) != 1:
            fail(f"expected exactly one resolved {name}, found {len(matching)}")
        source = matching[0].get("source")
        if not isinstance(source, str):
            fail(f"{name} resolved without an immutable source")
        expected_prefix = f"git+{REPOSITORY}?rev={revision}#"
        if not source.startswith(expected_prefix) or not source.endswith(f"#{revision}"):
            fail(f"{name} resolved from unexpected source: {source}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()
    revision = manifest_revision(args.manifest)
    if args.metadata is not None:
        check_metadata(args.metadata, revision)
    print(f"Libraries dependency source: PASS {revision}")


if __name__ == "__main__":
    main()
