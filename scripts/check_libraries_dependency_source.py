#!/usr/bin/env python3
"""Fail closed unless external Libraries dependencies share one exact Git revision."""
from __future__ import annotations

import argparse
import json
import re
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


def check_metadata(path: Path, revision: str) -> tuple[str, ...]:
    metadata = json.loads(path.read_text(encoding="utf-8"))
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        fail("Cargo metadata lacks packages")
    resolved: list[str] = []
    for name in CRATES:
        matching = [package for package in packages if package.get("name") == name]
        if len(matching) > 1:
            fail(f"resolved duplicate copies of {name}: {len(matching)}")
        # Virtual-workspace dependencies are declarations, not forced roots.
        # An unused declaration may legitimately be absent from Cargo metadata;
        # the manifest gate above still pins it exactly if a crate later opts in.
        if not matching:
            continue
        source = matching[0].get("source")
        if not isinstance(source, str):
            fail(f"{name} resolved without an immutable source")
        expected_prefix = f"git+{REPOSITORY}?rev={revision}#"
        if not source.startswith(expected_prefix) or not source.endswith(f"#{revision}"):
            fail(f"{name} resolved from unexpected source: {source}")
        resolved.append(name)
    if not resolved:
        fail("no Libraries dependency was resolved; metadata gate exercised nothing")
    return tuple(resolved)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()
    revision = manifest_revision(args.manifest)
    resolved: tuple[str, ...] = ()
    if args.metadata is not None:
        resolved = check_metadata(args.metadata, revision)
    suffix = f" resolved={','.join(resolved)}" if resolved else ""
    print(f"Libraries dependency source: PASS {revision}{suffix}")


if __name__ == "__main__":
    main()
