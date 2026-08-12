#!/usr/bin/env python3
"""Mirror repo-root mapping packs into the install-bundled location.

The single source of truth for every mapping pack YAML is
``mappings/<name>.yaml`` at the repo root. The wheel install cannot
ship those files directly (they live outside any Python package),
so we copy them into ``scanner/mappings/`` which IS inside the
``scanner`` package and is therefore picked up by
``[tool.setuptools.package-data]``.

``scanner/paths.py:resolve_mapping()`` reads from the repo-root copy
for editable installs (``<install-root>/mappings/<name>.yaml``) and
falls back to the in-package copy via ``importlib.resources`` for
wheel installs. Both copies are byte-identical by construction.

This script is idempotent: running it with no diffs is a no-op. It
also deletes stale copies in ``scanner/mappings/`` whose source has
been removed from ``mappings/`` (e.g. when a pack is renamed).

Usage::

    python scripts/sync_mappings.py            # default: repo root = parent of scripts/
    python scripts/sync_mappings.py --check    # exit 1 if drift detected (CI / pre-commit)
    python scripts/sync_mappings.py --verbose  # print per-file status

Exit codes:
    0  — no drift (or drift successfully synced)
    1  — --check mode and drift detected
    2  — I/O or argument error
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# Directory layout (relative to this script):
#   <repo_root>/
#       mappings/                      <- source of truth
#       scanner/
#           mappings/                  <- build-time copy destination
#       scripts/
#           sync_mappings.py           <- this file
#
# We resolve repo_root as the parent of this script's parent.

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SOURCE_DIR = REPO_ROOT / "mappings"
DEST_DIR = REPO_ROOT / "scanner" / "mappings"

# Files in scanner/mappings/ that are NOT build artifacts. These are
# allowed to differ from the source-of-truth (they are docs / metadata,
# not mapping packs).
ALLOWED_DEST_FILENAMES = frozenset({".gitkeep", "README.md"})


def _is_yaml(p: Path) -> bool:
    return p.suffix.lower() in {".yaml", ".yml"}


def _collect_sources() -> set[str]:
    if not SOURCE_DIR.is_dir():
        raise FileNotFoundError(f"source directory does not exist: {SOURCE_DIR}")
    return {p.name for p in SOURCE_DIR.iterdir() if p.is_file() and _is_yaml(p)}


def _collect_dest() -> set[str]:
    if not DEST_DIR.is_dir():
        return set()
    return {
        p.name
        for p in DEST_DIR.iterdir()
        if p.is_file() and _is_yaml(p)
    }


def _copy_one(name: str, *, verbose: bool) -> str:
    """Copy one source YAML to the destination. Returns 'copied', 'identical', or 'updated'."""
    src = SOURCE_DIR / name
    dst = DEST_DIR / name
    if not src.is_file():
        raise FileNotFoundError(f"source file vanished: {src}")
    if dst.is_file() and src.read_bytes() == dst.read_bytes():
        if verbose:
            print(f"  identical: {name}")
        return "identical"
    shutil.copyfile(src, dst)
    action = "updated" if dst.exists() else "copied"
    if verbose:
        print(f"  {action}: {name}")
    return action


def _delete_stale(stale: list[str], *, verbose: bool, dry_run: bool) -> int:
    removed = 0
    for name in stale:
        target = DEST_DIR / name
        if dry_run:
            if verbose:
                print(f"  would remove stale: {name}")
            removed += 1
            continue
        target.unlink()
        if verbose:
            print(f"  removed stale: {name}")
        removed += 1
    return removed


def _sync_one_source(
    name: str, *, verbose: bool, dry_run: bool
) -> bool:
    """Reconcile one source YAML into the destination. Returns True iff
    the destination drifted (new file, byte-different content, or a
    would-change event under --dry-run). Returns False for the
    identical-content path.

    Extracted from :func:`sync` so the parent function reads as a
    straight-line pipeline and the per-file decision logic stays
    testable in isolation.
    """
    dst = DEST_DIR / name
    if not dst.exists():
        if dry_run:
            if verbose:
                print(f"  would copy: {name}")
            return True
        _copy_one(name, verbose=verbose)
        return True
    # File exists — check for byte equality.
    if (SOURCE_DIR / name).read_bytes() != dst.read_bytes():
        if dry_run:
            if verbose:
                print(f"  would update: {name}")
            return True
        _copy_one(name, verbose=verbose)
        return True
    if verbose:
        print(f"  identical: {name}")
    return False


def sync(*, check: bool, verbose: bool, dry_run: bool) -> int:
    """Run the sync. Returns the number of files that drifted (caller maps to exit code)."""
    DEST_DIR.mkdir(parents=True, exist_ok=True)

    sources = _collect_sources()
    dests = _collect_dest()

    stale_in_dest = sorted(dests - sources - ALLOWED_DEST_FILENAMES)

    drifted = 0

    # 1. Copy / update sources into destination.
    for name in sorted(sources):
        if _sync_one_source(name, verbose=verbose, dry_run=dry_run):
            drifted += 1

    # 2. Delete stale destinations (e.g. mapping pack was renamed/removed).
    if stale_in_dest:
        drifted += _delete_stale(stale_in_dest, verbose=verbose, dry_run=dry_run)

    return drifted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mirror repo-root mapping packs into scanner/mappings/.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any drift is detected; do not write.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-file status.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing.",
    )
    args = parser.parse_args(argv)

    try:
        drifted = sync(check=args.check, verbose=args.verbose, dry_run=args.dry_run)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.check and drifted:
        print(
            f"drift detected: {drifted} file(s) would change in {DEST_DIR}. "
            f"Run `make sync-mappings` (or `python scripts/sync_mappings.py`) to fix.",
            file=sys.stderr,
        )
        return 1

    if not args.check and drifted:
        print(f"synced {drifted} file(s) into {DEST_DIR}.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
