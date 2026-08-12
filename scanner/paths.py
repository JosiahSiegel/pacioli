"""Canonical path resolution for the standalone Pacioli CLI."""

from __future__ import annotations

import argparse
import importlib.resources
import os
from dataclasses import dataclass
from pathlib import Path

from scanner.frameworks import scan_mapping_packs

# Filename suffixes treated as mapping-pack YAML. Bundled-directory scans
# in :func:`_probe_bundled_pack_filenames` and the editable-install
# :func:`scan_mapping_packs` helper both consult this set so the
# "what counts as a pack" rule lives in one place. A ``frozenset`` is
# not used here because :func:`scan_mapping_packs` already accepts a
# plain glob; the tuple is the smallest contract that both call sites
# can share.
YAML_SUFFIXES: tuple[str, ...] = (".yaml", ".yml")


class PathResolutionError(ValueError):
    """Raised when a required path cannot be resolved."""


@dataclass(frozen=True)
class TargetRepo:
    path: Path
    exists: bool


@dataclass(frozen=True)
class MappingPack:
    path: Path
    framework: str


@dataclass(frozen=True)
class Baseline:
    path: Path | None


@dataclass(frozen=True)
class RunDir:
    path: Path


def _cli_value(args: argparse.Namespace, *names: str) -> str | None:
    for name in names:
        value = getattr(args, name, None)
        if value is not None and str(value).strip():
            return str(value)
    return None


def _env_value(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return value
    return None


def _canonical(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def _install_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _framework(path: Path) -> str:
    name = path.name
    if name.endswith(".yaml"):
        name = name[:-5]
    return name


def _pick_default_pack(packs: list[dict[str, str]]) -> dict[str, str] | None:
    """Pick the default mapping pack from an auto-discovered list.

    Legacy behavior: prefer a ``pci_dss_*`` pack when one exists, so existing
    Pacioli installs continue to default to the PCI DSS mapping without any
    operator action. Falls back to the first alphabetically if no PCI pack
    is present (the entries are pre-sorted by :func:`scan_mapping_packs`).
    Returns ``None`` when ``packs`` is empty.
    """
    if not packs:
        return None
    for pack in packs:
        if pack["key"].startswith("pci_dss_"):
            return pack
    return packs[0]


def _default_mapping_dir() -> Path:
    """Locate the ``mappings/`` dir for default resolution.

    Resolves to ``<install_root>/mappings`` — the editable-install / source
    checkout layout. The wheel-install layout (``scanner/mappings/``) is
    handled separately by :func:`_bundled_mapping_pack`.
    """
    return _install_root() / "mappings"


def _bundled_mapping_pack(filename: str) -> Path | None:
    """Resolve a single ``scanner/mappings/<name>.yaml`` to a real Path.

    Wheel installs ship the mapping pack inside the ``scanner`` package
    itself (``site-packages/scanner/mappings/...``) rather than at the
    parent install root. This helper uses ``importlib.resources`` to
    locate the file, returning a usable :class:`Path` when the file
    exists, or ``None`` when it is missing or the lookup fails.

    Note: we resolve the FILE directly rather than the directory, because
    some Traversable implementations (``MultiplexedPath`` in Python 3.12+)
    do not produce a usable filesystem path via ``str(<dir-traversable>)``.
    Per-file lookup returns a normal Traversable whose ``str()`` round-trips
    cleanly through :class:`Path`.

    Returns ``None`` for any environment where the lookup cannot be
    performed (raw-tree execution, missing package, etc.).
    """
    try:
        traversable = importlib.resources.files("scanner").joinpath(
            f"mappings/{filename}"
        )
    except (ModuleNotFoundError, AttributeError, OSError):
        return None
    try:
        is_file = traversable.is_file()
    except (AttributeError, OSError):
        # Some Traversable implementations (including test mocks) do not
        # expose ``is_file()`` or raise during the call. Treat as missing.
        return None
    if not is_file:
        return None
    return Path(str(traversable))


def resolve_target_repo(args: argparse.Namespace) -> TargetRepo:
    value = _cli_value(args, "target_repo") or _env_value("PACIOLI_TARGET_REPO", "PCI_REPO_ROOT") or os.getcwd()
    path = _canonical(value)
    return TargetRepo(path=path, exists=path.is_dir())


def _resolve_bundled_mapping_pack() -> Path | None:
    """Wheel-install fallback for the default mapping pack.

    Returns the first usable mapping pack from ``scanner/mappings/``
    inside the installed package (picked via ``_pick_default_pack``
    priority so a ``pci_dss_*`` pack wins when present). Returns
    ``None`` when no bundled pack is reachable -- callers translate
    that to a ``PathResolutionError``.

    Extracted from :func:`resolve_mapping` so the parent function
    stays focused on the precedence story and the fallback logic
    is independently testable.
    """
    for chosen_filename in _probe_bundled_pack_filenames():
        bundled = _bundled_mapping_pack(chosen_filename)
        if bundled is not None and bundled.is_file():
            return _canonical(bundled)
    return None


def _resolve_editable_mapping_pack(default_dir: Path) -> Path | None:
    """Editable-install lookup for the default mapping pack.

    Scans ``<install_root>/mappings/`` (the source-checkout layout)
    via :func:`scan_mapping_packs` and returns the canonical path
    of the picker-selected default. Returns ``None`` when the
    directory is absent, empty, or the selected file is missing.
    """
    if not default_dir.is_dir():
        return None
    packs = scan_mapping_packs(default_dir)
    chosen = _pick_default_pack(packs)
    if chosen is None:
        return None
    candidate = default_dir / chosen["filename"]
    if not candidate.is_file():
        return None
    return _canonical(candidate)


def resolve_mapping(args: argparse.Namespace) -> MappingPack:
    """Resolve the mapping pack (CLI > env > installed default).

    Precedence (highest first):

    1. ``--mapping`` CLI flag / ``PACIOLI_MAPPING`` (or legacy
       ``PCI_MAPPING``) env var. When supplied, the path MUST exist
       — explicit user input is never silently swapped to a bundled
       default. This contract is exercised by
       ``test_explicit_missing_mapping_does_not_silently_swap_to_bundled``.
    2. Shipped default, editable-install layout — ``<install_root>/mappings/``.
    3. Shipped default, wheel-install layout — ``scanner/mappings/`` via
       :func:`importlib.resources`.

    The shipped default lives in two places (editable + wheel). We probe
    both because the Python process cannot reliably tell which layout
    it's running under without a sys.path inspection that would be
    brittle across packaging variants.
    """
    raw_value = _cli_value(args, "mapping") or _env_value("PACIOLI_MAPPING", "PCI_MAPPING")
    if raw_value is not None:
        path = _canonical(raw_value)
        if not path.is_file():
            raise PathResolutionError(f"Mapping pack does not exist: {path}")
        return MappingPack(path=path, framework=_framework(path))

    default_dir = _default_mapping_dir()
    path = _resolve_editable_mapping_pack(default_dir)
    if path is None:
        path = _resolve_bundled_mapping_pack()

    if path is None or not path.is_file():
        raise PathResolutionError(
            f"Mapping pack does not exist: {default_dir}. "
            "Pass --mapping <path> or set PACIOLI_MAPPING=<path>."
        )
    return MappingPack(path=path, framework=_framework(path))


def _probe_bundled_pack_filenames() -> list[str]:
    """Enumerate ``*.yaml`` filenames in the bundled ``scanner/mappings/``.

    Used by the wheel-install fallback in :func:`resolve_mapping` when the
    editable-install ``mappings/`` directory is missing. Returns filenames
    in lexicographic order with a ``pci_dss_*`` pack first (if one exists),
    matching the picker priority. Returns an empty list when the bundled
    directory cannot be inspected at all (no ``is_dir``/``iterdir`` API, or
    the package layout does not expose ``mappings/``).
    """
    try:
        traversable = importlib.resources.files("scanner").joinpath("mappings")
    except (ModuleNotFoundError, AttributeError, OSError):
        return []
    # Defensive: some Traversable implementations (incl. test mocks) do not
    # expose ``is_dir``. Treat absence as "not a directory".
    is_dir = getattr(traversable, "is_dir", None)
    if is_dir is None or not is_dir():
        return []
    iterdir = getattr(traversable, "iterdir", None)
    if iterdir is None:
        return []
    names: list[str] = []
    try:
        for entry in iterdir():
            # ``name`` is the base filename for both real filesystem
            # entries and Traversable entries (Python 3.9+).
            name = getattr(entry, "name", None) or str(entry).rsplit("/", 1)[-1]
            if name.endswith(YAML_SUFFIXES):
                names.append(name)
    except (AttributeError, OSError):
        return []
    names.sort()
    # Promote pci_dss_* to the front, matching _pick_default_pack priority.
    return sorted(names, key=lambda n: (not n.startswith("pci_dss_"), n))


def resolve_baseline(args: argparse.Namespace, target_repo: TargetRepo) -> Baseline:
    value = _cli_value(args, "baseline") or _env_value("PACIOLI_BASELINE_FILE")
    path = _canonical(value) if value else target_repo.path / "pci_baseline.yaml"
    return Baseline(path=path if path.is_file() else None)


def resolve_run_dir(args: argparse.Namespace, run_id: str | None = None) -> RunDir:
    value = _cli_value(args, "output_dir") or _env_value("PACIOLI_OUTPUT_DIR")
    if value:
        path = _canonical(value)
    else:
        identifier = run_id or _cli_value(args, "run_id") or "current"
        path = _canonical(Path.home() / ".pacioli" / "runs" / identifier)
    return RunDir(path=path)


def resolve_paths(cli_args: argparse.Namespace) -> tuple[TargetRepo, MappingPack, Baseline, RunDir]:
    """Resolve all CLI paths using CLI > environment > defaults precedence."""
    target_repo = resolve_target_repo(cli_args)
    if not target_repo.exists:
        raise PathResolutionError(f"Target repository does not exist: {target_repo.path}")
    mapping = resolve_mapping(cli_args)
    baseline = resolve_baseline(cli_args, target_repo)
    run_dir = resolve_run_dir(cli_args)
    return target_repo, mapping, baseline, run_dir


__all__ = [
    "Baseline",
    "MappingPack",
    "PathResolutionError",
    "RunDir",
    "TargetRepo",
    "YAML_SUFFIXES",
    "resolve_baseline",
    "resolve_mapping",
    "resolve_paths",
    "resolve_run_dir",
    "resolve_target_repo",
]
