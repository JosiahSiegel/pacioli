"""Canonical path resolution for the standalone Pacioli CLI."""

from __future__ import annotations

import argparse
import importlib.resources
import os
from dataclasses import dataclass
from pathlib import Path

from scanner.frameworks import scan_mapping_packs


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


def resolve_mapping(args: argparse.Namespace) -> MappingPack:
    raw_value = _cli_value(args, "mapping") or _env_value("PACIOLI_MAPPING", "PCI_MAPPING")
    explicit = raw_value is not None
    if explicit:
        path = _canonical(raw_value)
        if not path.is_file():
            raise PathResolutionError(f"Mapping pack does not exist: {path}")
        return MappingPack(path=path, framework=_framework(path))

    # Default resolution: ask the SHARED scanner.frameworks.scan_mapping_packs
    # helper to enumerate shipped mapping packs at the editable-install
    # location (<install_root>/mappings). If that directory is empty or
    # missing — the wheel-install layout — try each candidate filename
    # via importlib.resources to find one that ships inside the package.
    #
    # The first non-empty scan wins. Picking the default pack honors the
    # legacy preference (pci_dss_* over alphabetical first).
    path: Path | None = None
    default_dir = _default_mapping_dir()
    if default_dir.is_dir():
        packs = scan_mapping_packs(default_dir)
        chosen = _pick_default_pack(packs)
        if chosen is not None:
            candidate = default_dir / chosen["filename"]
            if candidate.is_file():
                path = _canonical(candidate)

    if path is None:
        # Try the wheel-install fallback. Use a real scan of the bundled
        # pack names — we know the file stem from the editable-install
        # scan, OR from a probe of the package itself. We re-run the scan
        # against the importlib Traversable to keep the enumeration logic
        # in one place (scanner.frameworks.scan_mapping_packs).
        for chosen_filename in _probe_bundled_pack_filenames():
            bundled = _bundled_mapping_pack(chosen_filename)
            if bundled is not None and bundled.is_file():
                path = _canonical(bundled)
                break

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
            if name.endswith(".yaml") or name.endswith(".yml"):
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
    "resolve_baseline",
    "resolve_mapping",
    "resolve_paths",
    "resolve_run_dir",
    "resolve_target_repo",
]
