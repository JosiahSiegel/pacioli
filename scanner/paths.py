"""Canonical path resolution for the standalone Pacioli CLI."""

from __future__ import annotations

import argparse
import importlib.resources
import os
from dataclasses import dataclass
from pathlib import Path


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


def resolve_target_repo(args: argparse.Namespace) -> TargetRepo:
    value = _cli_value(args, "target_repo") or _env_value("PACIOLI_TARGET_REPO", "PCI_REPO_ROOT") or os.getcwd()
    path = _canonical(value)
    return TargetRepo(path=path, exists=path.is_dir())


def resolve_mapping(args: argparse.Namespace) -> MappingPack:
    raw_value = _cli_value(args, "mapping") or _env_value("PACIOLI_MAPPING", "PCI_MAPPING")
    explicit = raw_value is not None
    path = _canonical(raw_value) if explicit else _canonical(
        _install_root() / "mappings" / "pci_dss_4.0.1.yaml"
    )
    if not path.is_file():
        # Default-resolution fallback: when the user did NOT pass an explicit
        # --mapping / PACIOLI_MAPPING, fall back to the install-bundled
        # mapping shipped via importlib.resources. This handles wheel installs
        # where the mapping lives at scanner/mappings/... (inside the package)
        # rather than at the parent install root.
        #
        # Mirrors the pattern in scanner/aggregate.py:main() (commit bcf5944).
        # Use Traversable.is_file() — works for both editable installs and
        # wheel installs (Python 3.9+).
        #
        # CRITICAL: this fallback MUST only fire for the default. If the user
        # passed --mapping <explicit-missing-path> and that file is missing,
        # we must surface the error rather than silently swap in the
        # install-bundled mapping (which would report against the wrong
        # framework and mask the user error).
        if not explicit:
            try:
                bundled = importlib.resources.files("scanner").joinpath(
                    "mappings/pci_dss_4.0.1.yaml"
                )
                if bundled.is_file():
                    path = Path(str(bundled))
            except (ModuleNotFoundError, AttributeError, OSError):
                # Traversable lookup can fail in raw-tree execution where the
                # scanner package isn't installed yet; fall through and let
                # the original PathResolutionError surface below.
                pass
    if not path.is_file():
        raise PathResolutionError(f"Mapping pack does not exist: {path}")
    return MappingPack(path=path, framework=_framework(path))


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
