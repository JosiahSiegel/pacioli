"""Canonical path resolution for the standalone Pacioli CLI."""

from __future__ import annotations

import argparse
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
    value = _cli_value(args, "mapping") or _env_value("PACIOLI_MAPPING", "PCI_MAPPING")
    path = _canonical(value or _install_root() / "mappings" / "pci_dss_4.0.1.yaml")
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
