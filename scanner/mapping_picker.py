"""Interactive mapping-pack picker for the standalone Pacioli CLI.

This module is the TTY-side companion to :func:`scanner.paths.resolve_mapping`.
The resolver itself stays pure (no ``input()``, no ``print()``): it consumes
``args.mapping`` and raises :class:`scanner.paths.PathResolutionError` when
the contract fails. The CLI dispatcher gates this picker on the same
"explicit value present" rule and only invokes it when:

* ``--mapping`` is unset AND ``PACIOLI_MAPPING`` is unset, AND
* the run is interactive (TTY, no CI flag, no ``--non-interactive``).

Cancellation contract
---------------------

Any cancelled picker (Esc / blank input / out-of-range / non-TTY stdin /
``KeyboardInterrupt``) raises :class:`scanner.paths.PathResolutionError`
with the same long-form message as the resolver. The exit code is
therefore 2, matching the existing user-facing error so first-time users
do not see a new failure mode.

Why a separate module
---------------------

The resolver's "explicit never silently swaps" contract is the most
important invariant in the CLI; touching ``resolve_mapping`` itself
risks regressing it. The picker is callerside: it sets ``args.mapping``
to a real on-disk path so the resolver sees the picked value as if the
user had typed ``--mapping``.

See ``.omo/plans/mapping-pack-picker.md`` for the decision record.
"""

from __future__ import annotations

import argparse
import importlib.resources
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Iterable

import yaml

from scanner.paths import (
    MappingPack,
    PathResolutionError,
    _canonical,
    _framework,
    _install_root,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Truthy values treated as "non-interactive" for PACIOLI_NON_INTERACTIVE.
#: Matches the lightest-possible parsing: any non-empty value is treated
#: as "set"; the CLI dispatcher sets ``os.environ["PACIOLI_NON_INTERACTIVE"]``
#: to the literal string ``"1"`` when ``--non-interactive`` is passed.
_TRUTHY_ENV: frozenset[str] = frozenset({"1", "true", "yes", "on"})

#: Filename suffixes treated as mapping-pack YAML. Mirrors the constant
#: in ``scanner.paths`` so the discovery rules stay in lockstep.
_YAML_SUFFIXES: tuple[str, ...] = (".yaml", ".yml")

#: Long-form error message -- mirroring the one raised by
#: :func:`scanner.paths.resolve_mapping` when no mapping cannot be resolved.
#: Centralized here so the cancellation tests assert one constant.
_CANCEL_MESSAGE: str = (
    "Mapping pack does not exist: <picker cancelled>. "
    "Pass --mapping <path> or set PACIOLI_MAPPING=<path>."
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_interactive(args: argparse.Namespace) -> bool:
    """Return True when the picker is allowed to run.

    Returns False when ANY of the following is true:

    * ``args.non_interactive`` is True (``--non-interactive`` flag).
    * ``PACIOLI_NON_INTERACTIVE`` is set to a truthy value.
    * ``CI`` is set to a truthy value (covers GitHub Actions, Azure
      DevOps, GitLab CI, CircleCI, etc.).
    * ``sys.stdin.isatty()`` returns False.

    Returns True otherwise.

    The CLI dispatcher MUST gate the call to :func:`pick_mapping_pack`
    on this guard so the picker never runs against non-TTY stdin.
    """
    if getattr(args, "non_interactive", False):
        return False
    if _is_truthy_env("PACIOLI_NON_INTERACTIVE"):
        return False
    if _is_truthy_env("CI"):
        return False
    try:
        is_tty = sys.stdin.isatty()
    except (AttributeError, ValueError):
        is_tty = False
    if not is_tty:
        return False
    return True


def pick_mapping_pack(args: argparse.Namespace) -> MappingPack:
    """Interactive picker for an installed mapping pack.

    Contract:

    * Call only when ``--mapping`` AND ``PACIOLI_MAPPING`` are both
      unset AND :func:`is_interactive` returns True. Callers MUST gate
      on :func:`is_interactive` before calling.
    * Lists every ``*.yaml`` under the same two locations
      :func:`scanner.paths.resolve_mapping` already probes:
      ``<install_root>/mappings/*.yaml`` (editable install) and the
      bundled ``scanner/mappings/*.yaml`` via ``importlib.resources``
      (wheel install). The two lists are deduplicated by resolved path.
    * Each row prints as
      ``"<n>.  <filename.yaml> - <framework_name> <framework_version>"``
      parsed from the YAML header (dotted access: ``framework_name``,
      ``framework_version``). When ``framework_name`` is missing, the
      row falls back to ``"(no framework_name)"`` rather than crashing.
    * Reads stdin via ``input("mapping pack [1-N] (Esc to cancel): ")``.
    * Empty input, ``KeyboardInterrupt``, value not parseable as int,
      or int out of range -> raise :class:`PathResolutionError` with
      the same long-form message :func:`scanner.paths.resolve_mapping`
      raises. A cancelled picker is semantically equivalent to "no
      mapping could be resolved", and the existing exit code 2 handling
      is correct.
    * Non-TTY stdin -> raise :class:`PathResolutionError` immediately.

    Returns:
        A :class:`scanner.paths.MappingPack` picking the user-selected
        mapping pack and its on-disk path.

    Raises:
        PathResolutionError: On cancellation, non-TTY stdin, or zero
            discovered packs.
    """
    # Belt-and-suspenders guard: refuse to prompt when stdin is not a TTY.
    # Callers MUST gate on is_interactive(), but a defensive guard here
    # keeps the unit-of-failure predictable.
    try:
        is_tty = sys.stdin.isatty()
    except (AttributeError, ValueError):
        is_tty = False
    if not is_tty:
        raise PathResolutionError(_CANCEL_MESSAGE)

    packs = _discover_packs()
    if not packs:
        raise PathResolutionError(_CANCEL_MESSAGE)

    # Print the numbered list. Use a leading blank line so the prompt
    # is visually separated from any prior CLI output.
    print()
    print("Pacioli: multiple mapping packs installed. Pick one:")
    print()
    for idx, pack in enumerate(packs, start=1):
        # Display the filename (stem is the "framework key") and the
        # framework_name / framework_version from the YAML header.
        # The path's name is the on-disk basename; framework_name is
        # pulled from the YAML header by _discover_packs().
        print(f"  {idx}. {pack.path.name} - {pack.framework_name} {pack.framework_version}")
    print()

    max_choice = len(packs)
    try:
        raw = input(f"mapping pack [1-{max_choice}] (Esc to cancel): ")
    except KeyboardInterrupt:
        # Ctrl-C / Esc on a TTY -> friendly cancellation, not a stack trace.
        raise PathResolutionError(_CANCEL_MESSAGE) from None

    choice_str = raw.strip()
    if not choice_str:
        raise PathResolutionError(_CANCEL_MESSAGE)
    if not choice_str.isdigit():
        raise PathResolutionError(_CANCEL_MESSAGE)
    choice = int(choice_str)
    if not (1 <= choice <= max_choice):
        raise PathResolutionError(_CANCEL_MESSAGE)

    chosen = packs[choice - 1]
    return MappingPack(path=chosen.path, framework=_framework(chosen.path))


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def _discover_packs() -> list[_PickerEntry]:
    """Enumerate installed mapping packs, deduped by canonical path.

    Returns a stable, filesystem-ordered list of _PickerEntry. The
    entry carries the YAML header metadata (framework_name +
    framework_version) so the row formatter can show both alongside
    the filename.
    """
    seen: set[Path] = set()
    out: list[_PickerEntry] = []
    for raw_path in _iter_discovered_paths():
        path = _canonical(raw_path)
        if path in seen:
            continue
        seen.add(path)
        if not path.is_file():
            continue
        framework_name = _read_framework_name(path)
        framework_version = _read_framework_version(path)
        # The returned MappingPack keeps the resolver's contract
        # (framework = bare stem). The richer _PickerEntry is internal.
        out.append(
            _PickerEntry(
                path=path,
                framework_name=framework_name or _framework(path),
                framework_version=framework_version or "",
            )
        )
    return out


def _discover_editable_packs() -> list[Path]:
    """Editable-install mapping packs under ``<install_root>/mappings/``.

    Returns ``[]`` when the directory is missing (e.g. wheel install).
    """
    default_dir = _install_root() / "mappings"
    if not default_dir.is_dir():
        return []
    return sorted(p for p in default_dir.iterdir() if p.suffix in _YAML_SUFFIXES)


def _discover_bundled_packs() -> list[Path]:
    """Wheel-install mapping packs under ``scanner/mappings/*.yaml``.

    Uses :func:`importlib.resources.files` so the lookup is robust across
    packaging variants. ``pci_dss_*`` packs are promoted to the front,
    matching :func:`scanner.paths._pick_default_pack` priority so the
    pack the user is most likely to recognise is always listed first.

    Returns ``[]`` when the bundled directory cannot be inspected.
    """
    try:
        traversable = importlib.resources.files("scanner").joinpath("mappings")
    except (ModuleNotFoundError, AttributeError, OSError):
        return []
    is_dir = getattr(traversable, "is_dir", None)
    if is_dir is None or not is_dir():
        return []
    iterdir = getattr(traversable, "iterdir", None)
    if iterdir is None:
        return []
    names: list[str] = []
    try:
        for entry in iterdir():
            name = getattr(entry, "name", None) or str(entry).rsplit("/", 1)[-1]
            if name.endswith(_YAML_SUFFIXES):
                names.append(name)
    except (AttributeError, OSError):
        return []
    names.sort()
    # Match _pick_default_pack priority: pci_dss_* packs first.
    names = sorted(names, key=lambda n: (not n.startswith("pci_dss_"), n))
    out: list[Path] = []
    for name in names:
        try:
            file_traversable = importlib.resources.files("scanner").joinpath(
                f"mappings/{name}"
            )
        except (ModuleNotFoundError, AttributeError, OSError):
            continue
        file_is_file = getattr(file_traversable, "is_file", None)
        if file_is_file is None or not file_is_file():
            continue
        try:
            out.append(Path(str(file_traversable)))
        except (TypeError, ValueError):
            continue
    return out


def _iter_discovered_paths() -> Iterable[Path]:
    """Yield candidate mapping-pack paths from both layouts."""
    yield from _discover_editable_packs()
    yield from _discover_bundled_packs()


def _read_yaml_header(path: Path) -> dict[str, object] | None:
    """Read the YAML header from a mapping pack file.

    Returns ``None`` when the file is unreadable, malformed, or does
    not parse as a dict. We never want to crash the picker on a
    malformed mapping pack -- we just skip the metadata fields.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _read_framework_name(path: Path) -> str | None:
    """Read ``framework_name`` from a mapping YAML header.

    Returns ``None`` when the YAML is unreadable, malformed, or has no
    ``framework_name`` key. The picker's row builder falls back to the
    filename stem in that case.
    """
    data = _read_yaml_header(path)
    if data is None:
        return None
    name = data.get("framework_name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def _read_framework_version(path: Path) -> str | None:
    """Read ``framework_version`` from a mapping YAML header.

    Returns ``None`` when missing or unreadable. The picker groups
    ``framework_name`` and ``framework_version`` together in the row so
    the user sees a complete identifier at a glance.
    """
    data = _read_yaml_header(path)
    if data is None:
        return None
    version = data.get("framework_version")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None


# ---------------------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------------------


def _is_truthy_env(name: str) -> bool:
    """Return True when env var ``name`` is set to a truthy value."""
    value = os.environ.get(name)
    if value is None:
        return False
    return value.strip().lower() in _TRUTHY_ENV


# ---------------------------------------------------------------------------
# Internal types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PickerEntry:
    """Internal record for the picker's row data.

    Carries the YAML header metadata (framework_name + framework_version)
    needed to render the row. The function returns a ``MappingPack``
    (the resolver's contract) so the picker can be slotted into the
    CLI as a drop-in replacement for an explicit ``--mapping`` value.
    """

    path: Path
    framework_name: str
    framework_version: str


__all__ = [
    "is_interactive",
    "pick_mapping_pack",
]
