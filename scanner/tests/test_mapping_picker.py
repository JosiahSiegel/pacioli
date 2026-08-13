"""Tests for ``scanner/mapping_picker.py`` — interactive mapping pack picker.

This module is the FIRST runner of the TDD loop per
``.omo/plans/mapping-pack-picker.md`` task 1. When this file is committed,
``scanner/mapping_picker`` does NOT exist yet — every test in this file
must fail with ImportError (or AttributeError). The follow-up task 2
creates the module and turns these 11 tests green.

Covered cases (from plan task 1, draft lines 167-194):

1. ``is_interactive`` returns True when interactive (TTY, no CI flag).
2. ``is_interactive`` returns False when CI=1.
3. ``is_interactive`` returns False when PACIOLI_NON_INTERACTIVE=1.
4. ``is_interactive`` returns False when args.non_interactive is True.
5. ``is_interactive`` returns False when stdin is not a TTY.
6. ``pick_mapping_pack`` returns the chosen YAML when the user picks "1".
7. ``pick_mapping_pack`` raises PathResolutionError on empty/blank input.
8. ``pick_mapping_pack`` raises PathResolutionError on KeyboardInterrupt.
9. ``pick_mapping_pack`` raises PathResolutionError on out-of-range input.
10. ``pick_mapping_pack`` row text includes framework_name + framework_version.
11. ``pick_mapping_pack`` raises PathResolutionError on non-TTY stdin.

Test strategy: TDD. The test file deliberately mirrors the import
pattern of ``scanner/tests/test_paths.py`` lines 23-63 so this file works
under both the editable install (PYTHONPATH=scanner) and the wheel
install (import scanner.mapping_picker).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

# Mirror the pattern in scanner/tests/test_paths.py:23-63: insert the
# repo root into sys.path so ``import scanner.mapping_picker`` resolves
# correctly when this file is invoked from a non-default cwd (e.g. inside
# an editor's test runner, or when the wheel install puts the package on
# sys.path under a different name). The legacy flat-system import
# (``import mapping_picker as picker_mod``) is kept as a fallback so the
# test itself runs in either layout — and so the ImportError that fires
# under both layouts is the observable "this module doesn't exist yet"
# state we want at task 1.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT_STR = str(_REPO_ROOT)
if _REPO_ROOT_STR not in sys.path:
    sys.path.insert(0, _REPO_ROOT_STR)

try:
    # Preferred: import via the scanner package (works with both
    # editable install and wheel install).
    from scanner import mapping_picker  # noqa: F401
    import scanner.mapping_picker as picker_mod  # noqa: F401
except (ModuleNotFoundError, ImportError):
    # Fallback: legacy flat-system import (works only when this file is
    # run with PYTHONPATH=scanner, e.g. via ``make test`` from the repo
    # root in an editable install).
    picker_mod = None
    try:
        import mapping_picker  # type: ignore[no-redef]  # noqa: F401
        import mapping_picker as picker_mod  # type: ignore[no-redef]  # noqa: F401
    except (ModuleNotFoundError, ImportError):
        # Module does not exist yet - task 1 expects all 11 tests to fail.
        pass

# Path types always come from a module that DOES exist.
try:
    from scanner.paths import (
        MappingPack,
        PathResolutionError,
    )
except ModuleNotFoundError:
    from paths import (  # type: ignore[no-redef]
        MappingPack,
        PathResolutionError,
    )


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _ns(**kwargs) -> argparse.Namespace:
    """Build a Namespace with the only field the picker reads.

    The picker is intentionally narrow: it only inspects
    ``args.non_interactive``. Other CLI fields are not required.
    """
    base = {"non_interactive": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


@pytest.fixture
def mapping_yaml(tmp_path: Path) -> Path:
    """Write a single mapping YAML with PCI DSS framework metadata."""
    yaml_path = tmp_path / "pci_dss_4.0.1.yaml"
    yaml_path.write_text(
        "version: 2\n"
        "framework_name: PCI DSS\n"
        "framework_version: '4.0.1'\n"
        "rules: []\n",
        encoding="utf-8",
    )
    return yaml_path


def _patch_discovery(monkeypatch: pytest.MonkeyPatch, mapping_yaml: Path) -> None:
    """Force the picker's discovery helpers to return one fake pack.

    The picker is expected to expose two helpers that the test can
    monkeypatch:
      - ``picker_mod._discover_editable_packs()`` -> list[Path]
      - ``picker_mod._discover_bundled_packs()`` -> list[Path]

    For the "user picks 1" test, both helpers return the same single
    pack so dedup-by-resolved-path still yields one entry.
    """
    monkeypatch.setattr(
        picker_mod,
        "_discover_editable_packs",
        lambda: [mapping_yaml],
        raising=False,
    )
    monkeypatch.setattr(
        picker_mod,
        "_discover_bundled_packs",
        lambda: [mapping_yaml],
        raising=False,
    )


# ---------------------------------------------------------------------------
# is_interactive — 5 tests
# ---------------------------------------------------------------------------


def test_is_interactive_true_when_tty_and_no_ci_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TTY + no CI env + no flag + no PACIOLI_NON_INTERACTIVE -> True."""
    # CI must be unset. PACIOLI_NON_INTERACTIVE must be unset.
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    # Pretend stdin is a TTY.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    args = _ns()  # non_interactive=False
    assert picker_mod.is_interactive(args) is True


def test_is_interactive_false_when_ci_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI=1 (any truthy value) -> False."""
    monkeypatch.setenv("CI", "1")
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    args = _ns()
    assert picker_mod.is_interactive(args) is False


def test_is_interactive_false_when_pacioli_non_interactive_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PACIOLI_NON_INTERACTIVE=1 -> False."""
    monkeypatch.setenv("PACIOLI_NON_INTERACTIVE", "1")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    args = _ns()
    assert picker_mod.is_interactive(args) is False


def test_is_interactive_false_when_non_interactive_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """args.non_interactive=True -> False."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    args = _ns(non_interactive=True)
    assert picker_mod.is_interactive(args) is False


def test_is_interactive_false_when_stdin_not_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sys.stdin.isatty() returns False -> False."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    args = _ns()
    assert picker_mod.is_interactive(args) is False


# ---------------------------------------------------------------------------
# pick_mapping_pack — 6 tests
# ---------------------------------------------------------------------------


def test_pick_mapping_pack_uses_first_yaml_when_input_is_1(
    monkeypatch: pytest.MonkeyPatch,
    mapping_yaml: Path,
) -> None:
    """User picks "1" -> MappingPack for the first discovered YAML."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    _patch_discovery(monkeypatch, mapping_yaml)
    # Simulate stdin returning "1\n".
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "1")

    args = _ns()
    chosen = picker_mod.pick_mapping_pack(args)
    assert isinstance(chosen, MappingPack)
    assert chosen.path == mapping_yaml.resolve()


def test_pick_mapping_pack_empty_input_raises(
    monkeypatch: pytest.MonkeyPatch,
    mapping_yaml: Path,
) -> None:
    """Empty in
put -> PathResolutionError with the long-form message."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    _patch_discovery(monkeypatch, mapping_yaml)
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "\n")

    args = _ns()
    with pytest.raises(PathResolutionError) as excinfo:
        picker_mod.pick_mapping_pack(args)
    # Match the long-form message used by paths.py:220-223.
    assert "Mapping pack does not exist" in str(excinfo.value)


def test_pick_mapping_pack_keyboard_interrupt_raises(
    monkeypatch: pytest.MonkeyPatch,
    mapping_yaml: Path,
) -> None:
    """Ctrl-C during input() -> PathResolutionError, not KeyboardInterrupt."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    _patch_discovery(monkeypatch, mapping_yaml)

    def _raise_kbint(*_a, **_kw) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _raise_kbint)

    args = _ns()
    with pytest.raises(PathResolutionError) as excinfo:
        picker_mod.pick_mapping_pack(args)
    assert "Mapping pack does not exist" in str(excinfo.value)


def test_pick_mapping_pack_out_of_range_raises(
    monkeypatch: pytest.MonkeyPatch,
    mapping_yaml: Path,
) -> None:
    """Out-of-range choice (9, when only 1 pack exists) -> PathResolutionError."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    _patch_discovery(monkeypatch, mapping_yaml)
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "9\n")

    args = _ns()
    with pytest.raises(PathResolutionError) as excinfo:
        picker_mod.pick_mapping_pack(args)
    assert "Mapping pack does not exist" in str(excinfo.value)


def test_pick_mapping_pack_row_includes_framework_name(
    monkeypatch: pytest.MonkeyPatch,
    mapping_yaml: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The displayed row includes framework_name + framework_version."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    _patch_discovery(monkeypatch, mapping_yaml)
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "1")

    args = _ns()
    picker_mod.pick_mapping_pack(args)
    captured = capsys.readouterr()
    # Row format: "filename.yaml — framework_name framework_version"
    assert "pci_dss_4.0.1.yaml" in captured.out
    assert "PCI DSS" in captured.out
    assert "4.0.1" in captured.out


def test_pick_mapping_pack_non_tty_stdin_raises(
    monkeypatch: pytest.MonkeyPatch,
    mapping_yaml: Path,
) -> None:
    """Non-TTY stdin -> PathResolutionError immediately (no prompt printed)."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    _patch_discovery(monkeypatch, mapping_yaml)
    # If the picker incorrectly tries to call input(), this raises
    # automatically; the test stays clean because the explicit
    # isatty guard fires first.
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "1")

    args = _ns()
    with pytest.raises(PathResolutionError) as excinfo:
        picker_mod.pick_mapping_pack(args)
    assert "Mapping pack does not exist" in str(excinfo.value)


def test_pick_mapping_pack_zero_discovered_packs_raises_install_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """HOTFIX 1.1.1: zero discovered packs -> distinct install message, not cancellation.

    When the user has NO mapping packs installed (e.g. fresh wheel install
    with no PACIOLI_MAPPING, no --mapping, no editable-install mappings),
    the picker must NOT raise the generic "<picker cancelled>" message --
    that message tells the user to pass --mapping, but the real problem
    is that they have no mapping pack to point at. The user needs to be
    told to install one, not configure a path.

    Regression: 1.1.0 raised PathResolutionError("<picker cancelled>")
    with a misleading message and a leaked traceback. This test pins
    both the message and the exit-code path.

    Expected: PathResolutionError whose message does NOT contain
    "<picker cancelled>", but DOES contain "install" (telling the user
    to run `pacioli init` or pass --mapping explicitly).
    """
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    # Force both discovery helpers to return empty -- simulating a
    # user with zero mapping packs installed.
    monkeypatch.setattr(
        picker_mod, "_discover_editable_packs", lambda: [], raising=False
    )
    monkeypatch.setattr(
        picker_mod, "_discover_bundled_packs", lambda: [], raising=False
    )
    # Belt-and-suspenders: if the picker incorrectly tries to call
    # input() before the zero-packs guard, this raises (which would
    # fail the test loudly).
    monkeypatch.setattr(
        "builtins.input", lambda *_a, **_kw: "1"
    )

    args = _ns()
    with pytest.raises(PathResolutionError) as excinfo:
        picker_mod.pick_mapping_pack(args)
    msg = str(excinfo.value)
    # The misleading "<picker cancelled>" copy must NOT appear here.
    assert "<picker cancelled>" not in msg, (
        f"zero-packs error must not use cancellation message: {msg!r}"
    )
    # The user must be told to install/configure, not just pass --mapping.
    assert "install" in msg.lower() or "no mapping pack" in msg.lower(), (
        f"zero-packs error must guide user to install: {msg!r}"
    )


def test_is_interactive_false_when_no_packs_discovered(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """HOTFIX 1.1.1: is_interactive() returns False when no packs installed.

    The picker should never be invoked when there is nothing to pick.
    is_interactive() is the gate every caller already honors, so the
    cheapest possible fix is to teach it to inspect disk. This keeps
    the CLI wiring trivial (no extra guard at the call site) and ensures
    the picker is never even entered in the zero-pack case.

    Mocking: we patch _discover_editable_packs to return [] so the
    function sees no packs. The bundled-discovery helper is also
    forced to [].
    """
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        picker_mod, "_discover_editable_packs", lambda: [], raising=False
    )
    monkeypatch.setattr(
        picker_mod, "_discover_bundled_packs", lambda: [], raising=False
    )

    args = _ns()
    assert picker_mod.is_interactive(args) is False, (
        "is_interactive() must return False when zero packs are discoverable"
    )
