"""Tests for scanner/paths.py path resolution precedence rules.

Covers:
- CLI flag > env var > default precedence for target_repo, mapping,
  baseline, and run_dir.
- PACIOLI_MAPPING env var wins over any config-picker default.
- Legacy PCI_REPO_ROOT alias is honored as a target_repo env var.
- Windows-style path canonicalization (via resolve()).
- Default install-bundled mapping pack (mappings/pci_dss_4.0.1.yaml
  relative to the install root).

These tests are intentionally hermetic: they do NOT depend on a real
install location, a real user home directory, or a real CWD outside
of pytest's tmp_path fixture.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import paths as paths_mod
from paths import (
    PathResolutionError,
    TargetRepo,
    resolve_baseline,
    resolve_mapping,
    resolve_paths,
    resolve_run_dir,
    resolve_target_repo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ns(**kwargs) -> argparse.Namespace:
    """Build a Namespace with all known CLI args defaulted to None."""
    base = {
        "target_repo": None,
        "mapping": None,
        "baseline": None,
        "output_dir": None,
        "run_id": None,
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


def _install_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point paths._install_root() at a tmp_path-based fake install.

    Returns the install root (which now hosts the 'scanner' subdir).
    """
    install_root = tmp_path / "fake_install"
    install_root.mkdir()
    # _install_root() returns parents[1] of paths.py -> parents[1] of
    # scanner/paths.py is the repo root that contains scanner/. We
    # arrange so that scanner/paths.py's parents[1] == install_root by
    # making the path module believe __file__ is install_root/scanner/paths.py.
    # Easiest way: monkeypatch Path(__file__).resolve() via the module's
    # own __file__ attribute. But _install_root calls Path(__file__).resolve(),
    # so we must change the module's __file__ string.
    fake_paths_py = install_root / "scanner" / "paths.py"
    fake_paths_py.parent.mkdir()
    fake_paths_py.write_text("# stub\n")
    monkeypatch.setattr(paths_mod, "__file__", str(fake_paths_py))
    return install_root


def _write_mapping(install_root: Path, name: str = "pci_dss_4.0.1.yaml") -> Path:
    """Create a stub mapping YAML at install_root/mappings/<name>."""
    mappings_dir = install_root / "mappings"
    mappings_dir.mkdir(exist_ok=True)
    p = mappings_dir / name
    p.write_text("# stub mapping\n")
    return p


# ---------------------------------------------------------------------------
# target_repo
# ---------------------------------------------------------------------------

def test_cli_flag_wins_over_env_var_for_target_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli_dir = tmp_path / "from_cli"
    env_dir = tmp_path / "from_env"
    env_dir.mkdir()
    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(env_dir))

    args = _ns(target_repo=str(cli_dir))
    result = resolve_target_repo(args)

    assert result.path == cli_dir.resolve()
    assert result.exists is False  # cli_dir not created


def test_env_var_wins_over_default_for_target_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_dir = tmp_path / "env_repo"
    env_dir.mkdir()
    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(env_dir))
    monkeypatch.delenv("PCI_REPO_ROOT", raising=False)

    args = _ns()
    result = resolve_target_repo(args)

    assert result.path == env_dir.resolve()
    assert result.exists is True


def test_target_repo_defaults_to_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("PACIOLI_TARGET_REPO", raising=False)
    monkeypatch.delenv("PCI_REPO_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)

    args = _ns()
    result = resolve_target_repo(args)

    assert result.path == tmp_path.resolve()
    assert result.exists is True


def test_target_repo_is_canonicalized_on_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """resolve() must collapse .. segments and drive casing consistently."""
    base = tmp_path / "a" / "b"
    base.mkdir(parents=True)
    # Use a path with redundant '..' segments.
    messy = base / ".." / "b" / "."
    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(messy))
    monkeypatch.delenv("PCI_REPO_ROOT", raising=False)

    args = _ns()
    result = resolve_target_repo(args)

    assert result.path == base.resolve()
    assert result.exists is True


def test_legacy_pci_repo_root_alias_honored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When PACIOLI_TARGET_REPO is unset, PCI_REPO_ROOT (legacy) wins."""
    legacy_dir = tmp_path / "legacy_repo"
    legacy_dir.mkdir()
    monkeypatch.delenv("PACIOLI_TARGET_REPO", raising=False)
    monkeypatch.setenv("PCI_REPO_ROOT", str(legacy_dir))

    args = _ns()
    result = resolve_target_repo(args)

    assert result.path == legacy_dir.resolve()
    assert result.exists is True


# ---------------------------------------------------------------------------
# mapping
# ---------------------------------------------------------------------------

def test_mapping_cli_flag_wins_over_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_root = _install_root(monkeypatch, tmp_path)
    _write_mapping(install_root, "cli_pick.yaml")

    cli_mapping = tmp_path / "cli_mapping.yaml"
    cli_mapping.write_text("# cli\n")
    env_mapping = tmp_path / "env_mapping.yaml"
    env_mapping.write_text("# env\n")

    monkeypatch.setenv("PACIOLI_MAPPING", str(env_mapping))
    monkeypatch.delenv("PCI_MAPPING", raising=False)

    args = _ns(mapping=str(cli_mapping))
    result = resolve_mapping(args)

    assert result.path == cli_mapping.resolve()
    assert result.framework == "cli_mapping"


def test_mapping_default_is_install_bundled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_root = _install_root(monkeypatch, tmp_path)
    bundled = _write_mapping(install_root, "pci_dss_4.0.1.yaml")

    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.delenv("PCI_MAPPING", raising=False)

    args = _ns()
    result = resolve_mapping(args)

    assert result.path == bundled.resolve()
    assert result.framework == "pci_dss_4.0.1"


def test_pacioli_mapping_env_var_overrides_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PACIOLI_MAPPING env var must win over the install-bundled default.

    Plan quote: 'PACIOLI_MAPPING precedence over config picker'.
    """
    install_root = _install_root(monkeypatch, tmp_path)
    _write_mapping(install_root, "pci_dss_4.0.1.yaml")  # the default

    override = tmp_path / "soc2.yaml"
    override.write_text("# soc2\n")
    monkeypatch.setenv("PACIOLI_MAPPING", str(override))
    monkeypatch.delenv("PCI_MAPPING", raising=False)

    args = _ns()
    result = resolve_mapping(args)

    assert result.path == override.resolve()
    assert result.framework == "soc2"


def test_mapping_legacy_pci_mapping_env_honored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_root = _install_root(monkeypatch, tmp_path)
    _write_mapping(install_root, "pci_dss_4.0.1.yaml")

    legacy = tmp_path / "legacy_map.yaml"
    legacy.write_text("# legacy\n")
    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.setenv("PCI_MAPPING", str(legacy))

    args = _ns()
    result = resolve_mapping(args)

    assert result.path == legacy.resolve()
    assert result.framework == "legacy_map"


def test_mapping_missing_file_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When BOTH the filesystem default AND the install-bundled mapping are
    unavailable, resolve_mapping must raise PathResolutionError.

    Updated for the v0.1.1 install-bundled fallback: the previous contract
    ("default file missing ⇒ raise") now first attempts the
    ``importlib.resources`` fallback. This test simulates a fully-broken
    install (neither the filesystem default nor the bundled mapping is
    resolvable) and confirms the error still surfaces.
    """
    install_root = _install_root(monkeypatch, tmp_path)  # noqa: F841  (fixture side-effect: monkeypatches env)
    # No mappings dir created -> default file does not exist.
    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.delenv("PCI_MAPPING", raising=False)

    # Disable the importlib.resources fallback so neither path can resolve.
    # We swap `paths_mod.importlib.resources.files` with a stub that returns
    # a Traversable whose `.is_file()` is always False — i.e. no bundled
    # mapping is available.
    class _MissingTraversable:
        def is_file(self) -> bool:
            return False

        def joinpath(self, _child: str) -> "_MissingTraversable":
            return self

    class _MissingResources:
        def files(self, _package: str) -> _MissingTraversable:
            return _MissingTraversable()

    monkeypatch.setattr(
        paths_mod.importlib.resources, "files", _MissingResources().files
    )

    args = _ns()
    with pytest.raises(PathResolutionError):
        resolve_mapping(args)


def test_default_mapping_falls_back_to_importlib_resources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When the filesystem default does not exist (wheel install layout), the
    install-bundled ``scanner/mappings/pci_dss_4.0.1.yaml`` shipped via
    ``importlib.resources`` must be used.

    Simulates the wheel-install scenario where the mapping lives inside the
    ``scanner`` package (e.g. ``site-packages/scanner/mappings/...``), NOT at
    the parent install root (which is what ``_install_root()/mappings/...``
    points at). Without the importlib.resources fallback this test reproduces
    the user-reported v0.1.0 bug:
        ERROR  Mapping pack does not exist: <site-packages>/mappings/pci_dss_4.0.1.yaml
    """
    import importlib.resources

    # _install_root() is monkeypatched to a tmp_path layout that does NOT
    # contain a `mappings/` sibling of the package — the wheel-install
    # scenario. No PACIOLI_MAPPING / PCI_MAPPING env vars, no --mapping CLI
    # flag — must use the default-resolution fallback.
    _install_root(monkeypatch, tmp_path)
    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.delenv("PCI_MAPPING", raising=False)

    args = _ns()
    result = resolve_mapping(args)

    expected = importlib.resources.files("scanner").joinpath(
        "mappings/pci_dss_4.0.1.yaml"
    )
    assert expected.is_file(), (
        "install-bundled mapping is missing from the test environment — "
        "this is a test-infra problem, not a paths.py bug. Confirm "
        "[tool.setuptools.package-data] in pyproject.toml still ships "
        "'mappings/*.yaml' under the 'scanner' entry."
    )
    assert result.path == Path(str(expected)).resolve()
    assert result.framework == "pci_dss_4.0.1"


def test_explicit_missing_mapping_does_not_silently_swap_to_bundled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When the user passes --mapping <missing-path>, the importlib.resources
    fallback MUST NOT fire. The error must surface as PathResolutionError so
    the user knows their explicit value was wrong (rather than getting a
    silent swap to the bundled default framework).
    """
    import importlib.resources

    _install_root(monkeypatch, tmp_path)  # noqa: F841  (monkeypatches paths.py layout)
    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.delenv("PCI_MAPPING", raising=False)

    # Confirm a bundled mapping actually exists — otherwise this test is
    # trivially true for the wrong reason.
    bundled = importlib.resources.files("scanner").joinpath(
        "mappings/pci_dss_4.0.1.yaml"
    )
    assert bundled.is_file()

    missing = tmp_path / "definitely_missing_mapping.yaml"
    assert not missing.exists()  # sanity

    args = _ns(mapping=str(missing))
    with pytest.raises(PathResolutionError) as excinfo:
        resolve_mapping(args)

    # Error message must reference the user-supplied path, NOT the bundled
    # default. If it referenced the bundled default, the test has regressed
    # into the silent-swap bug.
    assert str(missing.resolve()) in str(excinfo.value)
    assert "pci_dss_4.0.1.yaml" not in str(excinfo.value)


def test_explicit_env_var_missing_mapping_does_not_silently_swap_to_bundled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Same contract as the CLI-flag case, but for the PACIOLI_MAPPING env
    var. An explicit env var pointing at a missing file must raise
    PathResolutionError rather than falling back to the bundled mapping.
    """
    import importlib.resources

    _install_root(monkeypatch, tmp_path)  # noqa: F841
    monkeypatch.delenv("PCI_MAPPING", raising=False)

    # Confirm a bundled mapping actually exists.
    bundled = importlib.resources.files("scanner").joinpath(
        "mappings/pci_dss_4.0.1.yaml"
    )
    assert bundled.is_file()

    missing = tmp_path / "env_missing.yaml"
    assert not missing.exists()
    monkeypatch.setenv("PACIOLI_MAPPING", str(missing))

    args = _ns()
    with pytest.raises(PathResolutionError) as excinfo:
        resolve_mapping(args)

    assert str(missing.resolve()) in str(excinfo.value)


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------

def test_baseline_cli_flag_wins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    repo_default = repo / "pci_baseline.yaml"
    repo_default.write_text("# default\n")

    cli_baseline = tmp_path / "cli_baseline.yaml"
    cli_baseline.write_text("# cli\n")
    env_baseline = tmp_path / "env_baseline.yaml"
    env_baseline.write_text("# env\n")

    monkeypatch.setenv("PACIOLI_BASELINE_FILE", str(env_baseline))

    args = _ns(baseline=str(cli_baseline))
    target = TargetRepo(path=repo.resolve(), exists=True)
    result = resolve_baseline(args, target)

    assert result.path == cli_baseline.resolve()


def test_baseline_env_var_wins_over_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pci_baseline.yaml").write_text("# default\n")

    env_baseline = tmp_path / "env_baseline.yaml"
    env_baseline.write_text("# env\n")
    monkeypatch.setenv("PACIOLI_BASELINE_FILE", str(env_baseline))

    args = _ns()
    target = TargetRepo(path=repo.resolve(), exists=True)
    result = resolve_baseline(args, target)

    assert result.path == env_baseline.resolve()


def test_baseline_defaults_to_target_repo_pci_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    default = repo / "pci_baseline.yaml"
    default.write_text("# default\n")

    monkeypatch.delenv("PACIOLI_BASELINE_FILE", raising=False)

    args = _ns()
    target = TargetRepo(path=repo.resolve(), exists=True)
    result = resolve_baseline(args, target)

    assert result.path == default.resolve()


def test_baseline_defaults_to_none_when_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Plan quote: 'baseline default to None'."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # No pci_baseline.yaml inside repo.
    monkeypatch.delenv("PACIOLI_BASELINE_FILE", raising=False)

    args = _ns()
    target = TargetRepo(path=repo.resolve(), exists=True)
    result = resolve_baseline(args, target)

    assert result.path is None


# ---------------------------------------------------------------------------
# run_dir (--output-dir override)
# ---------------------------------------------------------------------------

def test_output_dir_cli_flag_wins_over_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli_out = tmp_path / "cli_out"
    env_out = tmp_path / "env_out"
    env_out.mkdir()
    monkeypatch.setenv("PACIOLI_OUTPUT_DIR", str(env_out))

    args = _ns(output_dir=str(cli_out))
    result = resolve_run_dir(args)

    assert result.path == cli_out.resolve()


def test_output_dir_env_var_used_when_no_cli_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_out = tmp_path / "env_out"
    env_out.mkdir()
    monkeypatch.setenv("PACIOLI_OUTPUT_DIR", str(env_out))

    args = _ns()
    result = resolve_run_dir(args)

    assert result.path == env_out.resolve()


def test_run_dir_default_uses_run_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("PACIOLI_OUTPUT_DIR", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    args = _ns(run_id="abc123")
    result = resolve_run_dir(args)

    assert result.path == (tmp_path / ".pacioli" / "runs" / "abc123").resolve()


def test_run_dir_default_falls_back_to_current(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("PACIOLI_OUTPUT_DIR", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    args = _ns()
    result = resolve_run_dir(args)

    assert result.path == (tmp_path / ".pacioli" / "runs" / "current").resolve()


# ---------------------------------------------------------------------------
# resolve_paths orchestrator
# ---------------------------------------------------------------------------

def test_resolve_paths_uses_all_precedence_layers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_root = _install_root(monkeypatch, tmp_path)
    _write_mapping(install_root, "pci_dss_4.0.1.yaml")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pci_baseline.yaml").write_text("# default\n")

    mapping_override = tmp_path / "soc2.yaml"
    mapping_override.write_text("# soc2\n")
    output_dir = tmp_path / "runs"
    baseline = tmp_path / "cli_baseline.yaml"
    baseline.write_text("# cli baseline\n")

    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(repo))  # overridden by CLI
    monkeypatch.setenv("PACIOLI_BASELINE_FILE", str(tmp_path / "env_baseline.yaml"))
    monkeypatch.setenv("PACIOLI_OUTPUT_DIR", str(tmp_path / "env_out"))

    args = _ns(
        target_repo=str(repo),
        mapping=str(mapping_override),
        baseline=str(baseline),
        output_dir=str(output_dir),
    )

    target, mapping, base, run_dir = resolve_paths(args)

    assert target.path == repo.resolve()
    assert mapping.path == mapping_override.resolve()
    assert base.path == baseline.resolve()
    assert run_dir.path == output_dir.resolve()


def test_resolve_paths_raises_when_target_repo_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_root = _install_root(monkeypatch, tmp_path)
    _write_mapping(install_root, "pci_dss_4.0.1.yaml")

    missing = tmp_path / "does_not_exist"
    args = _ns(target_repo=str(missing))

    with pytest.raises(PathResolutionError):
        resolve_paths(args)


def test_resolve_paths_target_repo_env_var_when_no_cli_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_root = _install_root(monkeypatch, tmp_path)
    _write_mapping(install_root, "pci_dss_4.0.1.yaml")

    repo = tmp_path / "env_repo"
    repo.mkdir()
    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(repo))
    monkeypatch.delenv("PCI_REPO_ROOT", raising=False)
    monkeypatch.delenv("PACIOLI_OUTPUT_DIR", raising=False)

    args = _ns()
    target, _mapping, _base, _run_dir = resolve_paths(args)

    assert target.path == repo.resolve()
    assert target.exists is True


# ---------------------------------------------------------------------------
# install-bundled mapping shipped via importlib.resources
# ---------------------------------------------------------------------------


def test_install_bundled_mapping_is_shipped_via_importlib_resources() -> None:
    """``importlib.resources.files("scanner").joinpath("mappings/pci_dss_4.0.1.yaml")``
    must resolve to a real file from the installed ``scanner`` package.

    This guards against future refactors that drop ``mappings/*.yaml``
    from ``[tool.setuptools.package-data]`` in ``pyproject.toml`` —
    without that entry, the wheel omits the mapping and the
    aggregate's install-bundled fallback silently fails to find the
    file at runtime. The aggregate tests in ``test_aggregate_pci.py``
    will also fail, but this test gives a focused regression message
    pointing at the exact configuration knob.
    """
    import importlib.resources

    bundled = importlib.resources.files("scanner").joinpath(
        "mappings/pci_dss_4.0.1.yaml"
    )
    assert bundled.is_file(), (
        f"install-bundled mapping not found at {bundled}; "
        "check [tool.setuptools.package-data] in pyproject.toml "
        "(requires 'mappings/*.yaml' under the 'scanner' entry)"
    )


# ---------------------------------------------------------------------------
# Single source of truth: mappings/ (repo root) is canonical,
# scanner/mappings/ is a build-time mirror.
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    """Path to the repo root (parent of both ``mappings/`` and ``scanner/``).

    ``scanner/tests/test_paths.py`` is two directories below the repo
    root, so ``parents[2]`` is the repo root regardless of where pytest
    is invoked from.
    """
    return Path(__file__).resolve().parents[2]


def test_mapping_pack_single_source_of_truth() -> None:
    """Assert that every YAML in ``scanner/mappings/`` is byte-identical to
    its counterpart under ``mappings/`` at the repo root.

    ``mappings/`` is the single source of truth. ``scanner/mappings/``
    is a build-time mirror produced by ``scripts/sync_mappings.py``
    (target ``make sync-mappings``) so the wheel install can ship the
    pack inside the ``scanner`` package. The mirror is git-ignored.

    This test catches two regression classes:

    1. **Drift** — someone edits ``mappings/<name>.yaml`` at the repo
       root but forgets to run ``make sync-mappings`` before the wheel
       is built. The runtime fallback would silently ship the stale
       pack. This test fires before ``pip install`` ever runs.
    2. **Orphan files** — a YAML exists under ``scanner/mappings/``
       that has no source in ``mappings/``. Either the source was
       renamed/deleted without a sync, or someone hand-edited the
       mirror (which is git-ignored precisely to prevent this).

    The test runs from the repo's checkout (not from the install), so
    it exercises the contract CI/pre-commit must enforce. For the
    install-time check (does the wheel still ship the mapping?), see
    ``test_install_bundled_mapping_is_shipped_via_importlib_resources``.
    """
    repo_root = _repo_root()
    source_dir = repo_root / "mappings"
    mirror_dir = repo_root / "scanner" / "mappings"

    # The source directory MUST exist — if it doesn't, the test runner
    # is not in a real checkout (e.g. installed wheel), and this test
    # is not applicable. Skip cleanly in that case.
    if not source_dir.is_dir():
        pytest.skip(
            f"repo-root mappings/ not found at {source_dir}; "
            "this test only runs from a source checkout"
        )

    # 1. Every YAML in scanner/mappings/ MUST be byte-identical to
    #    its counterpart under mappings/.
    if mirror_dir.is_dir():
        # Non-YAML files in the mirror (README.md, .gitkeep) are
        # documentation / VCS bookkeeping, not mapping packs, so they
        # are skipped — they are not data and have no source counterpart.
        for mirror_file in mirror_dir.iterdir():
            if not mirror_file.is_file():
                continue
            if mirror_file.suffix.lower() not in {".yaml", ".yml"}:
                continue
            source_file = source_dir / mirror_file.name
            assert source_file.is_file(), (
                f"orphan mapping pack in scanner/mappings/: {mirror_file.name} "
                f"has no source under {source_dir}. Either re-add the source "
                f"file, or run `make sync-mappings` to drop the stale mirror."
            )
            assert mirror_file.read_bytes() == source_file.read_bytes(), (
                f"mapping pack {mirror_file.name} has drifted between "
                f"{source_file} (source of truth) and {mirror_file} "
                f"(build-time mirror). Run `make sync-mappings` to repair."
            )

    # 2. Every YAML under mappings/ MUST be present (and identical) in
    #    scanner/mappings/. This catches the inverse drift: a developer
    #    added a new mapping pack at the repo root but forgot to sync.
    if mirror_dir.is_dir():
        for source_file in source_dir.iterdir():
            if not source_file.is_file():
                continue
            if source_file.suffix.lower() not in {".yaml", ".yml"}:
                continue
            mirror_file = mirror_dir / source_file.name
            assert mirror_file.is_file(), (
                f"source mapping pack {source_file.name} has no mirror "
                f"under {mirror_dir}. Run `make sync-mappings` to create it."
            )
            assert mirror_file.read_bytes() == source_file.read_bytes(), (
                f"mapping pack {source_file.name} has drifted: "
                f"{source_file} != {mirror_file}. "
                f"Run `make sync-mappings` to repair."
            )
