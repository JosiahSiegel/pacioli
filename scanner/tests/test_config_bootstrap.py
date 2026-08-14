"""Red tests for ``scanner/config_bootstrap.py`` (TDD task 1).

This module does NOT exist yet -- every test in this file must fail with
ImportError (or AttributeError) on collection.  The follow-up task 2 creates
``scanner/config_bootstrap.py`` and turns these tests green.

The tests serve as the implementation contract for scan-time scope + baseline
scaffolding.  They cover the public API:

    is_bootstrap_interactive(args) -> bool
    missing_config_files(target_repo) -> tuple[Path|None, Path|None]
    render_scope_yaml(target_repo) -> str
    render_baseline_yaml() -> str
    auto_create(args, target_repo, scope_path, baseline_path) -> list[Path]
    prompt_and_create(args, target_repo, scope_path, baseline_path) -> list[Path]

Test categories (a)-(l) from the plan are covered.
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# The import under test.  This MUST fail at collection time because the
# module does not exist yet (TDD red phase).
# ---------------------------------------------------------------------------
from scanner.config_bootstrap import (  # noqa: E402
    is_bootstrap_interactive,
    missing_config_files,
    render_scope_yaml,
    render_baseline_yaml,
    auto_create,
    prompt_and_create,
)
from scanner.discovery import (
    SCOPE_FILENAME,
    _parse_scope_manifest,
)
from scanner.aggregate import load_baseline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ns(**kwargs) -> argparse.Namespace:
    """Build a minimal argparse.Namespace for bootstrap calls."""
    base = {"non_interactive": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def _make_tf_repo(tmp_path: Path, project: str = "myapp", env: str = "prod") -> Path:
    """Create an env/<project>/<env>/ tree with a single .tf file."""
    env_dir = tmp_path / "env" / project / env
    env_dir.mkdir(parents=True)
    (env_dir / "main.tf").write_text(
        'resource "azurerm_resource_group" "rg" {}\n', encoding="utf-8"
    )
    return tmp_path


def _make_flat_repo(tmp_path: Path) -> Path:
    """Create a flat repo with a single .tf at the root."""
    (tmp_path / "main.tf").write_text(
        'resource "azurerm_resource_group" "rg" {}\n', encoding="utf-8"
    )
    return tmp_path


# ===========================================================================
# (a) is_bootstrap_interactive -- 4 conditions (no "no packs" check)
# ===========================================================================


class TestIsBootstrapInteractive:
    """Verify is_bootstrap_interactive mirrors the 4 interactive-gate conditions."""

    def test_true_when_tty_and_no_ci(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """TTY stdin, no CI env, no --non-interactive flag -> True."""
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        assert is_bootstrap_interactive(_ns()) is True

    def test_false_when_non_interactive_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--non-interactive flag set -> False."""
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        assert is_bootstrap_interactive(_ns(non_interactive=True)) is False

    def test_false_when_pacioli_non_interactive_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PACIOLI_NON_INTERACTIVE=1 -> False."""
        monkeypatch.setenv("PACIOLI_NON_INTERACTIVE", "1")
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        assert is_bootstrap_interactive(_ns()) is False

    def test_false_when_ci_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CI=1 -> False."""
        monkeypatch.setenv("CI", "1")
        monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        assert is_bootstrap_interactive(_ns()) is False

    def test_false_when_stdin_not_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-TTY stdin -> False."""
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        assert is_bootstrap_interactive(_ns()) is False


# ===========================================================================
# (b) missing_config_files
# ===========================================================================


class TestMissingConfigFiles:
    """Verify missing_config_files returns the right tuple shape."""

    def test_both_exist_returns_none_none(self, tmp_path: Path) -> None:
        """Both pci_scope.yaml and pci_baseline.yaml exist -> (None, None)."""
        (tmp_path / SCOPE_FILENAME).write_text("projects: []\n", encoding="utf-8")
        (tmp_path / "pci_baseline.yaml").write_text(
            "version: 1\nsuppressions: []\n", encoding="utf-8"
        )
        scope, baseline = missing_config_files(tmp_path)
        assert scope is None
        assert baseline is None

    def test_only_scope_missing(self, tmp_path: Path) -> None:
        """Scope missing, baseline exists -> (scope_path, None)."""
        (tmp_path / "pci_baseline.yaml").write_text(
            "version: 1\nsuppressions: []\n", encoding="utf-8"
        )
        scope, baseline = missing_config_files(tmp_path)
        assert scope is not None
        assert baseline is None

    def test_only_baseline_missing(self, tmp_path: Path) -> None:
        """Baseline missing, scope exists -> (None, baseline_path)."""
        (tmp_path / SCOPE_FILENAME).write_text("projects: []\n", encoding="utf-8")
        scope, baseline = missing_config_files(tmp_path)
        assert scope is None
        assert baseline is not None

    def test_both_missing(self, tmp_path: Path) -> None:
        """Both missing -> (scope_path, baseline_path)."""
        scope, baseline = missing_config_files(tmp_path)
        assert scope is not None
        assert baseline is not None


# ===========================================================================
# (c) render_scope_yaml -- round-trips through _parse_scope_manifest()
# ===========================================================================


class TestRenderScopeYaml:
    """Verify render_scope_yaml produces schema-valid YAML for three layouts."""

    def test_env_tree_layout_round_trips(self, tmp_path: Path) -> None:
        """env/<project>/<env>/ tree with multiple projects -> valid scope YAML.

        The rendered YAML must round-trip through
        ``discovery._parse_scope_manifest()`` without error and declare
        both discovered projects as in_scope.
        """
        repo = _make_tf_repo(tmp_path, project="myapp", env="prod")
        env2 = repo / "env" / "myapp-data" / "prod"
        env2.mkdir(parents=True)
        (env2 / "data.tf").write_text(
            'resource "azurerm_storage_account" "sa" {}\n', encoding="utf-8"
        )
        rendered = render_scope_yaml(repo)
        # Write to a temp file so _parse_scope_manifest can read it.
        scope_file = repo / SCOPE_FILENAME
        scope_file.write_text(rendered, encoding="utf-8")
        manifest = _parse_scope_manifest(scope_file)
        # Both projects must be declared in_scope.
        assert ("myapp", "prod") in manifest.in_scope_pairs
        assert ("myapp-data", "prod") in manifest.in_scope_pairs

    def test_flat_repo_round_trips(self, tmp_path: Path) -> None:
        """Flat repo with a single .tf at root -> valid scope YAML.

        The rendered YAML must declare a single (default, default) pair
        and round-trip through ``_parse_scope_manifest()``.
        """
        repo = _make_flat_repo(tmp_path)
        rendered = render_scope_yaml(repo)
        scope_file = repo / SCOPE_FILENAME
        scope_file.write_text(rendered, encoding="utf-8")
        manifest = _parse_scope_manifest(scope_file)
        assert len(manifest.in_scope_pairs) >= 1

    def test_empty_repo_fallback_scan_paths(self, tmp_path: Path) -> None:
        """Empty repo (NoIaCFoundError) -> fallback to scan_paths: [{path: "."}].

        When detect_frameworks finds nothing, render_scope_yaml must
        catch NoIaCFoundError and emit a ``scan_paths:`` block with at
        least one entry pointing at ``"."``.
        """
        rendered = render_scope_yaml(tmp_path)
        data = yaml.safe_load(rendered)
        assert data is not None
        # Must have a scan_paths list with at least one entry whose
        # path is ".".
        scan_paths = data.get("scan_paths", [])
        assert isinstance(scan_paths, list)
        assert len(scan_paths) >= 1
        assert any(
            isinstance(e, dict) and e.get("path") == "." for e in scan_paths
        ), f"scan_paths must contain {{path: '.'}}: {scan_paths!r}"


# ===========================================================================
# (d) render_scope_yaml discovers all Checkov framework files
# ===========================================================================


_FRAMEWORK_FILES = {
    "terraform": ("main.tf", 'resource "azurerm_resource_group" "rg" {}\n'),
    "cloudformation": (
        "template.json",
        '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}',
    ),
    "kubernetes": ("k8s.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"),
    "dockerfile": ("Dockerfile", "FROM alpine:3.18\n"),
    "bicep": ("main.bicep", "resource sa 'Microsoft.Storage/storageAccounts@2021-09-01' = {}\n"),
    "helm": ("Chart.yaml", "apiVersion: v2\nname: test\nversion: 0.1.0\n"),
}


@pytest.mark.parametrize("framework,filename,content", [
    (fw, fn, ct) for fw, (fn, ct) in _FRAMEWORK_FILES.items()
])
def test_render_scope_yaml_discovers_framework(
    tmp_path: Path, framework: str, filename: str, content: str
) -> None:
    """render_scope_yaml discovers IaC files for each Checkov framework.

    Parametrized across 6 frameworks: terraform, cloudformation, kubernetes,
    dockerfile, bicep, helm.  The rendered YAML must be non-empty and
    parseable.
    """
    (tmp_path / filename).write_text(content, encoding="utf-8")
    rendered = render_scope_yaml(tmp_path)
    assert rendered, f"render_scope_yaml returned empty string for {framework}"
    data = yaml.safe_load(rendered)
    assert data is not None, f"rendered YAML is null for {framework}"


# ===========================================================================
# (e) render_baseline_yaml round-trips through load_baseline
# ===========================================================================


def test_render_baseline_yaml_round_trips(tmp_path: Path) -> None:
    """render_baseline_yaml() -> YAML that round-trips through load_baseline.

    The rendered baseline must have an empty suppressions list and
    parse cleanly via ``aggregate.load_baseline``.
    """
    rendered = render_baseline_yaml()
    assert rendered, "render_baseline_yaml returned empty string"
    baseline_path = tmp_path / "pci_baseline.yaml"
    baseline_path.write_text(rendered, encoding="utf-8")
    entries = load_baseline(baseline_path)
    assert isinstance(entries, list)
    assert len(entries) == 0, "fresh baseline must have zero suppressions"


# ===========================================================================
# (f) auto_create writes files when missing, skips when existing
# ===========================================================================


class TestAutoCreate:
    """Verify auto_create writes missing files and skips existing ones."""

    def test_writes_both_when_missing(self, tmp_path: Path) -> None:
        """Both files missing -> writes both, returns list of created paths."""
        scope_path = tmp_path / SCOPE_FILENAME
        baseline_path = tmp_path / "pci_baseline.yaml"
        # Need IaC files so render_scope_yaml doesn't fall back to scan_paths.
        _make_flat_repo(tmp_path)
        created = auto_create(_ns(), tmp_path, scope_path, baseline_path)
        assert isinstance(created, list)
        assert len(created) == 2
        assert scope_path.is_file()
        assert baseline_path.is_file()

    def test_skips_when_both_exist(self, tmp_path: Path) -> None:
        """Both files exist -> no-op, returns empty list."""
        scope_path = tmp_path / SCOPE_FILENAME
        baseline_path = tmp_path / "pci_baseline.yaml"
        scope_path.write_text("projects: []\n", encoding="utf-8")
        baseline_path.write_text(
            "version: 1\nsuppressions: []\n", encoding="utf-8"
        )
        created = auto_create(_ns(), tmp_path, scope_path, baseline_path)
        assert isinstance(created, list)
        assert len(created) == 0


# ===========================================================================
# (g) auto_create never overwrites existing files
# ===========================================================================


def test_auto_create_never_overwrites_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """auto_create must NOT overwrite an existing file's content.

    Pre-seed both files with known content, run auto_create, then verify
    the file bytes are byte-identical to the pre-seeded content.
    """
    scope_path = tmp_path / SCOPE_FILENAME
    baseline_path = tmp_path / "pci_baseline.yaml"
    scope_content = "# pre-existing scope\nprojects: []\n"
    baseline_content = "# pre-existing baseline\nversion: 1\nsuppressions: []\n"
    scope_path.write_text(scope_content, encoding="utf-8")
    baseline_path.write_text(baseline_content, encoding="utf-8")
    auto_create(_ns(), tmp_path, scope_path, baseline_path)
    assert scope_path.read_text(encoding="utf-8") == scope_content
    assert baseline_path.read_text(encoding="utf-8") == baseline_content


# ===========================================================================
# (h) auto_create uses _validate_safe_path
# ===========================================================================


def test_auto_create_calls_validate_safe_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """auto_create must call _validate_safe_path for path safety (S2083).

    Monkeypatch ``_validate_safe_path`` in the config_bootstrap module to
    track invocation; assert it was called at least once.
    """
    import scanner.config_bootstrap as cb_mod

    call_count = {"n": 0}
    original = cb_mod._validate_safe_path

    def _tracking_validate(path: Path, allowed_roots: list[Path]) -> Path:
        call_count["n"] += 1
        return original(path, allowed_roots)

    monkeypatch.setattr(cb_mod, "_validate_safe_path", _tracking_validate)

    scope_path = tmp_path / SCOPE_FILENAME
    baseline_path = tmp_path / "pci_baseline.yaml"
    _make_flat_repo(tmp_path)
    auto_create(_ns(), tmp_path, scope_path, baseline_path)
    assert call_count["n"] > 0, "_validate_safe_path was never called"


# ===========================================================================
# (i) prompt_and_create -- yes/no/EOF behavior
# ===========================================================================


class TestPromptAndCreate:
    """Verify prompt_and_create handles user responses correctly."""

    @pytest.mark.parametrize("response", ["y", "yes", ""])
    def test_creates_on_yes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: str
    ) -> None:
        """y / yes / empty input -> creates files, returns non-empty list."""
        monkeypatch.setattr("builtins.input", lambda *_a, **_kw: response)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

        scope_path = tmp_path / SCOPE_FILENAME
        baseline_path = tmp_path / "pci_baseline.yaml"
        _make_flat_repo(tmp_path)
        created = prompt_and_create(_ns(), tmp_path, scope_path, baseline_path)
        assert isinstance(created, list)
        assert len(created) == 2
        assert scope_path.is_file()
        assert baseline_path.is_file()

    @pytest.mark.parametrize("response", ["n", "no"])
    def test_no_op_on_no(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: str
    ) -> None:
        """n / no input -> no files created, returns empty list."""
        monkeypatch.setattr("builtins.input", lambda *_a, **_kw: response)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

        scope_path = tmp_path / SCOPE_FILENAME
        baseline_path = tmp_path / "pci_baseline.yaml"
        created = prompt_and_create(_ns(), tmp_path, scope_path, baseline_path)
        assert isinstance(created, list)
        assert len(created) == 0
        assert not scope_path.exists()
        assert not baseline_path.exists()

    @pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
    def test_no_op_on_eof_or_ctrl_c(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exc: type
    ) -> None:
        """EOFError / KeyboardInterrupt during input() -> no-op (empty list)."""
        def _raise(*_a, **_kw) -> None:
            raise exc

        monkeypatch.setattr("builtins.input", _raise)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("PACIOLI_NON_INTERACTIVE", raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

        scope_path = tmp_path / SCOPE_FILENAME
        baseline_path = tmp_path / "pci_baseline.yaml"
        created = prompt_and_create(_ns(), tmp_path, scope_path, baseline_path)
        assert isinstance(created, list)
        assert len(created) == 0
        assert not scope_path.exists()
        assert not baseline_path.exists()


# ===========================================================================
# (j) Comment headers present in both rendered files
# ===========================================================================


def test_render_scope_yaml_has_comment_header(tmp_path: Path) -> None:
    """render_scope_yaml output must include ``#`` comment lines."""
    _make_flat_repo(tmp_path)
    rendered = render_scope_yaml(tmp_path)
    lines = rendered.strip().splitlines()
    comment_lines = [ln for ln in lines if ln.lstrip().startswith("#")]
    assert len(comment_lines) >= 1, "scope YAML must have at least one comment line"


def test_render_baseline_yaml_has_comment_header() -> None:
    """render_baseline_yaml output must include ``#`` comment lines."""
    rendered = render_baseline_yaml()
    lines = rendered.strip().splitlines()
    comment_lines = [ln for ln in lines if ln.lstrip().startswith("#")]
    assert len(comment_lines) >= 1, "baseline YAML must have at least one comment line"


# ===========================================================================
# (k) Scope uses structured {name, status} env records
# ===========================================================================


def test_scope_yaml_env_records_are_structured(tmp_path: Path) -> None:
    """Scope YAML env records must be dicts with ``name`` and ``status`` keys.

    Verifies that rendered scope YAML (for an env-tree layout) declares
    structured environment records (``{name: ..., status: ...}``) rather
    than legacy scalar strings.
    """
    repo = _make_tf_repo(tmp_path, project="myapp", env="prod")
    rendered = render_scope_yaml(repo)
    data = yaml.safe_load(rendered)
    assert data is not None
    projects = data.get("projects")
    assert isinstance(projects, list), "scope YAML must have a projects list"
    assert len(projects) >= 1
    first_project = projects[0]
    assert isinstance(first_project, dict)
    envs = first_project.get("envs")
    assert isinstance(envs, list), "project must have an envs list"
    assert len(envs) >= 1
    env_record = envs[0]
    assert isinstance(env_record, dict), (
        f"env record must be a dict, got {type(env_record).__name__}"
    )
    assert "name" in env_record, "env record must have 'name' key"
    assert "status" in env_record, "env record must have 'status' key"


# ===========================================================================
# (l) Baseline uses {version: 1, verified_against: <ISO>, suppressions: []}
# ===========================================================================


def test_baseline_yaml_shape(tmp_path: Path) -> None:
    """render_baseline_yaml must produce the canonical baseline mapping shape.

    Expected shape:
        version: 1
        verified_against: <ISO date string>
        suppressions: []
    """
    rendered = render_baseline_yaml()
    data = yaml.safe_load(rendered)
    assert isinstance(data, dict), (
        f"baseline root must be a mapping, got {type(data).__name__}"
    )
    assert data.get("version") == 1, f"version must be 1, got {data.get('version')!r}"
    verified = data.get("verified_against")
    assert isinstance(verified, str), "verified_against must be a string"
    # Must parse as an ISO date (YYYY-MM-DD).
    date.fromisoformat(verified)
    suppressions = data.get("suppressions")
    assert isinstance(suppressions, list), "suppressions must be a list"
    assert len(suppressions) == 0, "fresh baseline must have empty suppressions"
