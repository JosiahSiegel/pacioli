"""Tests for ``scanner/config.py``.

Covers:
    * save_config / load_config round-trip
    * CLI flag wins over env var
    * Env var wins over persisted config
    * NoMappingConfigError raised on non-TTY + no source
    * NoMappingConfigError message contains ``--mapping`` and ``PACIOLI_MAPPING``
    * Invalid JSON in config raises a clear ValueError
    * Missing config file yields default (None mapping_path) from load_config
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import config as scanner_config
from config import (
    MAPPING_ENV_VAR,
    NoMappingConfigError,
    PacioliConfig,
    load_config,
    resolve_mapping,
    save_config,
)


# ---------------------------------------------------------------------------
# round-trip
# ---------------------------------------------------------------------------

def test_save_load_round_trip(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config"
    cfg = PacioliConfig(mapping_path=Path("/abs/path/to/mapping.yaml"))

    save_config(cfg, config_path=cfg_path)
    loaded = load_config(config_path=cfg_path)

    assert loaded.mapping_path == Path("/abs/path/to/mapping.yaml")
    assert loaded.no_default is False


def test_save_creates_parent_directory(tmp_path: Path) -> None:
    cfg_path = tmp_path / "nested" / "dir" / "config"
    cfg = PacioliConfig(mapping_path=Path("/some/path.yaml"))

    save_config(cfg, config_path=cfg_path)

    assert cfg_path.exists()
    assert cfg_path.parent.is_dir()
    assert load_config(config_path=cfg_path).mapping_path == Path("/some/path.yaml")


def test_load_returns_default_when_missing(tmp_path: Path) -> None:
    cfg_path = tmp_path / "does_not_exist"
    loaded = load_config(config_path=cfg_path)

    assert loaded.mapping_path is None
    assert loaded.no_default is False


# ---------------------------------------------------------------------------
# precedence: CLI > env > config
# ---------------------------------------------------------------------------

def test_cli_flag_wins_over_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Persist a config with a non-conflicting mapping so the only
    # decision-worthy value is env vs CLI.
    cfg_path = tmp_path / "config"
    save_config(
        PacioliConfig(mapping_path=Path("/persisted/mapping.yaml")),
        config_path=cfg_path,
    )

    monkeypatch.setenv(MAPPING_ENV_VAR, "/from/env/mapping.yaml")

    chosen = resolve_mapping(
        cli_mapping=Path("/from/cli/mapping.yaml"),
        env_mapping=None,  # let resolver read the env var
        config_path=cfg_path,
        interactive=False,
    )

    assert chosen == Path("/from/cli/mapping.yaml").resolve()


def test_env_wins_over_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "config"
    save_config(
        PacioliConfig(mapping_path=Path("/persisted/mapping.yaml")),
        config_path=cfg_path,
    )

    chosen = resolve_mapping(
        cli_mapping=None,
        env_mapping="/from/env/mapping.yaml",
        config_path=cfg_path,
        interactive=False,
    )

    assert chosen == Path("/from/env/mapping.yaml").resolve()


def test_persisted_config_used_when_no_cli_or_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Ensure no env var contamination from the host shell.
    monkeypatch.delenv(MAPPING_ENV_VAR, raising=False)

    cfg_path = tmp_path / "config"
    save_config(
        PacioliConfig(mapping_path=Path("/persisted/mapping.yaml")),
        config_path=cfg_path,
    )

    chosen = resolve_mapping(
        cli_mapping=None,
        env_mapping=None,
        config_path=cfg_path,
        interactive=False,
    )

    assert chosen == Path("/persisted/mapping.yaml")


# ---------------------------------------------------------------------------
# non-TTY bypass -> NoMappingConfigError
# ---------------------------------------------------------------------------

def test_non_tty_no_source_raises_no_mapping_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv(MAPPING_ENV_VAR, raising=False)
    monkeypatch.delenv("PACIOLI_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    cfg_path = tmp_path / "config"  # does not exist -> defaults to None path

    with pytest.raises(NoMappingConfigError):
        resolve_mapping(
            cli_mapping=None,
            env_mapping=None,
            config_path=cfg_path,
            interactive=True,
        )


def test_non_tty_with_interactive_env_runs_picker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When ``PACIOLI_INTERACTIVE=1`` is set the picker runs even on non-TTY.

    We drive the picker by stubbing ``input`` to return valid choices.
    """
    monkeypatch.delenv(MAPPING_ENV_VAR, raising=False)
    monkeypatch.setenv("PACIOLI_INTERACTIVE", "1")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    # Need a shipped mapping file for the "shipped" branch.
    mappings_dir = tmp_path / "mappings"
    mappings_dir.mkdir()
    shipped_yaml = mappings_dir / "pci_dss_4.0.1.yaml"
    shipped_yaml.write_text("# stub", encoding="utf-8")

    monkeypatch.setenv("PACIOLI_MAPPINGS_DIR", str(mappings_dir))

    cfg_path = tmp_path / "config"
    inputs = iter(["1"])  # choose PCI DSS v4.0.1
    monkeypatch.setattr("builtins.input", lambda *_args, **_kw: next(inputs))

    chosen = resolve_mapping(
        cli_mapping=None,
        env_mapping=None,
        config_path=cfg_path,
        interactive=True,
    )

    assert chosen == shipped_yaml.resolve()
    # Persistence side-effect.
    assert load_config(config_path=cfg_path).mapping_path == shipped_yaml.resolve()


# ---------------------------------------------------------------------------
# error message contract
# ---------------------------------------------------------------------------

def test_no_mapping_error_message_contains_actionable_hints(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv(MAPPING_ENV_VAR, raising=False)
    monkeypatch.delenv("PACIOLI_INTERACTIVE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    cfg_path = tmp_path / "config"

    with pytest.raises(NoMappingConfigError) as excinfo:
        resolve_mapping(
            cli_mapping=None,
            env_mapping=None,
            config_path=cfg_path,
            interactive=True,
        )

    msg = str(excinfo.value)
    assert "--mapping" in msg
    assert "PACIOLI_MAPPING" in msg


# ---------------------------------------------------------------------------
# invalid config rejection
# ---------------------------------------------------------------------------

def test_load_invalid_json_raises_value_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config"
    cfg_path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_config(config_path=cfg_path)

    assert "malformed JSON" in str(excinfo.value)
    assert str(cfg_path) in str(excinfo.value)


def test_load_non_object_json_raises_value_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config"
    cfg_path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_config(config_path=cfg_path)

    assert "JSON object" in str(excinfo.value)


# ---------------------------------------------------------------------------
# first-run picker state
# ---------------------------------------------------------------------------

def test_first_run_picker_persists_choice(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Selecting option 1 in the picker persists the shipped path."""
    mappings_dir = tmp_path / "mappings"
    mappings_dir.mkdir()
    shipped_yaml = mappings_dir / "pci_dss_4.0.1.yaml"
    shipped_yaml.write_text("# stub", encoding="utf-8")
    monkeypatch.setenv("PACIOLI_MAPPINGS_DIR", str(mappings_dir))

    cfg_path = tmp_path / "config"
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    inputs = iter(["1"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kw: next(inputs))

    chosen = scanner_config.first_run_picker(config_path=cfg_path)

    assert chosen == shipped_yaml.resolve()
    persisted = load_config(config_path=cfg_path)
    assert persisted.mapping_path == shipped_yaml.resolve()


def test_first_run_picker_invalid_twice_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Two invalid picks cause NoMappingConfigError."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    cfg_path = tmp_path / "config"
    inputs = iter(["abc", "999"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kw: next(inputs))

    with pytest.raises(NoMappingConfigError):
        scanner_config.first_run_picker(config_path=cfg_path)
