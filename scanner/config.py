"""Pacioli CLI configuration loader, persister, and first-run mapping picker.

The config file lives at ``~/.pacioli/config`` (a JSON document). It records
the user's chosen compliance-framework mapping pack so subsequent scans
don't need to specify ``--mapping`` every time.

Resolution precedence for the mapping path (highest first):
    1. ``--mapping`` CLI flag (``cli_mapping``)
    2. ``PACIOLI_MAPPING`` environment variable (``env_mapping``)
    3. Persisted ``~/.pacioli/config`` ``mapping_path`` field
    4. First-run interactive picker (TTY or ``PACIOLI_INTERACTIVE=1``)

When none of the above yields a path AND stdin is not a TTY, ``resolve_mapping``
raises :class:`NoMappingConfigError` so the CLI can fail with an actionable
error rather than hanging on ``input()``.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scanner.frameworks import scan_mapping_packs


# --- constants -----------------------------------------------------------

#: Default per-user config file location. Cross-platform (uses Path.home()).
DEFAULT_CONFIG_PATH: Path = Path.home() / ".pacioli" / "config"

#: Environment variable that forces the first-run picker even on non-TTY.
INTERACTIVE_ENV_VAR: str = "PACIOLI_INTERACTIVE"

#: Environment variable that overrides the mapping path.
MAPPING_ENV_VAR: str = "PACIOLI_MAPPING"


def _shipped_mapping_dir() -> Path:
    """Locate the bundled ``mappings/`` directory shipped with the package.

    Resolution order:
        1. ``PACIOLI_MAPPINGS_DIR`` env var (for development / testing)
        2. ``<repo_root>/mappings`` relative to this file's location
        3. ``./mappings`` relative to CWD (fallback for installed wheel layouts)
    """
    override = os.environ.get("PACIOLI_MAPPINGS_DIR")
    if override:
        return Path(override)
    here = Path(__file__).resolve().parent.parent
    candidate = here / "mappings"
    if candidate.is_dir():
        return candidate
    cwd_candidate = Path.cwd() / "mappings"
    return cwd_candidate


def _discover_builtin_frameworks() -> list[dict[str, str]]:
    """Auto-discover mapping packs shipped under ``mappings/``.

    Wraps :func:`scanner.frameworks.scan_mapping_packs` with the project's
    shipped-mapping directory lookup (:func:`_shipped_mapping_dir`). The
    single source of truth for mapping-pack enumeration lives in
    ``scanner.frameworks``; this helper just provides the dir.

    Returns an empty list when the mappings directory is missing or empty
    (e.g., a wheel install before ``make sync-mappings`` has run, or a
    slim build). The first-run picker still offers the "Custom path"
    option in that case so the operator is not stranded.
    """
    mappings_dir = _shipped_mapping_dir()
    return scan_mapping_packs(mappings_dir)


#: Shipped framework choices shown in the first-run picker.
#: Each entry: {"key", "label", "filename", "status"}.
#:
#: Populated at import time by :func:`_discover_builtin_frameworks` from the
#: ``mappings/*.yaml`` files shipped with the package. Adding a new mapping
#: pack is purely a content change — drop a YAML into ``mappings/`` and the
#: picker picks it up on the next run. No code edit required.
BUILTIN_FRAMEWORKS: list[dict[str, str]] = _discover_builtin_frameworks()

#: Sentinel for the "custom path" option in the picker menu.
CUSTOM_PATH_KEY: str = "custom"


# --- errors --------------------------------------------------------------

class NoMappingConfigError(RuntimeError):
    """Raised when no mapping path is configured AND the picker cannot run.

    Carries no public attributes; the message is the whole contract.
    """


# --- dataclass -----------------------------------------------------------

@dataclass
class PacioliConfig:
    """Persisted Pacioli CLI configuration.

    Attributes:
        mapping_path: Absolute path to the user's chosen mapping pack YAML,
            or ``None`` if the user explicitly opted out of a default mapping.
        no_default: ``True`` if the user has disabled the default mapping
            fallback (reserved for future use; not yet wired into scan).
    """

    mapping_path: Optional[Path] = None
    no_default: bool = False

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict (Path -> str)."""
        return {
            "mapping_path": str(self.mapping_path) if self.mapping_path is not None else None,
            "no_default": self.no_default,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PacioliConfig":
        """Hydrate from a parsed JSON dict; tolerant of missing keys."""
        mp = data.get("mapping_path")
        return cls(
            mapping_path=Path(mp) if mp else None,
            no_default=bool(data.get("no_default", False)),
        )


# --- loader / persister --------------------------------------------------

def _default_config_path() -> Path:
    """Return the default config file path (~/.pacioli/config)."""
    return Path.home() / ".pacioli" / "config"


def load_config(config_path: Optional[Path] = None) -> PacioliConfig:
    """Load config from disk.

    Args:
        config_path: Override the default ``~/.pacioli/config`` location.

    Returns:
        A :class:`PacioliConfig`. If the file does not exist, returns a
        default instance (``mapping_path=None``, ``no_default=False``)
        rather than raising — the first-run picker handles that case.

    Raises:
        ValueError: If the file exists but contains malformed JSON or
            unexpected types.
    """
    path = Path(config_path) if config_path is not None else _default_config_path()
    if not path.exists():
        return PacioliConfig()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"config file {path} is malformed JSON: {e}") from e
    if not isinstance(raw, dict):
        raise ValueError(f"config file {path} must contain a JSON object at the top level")
    return PacioliConfig.from_dict(raw)


def save_config(config: PacioliConfig, config_path: Optional[Path] = None) -> None:
    """Persist config to disk as JSON.

    Creates the parent directory (``~/.pacioli/``) if missing.

    Args:
        config: The configuration to serialize.
        config_path: Override the default ``~/.pacioli/config`` location.

    Raises:
        OSError: If the parent directory cannot be created or the file
            cannot be written.
    """
    path = Path(config_path) if config_path is not None else _default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config.to_dict(), indent=2) + "\n", encoding="utf-8")


# --- first-run picker ----------------------------------------------------

def _format_picker_menu() -> str:
    """Build the numbered picker text shown to the user."""
    lines = [
        "Pacioli first-run setup: choose a compliance mapping pack.",
        "",
    ]
    for idx, fw in enumerate(BUILTIN_FRAMEWORKS, start=1):
        lines.append(f"  {idx}. {fw['label']}")
    custom_idx = len(BUILTIN_FRAMEWORKS) + 1
    lines.append(f"  {custom_idx}. Custom path")
    lines.append("")
    return "\n".join(lines)


def _prompt_for_custom_path() -> Path:
    """Prompt for a custom mapping path; validate it exists."""
    while True:
        raw = input("Path to mapping.yaml: ").strip()
        if not raw:
            print("  (path cannot be empty)")
            continue
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        if not p.exists():
            print(f"  ERROR: {p} does not exist. Try again.")
            continue
        return p


def first_run_picker(config_path: Optional[Path] = None) -> Path:
    """Run the interactive first-run mapping picker.

    Presents a numbered menu of the auto-discovered mapping packs shipped
    under ``mappings/`` plus a "Custom path" option. The chosen path is
    persisted to ``~/.pacioli/config`` before returning.

    This function MUST only be called when stdin is a TTY (or when
    ``PACIOLI_INTERACTIVE=1`` is set). It blocks on ``input()`` and will
    raise :class:`NoMappingConfigError` if the user enters an invalid choice
    twice in a row.

    Args:
        config_path: Override the default config file location (for tests).

    Returns:
        Absolute path to the chosen mapping pack.
    """
    print(_format_picker_menu())
    custom_idx = len(BUILTIN_FRAMEWORKS) + 1
    max_choice = custom_idx

    def _ask_once() -> Optional[Path]:
        choice_raw = input(f"Enter choice [1-{max_choice}]: ").strip()
        if not choice_raw.isdigit():
            return None
        choice = int(choice_raw)
        if 1 <= choice <= len(BUILTIN_FRAMEWORKS):
            fw = BUILTIN_FRAMEWORKS[choice - 1]
            # All auto-discovered packs are "shipped" — the picker used to
            # show entries with status="not yet shipped" that redirected to
            # the custom-path prompt. With auto-discovery, any pack the
            # operator sees is genuinely present in mappings/.
            return _shipped_mapping_dir() / fw["filename"]
        if choice == custom_idx:
            return _prompt_for_custom_path()
        return None

    chosen: Optional[Path] = None
    for _ in range(2):
        chosen = _ask_once()
        if chosen is not None:
            break
        print(f"  Invalid choice. Enter a number between 1 and {max_choice}.")

    if chosen is None:
        raise NoMappingConfigError(
            "no mapping configured. Set PACIOLI_MAPPING=/path/to/mapping.yaml "
            "or pass --mapping /path/to/mapping.yaml. See `pacioli scan --help`."
        )

    chosen = chosen.expanduser()
    if not chosen.is_absolute():
        chosen = (Path.cwd() / chosen).resolve()

    save_config(PacioliConfig(mapping_path=chosen), config_path=config_path)
    print(f"Saved default mapping to {config_path or _default_config_path()}")
    return chosen


# --- resolver ------------------------------------------------------------

def _is_interactive_override() -> bool:
    """True if ``PACIOLI_INTERACTIVE=1`` is set in the environment."""
    return os.environ.get(INTERACTIVE_ENV_VAR, "").strip() in {"1", "true", "yes"}


def resolve_mapping(
    *,
    cli_mapping: Optional[Path] = None,
    env_mapping: Optional[str] = None,
    config_path: Optional[Path] = None,
    interactive: bool = True,
) -> Path:
    """Resolve the mapping pack path from CLI flag, env var, config, or picker.

    Precedence (highest first):
        1. ``cli_mapping`` (the ``--mapping`` flag value)
        2. ``env_mapping`` (the ``PACIOLI_MAPPING`` env var, or ``None`` to skip)
        3. ``~/.pacioli/config`` ``mapping_path`` field
        4. First-run picker — only if ``interactive`` is True AND
           (stdin is a TTY OR ``PACIOLI_INTERACTIVE=1`` is set)

    Args:
        cli_mapping: Value of the ``--mapping`` CLI flag, if any.
        env_mapping: Override for the ``PACIOLI_MAPPING`` env var. Pass an
            explicit ``None`` to skip env-var lookup; pass a string to use it
            even if the env var is unset.
        config_path: Override for the default config file location.
        interactive: If ``False``, the picker is skipped even when conditions
            would otherwise allow it (used by tests / programmatic callers).

    Returns:
        Absolute :class:`Path` to a mapping pack YAML file.

    Raises:
        NoMappingConfigError: If no source produces a path AND the picker
            cannot run (non-TTY, no ``PACIOLI_INTERACTIVE=1``).
    """
    # 1. CLI flag wins outright
    if cli_mapping is not None:
        return Path(cli_mapping).expanduser().resolve()

    # 2. Env var (explicit override or process env)
    env_value = env_mapping if env_mapping is not None else os.environ.get(MAPPING_ENV_VAR)
    if env_value:
        return Path(env_value).expanduser().resolve()

    # 3. Persisted config
    cfg = load_config(config_path=config_path)
    if cfg.mapping_path is not None:
        return cfg.mapping_path

    # 4. First-run picker (only when conditions allow it)
    can_prompt = interactive and (sys.stdin.isatty() or _is_interactive_override())
    if can_prompt:
        return first_run_picker(config_path=config_path)

    # No source, no prompt available -> actionable error
    raise NoMappingConfigError(
        "no mapping configured. Set PACIOLI_MAPPING=/path/to/mapping.yaml "
        "or pass --mapping /path/to/mapping.yaml. See `pacioli scan --help`."
    )


__all__ = [
    "BUILTIN_FRAMEWORKS",
    "CUSTOM_PATH_KEY",
    "DEFAULT_CONFIG_PATH",
    "INTERACTIVE_ENV_VAR",
    "MAPPING_ENV_VAR",
    "NoMappingConfigError",
    "PacioliConfig",
    "first_run_picker",
    "load_config",
    "resolve_mapping",
    "save_config",
]
