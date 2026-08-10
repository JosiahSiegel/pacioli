"""Auto-discover (project, env) pairs in a Terraform target repo.

Ports the precedence rules from `scanner/lib/common.sh` (bash):

  1. If ``<target>/pci_scope.yaml`` exists, it is the source of truth.
     Only entries with ``status: in_scope`` are loaded; for each entry
     the YAML's ``envs`` list determines which envs to scan, walking
     ``env/<project>/<env>/`` for each (mirrors bash ``load_pci_scope``
     + ``require_env_dir``).

  2. Else if ``<target>/env/`` exists, walk ``env/<project>/<env>/``
     subdirectories and emit one pair per env that contains at least
     one real ``*.tf`` file (excluding ``~*`` stubs).

  3. Else scan every ``*.tf`` at the repo root; if any exist, return
     ``[("default", "default")]`` (a flat repo with no env layout).

  4. If none of the above produces any pairs, raise
     :class:`NoTerraformFoundError`.

``--project`` and ``--env`` filters are applied AFTER the YAML-vs-env-
tree decision so the precedence semantics match the bash scanner.

Why YAML takes precedence: in the bash scanner ``load_pci_scope`` is
the only authoritative source of the project list when the file
exists; the env/ tree is just where the .tf files live. A consumer
may have ``env/<project>/<env>`` directories for projects that are
explicitly NOT in PCI scope (sandbox, dev-sandbox) — the YAML is
the explicit allowlist.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

# Local YAML loader — stdlib only, no PyYAML dependency.
# Used because the bash scanner already requires PyYAML only via
# `yaml_to_json` (which is fine because bash has its own Python
# subprocess); on the Python side we keep this dependency-free so
# `discovery` is importable in any environment that has Python 3.12+
# (the project's stated minimum).

try:  # pragma: no cover — exercised only when PyYAML is installed
    import yaml as _yaml  # type: ignore[import-untyped]
    _HAVE_YAML = True
except ImportError:  # pragma: no cover
    _yaml = None
    _HAVE_YAML = False


class NoTerraformFoundError(FileNotFoundError):
    """Raised when the target repo has no Terraform files to scan.

    Inherits from ``FileNotFoundError`` so callers that catch the
    stdlib exception still work, but also has a distinct type so
    callers can catch this specifically.
    """


def _has_real_tf_files(env_dir: Path) -> bool:
    """Return True if ``env_dir`` contains at least one real .tf file.

    A "real" .tf file is any ``*.tf`` at the top level of ``env_dir``
    that does not start with ``~`` (tilde-prefixed files are stubs).
    Mirrors the bash ``require_env_dir`` check in ``common.sh``.
    """
    if not env_dir.is_dir():
        return False
    for entry in env_dir.iterdir():
        if not entry.is_file():
            continue
        name = entry.name
        if name.startswith("~"):
            continue
        if name.endswith(".tf"):
            return True
    return False


def _load_pci_scope(scope_file: Path) -> list[tuple[str, str]]:
    """Load in-scope (project, env) pairs from pci_scope.yaml.

    Only entries with ``status: in_scope`` are honored. The YAML's
    ``envs`` list per entry determines which envs are scanned.
    Raises :class:`NoTerraformFoundError` if no in-scope entries
    yield any pairs.
    """
    if not _HAVE_YAML:
        raise RuntimeError(
            "pci_scope.yaml was found at "
            f"{scope_file} but PyYAML is not installed; "
            "install pyyaml or remove pci_scope.yaml to fall back "
            "to env/-tree auto-discovery."
        )

    with scope_file.open("r", encoding="utf-8") as fh:
        data = _yaml.safe_load(fh) or {}

    projects = data.get("projects", []) or []
    pairs: list[tuple[str, str]] = []
    for proj in projects:
        if not isinstance(proj, dict):
            continue
        if proj.get("status") != "in_scope":
            continue
        project_name = proj.get("project")
        if not project_name:
            continue
        envs = proj.get("envs") or []
        for env_name in envs:
            if not env_name:
                continue
            pairs.append((str(project_name), str(env_name)))
    return pairs


def _discover_from_yaml(
    target_repo: Path,
    project_filter: Optional[str],
    env_filter: Optional[str],
) -> list[tuple[str, str]]:
    """Handle the ``pci_scope.yaml`` discovery branch.

    Loads in-scope (project, env) pairs from ``<target_repo>/pci_scope.yaml``
    and applies ``project_filter`` / ``env_filter``.

    The YAML is the source of truth: when it exists, env subdirectories
    outside the YAML are out of scope by definition. We trust the
    YAML's (project, env) list as-is; downstream ``require_env_dir``-
    style validation happens in the scan loop, not here. Replicating
    it here would conflate discovery with validation.

    Raises :class:`NoTerraformFoundError` if the YAML yields no
    in-scope pairs (the caller treats this as the "nothing to scan"
    case regardless of filter values).
    """
    pairs = _load_pci_scope(target_repo / "pci_scope.yaml")
    if not pairs:
        raise NoTerraformFoundError(
            f"No Terraform files found under {target_repo}. "
            "Expected one of: pci_scope.yaml, env/<project>/<env>/, "
            "or *.tf at the repo root."
        )
    return _apply_filters(pairs, project_filter, env_filter)


def _discover_from_env_tree(
    target_repo: Path,
    project_filter: Optional[str],
    env_filter: Optional[str],
) -> list[tuple[str, str]]:
    """Walk ``env/<project>/<env>/`` and emit one pair per real env.

    A subdirectory counts as a real env iff it contains at least one
    non-tilde-prefixed ``*.tf`` file at the top level (mirrors bash
    ``require_env_dir``). The walk is one level deep: ``env/<proj>``
    is a directory of env directories, not nested further.

    Raises :class:`NoTerraformFoundError` if the env/ tree is empty
    (i.e. no real envs under any project). An empty result after
    filtering is a valid non-error result and is returned as ``[]``.
    """
    env_root = target_repo / "env"
    if not env_root.is_dir():
        return []

    pairs: list[tuple[str, str]] = []
    # Sorted for deterministic output (matters for tests + CI logs).
    for project_dir in sorted(env_root.iterdir()):
        if not project_dir.is_dir():
            continue
        project_name = project_dir.name
        for env_dir in sorted(project_dir.iterdir()):
            if not env_dir.is_dir():
                continue
            if _has_real_tf_files(env_dir):
                pairs.append((project_name, env_dir.name))

    if not pairs:
        raise NoTerraformFoundError(
            f"No Terraform files found under {target_repo}. "
            "Expected one of: pci_scope.yaml, env/<project>/<env>/, "
            "or *.tf at the repo root."
        )
    return _apply_filters(pairs, project_filter, env_filter)


def _discover_flat_repo(target_repo: Path) -> list[tuple[str, str]]:
    """Fallback for a flat repo with no ``env/`` directory.

    Returns ``[("default", "default")]`` if any ``*.tf`` file exists
    at the repo root (NOT recursive — a flat repo means the .tf files
    live at the top level). Otherwise raises :class:`NoTerraformFoundError`.

    No filter parameters: a flat repo has exactly one pair, so there
    is nothing to narrow.
    """
    for entry in target_repo.iterdir():
        if entry.is_file() and entry.name.endswith(".tf"):
            return [("default", "default")]
    raise NoTerraformFoundError(
        f"No Terraform files found under {target_repo}. "
        "Expected one of: pci_scope.yaml, env/<project>/<env>/, "
        "or *.tf at the repo root."
    )


def _apply_filters(
    pairs: list[tuple[str, str]],
    project_filter: Optional[str],
    env_filter: Optional[str],
) -> list[tuple[str, str]]:
    """Apply ``--project`` / ``--env`` filters to a pair list.

    A ``None`` filter is a no-op. An empty result after filtering is
    a valid result (the caller decides how to surface "no matches"
    to the user); see ``discover_pairs`` for the contract.
    """
    if project_filter is not None:
        pairs = [p for p in pairs if p[0] == project_filter]
    if env_filter is not None:
        pairs = [p for p in pairs if p[1] == env_filter]
    return pairs


def discover_pairs(
    target_repo: Path,
    project_filter: Optional[str] = None,
    env_filter: Optional[str] = None,
) -> list[tuple[str, str]]:
    """Return the list of ``(project, env)`` pairs to scan.

    Precedence (mirrors bash ``load_pci_scope``):

      1. ``<target>/pci_scope.yaml`` exists → use it (in-scope only).
      2. ``<target>/env/`` exists → walk ``env/<project>/<env>/``.
      3. Otherwise → flat-repo fallback: scan root ``*.tf`` and emit
         ``[("default", "default")]`` if any exist.

    The chosen strategy is fully self-contained: each helper raises
    :class:`NoTerraformFoundError` directly if it cannot find any
    pairs. Filters are applied inside the helper AFTER the
    empty-pairs check, so a non-matching filter returns ``[]`` rather
    than raising (``NoTerraformFoundError`` is reserved for the
    "nothing to scan at all" case).
    """
    target_repo = Path(target_repo)

    if (target_repo / "pci_scope.yaml").is_file():
        return _discover_from_yaml(target_repo, project_filter, env_filter)
    if (target_repo / "env").is_dir():
        return _discover_from_env_tree(target_repo, project_filter, env_filter)
    return _discover_flat_repo(target_repo)


__all__ = [
    "NoTerraformFoundError",
    "discover_pairs",
]
