"""Auto-discover (project, env) pairs in a Terraform target repo.

Ports the precedence rules from ``scanner/lib/common.sh`` (bash):

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

``scan_paths:`` extension
-------------------------
In addition to the four legacy branches, ``pci_scope.yaml`` may carry an
OPTIONAL top-level ``scan_paths:`` list whose entries declare stack
roots directly (``{path, project?, env?, backend_key?, workspace?,
stack_label?}``). When present, these entries are unioned with whatever
the legacy branches produced. Stack roots in ``scan_paths:`` do NOT
have to live under ``<target>/env/<project>/<env>/`` — they may point
anywhere on the filesystem (a sibling checkout, a sibling repo in a
monorepo, etc.).

Two entries that resolve to the same ``(project, env)`` MUST carry a
per-entry ``stack_label:`` to disambiguate, otherwise the scanner
fail-closes with a clear message naming both entries. The contract is
the same as the bash scanner's ``--scan-path`` / ``--scan-glob`` flags
introduced alongside this Todo.

``--project`` and ``--env`` filters are applied AFTER the YAML-vs-env-
tree decision so the precedence semantics match the bash scanner. In
flat-root mode (legacy branch 3) the filters RELABEL the single
``(default, default)`` pair rather than filtering to zero.

Why YAML takes precedence: in the bash scanner ``load_pci_scope`` is
the only authoritative source of the project list when the file
exists; the env/ tree is just where the .tf files live. A consumer
may have ``env/<project>/<env>`` directories for projects that are
explicitly NOT in PCI scope (sandbox, dev-sandbox) — the YAML is
the explicit allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


class ScanPathsCollisionError(ValueError):
    """Raised when two ``scan_paths:`` entries collide on ``(project, env)``.

    The collision contract is fail-closed: if two declared stack roots
    resolve to the same ``(project, env)`` pair and neither carries a
    ``stack_label:``, the scanner refuses to proceed rather than
    silently picking one. The exception message names both entries so
    the operator can add a ``stack_label:`` to disambiguate.
    """


# ---------------------------------------------------------------------------
# Module directory exclusion list (source-tier scan_paths)
# ---------------------------------------------------------------------------
#
# These names are conventionally NOT standalone Terraform root modules:
#
#   modules/         : monorepo-internal reusable modules; not root
#   modules-<x>/     : per-tenant / per-component module library
#   .terraform/      : `terraform init` working dir; .tf files here
#                     are downloaded providers, not source code
#
# The list is exported (via ``EXCLUDED_MODULE_DIR_NAMES``) so callers
# (e.g. the orchestrator) can present an informative log line. It is
# matched on the IMMEDIATE child of the stack root, not recursively;
# a ``modules/`` subdirectory inside a real env dir is still scanned.
EXCLUDED_MODULE_DIR_NAMES: tuple[str, ...] = (
    "modules",
    ".terraform",
)


def _is_excluded_module_dir(name: str) -> bool:
    """Return True if a top-level child directory of a stack root is excluded.

    Excludes ``modules/`` and ``.terraform/`` exactly. Also excludes
    the ``modules-<anything>/`` family (per-component module libs).
    The check is intentionally a prefix match for the ``modules-``
    family — those names are conventionally per-component module
    libraries, not root modules.
    """
    if name in EXCLUDED_MODULE_DIR_NAMES:
        return True
    if name.startswith("modules-"):
        return True
    return False


@dataclass(frozen=True)
class ScanPathEntry:
    """A single declared stack root from ``pci_scope.yaml::scan_paths:``.

    Attributes:
        path: Absolute (or relative-to-target-repo) path to the stack
            root directory.
        project: ``(project, env)`` key — either the YAML-declared
            ``project:`` or the fallback ``"default"``.
        env: ``(project, env)`` key — either the YAML-declared
            ``env:`` or the basename of ``path`` (or ``"default"`` for
            a flat-root entry).
        backend_key: Storage backend key used by tier ``state``. Falls
            back to ``f"{env}.tfstate"`` when neither ``backend_key:``
            nor ``terraform.aztfexport.tf`` provides one.
        workspace: Terraform workspace name (``-var workspace=<x>``).
            Optional; default is ``None``.
        stack_label: Disambiguator suffix used when two entries share
            the same ``(project, env)``. Optional; default is ``None``.
    """

    path: Path
    project: str
    env: str
    backend_key: Optional[str] = None
    workspace: Optional[str] = None
    stack_label: Optional[str] = None

    # The ``(project, env)`` pair is the discovery key. ``stack_label``
    # is kept SEPARATE so two entries with the same key remain
    # discoverable as distinct entries (the collision check is in
    # ``_resolve_scan_paths``).
    @property
    def pair(self) -> tuple[str, str]:
        """Return the ``(project, env)`` tuple for this entry."""
        return (self.project, self.env)


@dataclass(frozen=True)
class DiscoveredPair:
    """A ``(project, env)`` pair produced by :func:`discover_pairs`.

    Carries the optional ``stack_root`` (used by ``scan_paths:`` and
    flat-root mode) and ``stack_label`` so downstream code (e.g. the
    orchestrator's ``_resolve_env_dir``) can pick the right directory
    without re-doing discovery.

    For legacy branches (env/ tree, pci_scope.yaml ``projects:``,
    flat-root fallback), ``stack_root`` is ``None`` and the
    orchestrator falls back to ``<target>/env/<project>/<env>/`` /
    ``<target>`` (the prior behavior).
    """

    project: str
    env: str
    stack_root: Optional[Path] = None
    stack_label: Optional[str] = None
    backend_key: Optional[str] = None
    workspace: Optional[str] = None

    def key(self) -> tuple[str, str]:
        """Return the ``(project, env)`` discovery key for this pair.

        Named ``key()`` (not ``pair``) so the dataclass ``frozen=True``
        auto-generated field namespace stays clean and the type works
        with set/dict lookups by tuple.
        """
        return (self.project, self.env)

    def __iter__(self):  # pragma: no cover — convenience for tuple unpacking
        """Allow unpacking like the legacy ``(project, env)`` tuples."""
        yield self.project
        yield self.env


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

    data = _read_scope_yaml(scope_file)
    projects = data.get("projects", []) or []
    return _collect_scope_pairs(projects)


def _read_scope_yaml(scope_file: Path) -> dict:
    """Read and parse the scope YAML file, returning an empty dict on load failure.

    Extracted from :func:`_load_pci_scope` so the parent function's
    cognitive complexity stays under the S3776 ceiling. Returns
    ``{}`` when the file is empty or contains a bare scalar — the
    caller's ``data.get("projects", []) or []`` then degrades to a
    no-op rather than raising.
    """
    with scope_file.open("r", encoding="utf-8") as fh:
        return _yaml.safe_load(fh) or {}


def _collect_scope_pairs(projects: list[object]) -> list[tuple[str, str]]:
    """Flatten the ``projects:`` list of a scope YAML into (project, env) pairs.

    Per-entry rules (kept here so the caller stays focused on I/O and
    YAML availability):

      * Skip entries that are not mappings (``isinstance(proj, dict)``).
      * Honor only ``status: in_scope`` entries.
      * Require a non-empty ``project`` field; skip otherwise.
      * Emit one pair per non-empty ``envs`` entry.

    Extracted from :func:`_load_pci_scope` to keep the parent function's
    cognitive complexity under the S3776 ceiling.
    """
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
    """Handle the ``pci_scope.yaml::projects:`` discovery branch.

    Loads in-scope (project, env) pairs from ``<target_repo>/pci_scope.yaml``
    and applies ``project_filter`` / ``env_filter``.

    The YAML is the source of truth: when it exists, env subdirectories
    outside the YAML are out of scope by definition. We trust the
    YAML's (project, env) list as-is; downstream ``require_env_dir``-
    style validation happens in the scan loop, not here. Replicating
    it here would conflate discovery with validation.

    This helper does NOT raise :class:`NoTerraformFoundError` when the
    ``projects:`` list is empty — it may legitimately be empty in the
    presence of a ``scan_paths:`` block. The caller (:func:`discover_pairs`)
    raises after consulting both branches, so the "scan_paths:
    only" YAML does not produce a false negative.
    """
    pairs = _load_pci_scope(target_repo / "pci_scope.yaml")
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


def _discover_flat_repo(
    target_repo: Path,
    project_filter: Optional[str],
    env_filter: Optional[str],
) -> list[tuple[str, str]]:
    """Fallback for a flat repo with no ``env/`` directory.

    Returns ``[("default", "default")]`` if any ``*.tf`` file exists
    at the repo root (NOT recursive — a flat repo means the .tf files
    live at the top level). Otherwise raises :class:`NoTerraformFoundError`.

    ``--project`` / ``--env`` filters RELABEL the single
    ``(default, default)`` pair rather than filtering to zero. A flat
    repo has exactly one stack root, so the only useful filter behavior
    is "what label should the output use?" — dropping it would lose
    the only available signal.
    """
    for entry in target_repo.iterdir():
        if entry.is_file() and entry.name.endswith(".tf"):
            label_project = project_filter or "default"
            label_env = env_filter or "default"
            return [(label_project, label_env)]
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


# ---------------------------------------------------------------------------
# scan_paths: schema parsing
# ---------------------------------------------------------------------------


def _load_scan_paths(
    scope_file: Path,
    target_repo: Path,
) -> list[ScanPathEntry]:
    """Parse the optional ``scan_paths:`` list from a pci_scope.yaml.

    Per-entry shape (only ``path`` is required):

        - path:           filesystem path (absolute or relative to
                          ``target_repo``)
        - project:        defaults to ``"default"``
        - env:            defaults to ``basename(path)``
        - backend_key:    optional storage key; default is
                          ``f"{env}.tfstate"`` (overridden by
                          ``terraform.aztfexport.tf`` in the orchestrator)
        - workspace:      optional Terraform workspace
        - stack_label:    optional disambiguator for collisions

    Returns ``[]`` when the YAML is missing the ``scan_paths:`` key or
    the list is empty. Raises ``RuntimeError`` if PyYAML is not
    installed.
    """
    if not _HAVE_YAML:
        raise RuntimeError(
            "pci_scope.yaml was found at "
            f"{scope_file} but PyYAML is not installed; "
            "install pyyaml or remove pci_scope.yaml."
        )

    data = _read_scope_yaml(scope_file)
    raw = data.get("scan_paths")
    if not raw:
        return []
    if not isinstance(raw, list):
        raise ValueError(
            f"pci_scope.yaml: scan_paths must be a list, got {type(raw).__name__}"
        )

    entries: list[ScanPathEntry] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(
                f"pci_scope.yaml: scan_paths[{index}] must be a mapping, "
                f"got {type(item).__name__}"
            )
        entries.append(_parse_scan_path_entry(item, index, target_repo))
    return entries


def _parse_scan_path_entry(
    raw: dict,
    index: int,
    target_repo: Path,
) -> ScanPathEntry:
    """Validate and normalize one ``scan_paths:`` entry.

    Resolution rules:

      * ``path`` is required and must be a non-empty string. Relative
        paths are resolved against ``target_repo``.
      * ``project`` defaults to ``"default"``; must be a string.
      * ``env`` defaults to ``basename(path)``; must be a string.
      * ``backend_key`` is optional; defaults to ``None`` so the
        orchestrator can apply the documented precedence (CLI override
        > aztfexport file > basename default > fail-closed).
      * ``workspace`` is optional.
      * ``stack_label`` is optional; required ONLY when two entries
        share the same ``(project, env)`` (enforced upstream in
        :func:`_resolve_scan_paths`).
    """
    raw_path = raw.get("path")
    if not raw_path or not isinstance(raw_path, str):
        raise ValueError(
            f"pci_scope.yaml: scan_paths[{index}].path is required and "
            "must be a non-empty string"
        )

    path = Path(raw_path)
    if not path.is_absolute():
        path = (target_repo / raw_path).resolve()

    project = raw.get("project", "default")
    if not isinstance(project, str) or not project:
        raise ValueError(
            f"pci_scope.yaml: scan_paths[{index}].project must be a "
            "non-empty string when present"
        )

    env_name = raw.get("env", path.name)
    if not isinstance(env_name, str) or not env_name:
        raise ValueError(
            f"pci_scope.yaml: scan_paths[{index}].env must be a "
            "non-empty string when present"
        )

    backend_key = raw.get("backend_key")
    if backend_key is not None and not isinstance(backend_key, str):
        raise ValueError(
            f"pci_scope.yaml: scan_paths[{index}].backend_key must be "
            "a string when present"
        )

    workspace = raw.get("workspace")
    if workspace is not None and not isinstance(workspace, str):
        raise ValueError(
            f"pci_scope.yaml: scan_paths[{index}].workspace must be "
            "a string when present"
        )

    stack_label = raw.get("stack_label")
    if stack_label is not None and not isinstance(stack_label, str):
        raise ValueError(
            f"pci_scope.yaml: scan_paths[{index}].stack_label must be "
            "a string when present"
        )

    return ScanPathEntry(
        path=path,
        project=project,
        env=env_name,
        backend_key=backend_key,
        workspace=workspace,
        stack_label=stack_label,
    )


def _resolve_scan_paths(
    entries: list[ScanPathEntry],
    include_modules: bool = False,
) -> list[DiscoveredPair]:
    """Convert ``scan_paths:`` entries into ``DiscoveredPair`` objects.

    Performs the collision check: if two entries resolve to the same
    ``(project, env)``, EVERY colliding entry must carry a
    ``stack_label``. If ANY entry in the collision group lacks one,
    raises :class:`ScanPathsCollisionError` with a message naming the
    offending entries.

    Also drops entries whose path is a top-level module dir
    (``modules/``, ``modules-<x>/``, ``.terraform/``) unless
    ``include_modules`` is True (source-tier scan-paths respect the
    flag; the default is False, matching the bash scanner contract).
    """
    if not include_modules:
        entries = [
            e for e in entries
            if not _is_excluded_module_dir(e.path.name)
        ]

    # Collision detection.
    # Rule: if two entries share (project, env), EVERY entry in the
    # collision group must carry a stack_label. An unlabeled entry in
    # a collision group is ambiguous — the orchestrator can't tell which
    # label to attribute it to. Fail closed.
    groups: dict[tuple[str, str], list[ScanPathEntry]] = {}
    for entry in entries:
        key = entry.pair
        groups.setdefault(key, []).append(entry)
    for key, group in groups.items():
        if len(group) < 2:
            continue
        unlabeled = [e for e in group if e.stack_label is None]
        if unlabeled:
            labeled = [e for e in group if e.stack_label is not None]
            others = unlabeled + labeled
            raise ScanPathsCollisionError(
                f"scan_paths entries collide on (project={key[0]!r}, "
                f"env={key[1]!r}): "
                + " vs ".join(str(e.path) for e in others)
                + ". Add a per-entry stack_label to disambiguate."
            )

    return [
        DiscoveredPair(
            project=e.project,
            env=e.env,
            stack_root=e.path,
            stack_label=e.stack_label,
            backend_key=e.backend_key,
            workspace=e.workspace,
        )
        for e in entries
    ]


def _discover_from_scan_paths(
    target_repo: Path,
    include_modules: bool,
) -> list[DiscoveredPair]:
    """Handle the ``pci_scope.yaml::scan_paths:`` discovery branch.

    Returns ``[]`` when the YAML has no ``scan_paths:`` list. The
    caller (in :func:`discover_pairs`) unions this list with the
    legacy branches when both are present.

    Raises :class:`NoTerraformFoundError` is NOT raised here — that
    signal belongs to the legacy branches. The scan_paths branch
    coexists with them.
    """
    scope_file = target_repo / "pci_scope.yaml"
    if not scope_file.is_file():
        return []
    entries = _load_scan_paths(scope_file, target_repo)
    return _resolve_scan_paths(entries, include_modules=include_modules)


def discover_pairs(
    target_repo: Path,
    project_filter: Optional[str] = None,
    env_filter: Optional[str] = None,
    include_modules: bool = False,
) -> list[DiscoveredPair]:
    """Return the list of ``(project, env)`` pairs to scan.

    Precedence (mirrors bash ``load_pci_scope``):

      1. ``<target>/pci_scope.yaml`` exists → use it (in-scope only).
         Any ``scan_paths:`` entries in the same YAML are unioned with
         the ``projects:`` list. A YAML with only ``scan_paths:`` (no
         ``projects:``) is valid; ``scan_paths:`` provides the pairs.
      2. ``<target>/env/`` exists → walk ``env/<project>/<env>/``.
         (scan_paths has no effect in this branch — the env/ tree
         IS the discovery source.)
      3. Otherwise → flat-repo fallback: scan root ``*.tf`` and emit
         ``[("default", "default")]`` if any exist. Filters RELABEL
         the single pair rather than filtering to zero.

    Filters are applied inside the branch helpers so a non-matching
    filter returns ``[]`` rather than raising (``NoTerraformFoundError``
    is reserved for the "nothing to scan at all" case — see below).

    Raises:
        NoTerraformFoundError: when NEITHER the ``projects:`` list NOR
            the ``scan_paths:`` list OR the env/-tree walk produces
            any pairs (the legacy "nothing to scan at all" signal).
        ScanPathsCollisionError: when two ``scan_paths:`` entries
            collide on ``(project, env)`` and neither has a
            ``stack_label``.
    """
    target_repo = Path(target_repo)
    legacy: list[tuple[str, str]] = []

    if (target_repo / "pci_scope.yaml").is_file():
        legacy = _discover_from_yaml(target_repo, project_filter, env_filter)
    elif (target_repo / "env").is_dir():
        legacy = _discover_from_env_tree(target_repo, project_filter, env_filter)
    else:
        legacy = _discover_flat_repo(target_repo, project_filter, env_filter)

    # scan_paths is OPTIONAL and only meaningful when pci_scope.yaml
    # exists (it's a YAML key). In env/-tree and flat-root modes we
    # don't widen the discovery surface.
    scan_path_pairs: list[DiscoveredPair] = []
    if (target_repo / "pci_scope.yaml").is_file():
        scan_path_pairs = _discover_from_scan_paths(target_repo, include_modules)

    # Union: convert legacy tuples to DiscoveredPair (no stack_root).
    legacy_pairs: list[DiscoveredPair] = [
        DiscoveredPair(project=p, env=e) for p, e in legacy
    ]

    # Deduplicate by (project, env, stack_label) — scan_paths and
    # projects: may legitimately declare the same stack (e.g.
    # projects: lists the env and scan_paths: lists the explicit
    # stack-root). We keep the scan_paths version because it carries
    # the explicit root. Two scan_paths entries with the same
    # (project, env) but different stack_labels are distinct rows
    # (the orchestrator uses stack_label to keep them separate).
    seen_pairs: set[tuple[str, str, Optional[str]]] = set()
    merged: list[DiscoveredPair] = []
    # scan_paths first so it wins on duplicate keys
    for pair in scan_path_pairs + legacy_pairs:
        key = (pair.project, pair.env, pair.stack_label)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        merged.append(pair)

    # Final "nothing to scan at all" guard. Previously raised inside
    # _discover_from_yaml, but a YAML with only ``scan_paths:`` and no
    # ``projects:`` is now valid — scan_paths provides the pairs.
    # When the merged result is empty AND no filters narrowed it, the
    # repo has nothing to scan. When filters ARE active, an empty
    # result is a valid "no matches" signal and returns ``[]``
    # (matching the legacy contract).
    if not merged and project_filter is None and env_filter is None:
        raise NoTerraformFoundError(
            f"No Terraform files found under {target_repo}. "
            "Expected one of: pci_scope.yaml, env/<project>/<env>/, "
            "or *.tf at the repo root."
        )

    return merged


__all__ = [
    "NoTerraformFoundError",
    "ScanPathsCollisionError",
    "ScanPathEntry",
    "DiscoveredPair",
    "EXCLUDED_MODULE_DIR_NAMES",
    "discover_pairs",
]
