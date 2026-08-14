"""Auto-discover the in-scope ``(project, env)`` pairs in an IaC repo.

``<target>/.pacioli/scope.yaml`` is authoritative when present. Its root may contain
only ``projects:`` and ``scan_paths:`` and must provide at least one non-empty
list. ``projects:`` records have this exact shape::

    - project: <non-blank string>
      description: <optional string>
      status: in_scope | pending | excluded
      reason: <required non-blank string for pending/excluded>
      envs:
        - name: <non-blank string>
          status: in_scope | pending | excluded
          reason: <required non-blank string for pending/excluded>

Legacy scalar environments (for example, ``- prod``) are invalid. Only pairs
whose project and environment are both ``in_scope`` are discovered. A pending
or excluded project overrides all of its environments. Pending and excluded
pairs are never scanned.

``scan_paths:`` may be the only root list or accompany ``projects:``. Each
entry permits only ``path`` (required non-blank string), optional ``project``,
``env``, ``backend_key``, ``workspace``, and ``stack_label`` strings. ``project``
defaults to ``"default"`` and ``env`` to the basename of ``path``. Colliding
``(project, env)`` entries require per-entry ``stack_label`` values. Explicit
stack paths are exclusion-gated only when their declared logical pair is pending
or excluded; unmatched paths remain discoverable.

Without a scope manifest, discovery walks ``env/<project>/<env>/`` directories
that contain a framework detected by :func:`scanner.frameworks.detect_frameworks`.
Otherwise it detects framework files at the repo root and emits
``[("default", "default")]``. If no branch produces a pair, it raises
:class:`NoIaCFoundError` (alias :class:`NoTerraformFoundError`).

``--project`` and ``--env`` filters apply to the fully resolved in-scope set.
They cannot add a pending or excluded pair. In flat-root mode only, filters
relabel the single ``(default, default)`` pair rather than filtering to zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

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

# Framework-aware directory scanner (SINGLE SOURCE OF TRUTH).
# Delegating here keeps ``_has_iac_files`` a one-liner and avoids
# any parallel file-globbing code in discovery.py.
from scanner.frameworks import detect_frameworks  # noqa: E402


class NoIaCFoundError(FileNotFoundError):
    """Raised when the target repo has no IaC files to scan.

    "IaC" is intentionally framework-agnostic — ``terraform``,
    ``kubernetes``, ``dockerfile``, ``cloudformation``, ``bicep``,
    etc. all count. The check is delegated to
    :func:`scanner.frameworks.detect_frameworks` so any framework
    Checkov supports is automatically detected.

    Inherits from ``FileNotFoundError`` so callers that catch the
    stdlib exception still work, but also has a distinct type so
    callers can catch this specifically.
    """


# Deprecated alias — keep old name working for backward compat.
# Existing callers (e.g. ``scanner/orchestrator.py``) import
# ``NoTerraformFoundError``; do not remove without coordinated update.
# This is a one-line alias, not a subclass — a single identity check
# (``x is NoIaCFoundError``) works for both names.
NoTerraformFoundError = NoIaCFoundError


# Repo-relative path of the optional in-scope YAML manifest under the
# target repo root. Centralised so a future rename updates every branch
# (legacy ``projects:`` loader, ``scan_paths:`` parser, top-level
# precedence check) in lockstep. SonarCloud flags a duplicated string
# literal as a code smell (python:S119); the constant is the canonical
# reference.
SCOPE_FILENAME: Final[str] = ".pacioli/scope.yaml"


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
    """A single declared stack root from ``.pacioli/scope.yaml::scan_paths:``.

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

    For legacy branches (env/ tree, .pacioli/scope.yaml ``projects:``,
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


def _has_iac_files(env_dir: Path) -> bool:
    """Return True if ``env_dir`` contains at least one real IaC file.

    "IaC" here means a file detected by
    :func:`scanner.frameworks.detect_frameworks` — Terraform
    ``*.tf``/``*.tf.json``, Kubernetes ``*.yaml``/``*.yml`` (sniffed),
    Dockerfile, Bicep, CloudFormation, ARM, Helm, etc. Tilde-prefixed
    files (``~*.tf`` and friends) are excluded because they are stubs;
    :func:`detect_frameworks` enforces that rule internally.

    Thin wrapper — the directory scan lives in
    ``scanner/frameworks.py`` (SINGLE SOURCE OF TRUTH). Adding a new
    framework to :data:`scanner.frameworks.FRAMEWORK_FILE_PATTERNS`
    automatically widens this check without further changes here.
    """
    if not env_dir.is_dir():
        return False
    return bool(detect_frameworks(env_dir))


@dataclass(frozen=True)
class SkippedScopeEnvironment:
    """A declared environment omitted because its scope status excludes it."""

    project: str
    env: str
    status: str
    reason: str


@dataclass(frozen=True)
class _ScopeManifest:
    """Parsed scope contract used to gate legacy and explicit stack pairs."""

    in_scope_pairs: list[tuple[str, str]]
    excluded_pairs: set[tuple[str, str]]
    skipped_environments: list[SkippedScopeEnvironment]
    raw: dict


def _scope_error(location: str, message: str) -> ValueError:
    """Build a schema error which names the offending YAML location."""
    return ValueError(f"{SCOPE_FILENAME}.{location}: {message}")


def _required_string(raw: dict, key: str, location: str) -> str:
    """Return a required non-blank string from a YAML mapping."""
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _scope_error(f"{location}.{key}", "must be a non-blank string")
    return value


def _optional_string(raw: dict, key: str, location: str) -> Optional[str]:
    """Return an optional string while preserving a present blank value."""
    value = raw.get(key)
    if value is not None and not isinstance(value, str):
        raise _scope_error(f"{location}.{key}", "must be a string when present")
    return value


def _scope_status(raw: dict, location: str) -> tuple[str, Optional[str]]:
    """Parse a scope status and its required exclusion reason."""
    status = _required_string(raw, "status", location)
    if status not in {"in_scope", "pending", "excluded"}:
        raise _scope_error(f"{location}.status", "must be in_scope, pending, or excluded")
    reason = _optional_string(raw, "reason", location)
    if status in {"pending", "excluded"} and (reason is None or not reason.strip()):
        raise _scope_error(f"{location}.reason", "is required and must be non-blank for pending or excluded status")
    return status, reason


def _expect_fields(raw: object, expected: set[str], location: str) -> dict:
    """Require a YAML mapping with exactly the declared field names."""
    if not isinstance(raw, dict):
        raise _scope_error(location, "must be a mapping")
    unknown = set(raw) - expected
    if unknown:
        raise _scope_error(location, f"contains unknown field(s): {', '.join(sorted(unknown))}")
    return raw


def _validate_root(data: object) -> dict:
    """Validate the scope root and require a non-empty projects or scan_paths list."""
    root = _expect_fields(data, {"projects", "scan_paths"}, "root")
    projects = root.get("projects")
    scan_paths = root.get("scan_paths")
    if projects is not None and not isinstance(projects, list):
        raise _scope_error("projects", "must be a list when present")
    if scan_paths is not None and not isinstance(scan_paths, list):
        raise _scope_error("scan_paths", "must be a list when present")
    if not projects and not scan_paths:
        raise _scope_error("root", "requires a non-empty projects or scan_paths list")
    return root


def _validate_project(project_raw: object, index: int) -> tuple[dict, str, str, Optional[str]]:
    """Validate one project record and return its parsed scope metadata."""
    location = f"projects[{index}]"
    project = _expect_fields(
        project_raw,
        {"project", "description", "status", "reason", "envs"},
        location,
    )
    project_name = _required_string(project, "project", location)
    _optional_string(project, "description", location)
    project_status, project_reason = _scope_status(project, location)
    envs = project.get("envs")
    if envs is None:
        raise _scope_error(f"{location}.envs", "is required and must be a list")
    if not isinstance(envs, list):
        raise _scope_error(f"{location}.envs", "must be a list")
    return project, project_name, project_status, project_reason


def _validate_environment(
    env_raw: object, project_location: str, env_index: int
) -> tuple[dict, str, str, Optional[str]]:
    """Validate one environment record and return its parsed scope metadata."""
    location = f"{project_location}.envs[{env_index}]"
    environment = _expect_fields(env_raw, {"name", "status", "reason"}, location)
    env_name = _required_string(environment, "name", location)
    env_status, env_reason = _scope_status(environment, location)
    return environment, env_name, env_status, env_reason


def _record_environment_decision(
    project: str,
    env: str,
    project_status: str,
    project_reason: Optional[str],
    env_status: str,
    env_reason: Optional[str],
    pairs: list[tuple[str, str]],
    excluded_pairs: set[tuple[str, str]],
    skipped: list[SkippedScopeEnvironment],
) -> None:
    """Record the effective in-scope or excluded decision for one environment."""
    key = (project, env)
    if project_status == "in_scope" and env_status == "in_scope":
        pairs.append(key)
        return
    excluded_pairs.add(key)
    status = project_status if project_status != "in_scope" else env_status
    reason = project_reason if project_status != "in_scope" else env_reason
    skipped.append(SkippedScopeEnvironment(project, env, status, reason or ""))


def _parse_scope_manifest(scope_file: Path) -> _ScopeManifest:
    """Parse the strict ``.pacioli/scope.yaml`` schema into exclusion-gating data.

    Root keys are exactly ``projects`` and ``scan_paths``; at least one must be
    a non-empty list. Project records accept only ``project``, ``description``,
    ``status``, ``reason``, and ``envs``. Environment records accept only
    ``name``, ``status``, and ``reason``. Both statuses are one of ``in_scope``,
    ``pending``, or ``excluded``; pending and excluded records require a
    non-blank reason. Scalar environment names and unknown keys are rejected.

    The returned in-scope pairs require both project and environment status to
    be ``in_scope``. A non-in-scope project overrides its child environment's
    status and reason. ``scan_paths`` is validated at the same root boundary
    and parsed separately by :func:`_load_scan_paths`.
    """
    if not _HAVE_YAML:
        raise RuntimeError(
            f"{SCOPE_FILENAME} was found at {scope_file} but PyYAML is not installed; install pyyaml or remove {SCOPE_FILENAME}."
        )
    root = _validate_root(_read_scope_yaml(scope_file))
    projects = root.get("projects") or []
    pairs: list[tuple[str, str]] = []
    excluded_pairs: set[tuple[str, str]] = set()
    skipped: list[SkippedScopeEnvironment] = []
    seen: set[tuple[str, str]] = set()
    for project_index, project_raw in enumerate(projects):
        project, project_name, project_status, project_reason = _validate_project(
            project_raw, project_index
        )
        project_location = f"projects[{project_index}]"
        for env_index, env_raw in enumerate(project["envs"]):
            _, env_name, env_status, env_reason = _validate_environment(
                env_raw, project_location, env_index
            )
            key = (project_name, env_name)
            if key in seen:
                raise _scope_error(
                    f"{project_location}.envs[{env_index}]",
                    f"duplicates declared environment {project_name}/{env_name}",
                )
            seen.add(key)
            _record_environment_decision(
                project_name,
                env_name,
                project_status,
                project_reason,
                env_status,
                env_reason,
                pairs,
                excluded_pairs,
                skipped,
            )
    return _ScopeManifest(pairs, excluded_pairs, skipped, root)


def _load_pci_scope(scope_file: Path) -> list[tuple[str, str]]:
    """Load only in-scope structured project/environment records."""
    return _parse_scope_manifest(scope_file).in_scope_pairs


def _read_scope_yaml(scope_file: Path) -> object:
    """Read the YAML document before validating its structured scope contract."""
    try:
        with scope_file.open("r", encoding="utf-8") as fh:
            return _yaml.safe_load(fh)
    except _yaml.YAMLError as exc:
        raise _scope_error("root", f"contains invalid YAML: {exc}") from exc


def discover_skipped_scope_environments(target_repo: Path) -> list[SkippedScopeEnvironment]:
    """Return declared pending/excluded environments for orchestrator logging."""
    scope_file = Path(target_repo) / SCOPE_FILENAME
    if not scope_file.is_file():
        return []
    return _parse_scope_manifest(scope_file).skipped_environments


def _discover_from_yaml(target_repo: Path) -> list[tuple[str, str]]:
    """Load in-scope structured project/environment pairs from the manifest.

    Filtering deliberately belongs after scan-path exclusion gating and the
    merge in :func:`discover_pairs`, so it applies identically to both sources.
    """
    return _load_pci_scope(target_repo / SCOPE_FILENAME)


def _discover_from_env_tree(
    target_repo: Path,
    project_filter: Optional[str],
    env_filter: Optional[str],
) -> list[tuple[str, str]]:
    """Walk ``env/<project>/<env>/`` and emit one pair per real env.

    A subdirectory counts as a real env iff
    :func:`scanner.frameworks.detect_frameworks` returns a non-empty
    set for it (mirrors bash ``require_env_dir``, generalized from
    Terraform-only to all Checkov frameworks). The walk is one level
    deep: ``env/<proj>`` is a directory of env directories, not
    nested further.

    Raises :class:`NoIaCFoundError` (alias
    :class:`NoTerraformFoundError`) if the env/ tree is empty
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
            if _has_iac_files(env_dir):
                pairs.append((project_name, env_dir.name))

    if not pairs:
        raise NoIaCFoundError(
            f"No IaC files found under {target_repo}. "
            "Expected one of: .pacioli/scope.yaml, env/<project>/<env>/, "
            "or framework files (*.tf, *.yaml, Dockerfile, *.bicep, "
            "*.template.json, etc.) at the repo root."
        )
    return _apply_filters(pairs, project_filter, env_filter)


def _discover_flat_repo(
    target_repo: Path,
    project_filter: Optional[str],
    env_filter: Optional[str],
) -> list[tuple[str, str]]:
    """Fallback for a flat repo with no ``env/`` directory.

    Returns ``[("default", "default")]`` if
    :func:`scanner.frameworks.detect_frameworks` returns a non-empty
    set for ``target_repo`` (NOT recursive — a flat repo means the
    IaC files live at the top level). Any framework Checkov supports
    qualifies: Terraform ``*.tf``, Kubernetes ``*.yaml``, Dockerfile,
    Bicep, CloudFormation, ARM, Helm, etc. Otherwise raises
    :class:`NoIaCFoundError` (alias :class:`NoTerraformFoundError`).

    ``--project`` / ``--env`` filters RELABEL the single
    ``(default, default)`` pair rather than filtering to zero. A flat
    repo has exactly one stack root, so the only useful filter behavior
    is "what label should the output use?" — dropping it would lose
    the only available signal.
    """
    if detect_frameworks(target_repo):
        label_project = project_filter or "default"
        label_env = env_filter or "default"
        return [(label_project, label_env)]
    raise NoIaCFoundError(
        f"No IaC files found under {target_repo}. "
        "Expected one of: .pacioli/scope.yaml, env/<project>/<env>/, "
        "or framework files (*.tf, *.yaml, Dockerfile, *.bicep, "
        "*.template.json, etc.) at the repo root."
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
    """Parse the optional ``scan_paths:`` list from .pacioli/scope.yaml.

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
            f"{SCOPE_FILENAME} was found at "
            f"{scope_file} but PyYAML is not installed; "
            f"install pyyaml or remove {SCOPE_FILENAME}."
        )

    data = _parse_scope_manifest(scope_file).raw
    raw = data.get("scan_paths", [])

    entries: list[ScanPathEntry] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(
                f"{SCOPE_FILENAME}: scan_paths[{index}] must be a mapping, "
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
    location = f"scan_paths[{index}]"
    raw = _expect_fields(
        raw,
        {"path", "project", "env", "backend_key", "workspace", "stack_label"},
        location,
    )
    raw_path = raw.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise _scope_error(f"{location}.path", "is required and must be a non-blank string")

    path = Path(raw_path)
    if not path.is_absolute():
        path = (target_repo / raw_path).resolve()

    project = raw.get("project", "default")
    if not isinstance(project, str) or not project.strip():
        raise _scope_error(f"{location}.project", "must be a non-blank string when present")

    env_name = raw.get("env", path.name)
    if not isinstance(env_name, str) or not env_name.strip():
        raise _scope_error(f"{location}.env", "must be a non-blank string when present")

    backend_key = _optional_string(raw, "backend_key", location)
    workspace = _optional_string(raw, "workspace", location)
    stack_label = _optional_string(raw, "stack_label", location)

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
    """Handle the ``.pacioli/scope.yaml::scan_paths:`` discovery branch.

    Returns ``[]`` when the YAML has no ``scan_paths:`` list. The
    caller (in :func:`discover_pairs`) unions this list with the
    legacy branches when both are present.

    Raises :class:`NoIaCFoundError` is NOT raised here — that
    signal belongs to the legacy branches. The scan_paths branch
    coexists with them.
    """
    scope_file = target_repo / SCOPE_FILENAME
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
    """Return the resolved in-scope ``(project, env)`` pairs to scan.

    If ``.pacioli/scope.yaml`` exists, its strict ``projects:`` and optional
    ``scan_paths:`` records are authoritative. A projects pair is returned only
    when both statuses are ``in_scope``. A manifest may instead contain only
    ``scan_paths:``; declared paths are excluded only when the same manifest
    declares their logical pair pending or excluded. Otherwise discovery uses
    the ``env/<project>/<env>/`` tree, then the flat-root framework fallback.

    ``--project`` and ``--env`` filter the fully merged, exclusion-gated
    in-scope set. A non-matching filter returns ``[]``; it does not make a
    pending or excluded pair scannable. In flat-root fallback mode alone, the
    filters relabel its single ``(default, default)`` pair.

    Raises:
        NoIaCFoundError: when an unfiltered manifest, env tree, or flat repo
            produces no scan pairs.
        ScanPathsCollisionError: when colliding ``scan_paths:`` entries lack a
            per-entry ``stack_label``.
    """
    target_repo = Path(target_repo)
    scope_file = target_repo / SCOPE_FILENAME
    legacy: list[tuple[str, str]] = []
    excluded_pairs: set[tuple[str, str]] = set()

    if scope_file.is_file():
        scope_manifest = _parse_scope_manifest(scope_file)
        legacy = scope_manifest.in_scope_pairs
        excluded_pairs = scope_manifest.excluded_pairs
    elif (target_repo / "env").is_dir():
        legacy = _discover_from_env_tree(target_repo, None, None)
    else:
        legacy = _discover_flat_repo(target_repo, project_filter, env_filter)

    # scan_paths is OPTIONAL and only meaningful when .pacioli/scope.yaml
    # exists (it's a YAML key). An explicitly declared stack is omitted
    # only when its logical pair is pending/excluded in the same manifest.
    scan_path_pairs: list[DiscoveredPair] = []
    if scope_file.is_file():
        scan_path_pairs = [
            pair
            for pair in _discover_from_scan_paths(target_repo, include_modules)
            if pair.key() not in excluded_pairs
        ]

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

    # The filters operate on the fully merged, exclusion-gated result so
    # YAML projects and explicit scan_paths have identical CLI semantics.
    merged = [
        pair
        for pair in merged
        if (project_filter is None or pair.project == project_filter)
        and (env_filter is None or pair.env == env_filter)
    ]

    # Final "nothing to scan at all" guard. A filtered empty result remains a
    # valid no-match response, while an unfiltered manifest must declare at
    # least one in-scope pair or unmatched explicit scan-path.
    if not merged and project_filter is None and env_filter is None:
        raise NoIaCFoundError(
            f"No IaC files found under {target_repo}. "
            "Expected one of: .pacioli/scope.yaml, env/<project>/<env>/, "
            "or framework files (*.tf, *.yaml, Dockerfile, *.bicep, "
            "*.template.json, etc.) at the repo root."
        )

    return merged


__all__ = [
    "NoIaCFoundError",
    "NoTerraformFoundError",  # deprecated alias for NoIaCFoundError
    "ScanPathsCollisionError",
    "ScanPathEntry",
    "DiscoveredPair",
    "EXCLUDED_MODULE_DIR_NAMES",
    "discover_pairs",
]
