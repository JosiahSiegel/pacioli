"""Tests for scanner/discovery.py.

Covers the four discovery branches in ``discover_pairs``:

  1. ``pci_scope.yaml`` exists → use YAML (in-scope entries only).
  2. ``env/<project>/<env>/`` tree → walk and emit one pair per real env.
  3. Flat repo → ``[("default", "default")]`` if any root ``*.tf``.
  4. None of the above → :class:`NoTerraformFoundError`.

Plus filter propagation (``--project``, ``--env``, both combined) and
the tilde-stub exclusion rule for env trees.

All tests use the ``tmp_path`` pytest fixture for isolated file-system
state. No real repo or fixture directory is touched.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the scanner package importable (conftest.py already does this,
# but tests should not assume the order).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery import (  # noqa: E402
    DiscoveredPair,
    NoTerraformFoundError,
    ScanPathEntry,
    ScanPathsCollisionError,
    discover_pairs,
)


def _pairs(pairs: list[DiscoveredPair]) -> list[tuple[str, str]]:
    """Extract ``(project, env)`` tuples from a list of DiscoveredPair.

    Centralized so tests don't have to repeat ``[(p.project, p.env) for
    p in pairs]`` everywhere. Returns a list of plain tuples so
    equality against literal ``[("a", "b")]`` works.
    """
    return [(p.project, p.env) for p in pairs]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env_tree(
    root: Path,
    layout: dict[str, dict[str, list[str]]],
) -> None:
    """Build an env/ tree under ``root`` from a nested-dict spec.

    ``layout`` is ``{project_name: {env_name: [list of .tf filenames]}}``.
    Each filename is written as an empty file. A special filename of
    ``"~stub.tf"`` (or anything starting with ``~``) is included so
    tests can verify the tilde-exclusion rule.
    """
    env_root = root / "env"
    env_root.mkdir()
    for project_name, envs in layout.items():
        project_dir = env_root / project_name
        project_dir.mkdir()
        for env_name, tf_files in envs.items():
            env_dir = project_dir / env_name
            env_dir.mkdir()
            for filename in tf_files:
                (env_dir / filename).write_text("", encoding="utf-8")


def _write_yaml(path: Path, content: str) -> None:
    """Write a utf-8 YAML file at ``path`` (creating parents)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. env/ tree detection
# ---------------------------------------------------------------------------


def test_env_tree_with_one_pair(tmp_path: Path) -> None:
    """An env/ tree with one (project, env) yields exactly one pair."""
    _make_env_tree(
        tmp_path,
        {"payments": {"prod": ["main.tf", "variables.tf"]}},
    )

    pairs = discover_pairs(tmp_path)

    assert _pairs(pairs) == [("payments", "prod")]


def test_env_tree_with_multiple_pairs(tmp_path: Path) -> None:
    """An env/ tree with several projects/envs emits all of them, sorted."""
    _make_env_tree(
        tmp_path,
        {
            "payments": {
                "dev": ["main.tf"],
                "staging": ["main.tf"],
                "prod": ["main.tf"],
            },
            "inventory": {
                "prod": ["main.tf"],
            },
        },
    )

    pairs = discover_pairs(tmp_path)

    # Sorted: alphabetical by project, then env within project.
    assert _pairs(pairs) == [
        ("inventory", "prod"),
        ("payments", "dev"),
        ("payments", "prod"),
        ("payments", "staging"),
    ]


# ---------------------------------------------------------------------------
# 2. default/default fallback (flat repo)
# ---------------------------------------------------------------------------


def test_flat_repo_returns_default_pair(tmp_path: Path) -> None:
    """A repo with no env/ dir and at least one root *.tf returns [('default','default')]."""
    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    (tmp_path / "variables.tf").write_text("", encoding="utf-8")
    # Noise: non-.tf files should not count, but should not crash either.
    (tmp_path / "README.md").write_text("", encoding="utf-8")

    pairs = discover_pairs(tmp_path)

    assert _pairs(pairs) == [("default", "default")]


# ---------------------------------------------------------------------------
# 3. Empty repo → NoTerraformFoundError
# ---------------------------------------------------------------------------


def test_empty_repo_raises_no_terraform_found_error(tmp_path: Path) -> None:
    """A repo with no .tf files, no env/, and no pci_scope.yaml raises."""
    # Add only a non-terraform file to prove "empty for our purposes".
    (tmp_path / "README.md").write_text("no terraform here", encoding="utf-8")

    with pytest.raises(NoTerraformFoundError):
        discover_pairs(tmp_path)


def test_no_terraform_found_error_is_file_not_found_error(tmp_path: Path) -> None:
    """NoTerraformFoundError subclasses FileNotFoundError for back-compat."""
    assert issubclass(NoTerraformFoundError, FileNotFoundError)

    # Verify it can be caught as FileNotFoundError (the bash scanner
    # sometimes wraps it that way).
    (tmp_path / "README.md").write_text("", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        discover_pairs(tmp_path)


# ---------------------------------------------------------------------------
# 4. Filter propagation
# ---------------------------------------------------------------------------


def test_project_filter_keeps_only_matching_project(tmp_path: Path) -> None:
    """--project retains only pairs whose project matches."""
    _make_env_tree(
        tmp_path,
        {
            "payments": {"prod": ["main.tf"]},
            "inventory": {"prod": ["main.tf"]},
        },
    )

    pairs = discover_pairs(tmp_path, project_filter="payments")

    assert _pairs(pairs) == [("payments", "prod")]


def test_env_filter_keeps_only_matching_env(tmp_path: Path) -> None:
    """--env retains only pairs whose env matches (across projects)."""
    _make_env_tree(
        tmp_path,
        {
            "payments": {"dev": ["main.tf"], "prod": ["main.tf"]},
            "inventory": {"dev": ["main.tf"], "prod": ["main.tf"]},
        },
    )

    pairs = discover_pairs(tmp_path, env_filter="prod")

    assert _pairs(pairs) == [("inventory", "prod"), ("payments", "prod")]


def test_project_and_env_filter_combined(tmp_path: Path) -> None:
    """Combining --project and --env narrows to a single pair."""
    _make_env_tree(
        tmp_path,
        {
            "payments": {"dev": ["main.tf"], "prod": ["main.tf"]},
            "inventory": {"dev": ["main.tf"], "prod": ["main.tf"]},
        },
    )

    pairs = discover_pairs(
        tmp_path,
        project_filter="payments",
        env_filter="prod",
    )

    assert _pairs(pairs) == [("payments", "prod")]


def test_project_filter_with_no_matches_returns_empty(tmp_path: Path) -> None:
    """Filtering to a non-existent project returns [] (not an error).

    The caller is expected to surface "no matches" as a user-facing
    message rather than an exception. ``NoTerraformFoundError`` is
    reserved for the "nothing to scan at all" case.
    """
    _make_env_tree(
        tmp_path,
        {"payments": {"prod": ["main.tf"]}},
    )

    pairs = discover_pairs(tmp_path, project_filter="nonexistent")

    assert pairs == []


# ---------------------------------------------------------------------------
# 5. Tilde-stub exclusion
# ---------------------------------------------------------------------------


def test_tilde_stub_tf_files_are_excluded(tmp_path: Path) -> None:
    """An env dir containing only ``~*.tf`` stubs is not a real env.

    ``~main.tf`` is the classic "intentionally empty / not yet started"
    stub convention from the bash scanner; it must not produce a pair.
    A real env alongside the stub one must still be detected.
    """
    _make_env_tree(
        tmp_path,
        {
            "payments": {
                "ghost": ["~ghost.tf"],  # stub only → should NOT emit
                "prod": ["main.tf"],     # real → should emit
            },
        },
    )

    pairs = discover_pairs(tmp_path)

    assert _pairs(pairs) == [("payments", "prod")]


def test_env_with_mixed_real_and_stub_tf_files_is_kept(tmp_path: Path) -> None:
    """If an env dir has at least one real *.tf, the pair is kept even with stubs."""
    _make_env_tree(
        tmp_path,
        {
            "payments": {
                "prod": ["main.tf", "~wip.tf", "~future.tf"],
            },
        },
    )

    pairs = discover_pairs(tmp_path)

    assert _pairs(pairs) == [("payments", "prod")]


# ---------------------------------------------------------------------------
# 6. pci_scope.yaml precedence + in-scope-only filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "yaml_text, expected_pairs",
    [
        # Only in_scope entries are honored.
        (
            """
projects:
  - project: payments
    status: in_scope
    envs: [dev, prod]
  - project: sandbox
    status: out_of_scope
    envs: [dev, prod]
  - project: dev_sandbox
    status: not_in_scope
    envs: [dev]
""",
            [("payments", "dev"), ("payments", "prod")],
        ),
        # No envs key for an in_scope entry → no pairs for it.
        (
            """
projects:
  - project: payments
    status: in_scope
    envs: [prod]
  - project: empty
    status: in_scope
""",
            [("payments", "prod")],
        ),
        # No in_scope entries → discovery falls through and (since
        # there's no env/ and no root .tf) raises.
        (
            """
projects:
  - project: sandbox
    status: out_of_scope
    envs: [dev]
""",
            None,  # sentinel: expect NoTerraformFoundError
        ),
    ],
    ids=["in_scope_only", "missing_envs", "no_in_scope_entries"],
)
def test_pci_scope_yaml_in_scope_only(
    tmp_path: Path,
    yaml_text: str,
    expected_pairs: list[tuple[str, str]] | None,
) -> None:
    """pci_scope.yaml is the source of truth; only ``status: in_scope`` entries load."""
    _write_yaml(tmp_path / "pci_scope.yaml", yaml_text)

    if expected_pairs is None:
        with pytest.raises(NoTerraformFoundError):
            discover_pairs(tmp_path)
    else:
        pairs = discover_pairs(tmp_path)
        assert _pairs(pairs) == expected_pairs


def test_pci_scope_yaml_takes_precedence_over_env_tree(tmp_path: Path) -> None:
    """When pci_scope.yaml exists, env/ subdirectories are ignored.

    The YAML is authoritative — a sandbox project may have
    env/<sandbox>/<env>/ on disk but the YAML marks it out_of_scope,
    so its pairs must not appear in the result.
    """
    # env/ tree has both in-scope and out-of-scope projects on disk.
    _make_env_tree(
        tmp_path,
        {
            "payments": {"prod": ["main.tf"]},
            "sandbox": {"dev": ["main.tf"]},
        },
    )
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        """
projects:
  - project: payments
    status: in_scope
    envs: [prod]
  - project: sandbox
    status: out_of_scope
    envs: [dev]
""",
    )

    pairs = discover_pairs(tmp_path)

    # sandbox/dev is on disk but the YAML excludes it.
    assert _pairs(pairs) == [("payments", "prod")]


def test_pci_scope_yaml_with_filters(tmp_path: Path) -> None:
    """--project/--env filters apply AFTER the YAML is consulted."""
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        """
projects:
  - project: payments
    status: in_scope
    envs: [dev, prod]
  - project: inventory
    status: in_scope
    envs: [dev, prod]
""",
    )

    pairs = discover_pairs(
        tmp_path,
        project_filter="payments",
        env_filter="prod",
    )

    assert _pairs(pairs) == [("payments", "prod")]


# ---------------------------------------------------------------------------
# 7. scan_paths: schema
# ---------------------------------------------------------------------------


def _make_stack_root(
    parent: Path,
    name: str,
    tf_files: list[str] | None = None,
) -> Path:
    """Create a stack-root directory with a few ``*.tf`` files.

    ``tf_files`` defaults to ``["main.tf"]``. The directory is returned
    as an absolute path so test assertions can compare against
    ``scan_paths:`` resolutions directly.
    """
    root = parent / name
    root.mkdir(parents=True, exist_ok=True)
    for filename in (tf_files if tf_files is not None else ["main.tf"]):
        (root / filename).write_text("# stub\n", encoding="utf-8")
    return root.resolve()


def test_scan_paths_basic_discovery(tmp_path: Path) -> None:
    """``scan_paths:`` entries with explicit project/env emit one pair each."""
    stack_a = _make_stack_root(tmp_path, "stack_a")
    stack_b = _make_stack_root(tmp_path, "stack_b")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {stack_a}
    project: payments
    env: prod
  - path: {stack_b}
    project: inventory
    env: prod
""",
    )

    pairs = discover_pairs(tmp_path)

    assert _pairs(pairs) == [("payments", "prod"), ("inventory", "prod")]
    # The pair's stack_root must equal the YAML's path verbatim.
    assert pairs[0].stack_root == stack_a
    assert pairs[1].stack_root == stack_b


def test_scan_paths_unions_with_projects_branch(tmp_path: Path) -> None:
    """``scan_paths:`` is unioned with the ``projects:`` branch.

    Both branches appear in the final result; the YAML is the source
    of truth for ``projects:``-only stacks and ``scan_paths:`` is
    authoritative for declared stack roots.
    """
    env_root = tmp_path / "env" / "payments" / "prod"
    env_root.mkdir(parents=True)
    (env_root / "main.tf").write_text("", encoding="utf-8")

    # Plus a scan_paths: stack that lives outside env/.
    other_stack = _make_stack_root(tmp_path, Path("monorepo") / "platform")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
projects:
  - project: payments
    status: in_scope
    envs: [prod]
scan_paths:
  - path: {other_stack}
    project: platform
    env: main
""",
    )

    pairs = discover_pairs(tmp_path)

    # Both branches contribute. scan_paths: stack_root is set;
    # projects: stack_root is None (legacy branch).
    payments_pair = next(p for p in pairs if p.project == "payments")
    platform_pair = next(p for p in pairs if p.project == "platform")
    assert payments_pair.stack_root is None
    assert platform_pair.stack_root == other_stack


def test_scan_paths_defaults_project_and_env(tmp_path: Path) -> None:
    """``project`` defaults to ``"default"``; ``env`` defaults to basename(path)."""
    stack = _make_stack_root(tmp_path, "my-cluster")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {stack}
""",
    )

    pairs = discover_pairs(tmp_path)

    assert len(pairs) == 1
    assert pairs[0].project == "default"
    assert pairs[0].env == "my-cluster"


def test_scan_paths_relative_path_resolved_against_target_repo(tmp_path: Path) -> None:
    """Relative ``path:`` values are resolved against the target repo."""
    stack = _make_stack_root(tmp_path, "relpath_stack")
    rel = stack.relative_to(tmp_path)
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {rel.as_posix()}
    project: relproject
    env: relenv
""",
    )

    pairs = discover_pairs(tmp_path)

    assert pairs[0].stack_root == stack


def test_scan_paths_collides_without_stack_label(tmp_path: Path) -> None:
    """Two entries with the same (project, env) raise ScanPathsCollisionError.

    The error message must name both paths so the operator can add
    a per-entry ``stack_label:`` to disambiguate.
    """
    stack_a = _make_stack_root(tmp_path, "stack_a")
    stack_b = _make_stack_root(tmp_path, "stack_b")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {stack_a}
    project: payments
    env: prod
  - path: {stack_b}
    project: payments
    env: prod
""",
    )

    with pytest.raises(ScanPathsCollisionError) as excinfo:
        discover_pairs(tmp_path)

    msg = str(excinfo.value)
    # Must reference both colliding paths so the operator can find them.
    assert str(stack_a) in msg
    assert str(stack_b) in msg
    # And mention stack_label as the disambiguator.
    assert "stack_label" in msg


def test_scan_paths_collision_resolved_by_stack_label(tmp_path: Path) -> None:
    """Two entries with the same (project, env) but distinct stack_labels coexist."""
    stack_a = _make_stack_root(tmp_path, "stack_a")
    stack_b = _make_stack_root(tmp_path, "stack_b")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {stack_a}
    project: payments
    env: prod
    stack_label: east
  - path: {stack_b}
    project: payments
    env: prod
    stack_label: west
""",
    )

    pairs = discover_pairs(tmp_path)

    assert len(pairs) == 2
    labels = {p.stack_label for p in pairs}
    assert labels == {"east", "west"}


def test_scan_paths_only_one_label_also_fails_closed(tmp_path: Path) -> None:
    """If one of two colliding entries has a stack_label but the other doesn't,
    discovery MUST still raise — the unlabeled entry is ambiguous.
    """
    stack_a = _make_stack_root(tmp_path, "stack_a")
    stack_b = _make_stack_root(tmp_path, "stack_b")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {stack_a}
    project: payments
    env: prod
    stack_label: east
  - path: {stack_b}
    project: payments
    env: prod
""",
    )

    with pytest.raises(ScanPathsCollisionError):
        discover_pairs(tmp_path)


def test_scan_paths_passes_backend_key_through(tmp_path: Path) -> None:
    """Per-entry ``backend_key:`` is preserved on the DiscoveredPair."""
    stack = _make_stack_root(tmp_path, "stack")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {stack}
    project: payments
    env: prod
    backend_key: payments-prod.tfstate
    workspace: my-ws
""",
    )

    pairs = discover_pairs(tmp_path)

    assert pairs[0].backend_key == "payments-prod.tfstate"
    assert pairs[0].workspace == "my-ws"


# ---------------------------------------------------------------------------
# 8. Module directory exclusion (source-tier default)
# ---------------------------------------------------------------------------


def test_scan_paths_excludes_modules_dir_by_default(tmp_path: Path) -> None:
    """A stack-root named ``modules`` is excluded when ``include_modules`` is False.

    Matches the bash scanner's source-tier contract: monorepo
    internal module libraries are not standalone root modules.
    """
    excluded = _make_stack_root(tmp_path, "modules")
    other = _make_stack_root(tmp_path, "real")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {excluded}
  - path: {other}
""",
    )

    pairs = discover_pairs(tmp_path, include_modules=False)

    # Only the non-modules entry is included.
    assert _pairs(pairs) == [("default", "real")]


def test_scan_paths_excludes_modules_dash_dir_by_default(tmp_path: Path) -> None:
    """``modules-<x>`` family is also excluded (per-component module libs)."""
    excluded = _make_stack_root(tmp_path, "modules-network")
    other = _make_stack_root(tmp_path, "real")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {excluded}
  - path: {other}
""",
    )

    pairs = discover_pairs(tmp_path, include_modules=False)

    assert _pairs(pairs) == [("default", "real")]


def test_scan_paths_excludes_terraform_dir_by_default(tmp_path: Path) -> None:
    """``.terraform/`` working dir is excluded by default.

    ``.terraform/`` is the ``terraform init`` working directory; the
    ``*.tf`` files inside are downloaded providers, not source code.
    """
    excluded = _make_stack_root(tmp_path, ".terraform")
    other = _make_stack_root(tmp_path, "real")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {excluded}
  - path: {other}
""",
    )

    pairs = discover_pairs(tmp_path, include_modules=False)

    assert _pairs(pairs) == [("default", "real")]


def test_scan_paths_include_modules_opts_in(tmp_path: Path) -> None:
    """``include_modules=True`` honors the modules/ entry as a stack root."""
    excluded = _make_stack_root(tmp_path, "modules")
    other = _make_stack_root(tmp_path, "real")
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        f"""
scan_paths:
  - path: {excluded}
  - path: {other}
""",
    )

    pairs = discover_pairs(tmp_path, include_modules=True)

    # Both entries are now honored.
    envs = {p.env for p in pairs}
    assert envs == {"modules", "real"}


# ---------------------------------------------------------------------------
# 9. Flat-root relabel behavior (--env / --project on the default pair)
# ---------------------------------------------------------------------------


def test_flat_repo_filters_relabel_instead_of_drop(tmp_path: Path) -> None:
    """--env / --project on a flat repo relabel the single (default, default) pair.

    A flat repo has exactly one stack root, so the only useful filter
    behavior is "what label should the output use?" — filtering to
    zero would lose the only available signal.
    """
    (tmp_path / "main.tf").write_text("", encoding="utf-8")

    pairs = discover_pairs(tmp_path, project_filter="payments", env_filter="prod")

    assert _pairs(pairs) == [("payments", "prod")]


def test_flat_repo_filter_only_project(tmp_path: Path) -> None:
    """--project relabels the project; env stays at ``default``."""
    (tmp_path / "main.tf").write_text("", encoding="utf-8")

    pairs = discover_pairs(tmp_path, project_filter="payments")

    assert _pairs(pairs) == [("payments", "default")]


def test_flat_repo_filter_only_env(tmp_path: Path) -> None:
    """--env relabels the env; project stays at ``default``."""
    (tmp_path / "main.tf").write_text("", encoding="utf-8")

    pairs = discover_pairs(tmp_path, env_filter="staging")

    assert _pairs(pairs) == [("default", "staging")]


# ---------------------------------------------------------------------------
# 10. No-op / backward-compat: empty scan_paths: list and missing key
# ---------------------------------------------------------------------------


def test_scan_paths_empty_list_is_noop(tmp_path: Path) -> None:
    """An empty ``scan_paths:`` list does not affect the projects: branch."""
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        """
scan_paths: []
projects:
  - project: payments
    status: in_scope
    envs: [prod]
""",
    )

    pairs = discover_pairs(tmp_path)

    assert _pairs(pairs) == [("payments", "prod")]


def test_scan_paths_missing_key_is_noop(tmp_path: Path) -> None:
    """A pci_scope.yaml without ``scan_paths:`` is unchanged in behavior."""
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        """
projects:
  - project: payments
    status: in_scope
    envs: [prod]
""",
    )

    pairs = discover_pairs(tmp_path)

    assert _pairs(pairs) == [("payments", "prod")]
    # Legacy branch: stack_root is None.
    assert pairs[0].stack_root is None


def test_scan_paths_invalid_path_raises(tmp_path: Path) -> None:
    """A scan_paths entry missing the required ``path:`` field raises ValueError."""
    _write_yaml(
        tmp_path / "pci_scope.yaml",
        """
scan_paths:
  - project: payments
    env: prod
""",
    )

    with pytest.raises(ValueError, match="path is required"):
        discover_pairs(tmp_path)


# ---------------------------------------------------------------------------
# 11. ScanPathEntry / DiscoveredPair dataclass shape
# ---------------------------------------------------------------------------


def test_scan_path_entry_pair_property(tmp_path: Path) -> None:
    """ScanPathEntry.pair is the ``(project, env)`` discovery key."""
    entry = ScanPathEntry(
        path=tmp_path / "x",
        project="p",
        env="e",
    )
    assert entry.pair == ("p", "e")


def test_discovered_pair_unpacks_like_tuple(tmp_path: Path) -> None:
    """DiscoveredPair is iterable as ``(project, env)`` for back-compat.

    Existing consumers that do ``for proj, env in pairs:`` keep working
    after the migration to DiscoveredPair.
    """
    p = DiscoveredPair(project="a", env="b")
    proj, env = p
    assert (proj, env) == ("a", "b")