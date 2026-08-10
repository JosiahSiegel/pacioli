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

from discovery import NoTerraformFoundError, discover_pairs  # noqa: E402


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

    assert pairs == [("payments", "prod")]


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
    assert pairs == [
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

    assert pairs == [("default", "default")]


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

    assert pairs == [("payments", "prod")]


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

    assert pairs == [("inventory", "prod"), ("payments", "prod")]


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

    assert pairs == [("payments", "prod")]


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

    assert pairs == [("payments", "prod")]


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

    assert pairs == [("payments", "prod")]


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
        assert pairs == expected_pairs


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
    assert pairs == [("payments", "prod")]


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

    assert pairs == [("payments", "prod")]