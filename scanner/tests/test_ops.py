"""scanner/tests/test_ops.py — pytest coverage for scanner.ops.

Every required behavior gets one test:

1. registry contains every required op name
2. unknown operation name raises UnknownOperation
3. argv schema validation rejects mismatched argv
4. tier violation rejects forbidden tier
5. shutil.which returning None raises TrustedBinaryMissing
6. env blocklist strips TF_PLUGIN_CACHE_DIR
7. refusal matrix is defense-in-depth (composed argv still fires)
8. ``python -m scanner.ops --self-test`` exits 0
"""
from __future__ import annotations

import subprocess
import sys

import pytest

import scanner.ops as ops
from scanner.ops import (
    OPERATION_REGISTRY,
    ArgvSchemaViolation,
    Operation,
    OpsError,
    TierViolation,
    TrustedBinaryMissing,
    UnknownOperation,
)


# ---------------------------------------------------------------------------
# 1. Registry completeness
# ---------------------------------------------------------------------------

REQUIRED_OPS: tuple[str, ...] = (
    "az.blob_download",
    "az.blob_list",
    "terraform.init_local",
    "terraform.plan_local",
    "terraform.show_json",
    "python.tfstate_to_plan",
    "python.drift_report",
    "shred",
)


def test_registry_contains_required_ops() -> None:
    """Every required op name is in OPERATION_REGISTRY."""
    missing = [name for name in REQUIRED_OPS if name not in OPERATION_REGISTRY]
    assert not missing, f"missing required ops: {missing}"


# ---------------------------------------------------------------------------
# 2. UnknownOperation
# ---------------------------------------------------------------------------


def test_unknown_operation_raises() -> None:
    """ops.run("nonexistent", ...) raises UnknownOperation.

    Uses a tier that's valid for many ops so the failure mode is
    unambiguously "no such name" (not "tier mismatch").
    """
    with pytest.raises(UnknownOperation):
        ops.run("nonexistent", "x", tier="plan")


# ---------------------------------------------------------------------------
# 3. ArgvSchemaViolation
# ---------------------------------------------------------------------------


def test_argv_schema_validation() -> None:
    """Extra argv that doesn't match schema raises ArgvSchemaViolation.

    terraform.init_local schema is exactly 6 tokens (Todo 6: added
    ``-backend=false``). Passing 7 (or any mismatched length) must
    fail with ArgvSchemaViolation, not silently drop tokens.
    """
    with pytest.raises(ArgvSchemaViolation):
        ops.run(
            "terraform.init_local",
            "-chdir", "/some/path", "init",
            "-input=false", "-backend=false", "-no-color",
            "EXTRA_TOKEN_SHOULD_FAIL",
            tier="plan",
        )


def test_argv_schema_literal_mismatch_raises() -> None:
    """A literal token at a wrong position is also ArgvSchemaViolation.

    Complements the length test above — covers the position-by-position
    literal match path.
    """
    with pytest.raises(ArgvSchemaViolation):
        ops.run(
            "terraform.init_local",
            "-WRONG-LITERAL", "/some/path", "init",
            "-input=false", "-backend=false", "-no-color",
            tier="plan",
        )


# ---------------------------------------------------------------------------
# 4. TierViolation
# ---------------------------------------------------------------------------


def test_tier_violation() -> None:
    """terraform.plan_local with tier=source raises TierViolation.

    plan_local's allowed_tiers is ("plan", "state"). tier="source"
    must be refused before any subprocess runs. The argv matches the
    new 8-token schema (Todo 6: ``-lock=false -refresh=false``).
    """
    with pytest.raises(TierViolation):
        ops.run(
            "terraform.plan_local",
            "-chdir", "/some/path", "plan",
            "-no-color", "-out=tfplan.binary",
            "-lock=false", "-refresh=false",
            tier="source",
        )


# ---------------------------------------------------------------------------
# 5. TrustedBinaryMissing
# ---------------------------------------------------------------------------


def test_trusted_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """monkeypatching shutil.which to return None raises TrustedBinaryMissing.

    We patch scanner.ops.shutil.which (the module-level binding the
    registry consults) so the resolution path inside run() sees None.
    """
    monkeypatch.setattr(ops.shutil, "which", lambda _name: None)
    with pytest.raises(TrustedBinaryMissing):
        ops.run(
            "terraform.init_local",
            "-chdir", "/some/path", "init",
            "-input=false", "-backend=false", "-no-color",
            tier="plan",
        )


# ---------------------------------------------------------------------------
# 6. Env blocklist
# ---------------------------------------------------------------------------


def test_env_blocklist_drops_tf_plugin_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TF_PLUGIN_CACHE_DIR is stripped from the per-op environment.

    terraform.init_local has env_allowlist=("*",) (pass-through minus
    blocklist), so we can observe the blocklist effect directly by
    calling _build_env. No subprocess is launched.
    """
    monkeypatch.setenv("TF_PLUGIN_CACHE_DIR", "/tmp/cache-should-not-leak")
    cleaned = ops._build_env(
        ops.OPERATION_REGISTRY["terraform.init_local"], caller_env=None,
    )
    assert "TF_PLUGIN_CACHE_DIR" not in cleaned, (
        "TF_PLUGIN_CACHE_DIR must be stripped from the env passed to "
        f"the subprocess; got: {sorted(k for k in cleaned if k.startswith('TF_'))}"
    )


# ---------------------------------------------------------------------------
# 7. Defense-in-depth refusal
# ---------------------------------------------------------------------------


def test_refusal_matrix_is_defense_in_depth() -> None:
    """Composing argv that matches REFUSE_PATTERN raises MutatingOperationRefused.

    We register a temp op whose argv composes to ``terraform apply
    -auto-approve`` and confirm the existing refusal matrix fires on
    the composed command line. Patches OPERATION_REGISTRY in place
    (it is a module-level dict, not frozen in mutation semantics) and
    restores it after the test.
    """
    from scanner.safety import MutatingOperationRefused, SafetyGuard

    saved = dict(ops.OPERATION_REGISTRY)
    try:
        ops.OPERATION_REGISTRY["test.dangerous_apply"] = Operation(
            name="test.dangerous_apply",
            executable="terraform",
            argv_schema=("apply", "-auto-approve"),
            allowed_tiers=("plan", "state"),
            default_timeout=60,
            mutation_class="mutate_azure",
            cleanup_obligation="none",
            env_allowlist=("*",),
        )
        # Either the refusal fires (success) or shutil.which returns
        # None (test env has no terraform binary) — both are
        # acceptable; the test fails only if NEITHER path is taken
        # (i.e. the composed argv reaches subprocess.run, which
        # would actually launch terraform).
        try:
            ops.run("test.dangerous_apply", "apply", "-auto-approve", tier="plan")
        except (MutatingOperationRefused, TrustedBinaryMissing):
            pass
        else:
            # Defense-in-depth was bypassed AND terraform was found AND
            # the subprocess returned without raising — extremely
            # unlikely (the regex would fire first), but explicit
            # assertion makes the contract clear.
            pytest.fail(
                "defense-in-depth refusal did not fire and no "
                "TrustedBinaryMissing was raised — composed argv "
                "may have leaked to a real subprocess"
            )
        # Sanity check: the refusal matrix itself still refuses this
        # command string (it would fire before any subprocess launch).
        with pytest.raises(MutatingOperationRefused):
            SafetyGuard().refuse_if_mutating("terraform apply -auto-approve")
    finally:
        ops.OPERATION_REGISTRY.clear()
        ops.OPERATION_REGISTRY.update(saved)


# ---------------------------------------------------------------------------
# 8. --self-test CLI exits 0
# ---------------------------------------------------------------------------


def test_self_test_script_exits_zero() -> None:
    """``python -m scanner.ops --self-test`` exits 0.

    Spawns a fresh interpreter to defeat the __main__ / scanner.ops
    class-identity split (the self-test calls _self.run, which would
    see the same __main__ classes otherwise).
    """
    result = subprocess.run(
        [sys.executable, "-m", "scanner.ops", "--self-test"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, (
        f"self-test exited {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# 9. Exact argv composition for the privileged tiers (Todo 6).
# ---------------------------------------------------------------------------


def test_init_local_composes_to_exact_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``terraform.init_local`` produces the exact 6-token argv.

    The argv after the resolved terraform binary must be exactly::

        -chdir <env_dir> init -input=false -backend=false -no-color

    ``-backend=false`` was added in Todo 6. If anyone swaps a literal
    or drops a token, this test fails before any real terraform is
    launched. ``subprocess.run`` is patched to capture the final argv
    and return a benign CompletedProcess so the test stays hermetic.
    """
    captured: dict[str, object] = {}

    def _fake_run(argv, *args, **kwargs):  # type: ignore[no-untyped-def]
        captured["argv"] = argv
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr="",
        )

    monkeypatch.setattr(ops.subprocess, "run", _fake_run)

    ops.run(
        "terraform.init_local",
        "-chdir", "/env/dir",
        "init",
        "-input=false",
        "-backend=false",
        "-no-color",
        tier="plan",
    )

    final_argv = captured["argv"]
    assert isinstance(final_argv, list)
    # First token is the resolved executable; the rest is the schema.
    assert final_argv[1:] == [
        "-chdir", "/env/dir",
        "init",
        "-input=false", "-backend=false", "-no-color",
    ], (
        f"terraform.init_local argv drifted from the documented 6-token "
        f"schema; got {final_argv[1:]!r}"
    )


def test_plan_local_composes_to_exact_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``terraform.plan_local`` produces the exact 8-token argv.

    The argv after the resolved terraform binary must be exactly::

        -chdir <env_dir> plan -no-color -out=<plan_bin> -lock=false -refresh=false

    ``-lock=true`` was replaced with ``-lock=false -refresh=false`` in
    Todo 6. This test pins the contract; a future schema change that
    drops or reorders any literal must update the test deliberately
    (this is the point — the schema is the primary safety control).
    """
    captured: dict[str, object] = {}

    def _fake_run(argv, *args, **kwargs):  # type: ignore[no-untyped-def]
        captured["argv"] = argv
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr="",
        )

    monkeypatch.setattr(ops.subprocess, "run", _fake_run)

    ops.run(
        "terraform.plan_local",
        "-chdir", "/env/dir",
        "plan",
        "-no-color",
        "-out=tfplan.binary",
        "-lock=false",
        "-refresh=false",
        tier="plan",
    )

    final_argv = captured["argv"]
    assert isinstance(final_argv, list)
    assert final_argv[1:] == [
        "-chdir", "/env/dir",
        "plan",
        "-no-color",
        "-out=tfplan.binary",
        "-lock=false", "-refresh=false",
    ], (
        f"terraform.plan_local argv drifted from the documented 8-token "
        f"schema; got {final_argv[1:]!r}"
    )


# ---------------------------------------------------------------------------
# Sanity: structural invariants
# ---------------------------------------------------------------------------


def test_all_ops_have_required_fields() -> None:
    """Every registered op has the required dataclass fields populated."""
    for name, op in OPERATION_REGISTRY.items():
        assert op.name == name, f"registry key {name!r} != op.name {op.name!r}"
        assert op.executable, f"{name}: empty executable"
        assert op.argv_schema, f"{name}: empty argv_schema"
        assert op.allowed_tiers, f"{name}: empty allowed_tiers"
        assert op.default_timeout > 0, f"{name}: non-positive default_timeout"


def test_ops_error_subclass_tree() -> None:
    """All OpsError subclasses inherit from OpsError (not from Exception directly)."""
    assert issubclass(UnknownOperation, OpsError)
    assert issubclass(ArgvSchemaViolation, OpsError)
    assert issubclass(TrustedBinaryMissing, OpsError)
    assert issubclass(TierViolation, OpsError)
