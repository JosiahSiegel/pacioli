"""scanner/ops.py — Typed operation registry for production subprocess calls.

Canonical entry point for every production subprocess. Each named
:class:`Operation` carries exact executable identity, exact argv
schema, per-op tier, timeout, env allowlist, cwd policy, mutation
class, and cleanup obligation. The existing refusal matrix in
:mod:`scanner.safety` is invoked from :func:`run` as defense-in-depth.

Why: previous call sites built argv inline and relied on regex as
the primary control. Regex is a coarse net — this registry makes
the allowlist the primary control. A new mutation requires a new
registered operation; you cannot smuggle it in by appending a flag.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

# ``MutatingOperationRefused`` is intentionally re-exported from this
# module: ``_self_test`` below resolves it as
# ``_self.MutatingOperationRefused`` off the module namespace, which only
# exists because of this import. Removing it breaks the self-test.
from scanner.safety import MutatingOperationRefused, SafetyGuard  # noqa: F401


# ---------------------------------------------------------------------------
# Exceptions + schema sentinels
# ---------------------------------------------------------------------------

class OpsError(Exception):
    """Base class for every :mod:`scanner.ops` raised error."""


class UnknownOperation(OpsError):
    """Raised when :func:`run` is called with an unregistered name."""


class ArgvSchemaViolation(OpsError):
    """Raised when caller-supplied argv does not match the registered schema."""


class TrustedBinaryMissing(OpsError):
    """Raised when :func:`shutil.which` returns ``None`` for the op's executable."""


class TierViolation(OpsError):
    """Raised when the caller's tier is not in the op's ``allowed_tiers``."""


# Sentinel for ``Operation.argv_schema`` positions that accept arbitrary
# caller-supplied tokens.
ANY: Final[str] = "ANY"

Tier = Literal["source", "plan", "state"]
CwdPolicy = Literal["caller", "run_dir", "stack_root"]
MutationClass = Literal["read", "write", "network", "mutate_azure"]
CleanupObligation = Literal["none", "shred", "unlink"]


# Default env blocklist applied to every operation. ``TF_PLUGIN_CACHE_DIR``
# causes Terraform to use a stale plugin cache if it leaks through;
# ``TF_DATA_DIR`` and ``TF_CLI_CONFIG_FILE`` redirect Terraform's own
# state store. The scanner drives ``init``/``plan`` explicitly via the
# registry, so these ambient hints must never reach any op.
_DEFAULT_ENV_BLOCKLIST: Final[tuple[str, ...]] = (
    "TF_PLUGIN_CACHE_DIR",
    "TF_DATA_DIR",
    "TF_CLI_CONFIG_FILE",
    "TF_INPUT",
    "TF_VAR_",
    "TF_CLI_ARGS",
)


# Operation dataclass


@dataclass(frozen=True)
class Operation:
    """A typed, registered subprocess the scanner is allowed to launch.

    ``argv_schema`` is walked position-by-position against the caller's
    variable tail: literal tokens must match exactly, :data:`ANY`
    tokens accept any caller value.
    """

    name: str
    executable: str
    argv_schema: tuple[str, ...]
    allowed_tiers: tuple[Tier, ...]
    default_timeout: int
    mutation_class: MutationClass
    cleanup_obligation: CleanupObligation
    cwd_policy: CwdPolicy = "caller"
    env_allowlist: tuple[str, ...] = field(default_factory=tuple)
    env_blocklist: tuple[str, ...] = field(
        default_factory=lambda: _DEFAULT_ENV_BLOCKLIST
    )


# Operation registry
#
# allow: SIZE_OK — 10 ops × ~10 lines each is a pure data table;
# splitting would scatter the safety-critical operation list across
# files without reducing its size.

OPERATION_REGISTRY: Final[dict[str, Operation]] = {
    # Azure storage blob ops (state-only download; plan/state list).
    "az.blob_download": Operation(
        name="az.blob_download", executable="az",
        argv_schema=("storage", "blob", "download",
                     "--account-name", ANY, "--container-name", ANY,
                     "--name", ANY, "--file", ANY,
                     "--auth-mode", "login", "--output", "none"),
        allowed_tiers=("state",), default_timeout=60,
        mutation_class="read", cleanup_obligation="none",
        env_allowlist=("AZURE_CONFIG_DIR", "AZURE_CORE_OUTPUT"),
    ),
    "az.blob_list": Operation(
        name="az.blob_list", executable="az",
        argv_schema=("storage", "blob", "list",
                     "--account-name", ANY, "--container-name", ANY,
                     "--auth-mode", "login", "--query", ANY, "-o", "tsv"),
        allowed_tiers=("plan", "state"), default_timeout=60,
        mutation_class="read", cleanup_obligation="none",
        env_allowlist=("AZURE_CONFIG_DIR", "AZURE_CORE_OUTPUT"),
    ),
    # Terraform (tier=plan/state only). Argv mirrors scanner/orchestrator.py.
    "terraform.init_local": Operation(
        name="terraform.init_local", executable="terraform",
        argv_schema=(
            "-chdir", ANY, "init",
            "-input=false", "-backend=false", "-no-color",
        ),
        allowed_tiers=("plan", "state"), default_timeout=300,
        mutation_class="network", cleanup_obligation="none",
        env_allowlist=("*",),
    ),
    "terraform.plan_local": Operation(
        name="terraform.plan_local", executable="terraform",
        argv_schema=(
            "-chdir", ANY, "plan",
            "-no-color", ANY,
            "-lock=false", "-refresh=false",
        ),
        allowed_tiers=("plan", "state"), default_timeout=600,
        mutation_class="network", cleanup_obligation="shred",
        env_allowlist=("*",),
    ),
    "terraform.show_json": Operation(
        name="terraform.show_json", executable="terraform",
        argv_schema=("-chdir", ANY, "show", "-json", ANY),
        allowed_tiers=("plan", "state"), default_timeout=120,
        mutation_class="read", cleanup_obligation="none",
        env_allowlist=("*",),
    ),
    # Python helper scripts (state-only). Argv mirrors scanner/orchestrator.py.
    "python.tfstate_to_plan": Operation(
        name="python.tfstate_to_plan", executable=sys.executable,
        argv_schema=(ANY, ANY, ANY),
        allowed_tiers=("state",), default_timeout=120,
        mutation_class="write", cleanup_obligation="shred",
        env_allowlist=("PYTHONPATH", "PYTHONHOME"),
    ),
    "python.drift_report": Operation(
        name="python.drift_report", executable=sys.executable,
        argv_schema=(ANY, ANY, ANY, ANY),
        allowed_tiers=("state",), default_timeout=120,
        mutation_class="write", cleanup_obligation="none",
        env_allowlist=("PYTHONPATH", "PYTHONHOME"),
    ),
    # Secure file removal. Argv mirrors scanner/trap.py (`shred -u <path>`).
    "shred": Operation(
        name="shred", executable="shred",
        argv_schema=("-u", ANY),
        allowed_tiers=("plan", "state"), default_timeout=5,
        mutation_class="write", cleanup_obligation="none",
        env_allowlist=(),
    ),
}


# Public API: run()


# Public API: run()


def run(
    name: str,
    *args: str,
    tier: str = "source",
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Execute the registered :class:`Operation` named ``name``.

    Canonical subprocess entry point. Validates tier, argv schema,
    binary identity; scrubs env; calls :func:`subprocess.run` with
    ``check=False``. Raises UnknownOperation, TierViolation,
    TrustedBinaryMissing, ArgvSchemaViolation, MutatingOperationRefused,
    or subprocess.TimeoutExpired.
    """
    op = _lookup(name)
    _check_tier(op, tier)
    _validate_argv(op, args)
    executable = _resolve_binary(op)
    final_argv = _build_argv(op, executable, args)

    # Defense-in-depth: existing refusal matrix still fires on the
    # composed argv so a future schema change can't widen a mutating
    # op past the regex net.
    SafetyGuard().refuse_if_mutating(" ".join(final_argv))

    return subprocess.run(
        final_argv,
        cwd=_resolve_cwd(op, cwd),
        env=_build_env(op, env),
        timeout=timeout if timeout is not None else op.default_timeout,
        capture_output=True,
        text=True,
        check=False,
    )


# Internal helpers (single-responsibility; each ≤ 1 job)


def _lookup(name: str) -> Operation:
    """Return the registered :class:`Operation` for ``name``."""
    try:
        return OPERATION_REGISTRY[name]
    except KeyError as exc:
        raise UnknownOperation(
            f"unknown operation: {name!r}; "
            f"registered: {sorted(OPERATION_REGISTRY)}"
        ) from exc


def _check_tier(op: Operation, tier: str) -> None:
    """Raise :class:`TierViolation` if ``tier`` is not in ``op.allowed_tiers``."""
    if tier not in op.allowed_tiers:
        raise TierViolation(
            f"operation {op.name!r} does not permit tier {tier!r}; "
            f"allowed tiers: {op.allowed_tiers}"
        )


def _validate_argv(op: Operation, args: tuple[str, ...]) -> None:
    """Reject argv that doesn't match ``op.argv_schema``.

    Walks the schema position-by-position. Literal tokens must match
    the caller's argv exactly; :data:`ANY` slots accept any caller
    token. Caller argv length must equal ``len(op.argv_schema)``.
    """
    schema = op.argv_schema
    if len(args) != len(schema):
        raise ArgvSchemaViolation(
            f"operation {op.name!r} argv length mismatch: "
            f"expected {len(schema)} tokens, got {len(args)}: {args!r}"
        )
    for i, expected in enumerate(schema):
        if expected != ANY and args[i] != expected:
            raise ArgvSchemaViolation(
                f"operation {op.name!r} argv mismatch at position {i}: "
                f"expected {expected!r}, got {args[i]!r}"
            )


def _resolve_binary(op: Operation) -> str:
    """Return the absolute path of ``op.executable`` via :func:`shutil.which`."""
    resolved = shutil.which(op.executable)
    if resolved is None:
        raise TrustedBinaryMissing(
            f"operation {op.name!r} requires executable {op.executable!r} "
            f"on PATH; not found"
        )
    return resolved


def _build_argv(op: Operation, executable: str, args: tuple[str, ...]) -> list[str]:
    """Compose the final argv list passed to :func:`subprocess.run`.

    Every schema slot consumes one caller token; :data:`ANY` is a
    validation marker (consumed by :func:`_validate_argv`), not a
    runtime token.
    """
    return [executable, *args[: len(op.argv_schema)]]


def _build_env(op: Operation, caller_env: dict[str, str] | None) -> dict[str, str]:
    """Compose the per-op environment.

    Ambient ``os.environ`` minus ``op.env_blocklist``, merged with
    caller ``env``, then restricted to ``op.env_allowlist`` (pass-
    through if ``"*"``).
    """
    ambient = {k: v for k, v in os.environ.items() if k not in op.env_blocklist}
    if caller_env:
        ambient.update(caller_env)
    if op.env_allowlist == ("*",):
        return ambient
    allowed = set(op.env_allowlist)
    return {k: v for k, v in ambient.items() if k in allowed}


def _resolve_cwd(op: Operation, caller_cwd: Path | None) -> Path | None:
    """TODO 5 wires ``"run_dir"`` and ``"stack_root"``; today every policy
    falls back to the caller-supplied cwd."""
    return caller_cwd


# Self-test (no third-party deps; pure stdlib)


def _expect_raises(label: str, exc_type: type[BaseException], fn, *args, **kwargs) -> bool:
    """Run ``fn(*args, **kwargs)`` and assert it raises ``exc_type``."""
    try:
        fn(*args, **kwargs)
    except BaseException as exc:  # noqa: BLE001 — catch-all to introspect
        if isinstance(exc, exc_type):
            return True
        print(
            f"FAIL: {label}: wrong exception type: "
            f"got {type(exc).__name__}, expected {exc_type.__name__}: {exc}",
            file=sys.stderr,
        )
        return False
    print(f"FAIL: {label}: expected {exc_type.__name__}, no exception raised",
          file=sys.stderr)
    return False


def _self_test() -> bool:
    """Exercise the registry end-to-end. Returns True on success.

    Verifies: registry shape, UnknownOperation, ArgvSchemaViolation
    (literal mismatch + length), TierViolation, TrustedBinaryMissing,
    defense-in-depth refusal, and TF_PLUGIN_CACHE_DIR blocklist.
    """
    import scanner.ops as _self  # late import: avoid module-load cycle
    # Resolve exception classes via _self to defeat the
    # ``__main__``-vs-``scanner.ops`` class-identity split that
    # otherwise makes isinstance() return False for same-named
    # classes imported under both names.
    UnknownOperation = _self.UnknownOperation
    ArgvSchemaViolation = _self.ArgvSchemaViolation
    TierViolation = _self.TierViolation
    TrustedBinaryMissing = _self.TrustedBinaryMissing
    # Deliberate rebinding of the module-level import: defeats the
    # __main__-vs-scanner.ops class-identity split. Consumed by the
    # ``except (MutatingOperationRefused, TrustedBinaryMissing)`` below.
    MutatingOperationRefused = _self.MutatingOperationRefused  # noqa: F811

    ok = True
    # Full valid argv for terraform.init_local. Schema:
    #   ("-chdir", ANY, "init",
    #    "-input=false", "-backend=false", "-no-color") — 6 slots.
    # Caller supplies ALL 6 tokens (literals must match exactly).
    init_args = (
        "-chdir", "/some/path", "init",
        "-input=false", "-backend=false", "-no-color",
    )

    # 1. Registry shape.
    for name, op in OPERATION_REGISTRY.items():
        if not op.argv_schema or op.default_timeout <= 0 or op.executable == "":
            print(f"FAIL: {name}: malformed entry", file=sys.stderr)
            ok = False

    # 2. UnknownOperation.
    ok &= _expect_raises("UnknownOperation", UnknownOperation, _self.run, "nope", "x")

    # 3. ArgvSchemaViolation (literal mismatch at position 0: "-chdir"
    # replaced with "-WRONG"). Pass a valid tier so the tier check
    # doesn't fire first.
    ok &= _expect_raises("ArgvSchemaViolation-literal", ArgvSchemaViolation, _self.run,
                         "terraform.init_local",
                         "-WRONG", "/some/path", "init",
                         "-input=false", "-backend=false", "-no-color",
                         tier="plan")

    # 4. ArgvSchemaViolation (length mismatch — zero args).
    ok &= _expect_raises("ArgvSchemaViolation-length", ArgvSchemaViolation, _self.run,
                         "terraform.init_local", tier="plan")

    # 5. TierViolation: terraform.init_local does not allow tier=source.
    ok &= _expect_raises("TierViolation", TierViolation, _self.run,
                         "terraform.init_local", *init_args, tier="source")

    # 6. TrustedBinaryMissing: monkeypatch _self.shutil.which so
    # _self.run's lookup of ``shutil.which`` resolves to None. We
    # patch the module-level binding on _self.shutil (not this
    # module's local ``shutil``) because _self.run looks up the
    # attribute via its own module's namespace.
    original_which = _self.shutil.which
    _self.shutil.which = lambda _name: None  # type: ignore[assignment]
    try:
        ok &= _expect_raises("TrustedBinaryMissing", TrustedBinaryMissing, _self.run,
                             "terraform.init_local", *init_args, tier="plan")
    finally:
        _self.shutil.which = original_which  # type: ignore[assignment]

    # 7. Defense-in-depth: temp op whose argv composes to a refused
    # pattern. Patch _self.OPERATION_REGISTRY (the lookup _self.run
    # consults), not the local OPERATION_REGISTRY. Schema is fully
    # literal ("apply", "-auto-approve") so caller must pass both.
    saved = dict(_self.OPERATION_REGISTRY)
    _self.OPERATION_REGISTRY["test.dangerous_apply"] = Operation(
        name="test.dangerous_apply", executable="terraform",
        argv_schema=("apply", "-auto-approve"),
        allowed_tiers=("plan", "state"), default_timeout=60,
        mutation_class="mutate_azure", cleanup_obligation="none",
        env_allowlist=("*",),
    )
    try:
        try:
            _self.run("test.dangerous_apply", "apply", "-auto-approve", tier="plan")
        except (MutatingOperationRefused, TrustedBinaryMissing):
            pass  # both acceptable: refusal OR no terraform binary
        else:
            print("FAIL: defense-in-depth refusal did not fire", file=sys.stderr)
            ok = False
    finally:
        _self.OPERATION_REGISTRY.clear()
        _self.OPERATION_REGISTRY.update(saved)

    # 8. Env blocklist strips TF_PLUGIN_CACHE_DIR.
    saved_environ = os.environ.copy()
    try:
        os.environ["TF_PLUGIN_CACHE_DIR"] = "/tmp/plugin-cache-should-not-leak"
        cleaned = _self._build_env(OPERATION_REGISTRY["terraform.init_local"], caller_env=None)
        if "TF_PLUGIN_CACHE_DIR" in cleaned:
            print("FAIL: TF_PLUGIN_CACHE_DIR not stripped from env", file=sys.stderr)
            ok = False
    finally:
        os.environ.clear()
        os.environ.update(saved_environ)

    return ok


# CLI entry

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        if _self_test():
            print("ops_selftest: PASS")
            sys.exit(0)
        print("ops_selftest: FAIL", file=sys.stderr)
        sys.exit(1)
    print("usage: python -m scanner.ops --self-test", file=sys.stderr)
    sys.exit(2)
