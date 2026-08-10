"""scanner/tests/test_safety.py — pytest port of safety_selftest.

Every REFUSE_PATTERN must refuse with rc=99 equivalent (raises
MutatingOperationRefused). Every ALLOWED_EXCEPTION must pass
silently. The check_checkov_version() guard is tested both
positive (3.3.9 returns "3.3.9") and negative (wrong version
raises AuditPinViolation).

This is the audit-grade refusal matrix. Do not weaken the tests
without updating the corresponding pattern in scanner/safety.py
AND the lib/safety.sh source — the bash and Python versions must
stay in lockstep.
"""
from __future__ import annotations

import sys

import pytest

from scanner.safety import (
    ALLOWED_EXCEPTIONS,
    AuditPinViolation,
    MutatingOperationRefused,
    REFUSE_PATTERN,
    REFUSE_REASON,
    SafetyGuard,
    check_checkov_version,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def guard() -> SafetyGuard:
    """A fresh SafetyGuard for each test."""
    return SafetyGuard()


# ---------------------------------------------------------------------------
# REFUSE_PATTERN coverage — one fixture command per pattern.
# ---------------------------------------------------------------------------

# Each tuple: (pattern, fixture_command) — the command is intentionally
# minimal so it matches the target pattern but not any other REFUSE_PATTERN.
# If a future pattern change causes a fixture command to match multiple
# patterns, the test for that command will still expect a refusal (which
# is what we want — refuse_if_mutating chooses the first match).
#
# We deliberately cover every entry in REFUSE_PATTERN so the matrix is
# fully exercised, including the trickier ones (lock bypass, state
# subcommands, role assignment).
REFUSE_FIXTURES: list[tuple[str, str]] = [
    # terraform apply / destroy
    (r"terraform\s+apply\b", "terraform apply -auto-approve"),
    (r"terraform\s+destroy\b", "terraform destroy"),
    # terraform state mutation subcommands
    (r"terraform\s+state\s+(rm|mv|import|replace-provider|list)\b",
     "terraform state rm foo"),
    # terraform taint / untaint / import
    (r"terraform\s+taint\b", "terraform taint azurerm_resource_group.main"),
    (r"terraform\s+untaint\b", "terraform untaint azurerm_resource_group.main"),
    (r"terraform\s+import\b",
     "terraform import azurerm_resource_group.main /subscriptions/abc"),
    # terraform lock bypass (note: contains additional flags)
    (r"terraform\s+plan.*-lock=false", "terraform plan -lock=false"),
    (r"terraform\s+apply.*-lock=false", "terraform apply -lock=false"),
    (r"terraform\s+destroy.*-lock=false", "terraform destroy -lock=false"),
    # auto-approve bypass
    (r"-auto-approve", "terraform apply -auto-approve"),
    # Azure CLI destructive operations
    (r"az\s+storage\s+account\s+delete\b",
     "az storage account delete -n myaccount -g myrg"),
    (r"az\s+resource\s+(delete|update|create)\b",
     "az resource delete --ids /subscriptions/abc/resourceGroups/rg/foo"),
    (r"az\s+group\s+delete\b", "az group delete -n myrg"),
    (r"az\s+keyvault\s+delete\b", "az keyvault delete -n myvault"),
    (r"az\s+sql\s+(server|db)\s+delete\b", "az sql server delete -n myserver"),
    # separate command for the db sub-branch
    (r"az\s+sql\s+(server|db)\s+delete\b",
     "az sql db delete -n mydb --server myserver"),
    (r"az\s+appservice\s+(plan|webapp)\s+delete\b",
     "az appservice plan delete -n myplan -g myrg"),
    (r"az\s+role\s+assignment\s+delete\b",
     "az role assignment delete --assignee user@contoso.com"),
    # checkov auto-fix
    (r"checkov.*--fix", "checkov -d . --fix"),
]


def test_refuse_pattern_count_matches_fixtures() -> None:
    """Belt-and-suspenders: the refusal matrix must be fully covered.

    If someone adds a REFUSE_PATTERN without a corresponding fixture,
    this test fails loudly and forces them to add coverage.
    """
    patterns_in_fixtures = {p for p, _ in REFUSE_FIXTURES}
    missing = set(REFUSE_PATTERN) - patterns_in_fixtures
    assert not missing, (
        f"REFUSE_PATTERN entries missing test fixtures: {missing}. "
        "Add a fixture command to REFUSE_FIXTURES for each pattern."
    )


@pytest.mark.parametrize(
    ("pattern", "command"),
    REFUSE_FIXTURES,
    ids=[p for p, _ in REFUSE_FIXTURES],
)
def test_refuse_if_mutating_refuses_each_pattern(
    guard: SafetyGuard, pattern: str, command: str
) -> None:
    """Every REFUSE_PATTERN must refuse with MutatingOperationRefused.

    The refusal message must include at least one of the REFUSE_REASON
    entries that matches the command (the matrix iterates patterns in
    declaration order and raises on the first hit, so a command like
    `terraform apply -lock=false` will surface the `terraform apply`
    reason, not the lock-bypass reason — both are correct refusals).

    The audit-relevant invariant is: the command is refused. The
    reason text is operator-guidance, not part of the security contract.
    """
    # Build the set of ACCEPTABLE refusal reasons for this command.
    # The matrix iterates patterns in declaration order and raises on
    # the first hit, so a command like `terraform apply -lock=false`
    # will surface the `terraform apply` reason (declared first), not
    # the lock-bypass reason. Both are correct refusals — the audit
    # contract is that the command is refused, not WHICH reason fires.
    pattern_index = {p: i for i, p in enumerate(REFUSE_PATTERN)}
    target_idx = pattern_index[pattern]
    # Among patterns that match, only the ones declared at or before
    # the target pattern can actually fire (the loop raises on first hit).
    acceptable_reasons = {
        REFUSE_REASON[p]
        for p in REFUSE_PATTERN
        if pattern_index[p] <= target_idx and _refuse_compiled_match(p, command)
    }

    with pytest.raises(MutatingOperationRefused) as excinfo:
        guard.refuse_if_mutating(command)

    actual = str(excinfo.value)
    assert any(reason in actual for reason in acceptable_reasons), (
        f"Refusal message for command {command!r} (target pattern "
        f"{pattern!r}) must include one of the matching reasons. "
        f"Got: {actual!s}"
    )


def _refuse_compiled() -> tuple:
    """Return the compiled REFUSE_PATTERN list for matching checks.

    Imported here (not at module top) so the test module avoids a
    circular import through the production module's pre-compiled
    tuple. The production module re-compiles the patterns on import;
    we just expose them for test introspection.
    """
    from scanner.safety import _REFUSE_COMPILED  # noqa: WPS433

    return _REFUSE_COMPILED


def _refuse_compiled_match(pattern: str, command: str) -> bool:
    """True if `pattern` (raw REFUSE_PATTERN source) matches `command`."""
    compiled = _refuse_compiled()
    pattern_index = {p: i for i, p in enumerate(REFUSE_PATTERN)}
    return compiled[pattern_index[pattern]].search(command) is not None


# ---------------------------------------------------------------------------
# ALLOWED_EXCEPTIONS coverage — every exception must pass.
# ---------------------------------------------------------------------------

ALLOWED_FIXTURES: list[tuple[str, str]] = [
    # network-rule add
    (r"az\s+storage\s+account\s+network-rule\s+(add|remove|list)\b",
     "az storage account network-rule add "
     "--account-name myaccount --ip-address 1.2.3.4"),
    # network-rule remove
    (r"az\s+storage\s+account\s+network-rule\s+(add|remove|list)\b",
     "az storage account network-rule remove "
     "--account-name myaccount --ip-address 1.2.3.4"),
    # network-rule list
    (r"az\s+storage\s+account\s+network-rule\s+(add|remove|list)\b",
     "az storage account network-rule list --account-name myaccount"),
    # state blob download (read-only)
    (r"az\s+storage\s+blob\s+download\b",
     "az storage blob download "
     "--container-name tfstate --name prod.tfstate "
     "--file prod.tfstate --account-name myaccount"),
]


def test_allowed_exception_count_matches_fixtures() -> None:
    """Every ALLOWED_EXCEPTION must have a fixture command.

    Adding an ALLOWED_EXCEPTION without test coverage is a security
    regression — the exception may match commands it shouldn't.
    """
    patterns_in_fixtures = {p for p, _ in ALLOWED_FIXTURES}
    missing = set(ALLOWED_EXCEPTIONS) - patterns_in_fixtures
    assert not missing, (
        f"ALLOWED_EXCEPTIONS entries missing test fixtures: {missing}. "
        "Add a fixture command to ALLOWED_FIXTURES for each exception."
    )


@pytest.mark.parametrize(
    ("pattern", "command"),
    ALLOWED_FIXTURES,
    ids=[f"{i}:{c}" for i, (_, c) in enumerate(ALLOWED_FIXTURES)],
)
def test_refuse_if_mutating_allows_each_exception(
    guard: SafetyGuard, pattern: str, command: str
) -> None:
    """Every ALLOWED_EXCEPTION must pass refuse_if_mutating silently.

    The exception pattern is checked BEFORE the refusal matrix, so a
    command like `az storage account network-rule add` MUST return
    without raising — even though `az storage account delete` would
    be blocked.
    """
    # Should not raise. Any exception here is a failure.
    guard.refuse_if_mutating(command)


# ---------------------------------------------------------------------------
# Negative-side sanity checks: ensure the matrix is NOT a rubber stamp.
# ---------------------------------------------------------------------------


def test_refuse_if_mutating_allows_pure_readonly_terraform(
    guard: SafetyGuard,
) -> None:
    """Plain `terraform plan` and `terraform show` must pass.

    These are the read-only commands the scanner actually uses. If
    the refusal matrix ever tightens to block them, this test fails
    and forces a deliberate decision.
    """
    guard.refuse_if_mutating("terraform plan -out=tfplan.binary")
    guard.refuse_if_mutating("terraform show -json tfplan.binary")
    guard.refuse_if_mutating("terraform init -backend=false")


def test_refuse_if_mutating_refuses_strange_command(guard: SafetyGuard) -> None:
    """Unknown commands that match nothing must pass.

    This guards against an over-broad pattern that accidentally
    refuses innocuous commands.
    """
    guard.refuse_if_mutating("echo hello world")
    guard.refuse_if_mutating("ls -la")
    guard.refuse_if_mutating("cat main.tf")


def test_refuse_if_mutating_rejects_non_string(guard: SafetyGuard) -> None:
    """Non-string input is a programming error, not a mutating command.

    The guard must surface it as TypeError, not silently coerce or
    swallow.
    """
    with pytest.raises(TypeError):
        guard.refuse_if_mutating(123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        guard.refuse_if_mutating(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# check_checkov_version() — the audit pin guard.
# ---------------------------------------------------------------------------


def test_checkov_version_positive_returns_pinned_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pinned checkov 3.3.9 must return the exact version string.

    We mock `importlib.metadata.version` so the test is hermetic —
    it does not depend on the test environment actually having
    checkov 3.3.9 installed. The mock returns the real pinned
    version that the production guard accepts.
    """
    import importlib.metadata as _real_ilmd

    monkeypatch.setattr(_real_ilmd, "version", lambda name: "3.3.9")

    # The function does `import importlib.metadata as _ilmd` INSIDE
    # the function body, so monkeypatch on the original module is
    # insufficient — we have to patch the binding the function will
    # actually look up. We re-import the module to capture the patched
    # binding, OR we patch the module that contains the function.
    # Simpler: monkeypatch the `importlib.metadata` attribute the
    # function reads by also patching the safety module's binding.
    #
    # The cleanest, most robust approach: re-import the module so
    # `import importlib.metadata as _ilmd` inside the function
    # resolves to the patched module. importlib.metadata is a
    # singleton module object, so monkeypatching one attribute on it
    # is visible everywhere — including the re-bound local name
    # inside the function.
    assert check_checkov_version() == "3.3.9"


def test_checkov_version_negative_wrong_version_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrong checkov version must raise AuditPinViolation.

    This is the audit-pin regression guard. If a future bump ships
    without updating this expectation, the bump must be intentional.
    """
    import importlib.metadata as _real_ilmd

    monkeypatch.setattr(_real_ilmd, "version", lambda name: "99.0.0")

    with pytest.raises(AuditPinViolation) as excinfo:
        check_checkov_version()
    assert "99.0.0" in str(excinfo.value), (
        f"AuditPinViolation must surface the actual version. Got: {excinfo.value!s}"
    )
    assert "3.3.9" in str(excinfo.value), (
        f"AuditPinViolation must include the expected version. Got: {excinfo.value!s}"
    )


def test_checkov_version_negative_metadata_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If metadata lookup raises, AuditPinViolation is raised.

    Defense-in-depth: even if the lookup fails for an unexpected
    reason (corrupted install, package not in metadata db), we
    refuse to scan rather than silently proceed.
    """

    def _boom(name: str) -> str:
        raise RuntimeError("metadata db corrupted")

    import importlib.metadata as _real_ilmd

    monkeypatch.setattr(_real_ilmd, "version", _boom)

    with pytest.raises(AuditPinViolation):
        check_checkov_version()


def test_checkov_version_negative_checkov_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If checkov is not installed at all, AuditPinViolation is raised.

    The function does `import checkov` to confirm the module is
    importable. If the import fails, we surface a clean
    AuditPinViolation with an actionable message.
    """
    # Make `import checkov` raise ImportError.
    monkeypatch.setitem(sys.modules, "checkov", None)

    with pytest.raises(AuditPinViolation) as excinfo:
        check_checkov_version()
    assert "checkov" in str(excinfo.value).lower()
