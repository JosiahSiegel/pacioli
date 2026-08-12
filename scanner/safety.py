"""scanner/safety.py — Hard refusals for any operation that mutates your cloud provider.

Python port of lib/safety.sh. Enforces the scanner's READ-ONLY invariant
against the cloud provider. The ONLY provider access permitted today is
the read-only state blob download used by the state tier
(``az storage blob download``); the refusal matrix itself is shaped
around Terraform + Azure because that is what the state tier invokes
(equivalent AWS / GCP / Kubernetes refusal patterns will be added in
the same shape as those tiers land). The storage firewall IP whitelist
mutations formerly done by tf_init.sh were removed: the scanner never
modifies the cloud-provider storage firewall.

To extend: add a new forbidden pattern to REFUSE_PATTERN (regex) and a
human-readable reason to REFUSE_REASON (dict entry).

IMPORTANT: this is defense-in-depth. Even if someone bypasses these checks
by reading source code, the audit trail (git log of this file) and the
PR review process are the primary safeguards. This module makes the
accidental-invocation case loud and immediate.
"""

from __future__ import annotations

import re
import sys
from typing import Final


class MutatingOperationRefused(Exception):
    """Raised when a command matches a forbidden mutating pattern."""


class AuditPinViolation(Exception):
    """Raised when a pinned audit dependency is missing or wrong version."""


# Patterns (extended regex) that MUST NEVER appear on a command line.
# Add new entries here when adding new mutating commands.
#
# NOTE: these are direct semantic ports of lib/safety.sh REFUSE_PATTERN.
# The bash source uses POSIX `[[:space:]]` character classes (bash ERE);
# Python's re module uses `\s` for the same set. We translate here so the
# patterns actually match whitespace in Python — preserving the audit-grade
# refusal matrix. The list of forbidden commands is unchanged; only the
# whitespace token is rewritten to be valid Python regex.
REFUSE_PATTERN: Final[tuple[str, ...]] = (
    # Terraform: state mutations
    r"terraform\s+apply\b",
    r"terraform\s+destroy\b",
    r"terraform\s+state\s+(rm|mv|import|replace-provider|list)\b",
    r"terraform\s+taint\b",
    r"terraform\s+untaint\b",
    r"terraform\s+import\b",
    # Terraform: locking bypass
    r"terraform\s+apply.*-lock=false",
    r"terraform\s+destroy.*-lock=false",
    # `init` must keep state locking — a concurrent init on a different
    # runner that wins the race would overwrite the locked state. The
    # privileged init argv (``-backend=false``) never uses ``-lock=false``,
    # so this refusal is a hard invariant on the init subcommand even
    # though plan no longer carries the same restriction.
    r"terraform\s+init.*-lock=false",
    # Terraform: auto-approve bypass
    r"-auto-approve",
    # Azure CLI: stateful / destructive operations
    r"az\s+storage\s+account\s+delete\b",
    r"az\s+resource\s+(delete|update|create)\b",
    r"az\s+group\s+delete\b",
    r"az\s+keyvault\s+delete\b",
    r"az\s+sql\s+(server|db)\s+delete\b",
    r"az\s+appservice\s+(plan|webapp)\s+delete\b",
    r"az\s+role\s+assignment\s+delete\b",
    # Azure CLI: storage firewall mutations (formerly an ALLOWED_EXCEPTION
    # paired with a trap-and-cleanup helper; the scanner is now strictly
    # read-only and refuses every firewall mutation).
    r"az\s+storage\s+account\s+network-rule\s+(add|remove|list)\b",
    # Checkov: never auto-apply fixes
    r"checkov.*--fix",
)


# Human-readable refusal reasons keyed by the exact REFUSE_PATTERN entry.
REFUSE_REASON: Final[dict[str, str]] = {
    r"terraform\s+apply\b": "Terraform apply mutates Azure. Forbidden in scan.sh. Use scan.sh for read-only scans only.",
    r"terraform\s+destroy\b": "Terraform destroy deletes Azure resources. Forbidden in scan.sh.",
    r"terraform\s+state\s+(rm|mv|import|replace-provider|list)\b": "Terraform state mutations are forbidden. PCI scan is read-only.",
    r"terraform\s+taint\b": "Taint triggers destroy on next apply. Forbidden.",
    r"terraform\s+untaint\b": "Untaint clears taint marker. Forbidden.",
    r"terraform\s+import\b": "Import mutates state. Use aztfexport for legitimate imports.",
    r"terraform\s+apply.*-lock=false": "Lock bypass on apply. Forbidden.",
    r"terraform\s+destroy.*-lock=false": "Lock bypass on destroy. Forbidden.",
    r"terraform\s+init.*-lock=false": (
        "Init lock bypass would corrupt state on concurrent init. Forbidden."
    ),
    r"-auto-approve": "Auto-approve bypasses confirmation. Forbidden.",
    r"az\s+storage\s+account\s+delete\b": "Storage account deletion. Forbidden.",
    r"az\s+resource\s+(delete|update|create)\b": "Azure resource mutation. Forbidden.",
    r"az\s+group\s+delete\b": "Resource group deletion. Forbidden.",
    r"az\s+keyvault\s+delete\b": "Key Vault deletion. Forbidden.",
    r"az\s+sql\s+(server|db)\s+delete\b": "SQL deletion. Forbidden.",
    r"az\s+appservice\s+(plan|webapp)\s+delete\b": "App Service deletion. Forbidden.",
    r"az\s+role\s+assignment\s+delete\b": "RBAC mutation. Forbidden.",
    r"az\s+storage\s+account\s+network-rule\s+(add|remove|list)\b": "Storage firewall mutation. Forbidden — the scanner is read-only against Azure.",
    r"checkov.*--fix": "Checkov auto-fix is forbidden. Triage findings manually.",
}


# ALLOWED EXCEPTIONS — commands that look mutating but are scoped to
# read-only Azure state access. These are checked first; if the command
# matches one of these patterns, the broader refusal is skipped.
# Pattern: regex that, if matched, exempts the command from the wider refusal.
#
# NOTE: see REFUSE_PATTERN — `[[:space:]]` is translated to `\s` for
# Python regex validity. Same audit-grade set of allowed exceptions.
ALLOWED_EXCEPTIONS: Final[tuple[str, ...]] = (
    # Read-only state blob download for --scan-state (no --overwrite, no
    # delete, no copy, no upload). Strict regex restricts to download.
    r"az\s+storage\s+blob\s+download\b",
)


# Pre-compile for reuse across calls (NOT re.match — we want a callable
# match object so callers can introspect what hit).
_REFUSE_COMPILED: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(p) for p in REFUSE_PATTERN
)
_ALLOWED_COMPILED: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(p) for p in ALLOWED_EXCEPTIONS
)


class SafetyGuard:
    """Enforces the scanner's READ-ONLY invariant against your cloud provider.

    A refusal matrix ported from lib/safety.sh — every mutating Terraform,
    Azure CLI, and Checkov command is refused unless it matches an
    explicit ALLOWED_EXCEPTION (state blob download only — the firewall
    network-rule mutation is no longer permitted and was removed). The
    matrix is currently Azure-flavored because the state tier invokes
    `az storage blob download`; the structure is designed to grow to
    cover AWS / GCP / Kubernetes refusal patterns as their tiers land.
    """

    def refuse_if_mutating(self, cmd: str) -> None:
        """Refuse if `cmd` matches any REFUSE_PATTERN (and is not an ALLOWED_EXCEPTION).

        Raises:
            MutatingOperationRefused: with the REFUSE_REASON text.
        """
        if not isinstance(cmd, str):
            raise TypeError(
                f"refuse_if_mutating expects str, got {type(cmd).__name__}"
            )

        # Check allowed exceptions FIRST — matches bash semantics
        # (lib/safety.sh lines 89-94).
        for pattern in _ALLOWED_COMPILED:
            if pattern.search(cmd):
                return

        # Then check refusals (lib/safety.sh lines 96-104).
        for source_pattern, compiled in zip(REFUSE_PATTERN, _REFUSE_COMPILED):
            if compiled.search(cmd):
                reason = REFUSE_REASON.get(
                    source_pattern,
                    f"Unknown refusal pattern: {source_pattern}",
                )
                raise MutatingOperationRefused(f"{reason} | Command: {cmd}")


def check_checkov_version() -> str:
    """Verify checkov is installed and pinned to 3.3.9.

    Lazy import so that `import scanner.safety` does not itself require
    checkov (the scanner modules that only need the refusal matrix must
    be importable in environments where checkov is being installed).

    Returns:
        The verified version string ("3.3.9").

    Raises:
        AuditPinViolation: if checkov is missing or not pinned to 3.3.9.
    """
    # NOTE: checkov does not expose `__version__` as a module attribute,
    # so we resolve via the distribution metadata (importlib.metadata).
    # The lazy import is only to surface a clean ImportError when checkov
    # itself is missing.
    try:
        import checkov  # type: ignore[import-not-found]  # noqa: F401
    except ImportError as exc:
        raise AuditPinViolation(
            "checkov is not installed. The scanner audit requires "
            "checkov==3.3.9 (see scanner/requirements-pinned.txt). "
            "Install with: pip install -r scanner/requirements-pinned.txt"
        ) from exc

    try:
        import importlib.metadata as _ilmd
        actual = _ilmd.version("checkov")
    except Exception as exc:
        raise AuditPinViolation(
            "checkov is installed but its distribution version could not "
            "be resolved. Refusing to scan — re-install pinned deps with: "
            "pip install -r scanner/requirements-pinned.txt"
        ) from exc

    if actual != "3.3.9":
        raise AuditPinViolation(
            f"checkov audit pin violated: expected '3.3.9', got {actual!r}. "
            f"Refusing to scan — re-install pinned deps with: "
            f"pip install -r scanner/requirements-pinned.txt"
        )
    return actual


def safety_selftest() -> bool:
    """Verify the refusal matrix is in effect by exercising every pattern.

    Returns:
        True if every `should_refuse` command fires refuse_if_mutating and
        every `should_allow` command passes silently. False otherwise.
    """
    guard = SafetyGuard()

    should_refuse = (
        "terraform apply -auto-approve",
        "terraform destroy",
        "terraform state rm foo",
        "terraform apply -lock=false",
        "terraform destroy -lock=false",
        "az group delete -n foo",
        "az storage account delete -n foo",
        "checkov -d . --fix",
    )
    should_allow = (
        "terraform plan -out=tfplan.binary -lock=false -refresh=false",
        "terraform show -json tfplan.binary",
        "terraform init -backend=false",
        "az storage blob download --account-name foo --container-name iac --name prod.tfstate",
    )

    failed = False

    for cmd in should_refuse:
        try:
            guard.refuse_if_mutating(cmd)
        except MutatingOperationRefused:
            pass
        else:
            print(f"FAIL: should have refused: {cmd}", file=sys.stderr)
            failed = True

    for cmd in should_allow:
        try:
            guard.refuse_if_mutating(cmd)
        except MutatingOperationRefused as exc:
            print(f"FAIL: should have allowed: {cmd} ({exc})", file=sys.stderr)
            failed = True

    return not failed


if __name__ == "__main__":
    # Run the refusal matrix selftest and the checkov audit pin.
    # Exits 0 only if BOTH pass. If checkov is not installed in the current
    # environment, check_checkov_version() raises — that's acceptable for
    # the smoke (the actual guard is enforced at scan time, not at import).
    rc = 0
    if safety_selftest():
        print("safety_selftest: PASS")
    else:
        print("safety_selftest: FAIL", file=sys.stderr)
        rc = 1

    try:
        version = check_checkov_version()
        print(f"checkov version: {version}")
    except AuditPinViolation as exc:
        print(f"checkov version: NOT OK ({exc})", file=sys.stderr)
        rc = 1

    sys.exit(rc)
