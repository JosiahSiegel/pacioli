"""scanner/cli.py — Standalone Pacioli CLI dispatcher.

Single entry point for the ``pacioli`` console script. Subcommands:

    pacioli scan <target_dir>        Run a scan (delegates to scanner.orchestrator).
    pacioli aggregate <run_dir>      Run aggregator only (delegates to scanner.aggregate).
    pacioli gate <target_dir>        Run scan in gate mode (delegates to scanner.orchestrator).
    pacioli audit [--latest|--run-id <id>] [--source local|remote]
                                     Re-emit a prior report from the archive
                                     (no re-scan).
    pacioli baseline init <run_dir>  Generate stub baseline entries
                                     (delegates to scanner.baseline_init).

Flags (top-level, accepted by ``scan``/``gate``/``audit`` as relevant):
    --target-repo PATH       Consumer Terraform repo (default: $PACIOLI_TARGET_REPO or cwd).
    --tier {source,plan,state}
                             Scan depth tier (default: source).
    --mode {gate,report,audit}
                             Scan mode (default: report; gate-mode promoted when CI=1).
    --mapping PATH           Framework mapping pack YAML.
    --baseline PATH          Baseline suppressions YAML.
    --output-dir PATH        Run-dir root (default: ~/.pacioli/runs/current).
    --project NAME           Restrict to one project (matches scan.sh).
    --env NAME               Restrict to one env (matches scan.sh).
    --label TEXT             Custom slug for the run-dir name.
    --state-account NAME     Storage account (required for tier=plan|state; audit uses
                             $PACIOLI_STATE_STORAGE_ACCOUNT by default).
    --source {local,remote}  Audit only. local = ~/.pacioli/runs/, remote = the
                             pacioli-reports Azure container.
    --dry-run                Print intended actions without executing (matches scan.sh).
    --verbose                Emit INFO logs (matches PCI_VERBOSE=1).
    --non-interactive        Disable the first-run interactive picker for `pacioli scan`.

Multi-stack flags (Todo 8 — declared-stack-root workflow):
    --scan-path SPEC         Repeatable. Declare a single stack root as JSON
                             (keys: path, project?, env?, backend_key?,
                             workspace?, stack_label?). The JSON form mirrors
                             ``pci_scope.yaml::scan_paths:`` 1:1 so an operator
                             can copy-paste between the two.
                             Example: --scan-path '{"path": "env/myapp/prod"}'
    --scan-glob PATTERN      Repeatable. Shell-style glob (resolved against the
                             target repo) expanded to one ``--scan-path``
                             entry per match. The pattern's stem is used as
                             ``env`` and the parent directory's basename as
                             ``project`` when neither is set explicitly.
                             Example: --scan-glob 'env/*/prod'
    --stack-label SLUG       Per-entry disambiguator (default: derived from
                             ``--scan-path``'s ``stack_label`` key, or the
                             path's basename when only one entry is given).
                             The label is the on-disk run-dir component.
    --state-file PATH        Offline tier=plan/state bypass: read state from
                             a local .tfstate file instead of running
                             ``az storage blob download``. Mirrors the bash
                             scanner's ``--state-file`` flag.
    --include-modules        Source-tier only. Honor ``scan_paths:`` entries
                             whose stack root is a module library
                             (``modules/``, ``modules-<x>/``, ``.terraform/``).
                             Errors out when combined with ``--tier plan`` or
                             ``--tier state`` (those tiers scan resolved
                             modules, not raw module libraries).
    --ignore-lockfile        Explicit opt-out: scan ``.terraform.lock.hcl``
                             even though it lives inside the same directory
                             the scanner is configured to ignore. Emits a
                             WARN log line so the choice is visible.
    --registry-mirror URL    Sets ``TF_CLI_CONFIG_FILE`` to an isolated,
                             generated per-run config that points Terraform
                             at a private module registry mirror. The config
                             is written to a tmpdir under the run-dir and
                             cleaned up via the EXIT/SIGINT/SIGTERM trap.
    --backend-key KEY        Default storage backend key applied to every
                             ``--scan-path`` entry that doesn't carry an
                             explicit ``backend_key:`` (and to flat-root
                             mode when no ``--scan-path`` is given). Mirrors
                             the precedence: per-entry > top-level >
                             aztfexport file > ``f"{env}.tfstate"``.

Back-compat aliases (deprecated; emit a DeprecationWarning to stderr):
    --scan-plan      Equivalent to --tier plan.
    --scan-state     Equivalent to --tier state (implies plan).
    --scope          Equivalent to --baseline.

The ``scan --help`` epilog preserves the safety disclaimer from
``scanner/scan.sh`` lines 120-129 verbatim (this is the read-only
invariant Pacioli enforces against Azure).
"""
from __future__ import annotations

# UTF-8 bootstrap FIRST (before any other imports).
# Mirrors scanner/_utf8.py docstring: this MUST land before checkov /
# aggregate / PyYAML touch stdin or default-encoding file handles.
import scanner._utf8  # noqa: F401  -- side-effect import

import argparse
import json
import os
import re
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Any, Optional, Sequence

# Make sibling scanner modules importable when invoked as
# `python -m scanner.cli` from the repo root (the package layout puts
# `scanner/` at the repo root, not under a src/ tree).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


from scanner.safety import MutatingOperationRefused  # noqa: E402


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_TIERS: tuple[str, ...] = ("source", "plan", "state")
VALID_MODES: tuple[str, ...] = ("gate", "report", "audit")
VALID_SOURCES: tuple[str, ...] = ("local", "remote")

# Top-level config directory under $HOME (matches lib/common.sh's
# PACIOLI_HOME / ~/.pacioli convention; used by audit-local to locate
# the runs archive).
GLOBAL_CONFIG_DIR: str = ".pacioli"

# Default HTML report filename written under <run-dir>/aggregate/.
# Mirrors scanner.aggregate which writes <run-dir>/aggregate/report.html.
REPORT_FILENAME: str = "report.html"

# Mirrors lib/common.sh: defaults to "pacioli-reports" container for the
# audit-from-remote source.
DEFAULT_REPORTS_CONTAINER: str = "pacioli-reports"

# Verbatim safety disclaimer from scan.sh lines 120-129 (the read-only
# invariant Pacioli enforces against Azure).
SAFETY_DISCLAIMER: str = (
    "Safety:\n"
    "  This script is READ-ONLY against Azure. It will REFUSE to run:\n"
    "  - terraform apply / destroy / state rm / state mv / state import / taint\n"
    "  - terraform plan/apply/destroy -lock=false\n"
    "  - az <resource> delete / update / create\n"
    "  - checkov --fix\n"
    "  Allowed (when their flag is set): terraform init/plan/show,\n"
    "           az storage blob download (state read-back only, --scan-state),\n"
    "           az storage account network-rule {add,remove,list} (cleanup).\n"
    "  See scanner/lib/safety.sh for the full list."
)

# Help text for the back-compat aliases — emitted alongside the deprecation
# warning so operators can grep their wrapper scripts for the new name.
DEPRECATION_TEMPLATE: str = (
    "WARNING: --{old} is deprecated; use --{new} instead."
)

# Allowed keys in a single ``--scan-path`` JSON spec. Matches the
# ``pci_scope.yaml::scan_paths:`` schema field-for-field so an operator
# can copy-paste between the two surfaces. Anything else is rejected
# with a clear validation error so a typo surfaces immediately.
SCAN_PATH_KEYS: frozenset[str] = frozenset({
    "path",
    "project",
    "env",
    "backend_key",
    "workspace",
    "stack_label",
})

# URL pattern for ``--registry-mirror`` validation. We deliberately
# keep this narrow (http/https + optional port + path) so a typo can't
# silently produce a malformed ``TF_CLI_CONFIG_FILE`` later. The mirror
# URL is the only value forwarded into the generated config; everything
# else stays local.
REGISTRY_MIRROR_PATTERN: str = r"^https?://[^\s/$.?#].[^\s]*$"

# Slug pattern for ``--stack-label`` — same constraints as the
# orchestrator's run-dir label (no ``/``, no spaces, no leading dash).
# The pattern is intentionally restrictive: ``--stack-label`` is used
# as an on-disk directory name, so anything unsafe is rejected. The
# leading-character class explicitly excludes ``-`` so a label like
# ``-foo`` doesn't get mis-parsed as a CLI flag by downstream tooling.
STACK_LABEL_PATTERN: str = r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _log(level: str, msg: str) -> None:
    """Emit a scan.sh-style ``pci_log`` line to stderr."""
    print(f"{level}  {msg}", file=sys.stderr, flush=True)


def _emit_deprecation(old: str, new: str) -> None:
    """Emit a DeprecationWarning to stderr for a back-compat alias.

    Uses :mod:`warnings` so Python tooling that filters on
    ``DeprecationWarning`` (e.g. ``python -W error::DeprecationWarning``)
    sees the same category the plan's MUST-DO contract requires.
    """
    message = DEPRECATION_TEMPLATE.format(old=old, new=new)
    # warnings.warn writes to stderr by default; the simplefilter below
    # ensures the warning always reaches the operator even if a higher
    # frame installed "ignore".
    warnings.simplefilter("always", DeprecationWarning)
    warnings.warn(message, DeprecationWarning, stacklevel=3)
    # Belt-and-suspenders: also print to stderr directly so an operator
    # tailing stderr sees the warning even if their warnings filter
    # silences the category.
    print(f"WARNING: {message}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Shared flag wiring
# ---------------------------------------------------------------------------


def _add_scan_flags(parser: argparse.ArgumentParser) -> None:
    """Attach the scan/gate-mode flags to a subparser.

    Includes all 14 legacy flags from the plan's MUST-DO contract
    (``--target-repo``, ``--tier``, ``--mode``, ``--mapping``,
    ``--baseline``, ``--output-dir``, ``--project``, ``--env``,
    ``--label``, ``--state-account``, ``--source``, ``--dry-run``,
    ``--verbose``, ``--non-interactive``) PLUS the 8 multi-stack flags
    introduced in Todo 8:

        --scan-path        (repeatable; JSON spec per entry)
        --scan-glob        (repeatable; expanded to --scan-path entries)
        --stack-label      (per-entry disambiguator slug)
        --state-file       (offline tier=plan/state state source)
        --include-modules  (source-tier only; errors w/ --tier plan/state)
        --ignore-lockfile  (explicit opt-out; emits WARN log line)
        --registry-mirror  (sets TF_CLI_CONFIG_FILE to isolated config)
        --backend-key      (top-level default for --scan-path entries)
    """
    parser.add_argument(
        "target_dir",
        nargs="?",
        default=None,
        help="Target Terraform repo (positional; falls back to --target-repo).",
    )
    parser.add_argument(
        "--target-repo",
        default=None,
        help="Consumer Terraform repo (default: $PACIOLI_TARGET_REPO or cwd).",
    )
    parser.add_argument(
        "--tier",
        choices=VALID_TIERS,
        default="source",
        help="Scan depth tier: source (default), plan, or state.",
    )
    parser.add_argument(
        "--mode",
        choices=VALID_MODES,
        default="report",
        help="Scan mode: gate, report (default), or audit.",
    )
    parser.add_argument(
        "--mapping",
        default=None,
        help="Framework mapping pack YAML (default: $PACIOLI_MAPPING or install-root fallback).",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Baseline suppressions YAML (default: <target_repo>/pci_baseline.yaml).",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Run-dir root (default: ~/.pacioli/runs/current).",
    )
    parser.add_argument(
        "--project",
        default=None,
        help="Restrict to one project (matches --project in scan.sh).",
    )
    parser.add_argument(
        "--env",
        default=None,
        help="Restrict to one env (matches --env in scan.sh).",
    )
    parser.add_argument(
        "--label",
        default=None,
        help="Custom slug for the run-dir name.",
    )
    parser.add_argument(
        "--state-account",
        default=None,
        help="Storage account name (required for tier=plan|state; audit uses "
        "$PACIOLI_STATE_STORAGE_ACCOUNT by default).",
    )
    parser.add_argument(
        "--source",
        choices=VALID_SOURCES,
        default=None,
        help="Audit only. local = ~/.pacioli/runs/, remote = pacioli-reports Azure container.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print intended actions without executing (matches scan.sh).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit INFO logs (matches PCI_VERBOSE=1).",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Disable the first-run interactive picker (for CI / scripts).",
    )

    # ------------------------------------------------------------------
    # Multi-stack flags (Todo 8) — declared-stack-root workflow.
    # ------------------------------------------------------------------
    # --scan-path is ``action="append"`` so the user can pass it
    # multiple times (``--scan-path A --scan-path B``); each entry is a
    # JSON object whose keys mirror the pci_scope.yaml::scan_paths:
    # schema. The JSON form is chosen because it keeps the surface
    # trivially copy-pasteable between the CLI and the YAML, and it
    # avoids the ambiguity of comma-separated key=value strings.
    parser.add_argument(
        "--scan-path",
        action="append",
        default=None,
        metavar="SPEC",
        help=(
            "Repeatable. Declare one stack root as a JSON object with "
            "keys: path (required), project?, env?, backend_key?, "
            "workspace?, stack_label?. Example: "
            "--scan-path '{\"path\": \"env/myapp/prod\", \"project\": \"myapp\"}'."
        ),
    )
    # --scan-glob uses the same action so multiple patterns can be
    # passed; each pattern is expanded via Path.glob into one synthetic
    # --scan-path entry. The expansion happens at dispatch time (in
    # _handle_scan / _handle_gate) so argparse never sees the matches.
    parser.add_argument(
        "--scan-glob",
        action="append",
        default=None,
        metavar="PATTERN",
        help=(
            "Repeatable. Shell-style glob resolved against the target "
            "repo's root. Each match becomes one --scan-path entry "
            "(path=<match>, env=<basename>, project=<parent>). Example: "
            "--scan-glob 'env/*/prod'."
        ),
    )
    parser.add_argument(
        "--stack-label",
        default=None,
        metavar="SLUG",
        help=(
            "Disambiguator slug appended to the on-disk run-dir component "
            f"(must match {STACK_LABEL_PATTERN}). Required when two "
            "scan-path entries collide on (project, env)."
        ),
    )
    parser.add_argument(
        "--state-file",
        default=None,
        metavar="PATH",
        help=(
            "Offline tier=plan|state bypass: read .tfstate from a local "
            "path instead of running 'az storage blob download'. Useful "
            "for local dev and CI sandboxes without storage access."
        ),
    )
    parser.add_argument(
        "--include-modules",
        action="store_true",
        help=(
            "Source-tier only: honor scan_path entries whose stack root "
            "is a module library (modules/, modules-<x>/, .terraform/). "
            "Errors out when combined with --tier plan or --tier state."
        ),
    )
    parser.add_argument(
        "--ignore-lockfile",
        action="store_true",
        help=(
            "Scan .terraform.lock.hcl even though it lives under a "
            "directory the scanner would otherwise exclude. Emits a "
            "WARN log line so the choice is visible in CI."
        ),
    )
    parser.add_argument(
        "--registry-mirror",
        default=None,
        metavar="URL",
        help=(
            "Sets TF_CLI_CONFIG_FILE to an isolated, generated config "
            "that points 'terraform init' at a private module registry "
            "mirror. The config is written under the run-dir and "
            "removed on EXIT/SIGINT/SIGTERM."
        ),
    )
    parser.add_argument(
        "--backend-key",
        default=None,
        metavar="KEY",
        help=(
            "Default storage backend key applied to every --scan-path "
            "entry that doesn't carry an explicit backend_key. Also "
            "applies to flat-root mode when no --scan-path is given."
        ),
    )


def _add_backcompat_aliases(parser: argparse.ArgumentParser) -> None:
    """Attach the three deprecated back-compat aliases.

    Each alias uses ``action='store_true'`` so the underlying scan flags
    (e.g. ``--tier``) keep their defaults; the dispatcher translates the
    alias into the new flag post-parse.
    """
    parser.add_argument(
        "--scan-plan",
        action="store_true",
        help="DEPRECATED: use --tier plan instead.",
    )
    parser.add_argument(
        "--scan-state",
        action="store_true",
        help="DEPRECATED: use --tier state instead.",
    )
    parser.add_argument(
        "--scope",
        default=None,
        help="DEPRECATED: use --baseline instead.",
    )


def _apply_backcompat(args: argparse.Namespace) -> argparse.Namespace:
    """Translate the deprecated aliases into the new flags.

    Order matters when both ``--scan-state`` and ``--scan-plan`` are
    passed: ``--scan-state`` implies ``--tier state`` (which itself
    implies plan via the orchestrator's TIER_PASSES table — see
    scanner/orchestrator.py line 105).
    """
    if getattr(args, "scan_state", False):
        _emit_deprecation("--scan-state", "--tier state")
        # State implies plan; tier='state' is the most-specific intent.
        if getattr(args, "tier", "source") == "source":
            args.tier = "state"

    if getattr(args, "scan_plan", False):
        _emit_deprecation("--scan-plan", "--tier plan")
        # Only escalate to 'plan' if the user didn't already ask for
        # 'state' via --scan-state.
        if getattr(args, "tier", "source") == "source":
            args.tier = "plan"

    scope_value = getattr(args, "scope", None)
    if scope_value:
        _emit_deprecation("--scope", "--baseline")
        # --scope overrides --baseline only when --baseline wasn't set
        # explicitly (so a user explicitly opting into the new flag wins).
        if not getattr(args, "baseline", None):
            args.baseline = scope_value

    return args


def _resolve_target_repo(args: argparse.Namespace) -> Path:
    """Pick the target repo from the positional, --target-repo, or env.

    Mirrors scanner/paths.resolve_target_repo precedence.
    """
    positional = getattr(args, "target_dir", None)
    cli_value = getattr(args, "target_repo", None)
    if positional:
        return Path(positional).expanduser().resolve()
    if cli_value:
        return Path(cli_value).expanduser().resolve()
    env_value = os.environ.get("PACIOLI_TARGET_REPO") or os.environ.get("PCI_REPO_ROOT")
    if env_value:
        return Path(env_value).expanduser().resolve()
    return Path.cwd().resolve()


# ---------------------------------------------------------------------------
# Multi-stack flag helpers (Todo 8)
# ---------------------------------------------------------------------------
#
# The eight new flags (``--scan-path``, ``--scan-glob``, ``--stack-label``,
# ``--state-file``, ``--include-modules``, ``--ignore-lockfile``,
# ``--registry-mirror``, ``--backend-key``) need three layers of glue
# before the orchestrator sees them:
#
#   1. Parse each ``--scan-path`` JSON spec into a flat dict with the
#      canonical ``SCAN_PATH_KEYS`` set; reject unknown keys / missing
#      ``path`` / wrong types with a clear message.
#   2. Expand ``--scan-glob`` patterns via ``Path.glob`` into synthetic
#      ``--scan-path`` specs (``env=basename``, ``project=parent``).
#   3. Validate cross-flag combinations (``--include-modules`` vs
#      ``--tier plan|state``; ``--registry-mirror`` URL syntax;
#      ``--stack-label`` slug syntax).
#
# The orchestrator receives the result of these helpers as plain argv
# (one ``--scan-path-entry <json>`` token per resolved entry, plus the
# other flags verbatim). Keeping the translation in ``cli.py`` means
# the orchestrator's argparse stays a thin validator — the dispatch
# logic for "how to interpret a multi-stack invocation" lives here.
# ---------------------------------------------------------------------------


def _parse_scan_path_spec(spec: str, index: int) -> dict[str, Any]:
    """Parse one ``--scan-path`` JSON spec into a validated dict.

    Args:
        spec: The raw JSON string from the CLI.
        index: Position in the user's argv (for error messages).

    Returns:
        A dict with the canonical ``SCAN_PATH_KEYS`` set. ``path`` is
        always present; the other fields are present only when the user
        provided them.

    Raises:
        ValueError: On malformed JSON, unknown keys, missing ``path``,
            or wrong types — each with a clear, operator-facing message.
    """
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError(
            f"--scan-path[{index}]: spec must be a non-empty JSON object string, "
            f"got {spec!r}"
        )
    try:
        parsed = json.loads(spec)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"--scan-path[{index}]: malformed JSON: {exc.msg} "
            f"(at line {exc.lineno}, column {exc.colno}); raw={spec!r}"
        ) from exc

    if not isinstance(parsed, dict):
        raise ValueError(
            f"--scan-path[{index}]: spec must be a JSON object, "
            f"got {type(parsed).__name__}: {spec!r}"
        )

    unknown = set(parsed.keys()) - SCAN_PATH_KEYS
    if unknown:
        raise ValueError(
            f"--scan-path[{index}]: unknown keys {sorted(unknown)!r} "
            f"(allowed: {sorted(SCAN_PATH_KEYS)!r})"
        )

    raw_path = parsed.get("path")
    if not raw_path or not isinstance(raw_path, str):
        raise ValueError(
            f"--scan-path[{index}]: 'path' is required and must be a non-empty string"
        )

    # Re-project to enforce types on the optional fields. Each field
    # is validated independently so the error message names the bad
    # field rather than just "object is wrong".
    out: dict[str, Any] = {"path": raw_path}
    for key, expected_type in (
        ("project", str),
        ("env", str),
        ("backend_key", str),
        ("workspace", str),
        ("stack_label", str),
    ):
        if key not in parsed:
            continue
        value = parsed[key]
        if not isinstance(value, expected_type) or (isinstance(value, str) and not value):
            raise ValueError(
                f"--scan-path[{index}]: '{key}' must be a non-empty "
                f"{expected_type.__name__}, got {type(value).__name__}: {value!r}"
            )
        out[key] = value
    return out


def _expand_scan_glob(pattern: str, target_repo: Path, index: int) -> list[dict[str, Any]]:
    """Expand one ``--scan-glob`` pattern into synthetic scan-path specs.

    Each match becomes a spec with ``path`` set to the match's path
    relative to ``target_repo`` (so the orchestrator can resolve it the
    same way as a YAML-declared ``scan_paths:`` entry). ``env`` and
    ``project`` are derived from the match's basename and parent
    directory respectively — operators who need different labels can
    always override them with an explicit ``--scan-path``.

    Returns an empty list (NOT a raise) when the pattern matches zero
    directories, matching bash's ``nullglob`` behaviour: a typo is
    surfaced later when the orchestrator tries to resolve a missing
    path, but an empty match (e.g. ``env/*/prod`` when no env dirs
    exist) doesn't kill the run. The orchestrator's
    ``--scan-glob`` integration still reports the empty match in the
    INFO banner so the operator can see what happened.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        raise ValueError(
            f"--scan-glob[{index}]: pattern must be a non-empty string, "
            f"got {pattern!r}"
        )
    matches = sorted(target_repo.glob(pattern))
    specs: list[dict[str, Any]] = []
    for match in matches:
        if not match.is_dir():
            # Skip non-directory matches silently — a glob like
            # ``*.tf`` would otherwise create bogus scan_path entries
            # pointing at files. Operators who need file-level scans
            # should use the legacy ``*.tf`` discovery branch.
            continue
        try:
            # ``relative_to`` returns the path with the host separator
            # (``\\`` on Windows, ``/`` on POSIX). The orchestrator's
            # resolver expects POSIX-style separators (the YAML
            # schema is documented in slash form), so we replace
            # the host separator with ``/`` here. This is a no-op on
            # POSIX hosts.
            rel = str(match.relative_to(target_repo)).replace(os.sep, "/")
        except ValueError:
            # Match lives outside target_repo (absolute glob path).
            # Pass it through verbatim so the orchestrator's resolver
            # can still find it.
            rel = str(match)
        specs.append(
            {
                "path": rel,
                "project": match.parent.name,
                "env": match.name,
            }
        )
    return specs


def _validate_include_modules_vs_tier(tier: str, include_modules: bool) -> None:
    """Reject ``--include-modules`` combined with tier ``plan`` / ``state``.

    ``--include-modules`` is a source-tier concept: it relaxes the
    default exclusion of ``modules/`` / ``modules-<x>/`` / ``.terraform/``
    stack roots so a source-only scan can sweep a module library.
    Tier ``plan`` / ``state`` scan RESOLVED modules via ``terraform
    init`` + ``terraform plan`` + state-blob download, which would
    scan modules regardless of any flag — so the flag is meaningless
    in those tiers and a silent no-op would be a UX trap.
    """
    if include_modules and tier in ("plan", "state"):
        raise ValueError(
            f"--include-modules is source-tier only; got --tier {tier!r}. "
            "Drop --include-modules or switch to --tier source."
        )


def _validate_registry_mirror(url: Optional[str]) -> None:
    """Validate ``--registry-mirror`` URL syntax.

    The mirror URL is the only untrusted value that ends up in the
    generated ``TF_CLI_CONFIG_FILE``. We do a narrow syntactic check
    (http/https + host) so a typo surfaces immediately; deeper
    validation (DNS / reachability) happens later inside ``terraform
    init`` when the operator tries to use the mirror.
    """
    if url is None:
        return
    if not re.match(REGISTRY_MIRROR_PATTERN, url):
        raise ValueError(
            f"--registry-mirror: invalid URL {url!r} "
            "(must be an http(s) URL with a host)"
        )


def _validate_stack_label(label: Optional[str]) -> None:
    """Validate ``--stack-label`` slug syntax.

    The label is appended to the on-disk run-dir component, so it
    must be a portable filesystem slug (no ``/``, no whitespace, no
    leading dash). A 64-char upper bound prevents accidental path
    blow-up when the operator forgets to set ``--label``.
    """
    if label is None:
        return
    if not re.match(STACK_LABEL_PATTERN, label):
        raise ValueError(
            f"--stack-label: invalid slug {label!r} "
            f"(must match {STACK_LABEL_PATTERN})"
        )


def _resolve_scan_path_entries(
    args: argparse.Namespace,
    target_repo: Path,
) -> list[dict[str, Any]]:
    """Build the unified list of scan-path specs from CLI input.

    Combines ``--scan-path`` and ``--scan-glob`` into one ordered list
    (preserving argv order: each ``--scan-glob`` expansion follows the
    preceding ``--scan-path`` entries in the order they appeared). The
    resulting list is what the orchestrator consumes via repeated
    ``--scan-path-entry`` argv tokens.

    Validation: rejects malformed JSON, unknown keys, invalid globs,
    invalid ``--stack-label`` / ``--registry-mirror`` syntax, and the
    ``--include-modules`` vs ``--tier plan|state`` combination. Each
    failure surfaces as a clear ``ValueError`` so the handler can
    convert it to a logged ERROR + non-zero rc.
    """
    target_repo = Path(target_repo).resolve()

    # Cross-flag validation (cheap, run before per-entry parsing).
    _validate_include_modules_vs_tier(
        tier=getattr(args, "tier", "source"),
        include_modules=bool(getattr(args, "include_modules", False)),
    )
    _validate_registry_mirror(getattr(args, "registry_mirror", None))
    _validate_stack_label(getattr(args, "stack_label", None))

    # ``--scan-glob`` may produce zero matches (silent skip), but
    # ``--scan-path`` entries with bad JSON / bad keys MUST surface
    # immediately so the operator sees the typo.
    scan_path_specs: list[str] = list(getattr(args, "scan_path", None) or [])
    scan_glob_patterns: list[str] = list(getattr(args, "scan_glob", None) or [])

    entries: list[dict[str, Any]] = []
    for index, raw_spec in enumerate(scan_path_specs):
        entries.append(_parse_scan_path_spec(raw_spec, index))

    # Default ``--backend-key`` (top-level) applies to entries that
    # don't carry an explicit per-entry ``backend_key``. Applied AFTER
    # parsing so per-entry values win.
    default_backend_key = getattr(args, "backend_key", None)
    for entry in entries:
        entry.setdefault("backend_key", default_backend_key)

    # Default ``--stack-label`` (top-level) is the LAST-RESORT override:
    # a per-entry ``stack_label`` already beats it; we only set the
    # default when the entry has no stack_label and no other entry
    # collides with this one (the collision check lives in the
    # orchestrator's ``_resolve_scan_paths``).
    default_stack_label = getattr(args, "stack_label", None)
    if default_stack_label:
        for entry in entries:
            entry.setdefault("stack_label", default_stack_label)

    # Expand ``--scan-glob`` patterns AFTER ``--scan-path`` parsing so
    # the operator's hand-written entries keep their priority in argv
    # order. Glob-derived entries still inherit the default
    # ``backend_key`` / ``stack_label``.
    for index, pattern in enumerate(scan_glob_patterns):
        glob_entries = _expand_scan_glob(pattern, target_repo, index)
        for glob_entry in glob_entries:
            glob_entry.setdefault("backend_key", default_backend_key)
            if default_stack_label:
                glob_entry.setdefault("stack_label", default_stack_label)
        entries.extend(glob_entries)

    return entries


def _write_registry_mirror_config(
    url: str,
    target_dir: Path,
) -> Path:
    """Generate an isolated Terraform CLI config pointing at ``url``.

    Writes ``terraform.rc`` (the canonical config filename for
    ``TF_CLI_CONFIG_FILE`` on every platform) into a fresh tmpdir
    under ``target_dir``. Returns the path of the generated file so the
    caller can pass it via ``TF_CLI_CONFIG_FILE``.

    The config is intentionally minimal — only the ``provider_installation``
    and ``credentials`` blocks needed to redirect Terraform to a private
    module registry mirror. Everything else (filesystem mirrors, etc.)
    inherits from the operator's ``~/.terraformrc`` defaults.

    The returned directory is cleaned up by the orchestrator's
    EXIT/SIGINT/SIGTERM trap (``scanner.trap``) — the caller doesn't
    need to manage lifecycle here.
    """
    config_dir = Path(target_dir).resolve() / ".pacioli-tf-config"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "terraform.rc"

    # The Terraform CLI config format is HCL, but the registry mirror
    # block is straightforward enough to template without depending
    # on the ``hcl2`` library. We deliberately quote the URL so a
    # registry mirror with ``#`` or ``?`` in its URL doesn't break the
    # generated file.
    quoted_url = json.dumps(url)
    config_path.write_text(
        'provider_installation {\n'
        '  network_mirror {\n'
        f'    url = {quoted_url}\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    # Surfaced in INFO log so the operator can see where the config
    # landed (helpful when troubleshooting "why is terraform using
    # this mirror?").
    _log("INFO", f"registry-mirror config written: {config_path}")
    return config_path


def _emit_ignore_lockfile_warning() -> None:
    """Emit a WARN log line when ``--ignore-lockfile`` is set.

    The flag is opt-in (default off), so the WARN is a deliberate
    signal that the operator chose to scan a directory the scanner
    would otherwise exclude. Belt-and-suspenders: we ALSO surface
    the choice in the orchestrator's banner so it shows up in the
    final HTML report.
    """
    _log(
        "WARN",
        "--ignore-lockfile: scanning .terraform.lock.hcl inside excluded "
        "directories (modules/, modules-*/, .terraform/)"
    )


def _build_orchestrator_argv(
    args: argparse.Namespace,
    *,
    base_argv: Optional[list[str]] = None,
) -> list[str]:
    """Translate the CLI namespace into orchestrator argv (incl. new flags).

    Shared between ``_handle_scan`` and ``_handle_gate``. The orchestrator
    consumes the SAME flag names for the legacy flags plus the new
    multi-stack flags (``--scan-path-entry``, ``--state-file``,
    ``--include-modules``, ``--ignore-lockfile``, ``--registry-mirror``,
    ``--backend-key``). Per-entry ``--scan-path-entry`` tokens are
    emitted in argv order so the orchestrator sees the same priority
    the operator typed.

    Returns the synthesized argv. The orchestrator's argparse never
    sees the operator's raw ``--scan-path`` JSON; we re-emit each
    resolved entry as one ``--scan-path-entry <json>`` token. This
    keeps the surface consistent: the orchestrator's parser only knows
    about the already-validated, already-glob-expanded entries.
    """
    target_repo = getattr(args, "target_repo", None) or "."
    try:
        entries = _resolve_scan_path_entries(args, Path(target_repo))
    except ValueError as exc:
        _log("ERROR", str(exc))
        return []  # sentinel: caller checks empty argv + logged error

    argv: list[str] = list(base_argv) if base_argv else []
    if getattr(args, "target_repo", None):
        argv += ["--target-repo", str(args.target_repo)]
    argv += ["--tier", args.tier]
    if getattr(args, "mode", None):
        argv += ["--mode", args.mode]
    if getattr(args, "mapping", None):
        argv += ["--mapping", args.mapping]
    if getattr(args, "baseline", None):
        argv += ["--baseline", args.baseline]
    if getattr(args, "output_dir", None):
        argv += ["--output-dir", args.output_dir]
    if getattr(args, "project", None):
        argv += ["--project", args.project]
    if getattr(args, "env", None):
        argv += ["--env", args.env]
    if getattr(args, "label", None):
        argv += ["--label", args.label]
    if getattr(args, "state_account", None):
        argv += ["--state-account", args.state_account]
    if getattr(args, "dry_run", False):
        argv += ["--dry-run"]
    if getattr(args, "verbose", False):
        argv += ["--verbose"]

    # New multi-stack flags. ``--include-modules`` is a boolean so it
    # appears as a bare token when set; the other flags are repeatable
    # / single-value and emit ``--flag value`` pairs.
    if getattr(args, "include_modules", False):
        argv += ["--include-modules"]
    if getattr(args, "ignore_lockfile", False):
        argv += ["--ignore-lockfile"]
    if getattr(args, "state_file", None):
        argv += ["--state-file", args.state_file]
    if getattr(args, "registry_mirror", None):
        argv += ["--registry-mirror", args.registry_mirror]
    if getattr(args, "backend_key", None):
        argv += ["--backend-key", args.backend_key]

    # Emit one ``--scan-path-entry`` per resolved entry. JSON-encoded
    # so the orchestrator's parser can ``json.loads`` each token
    # without ambiguity (the entry dict has at most 6 known keys).
    for entry in entries:
        argv += ["--scan-path-entry", json.dumps(entry, sort_keys=True)]

    return argv


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _handle_scan(args: argparse.Namespace) -> int:
    """Dispatch ``pacioli scan`` to :func:`scanner.orchestrator.main`."""
    args = _apply_backcompat(args)
    # Resolve target_repo from positional + flags.
    args.target_repo = str(_resolve_target_repo(args))

    from scanner import orchestrator as _orchestrator

    argv = _build_orchestrator_argv(args)
    if not argv:
        # ``_build_orchestrator_argv`` returns ``[]`` only when validation
        # failed (the helper already logged an ERROR). Don't double-log;
        # just return a non-zero rc so CI surfaces the failure.
        return 2

    return _orchestrator.main(argv)


def _handle_gate(args: argparse.Namespace) -> int:
    """Dispatch ``pacioli gate`` to the orchestrator with mode=gate.

    Mirrors scan.sh's ``--mode gate`` default in CI environments.
    """
    args = _apply_backcompat(args)
    args.mode = "gate"  # force regardless of what the user passed
    args.target_repo = str(_resolve_target_repo(args))

    from scanner import orchestrator as _orchestrator

    argv = _build_orchestrator_argv(args, base_argv=["--mode", "gate"])
    if not argv:
        return 2

    return _orchestrator.main(argv)


def _handle_aggregate(args: argparse.Namespace) -> int:
    """Dispatch ``pacioli aggregate`` to :func:`scanner.aggregate.main`.

    aggregate.main() reads sys.argv directly via argparse, so we swap
    argv in for the call and restore it on the way out (mirrors the
    orchestrator's pattern at lines 944-949).
    """
    run_dir = args.run_dir
    if not run_dir:
        _log("ERROR", "pacioli aggregate requires a <run_dir> positional argument")
        return 2

    aggregate_argv: list[str] = ["aggregate.py", "--run-dir", run_dir]
    if args.mapping:
        aggregate_argv += ["--mapping", args.mapping]
    if args.baseline:
        aggregate_argv += ["--baseline", args.baseline]
    if args.out:
        aggregate_argv += ["--out", args.out]
    if args.emit_fix_list:
        aggregate_argv += ["--emit-fix-list"]

    # aggregate.py is heavy (PyYAML + SARIF parsing + HTML setup) — import
    # lazily to keep `--help` snappy.
    from scanner import aggregate as _aggregate

    saved_argv = sys.argv
    try:
        sys.argv = aggregate_argv
        return _aggregate.main()
    finally:
        sys.argv = saved_argv


def _resolve_latest_run_dir(runs_root: Path) -> Optional[Path]:
    """Find the most-recently-modified run dir under ``runs_root``.

    Returns ``None`` if ``runs_root`` does not exist or contains no
    candidate subdirectories. Sorting is by mtime descending so the
    first entry is the freshest scan.
    """
    if not runs_root.is_dir():
        _log("ERROR", f"no runs found under {runs_root}")
        return None
    candidates = sorted(
        (p for p in runs_root.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        _log("ERROR", f"no runs found under {runs_root}")
        return None
    return candidates[0]


def _resolve_report_html(aggregate_dir: Path, out_path: str) -> None:
    """Copy ``report.html`` from ``aggregate_dir`` to ``out_path`` if present.

    Logs a WARN and returns silently when the source report is absent
    (the audit handler treats ``--out`` as best-effort).
    """
    src_html = aggregate_dir / REPORT_FILENAME
    if not src_html.is_file():
        _log("WARN", f"no {REPORT_FILENAME} in {aggregate_dir}; --out ignored")
        return
    out_resolved = Path(out_path).expanduser().resolve()
    out_resolved.parent.mkdir(parents=True, exist_ok=True)
    out_resolved.write_bytes(src_html.read_bytes())
    _log("INFO", f"{REPORT_FILENAME} copied to: {out_path}")


def _handle_audit(args: argparse.Namespace) -> int:
    """Re-emit a prior Pacioli report from the archive.

    Mirrors scan_audit.sh:
      * default source = local (~/.pacioli/runs/)
      * --source remote switches to the pacioli-reports Azure container
      * --latest lists the most recent run-id (or folder) and downloads
      * --run-id <id> targets a specific run-id directly

    CRITICAL: this handler MUST NOT re-run the scan — it only reads the
    prior SARIF/HTML artifacts and (optionally) copies report.html to
    --out. Mirrors scan_audit.sh lines 1-15.
    """
    source = getattr(args, "source_value", None) or os.environ.get(
        "PACIOLI_AUDIT_SOURCE", "local"
    )
    if source not in VALID_SOURCES:
        _log("ERROR", f"invalid --source: {source!r} (must be one of {VALID_SOURCES})")
        return 2

    if source == "remote":
        return _handle_audit_remote(args)
    return _handle_audit_local(args)


def _handle_audit_local(args: argparse.Namespace) -> int:
    """Re-emit a prior report from the local ``~/.pacioli/runs/`` archive.

    Mirrors scan_audit.sh's ``--source local`` branch (lines 30-72).
    """
    latest = bool(getattr(args, "latest", False))
    run_id = getattr(args, "run_id", None)
    out_path = getattr(args, "out", None)
    runs_root = Path.home() / GLOBAL_CONFIG_DIR / "runs"

    if not run_id and latest:
        latest_dir = _resolve_latest_run_dir(runs_root)
        if latest_dir is None:
            return 2
        run_id = latest_dir.name

    if not run_id:
        _log("ERROR", "pacioli audit requires --latest or --run-id")
        return 2

    run_dir = (runs_root / run_id).resolve()
    aggregate_dir = run_dir / "aggregate"
    if not aggregate_dir.is_dir():
        _log("ERROR", f"audit source missing: {aggregate_dir} (no aggregate/ subdir)")
        return 2

    _log("INFO", f"audit (local): {run_dir}")
    if out_path:
        _resolve_report_html(aggregate_dir, out_path)
    return 0


def _handle_audit_remote(args: argparse.Namespace) -> int:
    """Re-emit a prior report from the ``pacioli-reports`` Azure container.

    Mirrors scan_audit.sh's ``--source remote`` branch (lines 73-126).
    Requires ``PACIOLI_STATE_STORAGE_ACCOUNT`` (or ``--state-account``)
    to be set; refuses otherwise (defense in depth, scan_audit.sh 74-81).
    """
    from datetime import datetime, timezone

    latest = bool(getattr(args, "latest", False))
    run_id = getattr(args, "run_id", None)
    out_path = getattr(args, "out", None)

    storage_account = (
        getattr(args, "state_account", None)
        or os.environ.get("PACIOLI_STATE_STORAGE_ACCOUNT", "").strip()
    )
    container_name = (
        os.environ.get("PACIOLI_REPORTS_CONTAINER", "").strip()
        or DEFAULT_REPORTS_CONTAINER
    )
    if not storage_account:
        _log(
            "ERROR",
            "PACIOLI_STATE_STORAGE_ACCOUNT is not set. Export it before "
            "running `pacioli audit --source remote`.",
        )
        return 2

    if not run_id and not latest:
        _log("ERROR", "pacioli audit --source remote requires --latest or --run-id")
        return 2

    if not run_id:
        run_id = _resolve_latest_remote_run_id(
            storage_account=storage_account,
            container_name=container_name,
            dry_run=bool(args.dry_run),
        )
        if run_id is None:
            return 2

    _log("INFO", f"audit (remote): {storage_account}/{container_name}/{run_id}")

    dest_dir = (Path.home() / GLOBAL_CONFIG_DIR / "runs" / run_id / "aggregate").resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Register a cleanup trap so a SIGINT/SIGTERM in the middle of the
    # download loop (Ctrl+C, CI job timeout) leaves the run-dir in a
    # consistent state: partial downloads are removed instead of
    # silently lingering. The cleanup is best-effort — atexit + signal
    # handlers in scanner.trap swallow exceptions and re-raise the
    # signal so the process exits with the conventional 128+N status.
    if not bool(args.dry_run):
        from scanner.trap import register_traps

        _audit_blobs = ("coverage_matrix.csv", "combined.sarif", "junit.xml", REPORT_FILENAME)

        def _cleanup_partial_downloads() -> None:
            """Remove any partial downloads + the audit marker on signal.

            Only the artifacts that were earmarked for THIS audit run
            are touched; the directory itself is preserved so the
            surrounding runs/<run_id>/ tree (used by other tooling)
            stays intact.
            """
            for fname in _audit_blobs:
                target = dest_dir / fname
                if target.exists():
                    try:
                        target.unlink()
                    except OSError:
                        # Best-effort: a leftover partial download is
                        # worse than a partial download that survives
                        # a cleanup attempt — log + continue.
                        _log("WARN", f"cleanup: failed to remove {target}")
            marker = dest_dir / ".audit_pulled_at"
            if marker.exists():
                try:
                    marker.unlink()
                except OSError:
                    _log("WARN", f"cleanup: failed to remove {marker}")

        register_traps(_cleanup_partial_downloads)

    for fname in ("coverage_matrix.csv", "combined.sarif", "junit.xml", REPORT_FILENAME):
        _log("INFO", f"downloading {fname}")
        _az_blob_download(
            storage_account=storage_account,
            container_name=container_name,
            blob_name=f"{run_id}/{fname}",
            dest=dest_dir / fname,
            dry_run=bool(args.dry_run),
        )

    if out_path:
        _resolve_report_html(dest_dir, out_path)

    # Mark audit freshness so downstream tooling can distinguish an
    # audit-pull from a fresh scan.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (dest_dir / ".audit_pulled_at").write_text(
        f"{timestamp}\nrun_id={run_id}\nsource=remote\n",
        encoding="utf-8",
    )
    _log("INFO", f"audit complete: {dest_dir}")
    return 0


def _resolve_latest_remote_run_id(
    *,
    storage_account: str,
    container_name: str,
    dry_run: bool,
) -> Optional[str]:
    """Discover the latest run-id under ``container_name`` via ``az storage blob list``.

    Returns ``None`` (after logging an ERROR) when the container holds
    no run folders. In ``--dry-run`` mode, returns ``"DRYRUN-LATEST"``
    so the rest of the pipeline can exercise without contacting Azure.
    """
    from scanner import ops as _ops

    if dry_run:
        return "DRYRUN-LATEST"

    _log("INFO", f"fetching latest run_id from {container_name}")
    result = _ops.run(
        "az.blob_list",
        "storage",
        "blob",
        "list",
        "--account-name",
        storage_account,
        "--container-name",
        container_name,
        "--auth-mode",
        "login",
        "--query",
        "[?contains(name, '/')].[name]",
        "-o",
        "tsv",
        tier="state",
    )
    ids = sorted({
        line.split("/", 1)[0]
        for line in (result.stdout or "").splitlines()
        if "/" in line
    })
    if not ids:
        _log(
            "ERROR",
            f"no runs found in {storage_account}/{container_name}",
        )
        return None
    return ids[-1]


def _az_blob_download(
    *,
    storage_account: str,
    container_name: str,
    blob_name: str,
    dest: Path,
    dry_run: bool,
) -> bool:
    """Download ``blob_name`` from the Azure container to ``dest`` via ``az storage blob download``.

    Logs a WARN and returns ``False`` on non-zero exit; returns
    ``True`` on success (including ``--dry-run``). Module-level
    function so the remote audit handler stays under CC ≤ 15.
    """
    from scanner import ops as _ops

    if dry_run:
        print(
            f"[dry-run] az storage blob download "
            f"--account-name {storage_account} "
            f"--container-name {container_name} "
            f"--name {blob_name} --file {dest}"
        )
        return True
    result = _ops.run(
        "az.blob_download",
        "storage",
        "blob",
        "download",
        "--account-name",
        storage_account,
        "--container-name",
        container_name,
        "--name",
        blob_name,
        "--file",
        str(dest),
        "--auth-mode",
        "login",
        "--output",
        "none",
        tier="state",
    )
    if result.returncode != 0:
        _log(
            "WARN",
            f"download {blob_name} failed (rc={result.returncode}): "
            f"{(result.stderr or '').strip()[:300]}",
        )
        return False
    return True


def _handle_baseline(args: argparse.Namespace) -> int:
    """Dispatch ``pacioli baseline init`` to :func:`scanner.baseline_init.main`.

    `baseline` is registered as a sub-subcommand so the surface is
    ``pacioli baseline init <run_dir>``. The handler reshapes
    ``args.run_dir`` from the positional for compatibility with the
    baseline_init CLI (which accepts ``--run-dir``).
    """
    from scanner import baseline_init as _baseline_init

    # The init subcommand takes its own argv (it has its own argparse).
    # Translate the outer namespace into argv for that parser.
    bl_argv: list[str] = []
    run_dir = getattr(args, "run_dir", None)
    if run_dir:
        bl_argv += ["--run-dir", run_dir]
    if getattr(args, "baseline", None):
        bl_argv += ["--baseline", args.baseline]
    if getattr(args, "top", None) is not None:
        bl_argv += ["--top", str(args.top)]
    if getattr(args, "append", False):
        bl_argv += ["--append"]
    if getattr(args, "dry_run", False):
        bl_argv += ["--dry-run"]

    return _baseline_init.main(bl_argv)


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level ``pacioli`` argparse parser."""
    parser = argparse.ArgumentParser(
        prog="pacioli",
        description=(
            "Compliance-as-code for Azure Terraform. Read-only scanner that "
            "checks Terraform code against compliance frameworks (PCI DSS 4.0.1 "
            "by default), emits a self-contained HTML report, and gates CI on "
            "HIGH/CRITICAL findings."
        ),
    )

    # Global flag: --non-interactive disables the first-run picker.
    # It's declared on the top-level parser so it shows up in
    # `pacioli --help`, but the scan subcommand also re-declares it
    # so callers can pass it positionally after the subcommand.
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Disable the first-run interactive picker (global; honoured by `pacioli scan`).",
    )

    subparsers = parser.add_subparsers(
        title="subcommands",
        dest="subcommand",
        required=True,
        metavar="<subcommand>",
    )

    # --- scan ---------------------------------------------------------
    scan_epilog = (
        "Examples:\n"
        "  pacioli scan                                  # source-only scan of cwd\n"
        "  pacioli scan /path/to/tf-repo --tier plan     # adds terraform plan\n"
        "  pacioli scan /path/to/tf-repo --tier state    # adds state-blob + drift\n"
        "\n"
        "Back-compat aliases (deprecated):\n"
        "  --scan-plan   equivalent to --tier plan\n"
        "  --scan-state  equivalent to --tier state\n"
        "  --scope       equivalent to --baseline\n"
        "\n"
        + SAFETY_DISCLAIMER
    )
    scan_p = subparsers.add_parser(
        "scan",
        help="Run a scan (delegates to scanner.orchestrator).",
        description=(
            "Run a Pacioli scan against the consumer's Terraform repo. "
            "Defaults to a source-only scan in --mode report; CI=1 promotes "
            "to --mode gate. Use --tier plan|state to enable terraform "
            "init+plan and (optionally) state-blob download + drift diff."
        ),
        epilog=scan_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_scan_flags(scan_p)
    _add_backcompat_aliases(scan_p)
    scan_p.set_defaults(handler=_handle_scan)

    # --- gate ---------------------------------------------------------
    gate_p = subparsers.add_parser(
        "gate",
        help="Run a scan in CI gate mode (delegates to scanner.orchestrator with --mode gate).",
        description=(
            "Run a Pacioli scan in CI gate mode. Equivalent to `pacioli scan "
            "--mode gate` — propagates checkov non-zero exit codes AND "
            "aggregate's rc=7 (HIGH/CRITICAL findings) into SCAN_RC so the "
            "wrapper exits non-zero. Does NOT auto-aggregate."
        ),
        epilog=SAFETY_DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_scan_flags(gate_p)
    _add_backcompat_aliases(gate_p)
    gate_p.set_defaults(handler=_handle_gate)

    # --- aggregate ----------------------------------------------------
    agg_p = subparsers.add_parser(
        "aggregate",
        help="Run the aggregator only (delegates to scanner.aggregate).",
        description=(
            "Run the aggregator over a prior scan's run-dir without re-running "
            "checkov. Emits coverage_matrix.csv, combined.sarif, junit.xml, "
            "and report.html under <run-dir>/aggregate/."
        ),
    )
    agg_p.add_argument(
        "run_dir",
        help="Run dir produced by `pacioli scan` (the directory containing "
        "the per-project per-env SARIF files).",
    )
    agg_p.add_argument(
        "--mapping",
        default=None,
        help="Framework mapping YAML (default: install-root or env).",
    )
    agg_p.add_argument(
        "--baseline",
        default=None,
        help="Baseline suppressions YAML.",
    )
    agg_p.add_argument(
        "--out",
        default=None,
        help="Output dir (default: <run-dir>/aggregate).",
    )
    agg_p.add_argument(
        "--emit-fix-list",
        action="store_true",
        help="Also emit <run-id>/fix_list.md (developer-facing markdown).",
    )
    agg_p.set_defaults(handler=_handle_aggregate)

    # --- audit --------------------------------------------------------
    audit_p = subparsers.add_parser(
        "audit",
        help="Re-emit a prior Pacioli report from the archive (no re-scan).",
        description=(
            "Re-emit a prior Pacioli report from the archive. READ-ONLY: "
            "downloads coverage_matrix.csv, combined.sarif, junit.xml, and "
            "report.html from <PACIOLI_STATE_STORAGE_ACCOUNT>/<PACIOLI_REPORTS_CONTAINER>/<run_id>/. "
            "Does NOT re-run the scan."
        ),
        epilog=SAFETY_DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit_p.add_argument(
        "--latest",
        action="store_true",
        help="Audit the most recent run (from the local archive or Azure container).",
    )
    audit_p.add_argument(
        "--run-id",
        default=None,
        help="Specific run-id to audit (e.g. 20260804T153407Z-2455).",
    )
    audit_p.add_argument(
        "--out",
        default=None,
        help="Optional destination for report.html.",
    )
    audit_p.add_argument(
        "--source",
        choices=VALID_SOURCES,
        dest="source_value",
        default=None,
        help="Archive source: local (default, ~/.pacioli/runs/) or remote (pacioli-reports Azure container).",
    )
    audit_p.add_argument(
        "--state-account",
        default=None,
        help="Storage account for --source remote (default: $PACIOLI_STATE_STORAGE_ACCOUNT).",
    )
    audit_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print intended actions without downloading.",
    )
    audit_p.set_defaults(handler=_handle_audit)

    # --- baseline -----------------------------------------------------
    baseline_p = subparsers.add_parser(
        "baseline",
        help="Baseline-suppressions maintenance commands.",
        description=(
            "Subcommands for maintaining the repo's pci_baseline.yaml "
            "suppressions file."
        ),
    )
    baseline_sub = baseline_p.add_subparsers(
        title="baseline subcommands",
        dest="baseline_subcommand",
        required=True,
        metavar="<subcommand>",
    )
    init_p = baseline_sub.add_parser(
        "init",
        help="Generate stub baseline entries from a prior scan (delegates to scanner.baseline_init).",
        description=(
            "Read <run_dir>/aggregate/combined.sarif and emit one stub "
            "suppression per (check_id, resource) pair into "
            "pci_baseline.yaml. Stubs require manual triage "
            "(owner != TBD AND expires_on >= today) before the aggregator "
            "treats them as real suppressions."
        ),
    )
    init_p.add_argument(
        "run_dir",
        nargs="?",
        default=None,
        help="Run dir produced by `pacioli scan` (default: most recent under ~/.pacioli/runs/).",
    )
    init_p.add_argument(
        "--baseline",
        default=None,
        help="Destination baseline YAML (default: $PACIOLI_BASELINE_FILE or <target_repo>/pci_baseline.yaml).",
    )
    init_p.add_argument(
        "--top",
        type=int,
        default=50,
        help="Run-book reference count (every distinct (check_id, resource) still gets a stub).",
    )
    init_p.add_argument(
        "--append",
        action="store_true",
        help="Merge with existing pci_baseline.yaml (default: replace).",
    )
    init_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print intended actions without writing.",
    )
    init_p.set_defaults(handler=_handle_baseline)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Top-level CLI dispatcher for the ``pacioli`` console script.

    Parses argv, dispatches to the registered subcommand handler, and
    returns the handler's process exit code.
    """
    try:
        parser = _build_parser()
        args = parser.parse_args(list(argv) if argv is not None else None)

        handler = getattr(args, "handler", None)
        if handler is None:
            # Should be unreachable because subparsers are required=True,
            # but be defensive in case a future subcommand forgets to wire
            # a handler.
            parser.print_help(sys.stderr)
            return 2

        # Honor the global --non-interactive flag: when True, scrub stdin so
        # any first-run picker the orchestrator or aggregate might invoke
        # short-circuits to its default. The first-run picker lives in
        # scanner.config; we don't import it eagerly here to keep `--help`
        # snappy, but we set the env var that config.py consults.
        if getattr(args, "non_interactive", False):
            os.environ["PACIOLI_NON_INTERACTIVE"] = "1"

        return handler(args)
    except MutatingOperationRefused:
        sys.exit(99)


if __name__ == "__main__":
    sys.exit(main())