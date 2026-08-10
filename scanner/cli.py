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
import os
import sys
import warnings
from pathlib import Path
from typing import Optional, Sequence

# Make sibling scanner modules importable when invoked as
# `python -m scanner.cli` from the repo root (the package layout puts
# `scanner/` at the repo root, not under a src/ tree).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


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

    Includes all 14 flags from the plan's MUST-DO contract:
    --target-repo, --tier, --mode, --mapping, --baseline, --output-dir,
    --project, --env, --label, --state-account, --source, --dry-run,
    --verbose, --non-interactive.
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
# Subcommand handlers
# ---------------------------------------------------------------------------


def _handle_scan(args: argparse.Namespace) -> int:
    """Dispatch ``pacioli scan`` to :func:`scanner.orchestrator.main`."""
    args = _apply_backcompat(args)
    # Resolve target_repo from positional + flags.
    args.target_repo = str(_resolve_target_repo(args))

    # Translate the orchestrator's argv expectations: it consumes the
    # same flag names, so we can pass them through verbatim.
    # The orchestrator's argparse is internal — we synthesize argv and
    # let it parse.
    from scanner import orchestrator as _orchestrator

    argv: list[str] = []
    if args.target_repo:
        argv += ["--target-repo", args.target_repo]
    argv += ["--tier", args.tier]
    argv += ["--mode", args.mode]
    if args.mapping:
        argv += ["--mapping", args.mapping]
    if args.baseline:
        argv += ["--baseline", args.baseline]
    if args.output_dir:
        argv += ["--output-dir", args.output_dir]
    if args.project:
        argv += ["--project", args.project]
    if args.env:
        argv += ["--env", args.env]
    if args.label:
        argv += ["--label", args.label]
    if args.state_account:
        argv += ["--state-account", args.state_account]
    if args.dry_run:
        argv += ["--dry-run"]
    if args.verbose:
        argv += ["--verbose"]

    return _orchestrator.main(argv)


def _handle_gate(args: argparse.Namespace) -> int:
    """Dispatch ``pacioli gate`` to the orchestrator with mode=gate.

    Mirrors scan.sh's ``--mode gate`` default in CI environments.
    """
    args = _apply_backcompat(args)
    args.mode = "gate"  # force regardless of what the user passed
    args.target_repo = str(_resolve_target_repo(args))

    from scanner import orchestrator as _orchestrator

    argv: list[str] = ["--mode", "gate"]
    if args.target_repo:
        argv += ["--target-repo", args.target_repo]
    argv += ["--tier", args.tier]
    if args.mapping:
        argv += ["--mapping", args.mapping]
    if args.baseline:
        argv += ["--baseline", args.baseline]
    if args.output_dir:
        argv += ["--output-dir", args.output_dir]
    if args.project:
        argv += ["--project", args.project]
    if args.env:
        argv += ["--env", args.env]
    if args.label:
        argv += ["--label", args.label]
    if args.state_account:
        argv += ["--state-account", args.state_account]
    if args.dry_run:
        argv += ["--dry-run"]
    if args.verbose:
        argv += ["--verbose"]
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
    import subprocess

    if dry_run:
        return "DRYRUN-LATEST"

    _log("INFO", f"fetching latest run_id from {container_name}")
    result = subprocess.run(
        [
            "az",
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
        ],
        capture_output=True,
        text=True,
        check=False,
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
    import subprocess

    if dry_run:
        print(
            f"[dry-run] az storage blob download "
            f"--account-name {storage_account} "
            f"--container-name {container_name} "
            f"--name {blob_name} --file {dest}"
        )
        return True
    result = subprocess.run(
        [
            "az",
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
        ],
        capture_output=True,
        text=True,
        check=False,
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


if __name__ == "__main__":
    sys.exit(main())