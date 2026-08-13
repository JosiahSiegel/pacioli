"""scanner/orchestrator.py — Read-only PCI scan orchestrator (Python).

Replaces ``scanner/scan.sh`` as the in-process scan driver for the
standalone Pacioli CLI. The bash script remains the source of truth for
behavior; this module ports that behavior 1:1 into Python.

What it does
------------
For each ``(project, env)`` pair discovered in ``target_repo``:

1. (Tier ``plan``/``state`` only) Emit an alert that network access to
   the ``state_account`` storage account is required (fail-closed: if
   access is missing the per-pair plan/state passes are skipped).
   ``terraform init -backend=false`` + ``terraform plan -out=tfplan.binary
   -lock=false -refresh=false`` + ``terraform show -json``. The scanner
   never mutates the storage firewall — the operator is responsible
   for granting access.
2. ``checkov`` --framework terraform  + --external-checks-dir (paac).
3. ``checkov`` --framework terraform  built-in source scan.
4. (Tier ``plan``/``state`` only) ``checkov`` --framework terraform_plan
   on the plan JSON.
5. ``checkov`` --framework secrets on the .tf source.
6. (Tier ``state`` only) Download state blob, convert to plan-shape
   JSON, run ``checkov`` terraform_plan on it, emit drift_report.json.
7. Shred plan artifacts on exit (PCI 10.7 hygiene).

After the loop, the per-pair SARIFs are aggregated via
:func:`scanner.aggregate.main` to produce the HTML report + coverage
matrix + JUnit XML.

Modes
-----
* ``gate`` — CI gate. Propagates checkov's non-zero exit codes AND
  aggregate's ``rc=7`` (HIGH/CRITICAL findings present) into SCAN_RC so
  the wrapper exits non-zero.
* ``report`` — Manual scan. Default. Suppresses aggregate's ``rc=7``
  (the whole point of a report is to surface findings for triage); only
  propagates real aggregation failures (rc != 7).
* ``audit`` — Not implemented in this Python port; the bash script's
  ``scan_audit.sh`` companion handles that.

CI auto-promotion
-----------------
When ``CI`` env var is set to ``1`` and ``mode == "report"``, ``main()``
promotes ``mode`` to ``gate`` before any work begins. Mirrors scan.sh
lines 149-153.

Console scripts
---------------
* ``pacioli-scan``  → ``scanner.orchestrator:legacy_main`` (emits a
  deprecation warning to stderr and calls ``main()``).
* ``pacioli scan``  → ``scanner.orchestrator:main`` (preferred entry).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import stat
import sys
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# Lazy import: scanner/ops.py at module-load would import subprocess and
# the safety guard; that's fine, but we keep the symbol local so call
# sites read as ``ops.run(...)``.
from scanner import ops as scanner_ops  # noqa: E402

# Bootstrap UTF-8 I/O before any scan work (mirrors lib/common.sh).
import scanner._utf8  # noqa: F401  -- side-effect import

# Make sibling scanner modules importable when this file is executed
# directly (python scanner/orchestrator.py) and from `python -m`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.checkov_runner import CheckovRunner  # noqa: E402
from scanner.discovery import (  # noqa: E402
    DiscoveredPair,
    NoTerraformFoundError,
    discover_pairs,
    discover_skipped_scope_environments,
)
from scanner.frameworks import (  # noqa: E402
    SUPPORTED_FRAMEWORKS,
    detect_frameworks,
    is_terraform_family,
)
from scanner.paths import (  # noqa: E402
    PathResolutionError,
    resolve_mapping as resolve_mapping_path,
    resolve_paths,
)
from scanner.safety import MutatingOperationRefused, SafetyGuard  # noqa: E402
from scanner.trap import (  # noqa: E402
    create_secure_file,
    register_traps,
    safe_unlink,
    shred_plan_artifacts,
)

# Lazy import: aggregate.py is heavy (loads checkov SARIF parsing +
# HTML report rendering at import time).
# from scanner import aggregate  # noqa: E402  -- imported lazily in _run_aggregate


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Mirrors the bash scanner's SCAN_RC conventions:
#   - gate mode: SCAN_RC is the max of every checkov pass rc AND
#     aggregate's rc (including rc=7 from HIGH/CRITICAL findings).
#   - report mode: SCAN_RC stays 0 unless aggregate returns a real
#     failure rc (anything other than 7). Findings are the point of the
#     report, not a failure.
AGGREGATE_FINDINGS_RC: int = 7

# Tier -> which passes run. Source-only is the default (no terraform
# init / plan / storage read). The mapping itself is
# framework-agnostic — the per-pass dispatch in :meth:`_scan_one_pair`
# uses :func:`scanner.frameworks.is_terraform_family` to skip the
# ``plan``/``state``/``drift`` passes for non-Terraform-family
# frameworks. Tier *eligibility* (whether the tier itself is valid for
# the active framework) is enforced separately in
# :meth:`Orchestrator._validate_mode_and_tier`.
TIER_PASSES: dict[str, tuple[str, ...]] = {
    "source": ("paac", "source", "secrets"),
    "plan": ("paac", "source", "plan", "secrets"),
    "state": ("paac", "source", "plan", "state", "secrets", "drift"),
}

VALID_TIERS: tuple[str, ...] = ("source", "plan", "state")
VALID_MODES: tuple[str, ...] = ("gate", "report", "audit")

# Azure storage account name validation (Azure naming rules):
#  - 3-24 characters
#  - lowercase letters and digits only
# Used to validate the `--state-account` CLI flag before it reaches
# any subprocess (S8705 — subprocess invocation with tainted CLI value).
AZURE_STORAGE_ACCOUNT_PATTERN: str = r"^[a-z0-9]{3,24}$"

# Azure Instance Metadata Service (IMDS) link-local address. Only
# reachable from inside an Azure VM; used by ``_discover_public_ip`` to
# fetch the canonical public IP for the storage firewall whitelist.
# ``169.254.169.254`` is the canonical IMDS IP — there is no DNS name
# and no HTTPS variant (Azure IMDS requires HTTP for its metadata
# response). The literal must appear here exactly once; consumers
# reference it via the constant.
AZURE_IMDS_ENDPOINT: str = "169.254.169.254"  # noqa: S1313 — Azure IMDS link-local IP has no DNS form
AZURE_IMDS_IPV4_PATH: str = (
    "/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress"
    "?api-version=2021-02-01&format=text"
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OrchestratorError(RuntimeError):
    """Raised on unrecoverable orchestrator misconfiguration."""


class PreflightError(OrchestratorError):
    """Raised when a stack root fails the pre-terraform preflight checks.

    Todo 10: defense-in-depth against symlinked roots, ``..`` traversal,
    module-library directories (``modules/``, ``modules-<x>/``,
    ``.terraform/``) being scanned as Terraform roots, and missing
    ``.terraform.lock.hcl``. The orchestrator catches this in
    :meth:`Orchestrator._scan_one_pair` and fails the pair (per-pair
    scan_rc stays 0 in report mode; gate mode propagates it).

    Inherits from :class:`OrchestratorError` so existing callers that
    catch ``OrchestratorError`` still fire.
    """


# ---------------------------------------------------------------------------
# Logging helper (mirrors pci_log INFO/WARN/ERROR semantics)
# ---------------------------------------------------------------------------


def _log(level: str, msg: str) -> None:
    """Emit a scan.sh-style ``pci_log`` line to stderr.

    Format mirrors ``lib/common.sh::pci_log``:
        <LEVEL>  <msg>
    on stderr, so it interleaves cleanly with checkov's own output.
    """
    print(f"{level}  {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


@dataclass
class _PairState:
    """Per-pair working state carried through one scan iteration."""

    project: str
    env: str
    env_run_dir: Path
    env_dir: Path
    plan_bin: Optional[Path] = None
    plan_json: Optional[Path] = None
    state_local: Optional[Path] = None
    state_plan_json: Optional[Path] = None
    # Backend-key precedence (scan_paths: opt-in). ``None`` means the
    # helper will fall through to the aztfexport file / basename
    # default. Set by ``_run_scan_loop`` from a ``DiscoveredPair``.
    backend_key_override: Optional[str] = None
    # Optional Terraform workspace name (scan_paths: ``workspace:``).
    # Forwarded into the ``terraform plan -var workspace=<x>`` argv
    # by the per-tier pass; not used in tier=source.
    workspace: Optional[str] = None


@dataclass
class Orchestrator:
    """Stateful orchestrator that drives one full scan invocation.

    Attributes:
        mode: ``gate``, ``report``, or ``audit``. ``audit`` is not
            implemented (raises :class:`OrchestratorError`); the bash
            ``scan_audit.sh`` handles that flow.
        tier: ``source`` (default), ``plan``, or ``state``.
        dry_run: When True, print intended actions without executing.
            Matches scan.sh's ``--dry-run``.
        no_aggregate: When True, skip the post-loop aggregate step
            (matches scan.sh's ``--no-aggregate``).
        no_open: When True, skip the post-aggregate ``webbrowser.open``
            call that surfaces the generated ``report.html``. Mirrors
            scan.sh's ``--no-open`` (added in the slim-readme plan).
        verbose: When True, emit INFO logs (matches PCI_VERBOSE=1).
        safety: Pre-wired :class:`SafetyGuard` instance (defense-in-
            depth refusal matrix). Pass an instance to inject a stub
            in tests; production code uses the default.
    """

    mode: str = "report"
    tier: str = "source"
    dry_run: bool = False
    no_aggregate: bool = False
    no_open: bool = False
    verbose: bool = False
    safety: SafetyGuard = field(default_factory=SafetyGuard)
    # Optional Terraform registry mirror URL (--registry-mirror). When
    # set, ``_isolate_terraform_env`` writes a ``network_mirror`` block
    # into the per-run ``terraformrc`` so provider downloads go through
    # the declared mirror instead of registry.terraform.io.
    registry_mirror: Optional[str] = None

    # -- public --------------------------------------------------------

    def scan(
        self,
        *,
        target_repo: Path,
        project: Optional[str],
        env: Optional[str],
        label: Optional[str],
        output_dir: Path,
        mapping_path: Optional[Path],
        baseline_path: Optional[Path],
        state_account: Optional[str],
        include_modules: bool = False,
        ignore_lockfile: bool = False,
        registry_mirror: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> int:
        """Run the full scan and return the SCAN_RC.

        Args:
            target_repo: Path to the consumer's Terraform repo (must
                contain ``pci_scope.yaml`` or ``env/<project>/<env>/``
                or flat ``*.tf`` at the root).
            project: Optional ``--project`` filter.
            env: Optional ``--env`` filter.
            label: Optional ``--label`` slug for the run-dir name.
            output_dir: Root directory under which per-pair output
                subdirectories ``<output_dir>/<project>/<env>/`` are
                created.
            mapping_path: Absolute path to the framework mapping pack
                YAML (or ``None`` to defer to ``resolve_mapping``).
            baseline_path: Absolute path to the baseline suppressions
                YAML (or ``None``).
            state_account: Storage account name used for the firewall
                whitelist in tier ``plan``/``state``. Required for
                those tiers.
            include_modules: When ``True``, ``scan_paths:`` entries
                whose stack root is a module library (``modules/``,
                ``modules-<x>/``, ``.terraform/``) are honored. Default
                is ``False``; the CLI flag (Todo 8) overrides this.
            framework: Explicit Checkov framework name (e.g.,
                ``"terraform"``, ``"cloudformation"``, ``"kubernetes"``).
                When supplied, ``--tier plan`` / ``--tier state`` are
                rejected for non-Terraform-family frameworks via
                :func:`scanner.frameworks.is_terraform_family`. The CLI
                flag (Todo 12) wires ``--framework`` here. ``None``
                defers tier/framework validation to the per-pair loop,
                which auto-detects and skips the heavy passes
                accordingly.

        Returns:
            The shell-style SCAN_RC. ``gate`` mode may return any non-
            zero from aggregate.py (including 7); ``report`` mode
            returns ``0`` unless aggregate.py failed with rc != 7.
        """
        try:
            # Mode / tier validation first — fail fast before doing work.
            # Framework (when supplied) gates tier eligibility: non-
            # Terraform frameworks cannot request plan/state tiers.
            self._validate_mode_and_tier(framework=framework)

            # Store registry_mirror so _run_terraform_* call sites can
            # generate the per-run TF_CLI_CONFIG_FILE (Todo 9).
            self.registry_mirror = registry_mirror

            # Store preflight-related flags (Todo 10) so the per-pair
            # preflight helper can read them without having to thread them
            # through every helper signature. ``include_modules`` doubles
            # as the discovery-time filter (already used in
            # :meth:`_resolve_scan_inputs`) and the per-stack-root preflight
            # opt-out for ``modules/``-style stack roots.
            self._include_modules = bool(include_modules)
            self._ignore_lockfile = bool(ignore_lockfile)

            # Store the active framework so per-pair helpers can gate
            # Terraform-only passes (plan/state/drift/paac) via
            # :func:`scanner.frameworks.is_terraform_family` without
            # threading ``framework`` through every signature.
            self._framework = framework

            target_repo, resolved_mapping, resolved_baseline, pairs = (
                self._resolve_scan_inputs(
                    target_repo=target_repo,
                    project=project,
                    env=env,
                    mapping_path=mapping_path,
                    baseline_path=baseline_path,
                    include_modules=include_modules,
                )
            )
            skipped_environments = discover_skipped_scope_environments(target_repo)

            for skipped in skipped_environments:
                _log(
                    "INFO",
                    f"skipping declared {skipped.project}/{skipped.env}: "
                    f"status={skipped.status}; reason={skipped.reason}",
                )

            if not pairs:
                _log("WARN", "no (project, env) pairs matched --project/--env filters")
                return 0

            output_dir = Path(output_dir).resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
            run_root = self._setup_run_root(output_dir, label)

            self._emit_scan_banner(self.mode, self.tier, output_dir, resolved_mapping, resolved_baseline, pairs, framework=framework)

            runner = CheckovRunner(mode=self.mode)

            # SCAN_RC accumulates per checkov pass (max-of) AND aggregate
            # findings rc (gate mode only). See module docstring.
            scan_rc = self._run_scan_loop(runner, pairs, target_repo, run_root, state_account)

            # -- aggregate ------------------------------------------------
            scan_rc = self._run_aggregate_and_report(
                run_root, resolved_mapping, resolved_baseline, scan_rc
            )

            _log("INFO", f"scan complete: {output_dir}")
            return scan_rc
        except MutatingOperationRefused:
            sys.exit(99)

    # -- scan() helpers ----------------------------------------------

    def _resolve_scan_inputs(
        self,
        *,
        target_repo: Path,
        project: Optional[str],
        env: Optional[str],
        mapping_path: Optional[Path],
        baseline_path: Optional[Path],
        include_modules: bool = False,
    ) -> tuple[Path, Path, Optional[Path], list[DiscoveredPair]]:
        """Resolve target repo, mapping, baseline, and (project, env) pairs.

        Extracted from :meth:`scan` so that the top-level orchestrator
        reads as a thin glue layer (S3776). Raises :class:`OrchestratorError`
        on resolution failures (mapping, no-pair discovery) so the
        caller can convert them to a single log + non-zero rc.

        ``include_modules`` is forwarded to :func:`discover_pairs` and
        controls whether ``modules/`` / ``modules-<x>/`` / ``.terraform/``
        entries in ``scan_paths:`` are honored. Defaults to ``False``
        (excluded) for source-tier scans; the CLI flag (Todo 8) will
        override.
        """
        target_repo = Path(target_repo).resolve()
        if not target_repo.is_dir():
            raise OrchestratorError(f"target repo does not exist: {target_repo}")

        try:
            resolved_mapping = self._resolve_mapping_path(mapping_path)
        except PathResolutionError as exc:
            raise OrchestratorError(str(exc)) from exc

        resolved_baseline = self._resolve_baseline(baseline_path, target_repo)

        try:
            pairs = discover_pairs(
                target_repo,
                project_filter=project,
                env_filter=env,
                include_modules=include_modules,
            )
        except NoTerraformFoundError as exc:
            raise OrchestratorError(str(exc)) from exc

        return target_repo, resolved_mapping, resolved_baseline, pairs

    # -- scan() helpers ----------------------------------------------

    def _validate_mode_and_tier(
        self,
        framework: Optional[str] = None,
    ) -> None:
        """Fail fast on invalid mode / tier before doing any work.

        Extracted from :meth:`scan` to keep that method's cognitive
        complexity under control. ``audit`` mode is intentionally not
        implemented in the Python orchestrator — the bash
        ``scan_audit.sh`` companion handles that flow.

        Framework awareness (Todo 10): when ``framework`` is supplied,
        tier eligibility is checked via
        :func:`scanner.frameworks.is_terraform_family`. The ``plan``
        and ``state`` tiers require a Terraform-family framework
        (they invoke ``terraform init`` / ``terraform plan`` and read
        Azure state blobs). A user passing ``--tier plan`` or
        ``--tier state`` with a non-Terraform framework gets a hard
        :class:`OrchestratorError` — never a silent skip. Tier
        ``source`` is always valid for every framework.
        """
        if self.mode not in VALID_MODES:
            raise OrchestratorError(
                f"invalid mode: {self.mode!r} (must be one of {VALID_MODES})"
            )
        if self.mode == "audit":
            raise OrchestratorError(
                "audit mode is not implemented in the Python orchestrator; "
                "use scan_audit.sh for re-emit-from-archive flows"
            )
        if self.tier not in VALID_TIERS:
            raise OrchestratorError(
                f"invalid tier: {self.tier!r} (must be one of {VALID_TIERS})"
            )
        # Framework/tier compatibility: only enforce when a framework
        # is supplied AND it's not in the Terraform family. ``None``
        # (auto-detect deferred) skips this check — the per-pair loop
        # picks the framework and gates the heavy passes there.
        if (
            framework is not None
            and self.tier in ("plan", "state")
            and not is_terraform_family(framework)
        ):
            raise OrchestratorError(
                f"tier {self.tier!r} requires a Terraform-family "
                f"framework; {framework!r} does not support plan/state "
                f"tiers (terraform init/plan and Azure state-blob "
                f"download are Terraform-only)"
            )

    @staticmethod
    def _setup_run_root(output_dir: Path, label: Optional[str]) -> Path:
        """Return the per-run root, creating it if a ``label`` was supplied.

        ``label`` (from ``--label``) is an optional slug that
        disambiguates run-dirs when the operator wants to keep multiple
        scan runs side-by-side under the same parent. When supplied,
        per-pair output is written under
        ``<output_dir>/<label>/<project>/<env>/`` instead of
        ``<output_dir>/<project>/<env>/``. When ``None`` (the default),
        the layout is unchanged.
        """
        run_root = output_dir / label if label else output_dir
        if label:
            run_root.mkdir(parents=True, exist_ok=True)
        return run_root

    @staticmethod
    def _write_environment_metadata(env_run_dir: Path, pair: DiscoveredPair) -> None:
        """Atomically record the pair identity before any Checkov pass executes."""
        artifact = env_run_dir / "pacioli_environment.json"
        temporary = artifact.with_suffix(".json.tmp")
        metadata = {
            "schema_version": 1,
            "project": pair.project,
            "env": pair.env,
            "stack_label": pair.stack_label,
        }
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, artifact)

    @staticmethod
    def _resolve_baseline(
        baseline_path: Optional[Path],
        target_repo: Path,
    ) -> Optional[Path]:
        """Pick the effective baseline file (CLI > repo default).

        Returns ``None`` when no usable baseline file exists. Mirrors
        the bash scanner's ``$PCI_BASELINE_FILE`` precedence.
        """
        if baseline_path is not None:
            resolved: Optional[Path] = Path(baseline_path).resolve()
            if not resolved.is_file():
                resolved = None
            return resolved
        env_baseline = target_repo / "pci_baseline.yaml"
        return env_baseline if env_baseline.is_file() else None

    @staticmethod
    def _emit_scan_banner(
        mode: str,
        tier: str,
        output_dir: Path,
        resolved_mapping: Path,
        resolved_baseline: Optional[Path],
        pairs: list[DiscoveredPair],
        framework: Optional[str] = None,
    ) -> None:
        """Emit the per-run INFO banner before the per-pair loop starts.

        Extracted from :meth:`scan` so the top-level orchestrator reads
        as a thin glue layer.

        Framework awareness (Todo 10): when ``framework`` is supplied,
        the banner logs the detected framework(s) so the operator can
        see at a glance which Checkov framework is active. ``None``
        means auto-detect was deferred to the per-pair loop.
        """
        _log("INFO", f"mode: {mode}")
        _log("INFO", f"tier: {tier}")
        _log("INFO", f"output_dir: {output_dir}")
        _log("INFO", f"mapping: {resolved_mapping}")
        if resolved_baseline:
            _log("INFO", f"baseline: {resolved_baseline}")
        # Log the detected framework(s) so operators can confirm which
        # Checkov framework is active (Todo 10). ``None`` means the
        # per-pair loop will auto-detect from the env dir's contents.
        if framework is not None:
            family = (
                "terraform-family" if is_terraform_family(framework) else "non-terraform"
            )
            _log("INFO", f"framework: {framework} ({family})")
        else:
            _log("INFO", "framework: auto-detect (deferred to per-pair loop)")
        _log(
            "INFO",
            f"discovered {len(pairs)} (project, env) pair(s): "
            + ", ".join(f"{p}/{e}" for p, e in pairs),
        )

    def _run_scan_loop(
        self,
        runner: CheckovRunner,
        pairs: list[DiscoveredPair],
        target_repo: Path,
        run_root: Path,
        state_account: Optional[str],
    ) -> int:
        """Drive the (project, env) pair loop and return the per-pair max rc.

        Skips pairs whose env dir is missing. The per-pair dispatch into
        the tier-specific passes is delegated to
        :meth:`_scan_one_pair`.

        Each :class:`DiscoveredPair` carries the optional ``stack_root``
        (set by ``scan_paths:``) and ``backend_key_override`` /
        ``workspace`` (also from ``scan_paths:``). The legacy
        ``(project, env)`` branches produce ``DiscoveredPair`` instances
        with ``stack_root=None`` and override fields ``None``, so the
        behavior for those is unchanged.
        """
        scan_rc = 0
        for pair in pairs:
            proj = pair.project
            env_name = pair.env
            env_dir = self._resolve_env_dir(
                target_repo,
                proj,
                env_name,
                stack_root=pair.stack_root,
            )
            if not env_dir.is_dir():
                _log(
                    "WARN",
                    f"skipping {proj}/{env_name}: env dir invalid: {env_dir}",
                )
                continue

            # Per-pair output dir; scan_paths: stack_label is appended
            # so two colliding (project, env) entries don't clobber
            # each other's SARIFs.
            label_suffix = f"-{pair.stack_label}" if pair.stack_label else ""
            env_run_dir = run_root / proj / f"{env_name}{label_suffix}"
            env_run_dir.mkdir(parents=True, exist_ok=True)
            self._write_environment_metadata(env_run_dir, pair)

            _log("INFO", f"scanning {proj}/{env_name}")

            state = _PairState(
                project=proj,
                env=env_name,
                env_run_dir=env_run_dir,
                env_dir=env_dir,
                backend_key_override=pair.backend_key,
                workspace=pair.workspace,
            )

            pair_rc = self._scan_one_pair(runner, state, state_account)
            scan_rc = max(scan_rc, pair_rc)

            _log("INFO", f"done {proj}/{env_name}")
        return scan_rc

    def _run_aggregate_and_report(
        self,
        run_root: Path,
        resolved_mapping: Path,
        resolved_baseline: Optional[Path],
        scan_rc: int,
    ) -> int:
        """Run the post-loop aggregate step and print the report path.

        Returns the merged scan_rc. Skipped when ``--no-aggregate`` was
        set or the mode is ``audit``. Mirrors scan.sh lines 731-797.
        """
        if self.no_aggregate or self.mode == "audit":
            return scan_rc

        agg_rc = self._run_aggregate(
            run_dir=run_root,
            mapping_path=resolved_mapping,
            baseline_path=resolved_baseline,
        )
        scan_rc = self._merge_aggregate_rc(scan_rc, agg_rc)

        # Probe both candidate locations (aggregate.py default is
        # <run-dir>/aggregate/, but earlier versions emitted
        # <run-dir>/report.html). Mirrors scan.sh lines 759-774.
        report_html: Optional[Path] = None
        for candidate in (run_root / "aggregate" / "report.html", run_root / "report.html"):
            if candidate.is_file():
                report_html = candidate
                break
        if report_html is not None:
            # Always print the report path on stdout so consumers
            # following the consumption guide can `open` it directly.
            print(f"report: {report_html}")
            self._open_report(report_html, no_open=self.no_open)
        return scan_rc

    @staticmethod
    def _open_report(path: Path, *, no_open: bool) -> None:
        """Best-effort auto-open of ``report.html`` in the default browser.

        Suppressed (returns silently) when ``no_open`` is True OR when
        ``CI=1``. Never raises: any failure mode logs a WARN and
        swallows so the scan/audit exit code is preserved.

        Failure modes handled (matches the plan's webbrowser gotcha list):
          * ``OSError`` — Windows ``webbrowser.open`` can fail on paths
            with spaces; ``path.as_uri()`` percent-encodes so this is
            mostly mitigated, but log a WARN if it still triggers.
          * ``AttributeError`` / ``ValueError`` — registered browser
            binary missing or registry entry malformed.
          * ``webbrowser.open`` returns ``False`` — no browser registered
            on the host (headless container, CI runner, server SKU).
        """
        if no_open or os.environ.get("CI", "").strip() == "1":
            return
        try:
            opened = webbrowser.open(path.resolve().as_uri())
        except (OSError, AttributeError, ValueError) as exc:
            _log(
                "WARN",
                f"could not auto-open report ({type(exc).__name__}): {path}",
            )
            return
        if not opened:
            _log(
                "WARN",
                f"no browser registered; report not auto-opened: {path}",
            )

    # -- pair scan ----------------------------------------------------

    def _scan_one_pair(
        self,
        runner: CheckovRunner,
        state: _PairState,
        state_account: Optional[str],
    ) -> int:
        """Drive one (project, env) pair through the tier-dispatched passes.

        Framework awareness (Todo 10): the heavy Terraform-only passes
        (``paac``, ``plan``, ``state``, ``drift``) and the Azure-specific
        tier-2/3 prep (:meth:`_run_plan_tier`) are gated by
        :func:`scanner.frameworks.is_terraform_family`. The single
        ``is_terraform_family`` guard at the top of each heavy section
        ensures non-Terraform frameworks (CloudFormation, Kubernetes,
        Dockerfile, etc.) never invoke ``terraform init``, ``az storage
        blob download``, or the PaaC pack. The ``source`` and
        ``secrets`` passes are framework-agnostic and run for every
        framework.
        """
        pair_rc = 0

        # Active framework for this pair (set by :meth:`scan` from the
        # CLI ``--framework`` flag). ``None`` means auto-detect; the
        # per-tier guards below fall through to the framework-agnostic
        # passes only, so an unset framework still works for any repo
        # type (consumers that defer framework selection get a safe
        # source-tier-equivalent scan by default).
        framework = getattr(self, "_framework", None)
        is_tf = is_terraform_family(framework) if framework else True

        # Tier 2/3: terraform init + plan (acquires state lock, no mutation
        # beyond the firewall whitelist). Mirrors scan.sh lines 388-436.
        # Terraform-family only — non-Terraform frameworks never invoke
        # terraform or touch Azure storage.
        if self.tier in ("plan", "state") and is_tf:
            tier_rc = self._run_plan_tier(state, state_account)
            if tier_rc < 0:
                return pair_rc

        # Compute pass list based on tier.
        passes = TIER_PASSES[self.tier]

        # Pass 1: paac (custom policy-as-code). Terraform-family only —
        # the pack was authored for Azure Terraform and is meaningless
        # against CloudFormation/Kubernetes/Dockerfile.
        if "paac" in passes and is_tf:
            pair_rc = self._accumulate(pair_rc, self._emit_paac(runner, state))

        # Pass 2: source (built-in terraform framework).
        # Mirrors scan.sh line 503: source tier runs this; plan/state
        # tier ALSO runs this (it is the deepest source layer).
        # Framework-agnostic — every Checkov framework has a ``source``
        # pass (cloudformation, kubernetes, etc.).
        if "source" in passes:
            pair_rc = self._accumulate(pair_rc, self._emit_source(runner, state))

        # Pass 3: plan (terraform_plan framework on plan.json).
        # Terraform-family only — non-Terraform frameworks have no
        # ``terraform plan`` output to scan.
        if "plan" in passes and is_tf:
            plan_rc = self._emit_plan_pass(runner, state)
            if plan_rc is not None:
                pair_rc = self._accumulate(pair_rc, plan_rc)

        # Pass 4: secrets (always when tier allows).
        # Framework-agnostic — ``checkov --framework secrets`` runs on
        # any text file regardless of source framework.
        if "secrets" in passes:
            pair_rc = self._accumulate(pair_rc, self._emit_secrets(runner, state))

        # Pass 5 (state-only): state-as-plan scan + drift diff.
        # Terraform-family only — the state-blob download is Azure+TF
        # specific (az.blob_download) and has no analogue for other
        # frameworks.
        if "state" in passes and is_tf:
            self._scan_state_blob(runner, state, state_account)

        # Pass 6: shred plan artifacts (PCI 10.7 hygiene).
        # Always run — harmless for non-TF pairs (no plan artifacts
        # were created) and ensures the tier=plan/state paths still
        # clean up after themselves.
        self._shred_plan_artifacts(state)

        return pair_rc

    def _run_plan_tier(
        self,
        state: _PairState,
        state_account: Optional[str],
    ) -> int:
        """Tier 2/3 prep: whitelist IP, terraform init + plan + show.

        Returns 0 on success, -1 when an early bail-out was logged (caller
        should skip the pair's checkov passes). Logs the reason for
        skipping.

        Preflight (Todo 10): the per-pair ``terraform`` invocations
        call :meth:`_preflight_stack_root` first; a :class:`PreflightError`
        is caught HERE (not swallowed) and converted into a logged
        bail-out so the per-pair checkov passes still run on the
        stack-root's source files. The exception is re-raised to the
        caller only if the message is malformed — by policy we always
        log + bail.
        """
        if not self.dry_run and not state_account:
            _log(
                "ERROR",
                f"PACIOLI_STATE_STORAGE_ACCOUNT is not set; cannot run tier "
                f"{self.tier!r} for {state.project}/{state.env}",
            )
            return -1

        if not self._alert_network_required(state, state_account):
            _log(
                "ERROR",
                f"network access to {state_account} storage account is "
                f"required; cannot read remote state; "
                f"skipping {state.project}/{state.env}",
            )
            return -1

        try:
            if not self._run_terraform_init(state):
                _log(
                    "ERROR",
                    f"terraform init failed for {state.project}/{state.env}; "
                    "skipping plan layer",
                )
                return -1

            if not self._run_terraform_plan(state):
                _log(
                    "ERROR",
                    f"terraform plan failed for {state.project}/{state.env}; "
                    "skipping plan layer",
                )
                return -1

            self._run_terraform_show(state)
        except PreflightError as exc:
            _log(
                "ERROR",
                f"preflight refused {state.project}/{state.env}: {exc}; "
                "skipping plan/state layer",
            )
            return -1

        return 0

    def _emit_paac(self, runner: CheckovRunner, state: _PairState) -> int:
        """Run the paac (custom policy-as-code) pass; record + return rc.

        Generic SARIF filename (``results_paac.sarif``) — single naming
        contract shared with :mod:`scanner.aggregate` (Todo 9). The
        caller (:meth:`_scan_one_pair`) gates the invocation behind
        :func:`scanner.frameworks.is_terraform_family` so non-Terraform
        frameworks never see the PaaC pass.
        """
        paac_out = state.env_run_dir / "results_paac.sarif"
        rc = runner.run_paac(state.env_dir, paac_out)
        self._record_checkov_rc(rc, state, "paac")
        return rc

    def _emit_source(self, runner: CheckovRunner, state: _PairState) -> int:
        """Run the built-in source pass; record + return rc.

        Generic SARIF filename (``results_source.sarif``) — single
        naming contract shared with :mod:`scanner.aggregate` (Todo 9).
        The aggregator's :data:`scanner.aggregate.OLD_TO_NEW_FILENAME`
        still maps legacy ``results_terraform_source.sarif`` to
        ``"source"`` for backward compatibility with old run-dirs.

        Framework-aware (T11 — fix for F3 acceptance): the active
        Checkov framework is selected via the ``--framework`` CLI flag
        stored on ``self._framework`` (set in :meth:`scan`). When the
        operator passed ``--framework cloudformation``, the source pass
        MUST run with ``--framework cloudformation`` — otherwise the
        default 'terraform' framework was scanning non-Terraform files
        and emitting 0 findings plus a flood of irrelevant terraform
        remediation blocks. When ``self._framework`` is ``None`` the
        helper auto-detects from the env tree via
        :func:`scanner.frameworks.detect_frameworks` and picks the
        first detected framework as a best-effort default.
        """
        src_out = state.env_run_dir / "results_source.sarif"
        fw = self._resolve_source_framework(state.env_dir)
        rc = runner.run_source(state.env_dir, src_out, framework=fw)
        self._record_checkov_rc(rc, state, "source")
        return rc

    def _emit_plan_pass(
        self,
        runner: CheckovRunner,
        state: _PairState,
    ) -> Optional[int]:
        """Run the terraform_plan pass on plan.json if it exists.

        Returns ``None`` when no plan.json is available (caller should
        skip accumulation); otherwise the checkov rc.

        Generic SARIF filename (``results_plan.sarif``) — single naming
        contract shared with :mod:`scanner.aggregate` (Todo 9). The
        caller (:meth:`_scan_one_pair`) gates the invocation behind
        :func:`scanner.frameworks.is_terraform_family` so non-Terraform
        frameworks never invoke this pass.
        """
        if not (state.plan_json and state.plan_json.is_file()):
            return None
        plan_out = state.env_run_dir / "results_plan.sarif"
        rc = runner.run_plan(state.plan_json, plan_out, env_dir=state.env_dir)
        self._record_checkov_rc(rc, state, "plan")
        return rc

    def _resolve_source_framework(self, env_dir: Path) -> str:
        """Pick the framework to pass to :meth:`CheckovRunner.run_source`.

        Resolution order (T11 — F3 fix):

          1. If ``self._framework`` is set (``--framework <x>`` was passed),
             use it verbatim. Checkov rejects unknown values, so no
             name validation here.
          2. Otherwise, auto-detect via
             :func:`scanner.frameworks.detect_frameworks` and pick the
             first detected framework. This is the per-pair equivalent
             of the banner-level "auto-detect" log line emitted in
             :meth:`_emit_scan_banner`.
          3. If both fall through (no detection hits), default to
             ``"terraform"`` so the historical contract — a generic
             source scan over ``.tf`` files — is preserved for legacy
             repos where detect_frameworks finds nothing.

        Note that ``secrets`` is deliberately NOT in the auto-detect
        set (see :data:`scanner.frameworks._DETECT_EXCLUDED`) — secrets
        is handled by its own pass via :meth:`_emit_secrets`, not via
        this helper.

        Returns:
            A non-empty Checkov framework name ready to pass to
            :meth:`CheckovRunner.run_source` as the ``framework=`` arg.
        """
        explicit = getattr(self, "_framework", None)
        if explicit:
            return explicit
        detected = sorted(detect_frameworks(env_dir))
        if detected:
            return detected[0]
        return "terraform"

    def _emit_secrets(self, runner: CheckovRunner, state: _PairState) -> int:
        """Run the secrets pass on the .tf source; record + return rc.

        Generic SARIF filename (``results_secrets.sarif``) — single
        naming contract shared with :mod:`scanner.aggregate` (Todo 9).
        """
        secrets_out = state.env_run_dir / "results_secrets.sarif"
        rc = runner.run_secrets(state.env_dir, secrets_out)
        self._record_checkov_rc(rc, state, "secrets")
        return rc

    @staticmethod
    def _check_storage_account_valid(account: str) -> None:
        """Validate a storage account name before it reaches any subprocess.

        Azure storage account naming rules:
          * 3-24 characters
          * lowercase letters and digits only

        The CLI flag ``--state-account`` is the only producer of this
        value (S8705 — subprocess invocation with tainted CLI value).
        Validating here gives a fail-fast error before any ``az``
        subprocess is invoked, and removes the injection surface.

        Raises:
            ValueError: when ``account`` does not match the Azure
                storage account naming pattern.
        """
        if not re.fullmatch(AZURE_STORAGE_ACCOUNT_PATTERN, account):
            raise ValueError(
                f"invalid Azure storage account name: {account!r} "
                f"(must match {AZURE_STORAGE_ACCOUNT_PATTERN})"
            )

    # -- helpers ------------------------------------------------------

    def _resolve_env_dir(
        self,
        target_repo: Path,
        project: str,
        env_name: str,
        stack_root: Optional[Path] = None,
    ) -> Path:
        """Resolve the env dir for a (project, env) pair.

        Precedence:

          1. ``stack_root`` (set by ``scan_paths:`` entries) → used
             verbatim. This is the path the operator declared in
             ``pci_scope.yaml::scan_paths:`` and is authoritative for
             stacks that don't live under
             ``<target_repo>/env/<project>/<env>/`` (sibling checkouts,
             monorepo roots, etc.).
          2. Flat-repo fallback (``project == 'default' and env ==
             'default'``) → ``target_repo`` itself.
          3. Default bash convention → ``<target_repo>/env/<project>/<env>/``.

        Mirrors scan.sh line 370 for cases (2) and (3); case (1) is the
        new ``scan_paths:`` opt-in.
        """
        if stack_root is not None:
            return Path(stack_root)
        if project == "default" and env_name == "default":
            return target_repo
        return target_repo / "env" / project / env_name

    def _record_checkov_rc(self, rc: int, state: _PairState, pass_name: str) -> None:
        """Log a checkov pass result and rewrite the SARIF helpUri (best-effort)."""
        if rc != 0:
            _log(
                "WARN",
                f"checkov {pass_name} returned rc={rc} for "
                f"{state.project}/{state.env}",
            )

    def _accumulate(self, current: int, new: int) -> int:
        """Mirror bash ``accumulate_checkov_rc``: in gate mode, max-of.

        Report mode keeps the running scan_rc unchanged on non-zero
        checkov rc — findings are reported via the SARIF, not via the
        exit code.
        """
        if self.mode != "gate":
            return current
        return max(current, new)

    # -- terraform env isolation (Todo 9) -----------------------------

    def _isolate_terraform_env(self, state: _PairState) -> dict[str, str]:
        """Create an ephemeral TF_DATA_DIR + TF_CLI_CONFIG_FILE for this run.

        Generates ``<run_dir>/terraform-tmp/`` with mode 0o700 on POSIX,
        writes a minimal ``terraformrc`` inside it, and returns the env
        dict to pass to ``ops.run(..., env=...)``.

        The generated terraformrc content:

          * If ``self.registry_mirror`` is set: a ``provider_installation``
            block with a ``network_mirror`` pointing at the mirror URL.
            This forces Terraform to resolve providers through the
            declared mirror instead of ``registry.terraform.io``.
          * Otherwise: a minimal empty config. The file's mere existence
            (and the fact that ``TF_CLI_CONFIG_FILE`` points here) prevents
            the consumer's ``~/.terraformrc`` from leaking into the scan.

        The returned dict does NOT include ``TF_PLUGIN_CACHE_DIR``; the
        registry's ``_DEFAULT_ENV_BLOCKLIST`` already strips it from the
        ambient env, and we intentionally never re-add it.

        Returns:
            A dict with ``TF_DATA_DIR`` and ``TF_CLI_CONFIG_FILE`` keys,
            ready to pass as ``env=`` to :func:`scanner.ops.run`.
        """
        tf_tmp = state.env_run_dir / "terraform-tmp"
        tf_tmp.mkdir(parents=True, exist_ok=True)
        # Restrict permissions on POSIX (0o700 — rwx------).
        if sys.platform != "win32":
            try:
                os.chmod(tf_tmp, stat.S_IRWXU)
            except OSError as exc:
                _log("WARN", f"  failed to chmod terraform-tmp: {exc}")

        terraformrc = tf_tmp / "terraformrc"
        if self.registry_mirror:
            # Network mirror config: force provider resolution through
            # the declared mirror URL.
            terraformrc_content = (
                'provider_installation {\n'
                '  network_mirror {\n'
                f'    url = "{self.registry_mirror}"\n'
                '  }\n'
                '}\n'
            )
        else:
            # Minimal allow-only-default-registry config. An empty file
            # is sufficient — Terraform reads it, finds no overrides,
            # and proceeds with defaults. The key security property is
            # that the consumer's ~/.terraformrc is NOT consulted.
            terraformrc_content = "# Generated by pacioli — no overrides\n"

        terraformrc.write_text(terraformrc_content, encoding="utf-8")

        return {
            "TF_DATA_DIR": str(tf_tmp),
            "TF_CLI_CONFIG_FILE": str(terraformrc),
        }

    @staticmethod
    def _shred_terraform_tmp(state: _PairState) -> None:
        """Shred the ephemeral ``<run_dir>/terraform-tmp/`` directory.

        Called after each ``_run_terraform_*`` invocation (or sequence
        thereof) to prevent sensitive Terraform state (credentials,
        plugin cache, etc.) from lingering on disk. Best-effort: errors
        are logged at WARN and swallowed.
        """
        tf_tmp = state.env_run_dir / "terraform-tmp"
        if not tf_tmp.exists():
            return
        try:
            # Overwrite files with zeros before removing (best-effort
            # secure delete; ``shred`` may not be available on all
            # platforms, and rmtree is the reliable cross-platform path).
            for item in tf_tmp.rglob("*"):
                if item.is_file():
                    try:
                        size = item.stat().st_size
                        with open(item, "wb") as fh:
                            fh.write(b"\x00" * size)
                    except OSError:
                        pass  # best-effort overwrite
            shutil.rmtree(tf_tmp)
            _log("INFO", "  shredded terraform-tmp directory")
        except OSError as exc:
            _log("WARN", f"  failed to shred terraform-tmp: {exc}")

    # -- terraform + state-blob --------------------------------------

    def _alert_network_required(
        self,
        state: _PairState,
        state_account: Optional[str],
    ) -> bool:
        """Emit a one-line warning that this storage account needs network access.

        Replaces the prior helper which fired an Azure CLI storage-account
        network-rule mutation to whitelist the runner's IP. That mutation
        is now deliberately NOT performed: the orchestrator is read-only
        and the firewall-whitelist step was the only mutation it issued.
        The caller (``_run_plan_tier``) treats the ``False`` return as a
        bail-out so the per-pair plan/state passes are skipped.

        The alert format is the single-line, machine-grep-friendly token
        ``STORAGE_ACCOUNT=<x>; RUNNER_IP=<y>; you need network access
        to this storage account from this IP`` so an operator can
        audit logs for missing-network-access pairs after the fact.

        Args:
            state: Per-pair working state. ``state.env_run_dir`` is
                unused (no artifact is written) but is kept on the
                signature for parity with the prior helper.
            state_account: Storage account name. May be ``None`` when
                the caller failed the early-bail check; in that case
                ``runner_ip`` is reported as ``"unknown"`` so the log
                line is still useful.

        Returns:
            ``False`` — the caller MUST treat this as a per-pair skip
            (fail-closed: tier=plan/state cannot read remote state
            without firewall access, and the scanner will not mutate
            Azure to grant it).
        """
        # Defense-in-depth: still validate the CLI-derived value so a
        # bogus ``--state-account`` lands in the log with a clear shape
        # rather than being echoed raw.
        if state_account is not None:
            try:
                self._check_storage_account_valid(state_account)
            except ValueError as exc:
                _log("ERROR", f"  invalid state_account for alert: {exc}")
                state_account = "<invalid>"

        # Best-effort discovery: if it fails we still want the alert.
        runner_ip = _discover_public_ip() or "unknown"
        storage = state_account if state_account is not None else "<unset>"

        logging.warning(
            "STORAGE_ACCOUNT=%s; RUNNER_IP=%s; you need network access "
            "to this storage account from this IP",
            storage,
            runner_ip,
        )
        return False

    # -- preflight (Todo 10) ------------------------------------------

    @staticmethod
    def _is_symlinked(path: Path) -> bool:
        """Return True if ``path`` is itself a symlink.

        Thin wrapper around :meth:`Path.is_symlink` so the preflight
        test list reads as a flat checklist and the symlink-detection
        policy lives in one place.
        """
        return path.is_symlink()

    @staticmethod
    def _has_parent_traversal(resolved_path: Path) -> bool:
        """Return True if ``resolved_path`` still contains ``..`` segments.

        Defends against a path that survives :meth:`Path.resolve` but
        was assembled from segments like ``a/../../etc`` that resolve
        to an unexpected location. ``resolve()`` collapses ``..`` on
        POSIX by walking up; on Windows it does the same. We re-check
        the segments anyway so the policy is portable and the
        preflight never depends on OS-specific resolve behavior.
        """
        return ".." in resolved_path.parts

    @staticmethod
    def _find_disallowed_subdir(stack_root: Path) -> Optional[str]:
        """Return the first disallowed module-library subdir, or ``None``.

        Scans the immediate children of ``stack_root`` for entries
        whose name matches ``modules``, ``modules-<x>``, or
        ``.terraform``. These are Terraform's well-known module-library
        directories and are NEVER valid scan targets: scanning them
        would re-enter the consumer's ``modules/`` library as if it were
        a stack, generating massive false-positive SARIFs. The check
        is a one-level listing (``iterdir``) so a nested
        ``modules/foo/modules`` does NOT trigger it; only direct
        children of ``stack_root`` count, matching the scan_paths:
        exclusion semantics in :mod:`scanner.discovery`.

        Returns the offending directory name (basename) so the error
        message can name it specifically.
        """
        if not stack_root.is_dir():
            return None
        for child in stack_root.iterdir():
            if not child.is_dir():
                continue
            name = child.name
            if name == "modules":
                return name
            if name.startswith("modules-"):
                return name
            if name == ".terraform":
                return name
        return None

    def _preflight_stack_root(self, state: _PairState) -> None:
        """Validate ``state.env_dir`` before any ``terraform`` subprocess fires.

        Todo 10: the last line of defense between the orchestrator and
        a real ``terraform init`` / ``terraform plan`` /
        ``terraform show`` invocation. Each check exists for a reason:

        * **Symlink check**: a symlinked stack root could escape the
          declared target repo (e.g. ``env/payments/prod`` → a sibling
          checkout, an attacker's writable directory, or ``/tmp``).
          ``Path.is_symlink`` returns True for the link itself, not
          its target; we reject before resolve() so a chained symlink
          doesn't accidentally pass.
        * **Path-traversal check**: any remaining ``..`` segment in
          the resolved path means the resolved path crossed outside
          the declared root. We refuse rather than follow.
        * **Module-library subdir check**: scanning ``modules/``,
          ``modules-<x>/``, or ``.terraform/`` would emit thousands of
          duplicate findings (one per consumer module that re-uses the
          library). The ``--include-modules`` flag (Todo 8) is the
          documented opt-out; preflight honors it.
        * **Lockfile presence check**: ``.terraform.lock.hcl`` is the
          canonical Terraform dependency-lock file. When missing, the
          consumer's provider set is ambiguous, and ``terraform
          init`` will silently download whatever is on the registry —
          which is exactly the "pull from registry.terraform.io" path
          Todo 9's ``network_mirror`` exists to redirect. The
          ``--ignore-lockfile`` flag (Todo 8) is the documented opt-out;
          preflight honors it.

        ``include_modules`` and ``ignore_lockfile`` are read off
        ``self`` (set by :meth:`scan`) so the helper signature stays
        single-arg. Passes the per-pair ``_PairState`` so the error
        message names the offending path.

        Raises:
            PreflightError: when any of the four checks fails. The
                caller (:meth:`_scan_one_pair`) catches this and fails
                the pair.
        """
        include_modules = bool(getattr(self, "_include_modules", False))
        ignore_lockfile = bool(getattr(self, "_ignore_lockfile", False))

        env_dir = Path(state.env_dir)

        # 1. Symlink check. Reject the link itself (not the target) so a
        #    consumer cannot smuggle a stack root through a symlink that
        #    resolves to a directory outside the declared scope.
        if self._is_symlinked(env_dir):
            raise PreflightError(
                f"preflight: stack root is a symlink: {env_dir} "
                f"(refusing to follow symlinks; move the stack to its "
                f"real location or update scan_paths:)"
            )

        # 2. Path-traversal check. ``..`` segments in the resolved
        #    path mean the resolver walked up outside the intended
        #    root. Reject — never follow.
        try:
            resolved = env_dir.resolve()
        except OSError as exc:
            raise PreflightError(
                f"preflight: cannot resolve stack root {env_dir}: {exc}"
            ) from exc
        if self._has_parent_traversal(resolved):
            raise PreflightError(
                f"preflight: stack root resolves to a path containing "
                f"'..' segments: {resolved} (refusing parent traversal; "
                f"fix scan_paths: or env dir layout)"
            )

        # 3. Module-library subdir check. Direct children only; nested
        #    module libraries are intentionally not flagged (matching
        #    scanner.discovery's exclusion semantics).
        if not include_modules:
            disallowed = self._find_disallowed_subdir(env_dir)
            if disallowed is not None:
                raise PreflightError(
                    f"preflight: stack root contains excluded module "
                    f"library '{disallowed}/' (refusing to scan module "
                    f"libraries as stacks; pass --include-modules to "
                    f"override)"
                )

        # 4. Lockfile presence check. Skip when --ignore-lockfile.
        if not ignore_lockfile:
            lockfile = env_dir / ".terraform.lock.hcl"
            if not lockfile.is_file():
                raise PreflightError(
                    f"preflight: missing {env_dir / '.terraform.lock.hcl'} "
                    f"(refusing to run 'terraform init' without a "
                    f"declared provider lock; pass --ignore-lockfile to "
                    f"override)"
                )

    def _run_terraform_init(self, state: _PairState) -> bool:
        """Run ``terraform init -input=false`` in the env dir.

        Mirrors scan.sh line 418. ``-input=false`` disables interactive
        prompts. Providers are downloaded from the registry or
        filesystem_mirror; no Azure mutations. Routed through the
        :mod:`scanner.ops` registry; argv schema is the 5 tokens
        ``("-chdir", <env_dir>, "init", "-input=false", "-no-color")``.

        TF env isolation (Todo 9): before the run, an ephemeral
        ``<run_dir>/terraform-tmp/`` directory is created with a
        generated ``terraformrc``. ``TF_DATA_DIR`` and
        ``TF_CLI_CONFIG_FILE`` are set to point into it, and
        ``TF_PLUGIN_CACHE_DIR`` is never set (the registry blocklist
        strips it from ambient env). After the run, the directory is
        shredded.

        Preflight (Todo 10): :meth:`_preflight_stack_root` is invoked
        first thing so a malformed stack root never reaches the real
        ``terraform`` binary. The check is cheap (4 stat-style
        inspections) and re-runs at the top of ``_run_terraform_plan``
        and ``_run_terraform_show`` for defense-in-depth.
        """
        self._preflight_stack_root(state)
        _log("INFO", "  terraform init")
        if self.dry_run:
            print("[dry-run] terraform init")
            return True

        tf_env = self._isolate_terraform_env(state)
        try:
            result = scanner_ops.run(
                "terraform.init_local",
                "-chdir",
                str(state.env_dir),
                "init",
                "-input=false",
                "-backend=false",
                "-no-color",
                tier=self.tier,
                timeout=300,
                env=tf_env,
            )
        except scanner_ops.TrustedBinaryMissing as exc:
            _log("ERROR", f"  terraform binary not found on PATH: {exc}")
            return False
        except scanner_ops.TierViolation as exc:
            _log("ERROR", f"  terraform.init_local tier refused: {exc}")
            return False
        except scanner_ops.ArgvSchemaViolation as exc:
            _log("ERROR", f"  terraform.init_local argv rejected: {exc}")
            return False
        finally:
            # Shred the ephemeral TF env on ALL exit paths. Idempotent.
            self._shred_terraform_tmp(state)

        if result.returncode != 0:
            _log(
                "ERROR",
                f"  terraform init failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout or '').strip()[:500]}",
            )
            return False
        return True

    def _run_terraform_plan(self, state: _PairState) -> bool:
        """Run ``terraform plan -out=tfplan.binary`` in the env dir.

        Reads remote state but does NOT mutate it (no lock acquisition,
        no refresh). The plan binary is shredded on exit by the trap
        (or by :meth:`_shred_plan_artifacts` per-pair). Mirrors scan.sh
        lines 425-431. Routed through the :mod:`scanner.ops` registry;
        argv schema is the 8 tokens ``("-chdir", <env_dir>, "plan",
        "-no-color", "-out=<plan_bin>", "-lock=false",
        "-refresh=false")``.

        TF env isolation (Todo 9): same as :meth:`_run_terraform_init`.

        Preflight (Todo 10): same as :meth:`_run_terraform_init`.
        """
        self._preflight_stack_root(state)
        plan_bin = state.env_run_dir / "tfplan.binary"
        state.plan_bin = plan_bin

        # Pre-create the plan binary with restrictive POSIX mode
        # (0o600) so terraform inherits the permissions when it
        # writes the file. This is the creation-side companion to
        # safe_unlink: the artifact is owner-only from the moment it
        # exists, narrowing the window where it could be read by a
        # second local user. On Windows the helper logs a one-line
        # note that POSIX-mode narrowing is skipped; we accept that
        # gap rather than introducing a new dependency (no portable
        # stdlib ACL helper).
        try:
            create_secure_file(plan_bin, state.env_run_dir)
        except ValueError as exc:
            _log("ERROR", f"  refused to prepare plan binary: {exc}")
            return False

        _log("INFO", f"  terraform plan -out={plan_bin.name}")
        if self.dry_run:
            print(f"[dry-run] terraform plan -out={plan_bin}")
            return True

        tf_env = self._isolate_terraform_env(state)
        try:
            result = scanner_ops.run(
                "terraform.plan_local",
                "-chdir",
                str(state.env_dir),
                "plan",
                "-no-color",
                f"-out={plan_bin}",
                "-lock=false",
                "-refresh=false",
                tier=self.tier,
                timeout=600,
                env=tf_env,
            )
        except scanner_ops.TrustedBinaryMissing as exc:
            _log("ERROR", f"  terraform binary not found on PATH: {exc}")
            return False
        except scanner_ops.TierViolation as exc:
            _log("ERROR", f"  terraform.plan_local tier refused: {exc}")
            return False
        except scanner_ops.ArgvSchemaViolation as exc:
            _log("ERROR", f"  terraform.plan_local argv rejected: {exc}")
            return False
        finally:
            self._shred_terraform_tmp(state)

        if result.returncode != 0:
            _log(
                "ERROR",
                f"  terraform plan failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout or '').strip()[:500]}",
            )
            return False
        return True

    def _run_terraform_show(self, state: _PairState) -> None:
        """Run ``terraform show -json`` and write plan.json.

        Mirrors scan.sh line 435. Idempotent: overwrites plan_json if
        it already exists. Routed through the :mod:`scanner.ops`
        registry; the registry captures stdout (it cannot redirect),
        so the caller's flow is: invoke the op, then write
        ``result.stdout`` to ``plan_json``. argv schema is the 5 tokens
        ``("-chdir", <env_dir>, "show", "-json", <plan_bin>)``.

        TF env isolation (Todo 9): same as :meth:`_run_terraform_init`.

        Preflight (Todo 10): same as :meth:`_run_terraform_init`.
        """
        if state.plan_bin is None:
            return
        self._preflight_stack_root(state)
        plan_json = state.env_run_dir / "plan.json"
        state.plan_json = plan_json

        # Pre-create plan.json with restrictive POSIX mode so the
        # registry-captured stdout write (line below) lands on a
        # file that is already owner-only. See the matching call in
        # ``_run_terraform_plan`` for the rationale.
        try:
            create_secure_file(plan_json, state.env_run_dir)
        except ValueError as exc:
            _log("ERROR", f"  refused to prepare plan.json: {exc}")
            return

        _log("INFO", "  terraform show -json")
        if self.dry_run:
            print(f"[dry-run] terraform show -json {state.plan_bin} > {plan_json}")
            return

        tf_env = self._isolate_terraform_env(state)
        try:
            result = scanner_ops.run(
                "terraform.show_json",
                "-chdir",
                str(state.env_dir),
                "show",
                "-json",
                str(state.plan_bin),
                tier=self.tier,
                timeout=120,
                env=tf_env,
            )
        except scanner_ops.TrustedBinaryMissing as exc:
            _log("ERROR", f"  terraform binary not found on PATH: {exc}")
            return
        except scanner_ops.TierViolation as exc:
            _log("ERROR", f"  terraform.show_json tier refused: {exc}")
            return
        except scanner_ops.ArgvSchemaViolation as exc:
            _log("ERROR", f"  terraform.show_json argv rejected: {exc}")
            return
        finally:
            self._shred_terraform_tmp(state)

        if result.returncode != 0:
            _log(
                "ERROR",
                f"  terraform show failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout or '').strip()[:500]}",
            )
            return

        # The registry captured stdout; write it to plan_json. This
        # preserves the prior ``stdout=fh`` semantics (overwrite on
        # each run; idempotent).
        try:
            plan_json.write_text(result.stdout or "", encoding="utf-8")
        except OSError as exc:
            _log("ERROR", f"  failed to write plan.json: {exc}")

    # -- state-blob scan (tier=state) --------------------------------

    def _scan_state_blob(
        self,
        runner: CheckovRunner,
        state: _PairState,
        state_account: Optional[str],
    ) -> None:
        """Download the state blob, scan it as plan, emit drift_report.

        Mirrors scan.sh lines 605-684. Reads the backend key from
        ``<env_dir>/terraform.aztfexport.tf``; falls back to a
        synthesized key (``CR_<Env>_<project>.tfstate``) when missing.
        """
        assert state_account is not None
        # Defense-in-depth: validate the CLI-derived value before any
        # subprocess invocation (S8705 — taint from CLI flag).
        self._check_storage_account_valid(state_account)
        _log("INFO", "  state-scan: download state blob from Azure")

        backend_key = self._resolve_backend_key(
            stack_root=state.env_dir,
            cli_override=state.backend_key_override,
            aztfexport_key=self._resolve_backend_key_from_aztfexport(state),
            env_default=f"{state.env}.tfstate",
        )
        paths = self._resolve_state_blob_paths(state)

        if self.dry_run:
            self._print_state_blob_dry_run(state_account, backend_key, paths)
            return

        # Refuse guard (defense in depth).
        self.safety.refuse_if_mutating(
            f"az storage blob download --account-name {state_account} "
            f"--container-name iac --name {backend_key}"
        )

        if not self._download_state_blob(state_account, backend_key, paths["state_local"]):
            return
        if not self._convert_state_to_plan(paths["state_local"], paths["state_plan_json"]):
            return
        self._scan_state_as_plan(runner, state, paths["state_plan_json"])
        self._emit_drift_report(state, paths["state_plan_json"], paths["drift_report"])

        # Shred state plan after drift extraction.
        self._shred_state_plan(paths["state_plan_json"])

    @staticmethod
    def _resolve_state_blob_paths(state: _PairState) -> dict[str, Path]:
        """Return the local paths used by the state-blob scan pipeline.

        Also annotates ``state.state_local`` / ``state.state_plan_json``
        so downstream helpers (e.g. shred, drift) find them.

        Pre-creates ``state.tfstate`` and ``state_as_plan.json`` with
        restrictive POSIX permissions (0o600) so the subsequent
        ``az storage blob download`` and ``tfstate_to_plan.py``
        invocations inherit owner-only mode. The state blob may
        contain sensitive Azure resource attributes; the same
        best-effort data minimization that applies to plan
        artifacts applies here.
        """
        state_local = state.env_run_dir / "state.tfstate"
        state_plan_json = state.env_run_dir / "state_as_plan.json"
        drift_report = state.env_run_dir / "drift_report.json"
        state.state_local = state_local
        state.state_plan_json = state_plan_json
        # Pre-create with restrictive mode. Containment is guaranteed
        # because the paths are constructed from ``state.env_run_dir``
        # which is itself resolved+contained by ``_run_scan_loop``.
        for sensitive in (state_local, state_plan_json):
            try:
                create_secure_file(sensitive, state.env_run_dir)
            except ValueError as exc:
                # Programming error — paths were just constructed
                # from a resolved run_dir, so this should never fire.
                # Surface it so the pair is failed rather than
                # silently continuing with world-readable state.
                _log("ERROR", f"  refused to prepare state artifact: {exc}")
        return {
            "state_local": state_local,
            "state_plan_json": state_plan_json,
            "drift_report": drift_report,
        }

    @staticmethod
    def _print_state_blob_dry_run(
        state_account: str,
        backend_key: str,
        paths: dict[str, Path],
    ) -> None:
        """Echo the intended ``az`` / tfstate_to_plan invocations."""
        print(
            f"[dry-run] az storage blob download "
            f"--account-name {state_account} --container-name iac "
            f"--name {backend_key} --file {paths['state_local']}"
        )
        print(
            f"[dry-run] python scanner/tfstate_to_plan.py "
            f"{paths['state_local']} {paths['state_plan_json']}"
        )

    def _download_state_blob(
        self,
        state_account: str,
        backend_key: str,
        state_local: Path,
    ) -> bool:
        """Download the state blob to ``state_local``; True on success.

        Logs and returns False on registry refusal, timeout, missing
        binary, non-zero rc, or empty result. The downloaded blob is
        shredded ASAP in the caller (PCI 10.7 hygiene). Routed through
        the :mod:`scanner.ops` registry; argv schema is the 15 tokens
        ``("storage", "blob", "download", "--account-name", <account>,
        "--container-name", "iac", "--name", <key>, "--file",
        <state_local>, "--auth-mode", "login", "--output", "none")``.
        """
        # Defense-in-depth: validate the CLI-derived value here too so
        # the data-flow analyzer sees the check immediately before the
        # subprocess invocation (S8705 — taint from CLI flag).
        self._check_storage_account_valid(state_account)
        try:
            dl = scanner_ops.run(
                "az.blob_download",
                "storage",
                "blob",
                "download",
                "--account-name",
                state_account,
                "--container-name",
                "iac",
                "--name",
                backend_key,
                "--file",
                str(state_local),
                "--auth-mode",
                "login",
                "--output",
                "none",
                tier=self.tier,
                timeout=60,
            )
        except scanner_ops.TrustedBinaryMissing as exc:
            _log("ERROR", f"  az binary not found on PATH: {exc}")
            return False
        except scanner_ops.TierViolation as exc:
            _log("ERROR", f"  az.blob_download tier refused: {exc}")
            return False
        except scanner_ops.ArgvSchemaViolation as exc:
            _log("ERROR", f"  az.blob_download argv rejected: {exc}")
            return False

        if dl.returncode != 0:
            _log(
                "ERROR",
                f"  az storage blob download failed (rc={dl.returncode}): "
                f"{(dl.stderr or '').strip()[:500]}",
            )
            return False

        if not state_local.is_file() or state_local.stat().st_size == 0:
            _log("WARN", "  state blob download produced an empty file")
            return False

        _log(
            "INFO",
            f"  state blob downloaded: {state_local.stat().st_size} bytes",
        )
        return True

    def _convert_state_to_plan(
        self,
        state_local: Path,
        state_plan_json: Path,
    ) -> bool:
        """Convert ``state_local`` -> ``state_plan_json`` via tfstate_to_plan.

        Shreds ``state_local`` on a successful conversion (PCI 10.7).
        Returns False if conversion failed or output is missing.
        Routed through the :mod:`scanner.ops` registry; argv schema is
        the 3 ``ANY`` slots ``(<tfstate_to_plan.py>, <state_local>,
        <state_plan_json>)`` (executable resolves to ``sys.executable``
        inside the registry).
        """
        try:
            conv = scanner_ops.run(
                "python.tfstate_to_plan",
                str(Path(__file__).resolve().parent / "tfstate_to_plan.py"),
                str(state_local),
                str(state_plan_json),
                tier=self.tier,
                timeout=120,
            )
        except scanner_ops.TrustedBinaryMissing as exc:
            _log("ERROR", f"  python interpreter not found on PATH: {exc}")
            return False
        except scanner_ops.TierViolation as exc:
            _log("ERROR", f"  python.tfstate_to_plan tier refused: {exc}")
            return False
        except scanner_ops.ArgvSchemaViolation as exc:
            _log("ERROR", f"  python.tfstate_to_plan argv rejected: {exc}")
            return False

        # Shred the encrypted state blob ASAP (PCI 10.7 hygiene).
        if state_local.is_file():
            try:
                # safe_unlink enforces run_dir containment and
                # prefers shred with an overwrite-with-zeros fallback.
                # Failure is logged inside the helper; we do not
                # surface a duplicate WARN here.
                # ``state_local`` is built as
                # ``state.env_run_dir / "state.tfstate"`` in
                # _resolve_state_blob_paths, so its parent IS the
                # env run dir and the containment guarantee holds.
                safe_unlink(state_local, state_local.parent)
            except ValueError as exc:
                # Containment failure is a programming error; surface
                # it loudly so the caller can fail the pair.
                _log("ERROR", f"  refused to remove state blob: {exc}")

        if conv.returncode != 0 or not state_plan_json.is_file():
            _log("ERROR", "  tfstate_to_plan did not produce a plan JSON")
            return False
        return True

    def _scan_state_as_plan(
        self,
        runner: CheckovRunner,
        state: _PairState,
        state_plan_json: Path,
    ) -> None:
        """Run checkov's ``terraform_plan`` framework on ``state_plan_json``.

        State-pass rc is intentionally NOT propagated into pair_rc here:
        the SARIF carries the findings and the aggregate step drives the
        gate. We log a WARN on non-zero so operators see the per-pair
        signal in stderr.
        """
        state_sarif = state.env_run_dir / "results_state.sarif"
        rc = runner.run_plan(state_plan_json, state_sarif, env_dir=state.env_dir)
        if rc != 0:
            _log(
                "WARN",
                f"checkov state returned rc={rc} for {state.project}/{state.env}",
            )

    def _emit_drift_report(
        self,
        state: _PairState,
        state_plan_json: Path,
        drift_report: Path,
    ) -> None:
        """Run ``drift_report.py`` to diff ``state.plan_json`` vs state-as-plan.

        Best-effort: errors are logged at WARN, never raised. Skipped
        when ``state.plan_json`` is unavailable. Routed through the
        :mod:`scanner.ops` registry; argv schema is the 4 ``ANY`` slots
        ``(<drift_report.py>, <plan_json>, <state_plan_json>,
        <drift_report>)``.
        """
        if not (state.plan_json and state.plan_json.is_file() and state_plan_json.is_file()):
            return
        try:
            scanner_ops.run(
                "python.drift_report",
                str(Path(__file__).resolve().parent / "drift_report.py"),
                str(state.plan_json),
                str(state_plan_json),
                str(drift_report),
                tier=self.tier,
                timeout=120,
            )
        except scanner_ops.TrustedBinaryMissing as exc:
            _log("WARN", f"  drift_report.py unavailable: {exc}")
        except scanner_ops.TierViolation as exc:
            _log("WARN", f"  python.drift_report tier refused: {exc}")
        except scanner_ops.ArgvSchemaViolation as exc:
            _log("WARN", f"  python.drift_report argv rejected: {exc}")

    @staticmethod
    def _shred_state_plan(state_plan_json: Path) -> None:
        """Shred the state-as-plan JSON (PCI 10.7 hygiene, best-effort).

        Routes through :func:`scanner.trap.safe_unlink` so the
        containment check, shred-vs-overwrite policy, and JSON-safe
        log line are uniform across every sensitive-artifact cleanup
        site. The :class:`ValueError` from the containment check is
        a programming error — surface it loudly so the caller can
        fail the pair rather than silently skipping cleanup.
        """
        if not state_plan_json.is_file():
            return
        try:
            safe_unlink(state_plan_json, state_plan_json.parent)
        except ValueError as exc:  # noqa: BLE001 — surface containment failures
            _log("ERROR", f"  refused to shred state plan: {exc}")

    @staticmethod
    def _resolve_backend_key_from_aztfexport(state: _PairState) -> Optional[str]:
        """Read the storage backend key from terraform.aztfexport.tf.

        Mirrors scan.sh lines 610-613. Returns ``None`` when the file is
        missing or the key field is absent.

        This is the third tier of the documented backend-key precedence:

          1. CLI override (``--backend-key`` / per-entry ``scan_paths:
             backend_key:``) — handled by ``_resolve_backend_key`` via
             its ``cli_override`` argument.
          2. ``<stack_root>/terraform.aztfexport.tf`` — this method.
          3. ``f"{env}.tfstate"`` basename default — handled by
             ``_resolve_backend_key`` via its ``env_default`` argument.
          4. Fail-closed: no synthesized key. The caller surfaces the
             empty result so the operator can fix the missing input.

        Splitting the reader from the precedence resolver keeps the
        orchestrator's hot path testable without filesystem state.
        """
        aztf_file = state.env_dir / "terraform.aztfexport.tf"
        if not aztf_file.is_file():
            return None
        try:
            text = aztf_file.read_text(encoding="utf-8")
        except OSError:
            return None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("key"):
                continue
            # Match `key = "<value>"` (allow whitespace, single or double quotes).
            if "=" not in stripped:
                continue
            _, rhs = stripped.split("=", 1)
            value = rhs.strip().strip('"').strip("'")
            if value:
                return value
        return None

    @staticmethod
    def _resolve_backend_key(
        stack_root: Path,
        cli_override: Optional[str],
        aztfexport_key: Optional[str],
        env_default: str,
    ) -> str:
        """Return the storage backend key for a stack using documented precedence.

        Documented precedence (highest → lowest):

          1. ``cli_override`` — explicit per-pair value from
             ``scan_paths:`` ``backend_key:`` (or a future CLI flag).
             Wins unconditionally when set.
          2. ``aztfexport_key`` — value parsed from
             ``<stack_root>/terraform.aztfexport.tf`` (the legacy
             bash scanner's source).
          3. ``env_default`` — the basename-style default
             ``f"{env}.tfstate"``. Used when neither (1) nor (2) is
             available.
          4. Fail-closed: when ``env_default`` is empty (caller chose
             to disable it), return the empty string. The caller is
             responsible for surfacing the failure — this helper does
             NOT synthesize a key.

        Replaces the prior ``_resolve_or_synthesize_backend_key``
        helper, which silently invented a ``CR_<Env>_<project>.tfstate``
        key when the aztfexport file was missing. Silent synthesis
        hides configuration bugs; the fail-closed contract surfaces
        them.
        """
        if cli_override:
            return cli_override
        if aztfexport_key:
            return aztfexport_key
        return env_default

    def _shred_plan_artifacts(self, state: _PairState) -> None:
        """Shred tfplan.binary and plan.json for this pair (PCI 10.7 hygiene).

        Mirrors scan.sh lines 686-694. Idempotent: missing files are
        silently skipped. Every cleanup goes through
        :func:`scanner.trap.safe_unlink` so the run_dir containment
        check, shred-vs-overwrite policy, and JSON-safe log line are
        uniform across the orchestrator.
        """
        if state.plan_bin is None and state.plan_json is None:
            return

        _log("INFO", "  shred plan artifacts")
        if self.dry_run:
            return

        for path in (state.plan_bin, state.plan_json):
            if path is None:
                continue
            if not path.exists():
                continue
            try:
                # safe_unlink enforces containment, prefers shred
                # (via ops.run) with an overwrite-with-zeros
                # fallback, and emits a JSON-safe log line. The
                # helper handles all error paths internally; a
                # ValueError here is a programming error (path not
                # under env_run_dir) and is surfaced loudly.
                safe_unlink(path, state.env_run_dir)
            except ValueError as exc:  # noqa: BLE001 — surface containment failures
                _log("ERROR", f"  refused to shred {path.name}: {exc}")

    # -- mapping resolution ------------------------------------------

    def _resolve_mapping_path(
        self,
        cli_mapping: Optional[Path],
    ) -> Path:
        """Resolve the mapping pack path via CLI > env > install-root fallback.

        Uses :func:`scanner.paths.resolve_mapping` which already implements
        the precedence chain with an install-root fallback
        (``<repo>/mappings/pci_dss_4.0.1.yaml``). The first-run picker from
        :mod:`scanner.config` is intentionally NOT used here: this path
        is reached from CI/automation where a TTY prompt is unwanted.
        """
        ns = argparse.Namespace(mapping=str(cli_mapping) if cli_mapping is not None else None)
        pack = resolve_mapping_path(ns)
        return pack.path

    # -- aggregate ----------------------------------------------------

    def _run_aggregate(
        self,
        *,
        run_dir: Path,
        mapping_path: Optional[Path],
        baseline_path: Optional[Path],
    ) -> int:
        """Invoke :func:`scanner.aggregate.main` with the right argv.

        Mirrors scan.sh lines 731-797. The aggregate module's CLI does
        its own scope/mapping/baseline resolution; we pass absolute
        paths so it locates them without depending on CWD.
        """
        argv = self._resolve_aggregate_argv(run_dir, mapping_path, baseline_path)

        if self.dry_run:
            _log("INFO", f"aggregation (dry-run): {argv}")
            return 0

        _log(
            "INFO",
            f"aggregating {run_dir} (coverage matrix + HTML report)",
        )

        agg_rc = self._invoke_aggregate(argv)
        if agg_rc == 0:
            return 0
        self._log_aggregate_rc(agg_rc, run_dir)
        return agg_rc

    def _resolve_aggregate_argv(
        self,
        run_dir: Path,
        mapping_path: Optional[Path],
        baseline_path: Optional[Path],
    ) -> list[str]:
        """Build the argv list passed to ``scanner.aggregate.main``.

        Mirrors scan.sh's aggregate invocation flags. Absolute paths
        are used so the aggregate step does not depend on CWD.

        ``--source-framework`` (F3 fix — second stage): when the
        orchestrator's active ``self._framework`` is set AND is not in
        the Terraform family (e.g. ``"cloudformation"``,
        ``"kubernetes"``, ``"dockerfile"``, …), we append
        ``--source-framework <self._framework>`` so the aggregator
        tags the source-pass findings with the correct framework label
        instead of the historical ``"terraform"`` default. The
        mapping from framework name to the loader's ``source`` key is
        direct: the framework name IS the source key (e.g.
        ``--framework cloudformation`` → ``--source-framework
        cloudformation``), because Checkov emits the framework name
        verbatim on its findings and ``parse_sarif`` carries it through
        to ``Finding.framework``. When ``self._framework`` is in the
        Terraform family (``"terraform"`` or ``"terraform_plan"``),
        or is unset (auto-detect deferred to per-pair loop), we omit
        the flag — the aggregate default ``--source-framework
        terraform`` matches the historical contract for those scans.
        """
        argv: list[str] = ["aggregate.py", "--run-dir", str(run_dir)]
        if mapping_path is not None:
            argv += ["--mapping", str(mapping_path)]
        if baseline_path is not None:
            argv += ["--baseline", str(baseline_path)]
        # Emit --source-framework ONLY for non-Terraform-family scans.
        # The framework name from --framework IS the value to forward
        # (Checkov emits the framework name verbatim on findings).
        fw = getattr(self, "_framework", None)
        if fw is not None and not is_terraform_family(fw):
            argv += ["--source-framework", fw]
        return argv

    @staticmethod
    def _invoke_aggregate(argv: list[str]) -> int:
        """Call ``scanner.aggregate.main`` with ``sys.argv`` swapped in/out.

        Lazy import keeps ``aggregate.py`` (PyYAML + SARIF parsing +
        HTML rendering) out of the import path for callers that skip
        the aggregate step (CI gate mode).
        """
        from scanner import aggregate as _aggregate

        # aggregate.main() reads sys.argv directly via argparse. We
        # stash the original argv, swap in our constructed one, and
        # restore it on every exit path so this orchestrator's own
        # callers see no change to sys.argv.
        saved_argv = sys.argv
        try:
            sys.argv = argv
            return _aggregate.main()
        finally:
            sys.argv = saved_argv

    @staticmethod
    def _log_aggregate_rc(agg_rc: int, run_dir: Path) -> None:
        """Log the aggregate step's non-zero return code with context.

        Mirrors scan.sh lines 748-794: rc=7 is the "findings-present"
        signal and is informational in report mode; anything else is a
        real failure and logged as ERROR.
        """
        if agg_rc == AGGREGATE_FINDINGS_RC:
            _log(
                "INFO",
                f"aggregate.py finished with rc=7 "
                "(HIGH/CRITICAL findings present); "
                f"raw SARIFs are still in {run_dir}",
            )
            return
        _log(
            "ERROR",
            f"aggregate.py failed (rc={agg_rc}); "
            f"raw SARIFs are still in {run_dir}",
        )

    def _merge_aggregate_rc(self, scan_rc: int, agg_rc: int) -> int:
        """Decide how aggregate's rc merges into SCAN_RC.

        Mirrors scan.sh lines 786-795.
        """
        if agg_rc == 0:
            return scan_rc
        # report mode suppresses rc=7 (findings-present is the report's job).
        if self.mode == "report" and agg_rc == AGGREGATE_FINDINGS_RC:
            return scan_rc
        return max(scan_rc, agg_rc)


# ---------------------------------------------------------------------------
# Public IP discovery (best-effort)
# ---------------------------------------------------------------------------


def _discover_public_ip() -> Optional[str]:
    """Return the current public IP, or ``None`` on failure.

    Tries the Azure instance metadata service first (only works from
    inside an Azure VM), then falls back to ipify.org. Bounded timeouts
    to avoid stalling the run.
    """
    import urllib.request

    candidates = (
        # Azure IMDS — only works from an Azure VM, but produces the
        # canonical IP the firewall will see.
        # The Azure Instance Metadata Service (IMDS) endpoint is
        # intentionally served over HTTP (not HTTPS) and the request
        # must include the ``Metadata: true`` header to be accepted.
        # Azure IMDS specifically uses HTTP; this is by design.
        (f"http://{AZURE_IMDS_ENDPOINT}{AZURE_IMDS_IPV4_PATH}", "Azure-IMDS"),  # noqa: S5332 — Azure IMDS requires HTTP
        ("https://api.ipify.org", "ipify"),
    )
    for url, label in candidates:
        try:
            req = urllib.request.Request(url, headers={"Metadata": "true"} if AZURE_IMDS_ENDPOINT in url else {})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode("utf-8").strip()
            if ip:
                return ip
        except Exception:  # noqa: BLE001 — discovery is best-effort
            continue
    return None


# ---------------------------------------------------------------------------
# CLI entry points
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct the argument parser shared by main() and legacy_main()."""
    parser = argparse.ArgumentParser(
        prog="pacioli-scan",
        description=(
            "Read-only PCI scan orchestrator. Port of scan.sh to Python. "
            "Defaults to a source-only scan in --mode report; use --tier plan "
            "or state to enable terraform init+plan and (optionally) state-blob "
            "download + drift diff."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=VALID_MODES,
        default="report",
        help="gate|report|audit. CI=1 auto-promotes report -> gate.",
    )
    parser.add_argument(
        "--tier",
        choices=VALID_TIERS,
        default="source",
        help="source (default), plan, or state.",
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
        "--no-aggregate",
        action="store_true",
        help="Skip the end-of-run aggregate.py call (gate mode never aggregates).",
    )
    parser.add_argument(
        "--target-repo",
        default=None,
        help="Target Terraform repo path (default: $PACIOLI_TARGET_REPO or $PCI_REPO_ROOT or cwd).",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Root directory for per-pair output (default: ~/.pacioli/runs/current).",
    )
    parser.add_argument(
        "--mapping",
        default=None,
        help="Mapping pack YAML (default: $PACIOLI_MAPPING or ~/.pacioli/config).",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Baseline suppressions YAML (default: <target_repo>/pci_baseline.yaml).",
    )
    parser.add_argument(
        "--state-account",
        default=None,
        help="Storage account name (required for tier=plan|state).",
    )
    # Multi-stack flags (Todo 8). Each ``--scan-path-entry`` token is a
    # JSON object produced by ``scanner.cli._resolve_scan_path_entries``
    # (after glob expansion + per-entry validation). ``action="append"``
    # preserves argv order so the orchestrator sees entries in the
    # priority the operator typed.
    parser.add_argument(
        "--scan-path-entry",
        action="append",
        default=None,
        metavar="JSON",
        help=(
            "Repeatable. One resolved scan-path entry as a JSON object "
            "(CLI-only; populated by scanner.cli from --scan-path / "
            "--scan-glob). Keys: path, project?, env?, backend_key?, "
            "workspace?, stack_label?."
        ),
    )
    parser.add_argument(
        "--include-modules",
        action="store_true",
        help=(
            "Source-tier only: honor scan_path entries whose stack root "
            "is a module library (modules/, modules-<x>/, .terraform/)."
        ),
    )
    parser.add_argument(
        "--ignore-lockfile",
        action="store_true",
        help=(
            "Scan .terraform.lock.hcl even when it lives inside an "
            "excluded directory."
        ),
    )
    parser.add_argument(
        "--state-file",
        default=None,
        metavar="PATH",
        help=(
            "Offline tier=plan|state bypass: read .tfstate from a local "
            "file instead of running 'az storage blob download'."
        ),
    )
    parser.add_argument(
        "--registry-mirror",
        default=None,
        metavar="URL",
        help=(
            "URL of a private Terraform module registry mirror. Sets "
            "TF_CLI_CONFIG_FILE to an isolated, generated config for "
            "this run."
        ),
    )
    parser.add_argument(
        "--backend-key",
        default=None,
        metavar="KEY",
        help=(
            "Default storage backend key for entries that don't carry "
            "an explicit per-entry backend_key."
        ),
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not auto-open the generated report.html in the default browser after the scan.",
    )
    parser.add_argument(
        "--framework",
        choices=tuple(SUPPORTED_FRAMEWORKS),
        default=None,
        metavar="NAME",
        help=(
            "Explicit Checkov framework (e.g., terraform, cloudformation, "
            "kubernetes, dockerfile). Defaults to auto-detect from "
            "<target-repo>. When set, tier 'plan' and tier 'state' are "
            "rejected for non-Terraform-family frameworks — those tiers "
            "require terraform init/plan and Azure state-blob download."
        ),
    )
    return parser


def _register_cleanup_trap(output_dir: Path) -> None:
    """Wire the EXIT/SIGINT/SIGTERM cleanup trap.

    Mirrors scan.sh's ``trap trap_on_exit EXIT INT TERM``. The cleanup
    lambda calls :func:`scanner.trap.shred_plan_artifacts` to remove
    sensitive plan artifacts (PCI 10.7 hygiene). Best-effort: missing
    files or missing ``shred`` binary are logged and swallowed.

    The prior firewall-revert step (the storage-account network-rule
    cleanup) was removed: the scanner never mutates the Azure storage
    firewall, so there is nothing to revert. ``output_dir`` is kept on
    the signature for parity with the prior wiring; ``state_account``
    is no longer needed.
    """
    captured_run_dir = output_dir

    def _cleanup() -> None:
        shred_plan_artifacts(captured_run_dir)

    register_traps(_cleanup)


def _ci_auto_promote(args: argparse.Namespace) -> None:
    """CI=1 auto-promotes mode=report to mode=gate. Mirrors scan.sh lines 149-153.

    MUST run before any validation/handler so the promotion is the
    first thing the user-visible configuration sees.
    """
    if args.mode == "report" and os.environ.get("CI", "").strip() == "1":
        args.mode = "gate"
        _log("INFO", "CI environment detected; mode=gate")


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entry point for the ``pacioli scan`` subcommand.

    Returns:
        Process exit code (SCAN_RC). ``0`` = success, non-zero = findings
        (gate mode) or real failure (report mode).
    """
    parser = _build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    # CI=1 gate promotion: must happen FIRST, before any other handling.
    _ci_auto_promote(args)

    # CI=1 also suppresses the post-scan browser open (no display in CI).
    if not getattr(args, "no_open", False) and os.environ.get("CI", "").strip() == "1":
        args.no_open = True
        _log("INFO", "CI environment detected; --no-open")

    # Validate the state-account CLI flag at the boundary so an
    # invalid value never reaches subprocess (S8705). When the caller
    # is on a non-plan/state tier the flag is unused, but validating
    # unconditionally keeps the surface uniform and surfaces typos.
    if args.state_account is not None:
        try:
            Orchestrator._check_storage_account_valid(args.state_account)
        except ValueError as exc:
            _log("ERROR", str(exc))
            return 2

    # Resolve paths (CLI > env > defaults). This mirrors the precedence
    # rules in scanner/paths.py.
    #
    # The Orchestrator.scan() API wants explicit target_repo /
    # output_dir / mapping_path / baseline_path arguments; we use
    # resolve_paths() for those four so the precedence (CLI > env >
    # install defaults) matches the standalone-CLI dispatcher.
    ns = argparse.Namespace(
        target_repo=args.target_repo,
        output_dir=args.output_dir,
        mapping=args.mapping,
        baseline=args.baseline,
    )
    try:
        target_repo, mapping_pack, baseline, run_dir = resolve_paths(ns)
    except Exception as exc:  # paths.py raises PathResolutionError
        _log("ERROR", str(exc))
        return 2

    # Register the EXIT/SIGINT/SIGTERM cleanup trap NOW, before any
    # work that might fail. The cleanup_fn captures output_dir via
    # closure so it has access to it on signal delivery. The trap
    # only shreds plan artifacts now (the firewall-whitelist revert
    # was removed: the scanner is read-only against Azure).
    _register_cleanup_trap(run_dir.path)

    if args.verbose or os.environ.get("PCI_VERBOSE", "").strip() == "1":
        _log("INFO", "verbose logging enabled")

    orchestrator = Orchestrator(
        mode=args.mode,
        tier=args.tier,
        dry_run=args.dry_run,
        no_aggregate=args.no_aggregate,
        no_open=getattr(args, "no_open", False),
        verbose=args.verbose,
    )

    try:
        rc = orchestrator.scan(
            target_repo=target_repo.path,
            project=args.project,
            env=args.env,
            label=args.label,
            output_dir=run_dir.path,
            mapping_path=mapping_pack.path,
            baseline_path=baseline.path,
            state_account=args.state_account,
            include_modules=bool(getattr(args, "include_modules", False)),
            ignore_lockfile=bool(getattr(args, "ignore_lockfile", False)),
            registry_mirror=getattr(args, "registry_mirror", None),
            framework=getattr(args, "framework", None),
        )
    except OrchestratorError as exc:
        _log("ERROR", str(exc))
        return 1

    return rc


def legacy_main(argv: Optional[Iterable[str]] = None) -> int:
    """Console-script entry point for ``pacioli-scan``.

    Forwards to :func:`main` after emitting a deprecation warning.
    Kept so the legacy entry point installed by older pip wheels keeps
    working; new consumers should prefer ``pacioli scan``.
    """
    print(
        "WARNING: `pacioli-scan` is deprecated; use `pacioli scan` instead.",
        file=sys.stderr,
    )
    return main(argv)


if __name__ == "__main__":
    sys.exit(main())
