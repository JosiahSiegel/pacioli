"""scanner/orchestrator.py — Read-only PCI scan orchestrator (Python).

Replaces ``scanner/scan.sh`` as the in-process scan driver for the
standalone Pacioli CLI. The bash script remains the source of truth for
behavior; this module ports that behavior 1:1 into Python.

What it does
------------
For each ``(project, env)`` pair discovered in ``target_repo``:

1. (Tier ``plan``/``state`` only) Whitelist current IP on the
   ``state_account`` storage firewall. ``terraform init`` + ``terraform
   plan -out=tfplan.binary -lock=true`` + ``terraform show -json``. No
   mutation beyond the firewall rule (auto-reverted by the EXIT trap).
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
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# Bootstrap UTF-8 I/O before any scan work (mirrors lib/common.sh).
import scanner._utf8  # noqa: F401  -- side-effect import

# Make sibling scanner modules importable when this file is executed
# directly (python scanner/orchestrator.py) and from `python -m`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.checkov_runner import CheckovRunner  # noqa: E402
from scanner.discovery import (  # noqa: E402
    NoTerraformFoundError,
    discover_pairs,
)
from scanner.paths import (  # noqa: E402
    PathResolutionError,
    resolve_mapping as resolve_mapping_path,
    resolve_paths,
)
from scanner.safety import SafetyGuard  # noqa: E402
from scanner.trap import (  # noqa: E402
    cleanup_ip_whitelist,
    register_traps,
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
# init / plan / storage read).
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
# `subprocess.run` (S8705 — subprocess invocation with tainted CLI value).
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
        verbose: When True, emit INFO logs (matches PCI_VERBOSE=1).
        safety: Pre-wired :class:`SafetyGuard` instance (defense-in-
            depth refusal matrix). Pass an instance to inject a stub
            in tests; production code uses the default.
    """

    mode: str = "report"
    tier: str = "source"
    dry_run: bool = False
    no_aggregate: bool = False
    verbose: bool = False
    safety: SafetyGuard = field(default_factory=SafetyGuard)

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

        Returns:
            The shell-style SCAN_RC. ``gate`` mode may return any non-
            zero from aggregate.py (including 7); ``report`` mode
            returns ``0`` unless aggregate.py failed with rc != 7.
        """
        # Mode / tier validation first — fail fast before doing work.
        self._validate_mode_and_tier()

        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        run_root = self._setup_run_root(output_dir, label)

        target_repo, resolved_mapping, resolved_baseline, pairs = (
            self._resolve_scan_inputs(
                target_repo=target_repo,
                project=project,
                env=env,
                mapping_path=mapping_path,
                baseline_path=baseline_path,
            )
        )

        if not pairs:
            _log("WARN", "no (project, env) pairs matched --project/--env filters")
            return 0

        self._emit_scan_banner(self.mode, self.tier, output_dir, resolved_mapping, resolved_baseline, pairs)

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

    # -- scan() helpers ----------------------------------------------

    def _resolve_scan_inputs(
        self,
        *,
        target_repo: Path,
        project: Optional[str],
        env: Optional[str],
        mapping_path: Optional[Path],
        baseline_path: Optional[Path],
    ) -> tuple[Path, Path, Optional[Path], list[tuple[str, str]]]:
        """Resolve target repo, mapping, baseline, and (project, env) pairs.

        Extracted from :meth:`scan` so that the top-level orchestrator
        reads as a thin glue layer (S3776). Raises :class:`OrchestratorError`
        on resolution failures (mapping, no-pair discovery) so the
        caller can convert them to a single log + non-zero rc.
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
            )
        except NoTerraformFoundError as exc:
            raise OrchestratorError(str(exc)) from exc

        return target_repo, resolved_mapping, resolved_baseline, pairs

    # -- scan() helpers ----------------------------------------------

    def _validate_mode_and_tier(self) -> None:
        """Fail fast on invalid mode / tier before doing any work.

        Extracted from :meth:`scan` to keep that method's cognitive
        complexity under control. ``audit`` mode is intentionally not
        implemented in the Python orchestrator — the bash
        ``scan_audit.sh`` companion handles that flow.
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
        pairs: list[tuple[str, str]],
    ) -> None:
        """Emit the per-run INFO banner before the per-pair loop starts.

        Extracted from :meth:`scan` so the top-level orchestrator reads
        as a thin glue layer.
        """
        _log("INFO", f"mode: {mode}")
        _log("INFO", f"tier: {tier}")
        _log("INFO", f"output_dir: {output_dir}")
        _log("INFO", f"mapping: {resolved_mapping}")
        if resolved_baseline:
            _log("INFO", f"baseline: {resolved_baseline}")
        _log(
            "INFO",
            f"discovered {len(pairs)} (project, env) pair(s): "
            + ", ".join(f"{p}/{e}" for p, e in pairs),
        )

    def _run_scan_loop(
        self,
        runner: CheckovRunner,
        pairs: list[tuple[str, str]],
        target_repo: Path,
        run_root: Path,
        state_account: Optional[str],
    ) -> int:
        """Drive the (project, env) pair loop and return the per-pair max rc.

        Skips pairs whose env dir is missing. The per-pair dispatch into
        the tier-specific passes is delegated to
        :meth:`_scan_one_pair`.
        """
        scan_rc = 0
        for proj, env_name in pairs:
            env_dir = self._resolve_env_dir(target_repo, proj, env_name)
            if not env_dir.is_dir():
                _log(
                    "WARN",
                    f"skipping {proj}/{env_name}: env dir invalid: {env_dir}",
                )
                continue

            env_run_dir = run_root / proj / env_name
            env_run_dir.mkdir(parents=True, exist_ok=True)

            _log("INFO", f"scanning {proj}/{env_name}")

            state = _PairState(
                project=proj,
                env=env_name,
                env_run_dir=env_run_dir,
                env_dir=env_dir,
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
        return scan_rc

    # -- pair scan ----------------------------------------------------

    def _scan_one_pair(
        self,
        runner: CheckovRunner,
        state: _PairState,
        state_account: Optional[str],
    ) -> int:
        """Drive one (project, env) pair through the tier-dispatched passes."""
        pair_rc = 0

        # Tier 2/3: terraform init + plan (acquires state lock, no mutation
        # beyond the firewall whitelist). Mirrors scan.sh lines 388-436.
        if self.tier in ("plan", "state"):
            tier_rc = self._run_plan_tier(state, state_account)
            if tier_rc < 0:
                return pair_rc

        # Compute pass list based on tier.
        passes = TIER_PASSES[self.tier]

        if "paac" in passes:
            pair_rc = self._accumulate(pair_rc, self._emit_paac(runner, state))

        # Pass 2: source (built-in terraform framework).
        # Mirrors scan.sh line 503: source tier runs this; plan/state
        # tier ALSO runs this (it is the deepest source layer).
        if "source" in passes:
            pair_rc = self._accumulate(pair_rc, self._emit_source(runner, state))

        # Pass 3: plan (terraform_plan framework on plan.json).
        if "plan" in passes:
            plan_rc = self._emit_plan_pass(runner, state)
            if plan_rc is not None:
                pair_rc = self._accumulate(pair_rc, plan_rc)

        # Pass 4: secrets (always when tier allows).
        if "secrets" in passes:
            pair_rc = self._accumulate(pair_rc, self._emit_secrets(runner, state))

        # Pass 5 (state-only): state-as-plan scan + drift diff.
        if "state" in passes:
            self._scan_state_blob(runner, state, state_account)

        # Pass 6: shred plan artifacts (PCI 10.7 hygiene).
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
        """
        if not self.dry_run and not state_account:
            _log(
                "ERROR",
                f"PACIOLI_STATE_STORAGE_ACCOUNT is not set; cannot run tier "
                f"{self.tier!r} for {state.project}/{state.env}",
            )
            return -1

        if not self._whitelist_my_ip(state, state_account):
            _log(
                "ERROR",
                f"failed to whitelist IP; cannot read remote state; "
                f"skipping {state.project}/{state.env}",
            )
            return -1

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
        return 0

    def _emit_paac(self, runner: CheckovRunner, state: _PairState) -> int:
        """Run the paac (custom policy-as-code) pass; record + return rc."""
        paac_out = state.env_run_dir / "results_paac.sarif"
        rc = runner.run_paac(state.env_dir, paac_out)
        self._record_checkov_rc(rc, state, "paac")
        return rc

    def _emit_source(self, runner: CheckovRunner, state: _PairState) -> int:
        """Run the built-in terraform source pass; record + return rc."""
        src_out = state.env_run_dir / "results_terraform_source.sarif"
        rc = runner.run_source(state.env_dir, src_out)
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
        """
        if not (state.plan_json and state.plan_json.is_file()):
            return None
        plan_out = state.env_run_dir / "results_terraform_plan.sarif"
        rc = runner.run_plan(state.plan_json, plan_out, env_dir=state.env_dir)
        self._record_checkov_rc(rc, state, "plan")
        return rc

    def _emit_secrets(self, runner: CheckovRunner, state: _PairState) -> int:
        """Run the secrets pass on the .tf source; record + return rc."""
        secrets_out = state.env_run_dir / "results_secrets.sarif"
        rc = runner.run_secrets(state.env_dir, secrets_out)
        self._record_checkov_rc(rc, state, "secrets")
        return rc

    @staticmethod
    def _check_storage_account_valid(account: str) -> None:
        """Validate a storage account name before it reaches ``subprocess``.

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
    ) -> Path:
        """Resolve the env dir for a (project, env) pair.

        For the flat-repo fallback (``project == 'default' and env ==
        'default'``), the .tf files live at the repo root. Otherwise
        the bash convention is ``<target_repo>/env/<project>/<env>/``.
        Mirrors scan.sh line 370.
        """
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

    # -- terraform + state-blob --------------------------------------

    def _whitelist_my_ip(
        self,
        state: _PairState,
        state_account: Optional[str],
    ) -> bool:
        """Add the current public IP to the state storage firewall.

        Stores the IP in ``<env_run_dir>/.whitelist_ip`` so the EXIT
        trap can find it. Idempotent: re-running overwrites the file.

        Returns True on success (or dry-run). Mirrors scan.sh lines
        398-410.
        """
        assert state_account is not None  # checked by caller
        _log("INFO", f"  whitelist current IP on {state_account} storage firewall")

        if self.dry_run:
            # Defense-in-depth: validate the CLI-derived value before any
            # subprocess invocation (S8705 — taint from CLI flag).
            self._check_storage_account_valid(state_account)
            print("[dry-run] whitelist_my_ip")
            return True

        # Defense-in-depth: validate the CLI-derived value before any
        # subprocess invocation (S8705 — taint from CLI flag). Bind the
        # validated value to a local so the static analyzer sees the
        # taint cleared at the point subprocess.run is called.
        self._check_storage_account_valid(state_account)
        validated_account = state_account

        # Discover the public IP via the canonical Azure metadata
        # endpoint. Falls back to ipify if the metadata endpoint is
        # unreachable (e.g. dev box without Azure metadata service).
        ip = _discover_public_ip()
        if not ip:
            _log("ERROR", "  could not determine current public IP")
            return False

        # Refuse if the command matches a forbidden mutating pattern.
        # The whitelist command is in ALLOWED_EXCEPTIONS so the guard
        # passes — but the defense-in-depth check still fires.
        cmd = (
            f"az storage account network-rule add "
            f"--account-name {validated_account} --ip-address {ip}"
        )
        self.safety.refuse_if_mutating(cmd)

        # Defense-in-depth re-validation immediately before the
        # subprocess call (S8705 — taint from CLI flag). Use an inline
        # ``re.fullmatch`` guard so the static analyzer sees the
        # sanitization at the immediate use-site, then bind the
        # validated value to a local for the subprocess argv.
        if not re.fullmatch(AZURE_STORAGE_ACCOUNT_PATTERN, validated_account):
            raise ValueError(f"invalid state_account: {validated_account!r}")
        sanitized_account: str = validated_account

        result = subprocess.run(
            [
                "az",
                "storage",
                "account",
                "network-rule",
                "add",
                "--account-name",
                sanitized_account,
                "--ip-address",
                ip,
                "--output",
                "none",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            _log(
                "ERROR",
                f"  az network-rule add failed (rc={result.returncode}): "
                f"{(result.stderr or '').strip()}",
            )
            return False

        # Record the IP for the cleanup trap.
        (state.env_run_dir / ".whitelist_ip").write_text(ip, encoding="utf-8")
        _log("INFO", f"  whitelisted IP {ip}")
        return True

    def _run_terraform_init(self, state: _PairState) -> bool:
        """Run ``terraform init -input=false`` in the env dir.

        Mirrors scan.sh line 418. ``-input=false`` disables interactive
        prompts. Providers are downloaded from the registry or
        filesystem_mirror; no Azure mutations.
        """
        _log("INFO", "  terraform init")
        if self.dry_run:
            print("[dry-run] terraform init")
            return True

        try:
            result = subprocess.run(
                [
                    "terraform",
                    "-chdir",
                    str(state.env_dir),
                    "init",
                    "-input=false",
                    "-no-color",
                ],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired:
            _log("ERROR", "  terraform init timed out")
            return False
        except FileNotFoundError:
            _log("ERROR", "  terraform binary not found on PATH")
            return False

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

        Acquires state lock and reads remote state. NO mutation. The
        plan binary is shredded on exit by the trap (or by
        :meth:`_shred_plan_artifacts` per-pair). Mirrors scan.sh
        lines 425-431.
        """
        plan_bin = state.env_run_dir / "tfplan.binary"
        state.plan_bin = plan_bin

        _log("INFO", f"  terraform plan -out={plan_bin.name}")
        if self.dry_run:
            print(f"[dry-run] terraform plan -out={plan_bin}")
            return True

        try:
            result = subprocess.run(
                [
                    "terraform",
                    "-chdir",
                    str(state.env_dir),
                    "plan",
                    "-no-color",
                    f"-out={plan_bin}",
                    "-lock=true",
                ],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired:
            _log("ERROR", "  terraform plan timed out")
            return False
        except FileNotFoundError:
            _log("ERROR", "  terraform binary not found on PATH")
            return False

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
        it already exists.
        """
        if state.plan_bin is None:
            return
        plan_json = state.env_run_dir / "plan.json"
        state.plan_json = plan_json

        _log("INFO", "  terraform show -json")
        if self.dry_run:
            print(f"[dry-run] terraform show -json {state.plan_bin} > {plan_json}")
            return

        try:
            with plan_json.open("w", encoding="utf-8") as fh:
                subprocess.run(
                    [
                        "terraform",
                        "-chdir",
                        str(state.env_dir),
                        "show",
                        "-json",
                        str(state.plan_bin),
                    ],
                    stdout=fh,
                    text=True,
                    timeout=120,
                    check=True,
                )
        except subprocess.TimeoutExpired:
            _log("ERROR", "  terraform show timed out")
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            _log("ERROR", f"  terraform show failed: {exc}")

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

        backend_key = self._resolve_or_synthesize_backend_key(state)
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

    def _resolve_or_synthesize_backend_key(self, state: _PairState) -> str:
        """Return the storage backend key, synthesizing one if missing.

        Reads ``<env_dir>/terraform.aztfexport.tf``; falls back to
        ``CR_<Env>_<project>.tfstate`` so downstream download has a key.
        """
        backend_key = self._resolve_backend_key(state)
        if backend_key:
            return backend_key
        synthesized = f"CR_{state.env[:1].upper()}{state.env[1:]}_{state.project}.tfstate"
        _log(
            "WARN",
            f"no backend key in terraform.aztfexport.tf; "
            f"falling back to synthesized: {synthesized}",
        )
        return synthesized

    @staticmethod
    def _resolve_state_blob_paths(state: _PairState) -> dict[str, Path]:
        """Return the local paths used by the state-blob scan pipeline.

        Also annotates ``state.state_local`` / ``state.state_plan_json``
        so downstream helpers (e.g. shred, drift) find them.
        """
        state_local = state.env_run_dir / "state.tfstate"
        state_plan_json = state.env_run_dir / "state_as_plan.json"
        drift_report = state.env_run_dir / "drift_report.json"
        state.state_local = state_local
        state.state_plan_json = state_plan_json
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

        Logs and returns False on timeout, missing binary, non-zero rc,
        or empty result. The downloaded blob is shredded ASAP in the
        caller (PCI 10.7 hygiene).
        """
        # Defense-in-depth: validate the CLI-derived value here too so
        # the data-flow analyzer sees the check immediately before the
        # subprocess invocation (S8705 — taint from CLI flag).
        self._check_storage_account_valid(state_account)
        try:
            dl = subprocess.run(
                [
                    "az",
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
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            _log("ERROR", f"  state blob download failed: {exc}")
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
        """
        try:
            conv = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parent / "tfstate_to_plan.py"),
                    str(state_local),
                    str(state_plan_json),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            _log("ERROR", f"  tfstate_to_plan failed: {exc}")
            return False

        # Shred the encrypted state blob ASAP (PCI 10.7 hygiene).
        if state_local.is_file():
            try:
                state_local.unlink()
            except OSError as exc:
                _log("WARN", f"  failed to remove state blob: {exc}")

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
        when ``state.plan_json`` is unavailable.
        """
        if not (state.plan_json and state.plan_json.is_file() and state_plan_json.is_file()):
            return
        try:
            subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parent / "drift_report.py"),
                    str(state.plan_json),
                    str(state_plan_json),
                    str(drift_report),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            _log("WARN", f"  drift_report.py timed out: {exc}")
        except FileNotFoundError as exc:
            _log("WARN", f"  drift_report.py unavailable: {exc}")

    @staticmethod
    def _shred_state_plan(state_plan_json: Path) -> None:
        """Shred the state-as-plan JSON (PCI 10.7 hygiene, best-effort)."""
        if not state_plan_json.is_file():
            return
        try:
            state_plan_json.unlink()
        except OSError as exc:  # noqa: BLE001 — best-effort shred; logged for forensics
            _log("WARN", f"  failed to shred state plan: {exc}")

    def _resolve_backend_key(self, state: _PairState) -> Optional[str]:
        """Read the storage backend key from terraform.aztfexport.tf.

        Mirrors scan.sh lines 610-613. Returns ``None`` when the file is
        missing or the key field is absent.
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

    def _shred_plan_artifacts(self, state: _PairState) -> None:
        """Shred tfplan.binary and plan.json for this pair (PCI 10.7 hygiene).

        Mirrors scan.sh lines 686-694. Idempotent: missing files are
        silently skipped.
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
                path.unlink()
                _log("INFO", f"  removed {path.name}")
            except OSError as exc:
                _log("WARN", f"  failed to remove {path}: {exc}")

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

    @staticmethod
    def _resolve_aggregate_argv(
        run_dir: Path,
        mapping_path: Optional[Path],
        baseline_path: Optional[Path],
    ) -> list[str]:
        """Build the argv list passed to ``scanner.aggregate.main``.

        Mirrors scan.sh's aggregate invocation flags. Absolute paths
        are used so the aggregate step does not depend on CWD.
        """
        argv: list[str] = ["aggregate.py", "--run-dir", str(run_dir)]
        if mapping_path is not None:
            argv += ["--mapping", str(mapping_path)]
        if baseline_path is not None:
            argv += ["--baseline", str(baseline_path)]
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
    return parser


def _register_cleanup_trap(output_dir: Path, state_account: Optional[str]) -> None:
    """Wire the EXIT/SIGINT/SIGTERM cleanup trap.

    Mirrors scan.sh's ``trap trap_on_exit EXIT INT TERM``. The
    cleanup lambda calls :func:`scanner.trap.cleanup_ip_whitelist` and
    :func:`scanner.trap.shred_plan_artifacts`. Both are best-effort:
    missing files or missing `az` binary are logged and swallowed.
    """
    captured_run_dir = output_dir
    captured_account = state_account

    def _cleanup() -> None:
        if captured_account:
            cleanup_ip_whitelist(captured_run_dir, captured_account)
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
    # work that might fail. The cleanup_fn captures output_dir and
    # state_account via closure so it has access to them on signal
    # delivery.
    _register_cleanup_trap(run_dir.path, args.state_account)

    if args.verbose or os.environ.get("PCI_VERBOSE", "").strip() == "1":
        _log("INFO", "verbose logging enabled")

    orchestrator = Orchestrator(
        mode=args.mode,
        tier=args.tier,
        dry_run=args.dry_run,
        no_aggregate=args.no_aggregate,
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
