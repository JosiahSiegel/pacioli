"""checkov_runner.py — Python wrapper for the layered Checkov passes.

Ports the four Checkov invocations from ``scanner/scan.sh`` (lines
461-597) to the Checkov Python API, so the standalone CLI can run the
scan without shelling out. The runner is framework-agnostic: it accepts
any Checkov framework name (terraform, terraform_plan, secrets,
cloudformation, kubernetes, dockerfile, arm, bicep, helm, etc.) and
only special-cases terraform-family frameworks for ``--external-checks-dir``
(custom PaaC checks subclass Terraform's ``BaseResourceCheck``).

Public passes — all thin delegates over :meth:`run_framework`:

  * ``run_paac``   — ``--framework terraform`` + ``--external-checks-dir``
                     (the custom policy-as-code checks under
                     ``scanner/checks/``).
  * ``run_source`` — built-in source scan over the source tree.
  * ``run_plan``   — ``terraform_plan`` framework over a
                     ``terraform show -json`` document.
  * ``run_secrets``— ``secrets`` framework over the same source tree.

Each method returns Checkov's exit code and writes SARIF to the caller-
supplied path, with ``helpUri`` fields rewritten to canonical GitHub
source URLs via :func:`scanner.url_rewrite.rewrite_sarif_file`.

WORKAROUND for Checkov 3.3.9 on Windows
---------------------------------------
Checkov's runner calls ``os.path.relpath(full_file_path.file_path)`` on
every scanned file. On Windows that raises

    ValueError: path is on mount 'C:', start on mount 'S:'

whenever the CWD sits on a different drive than the scanned file. The
bash scanner works around this with ``( cd "$env_dir" && checkov ... )``
in a subshell. A Python subshell equivalent does not exist, so *every*
Checkov invocation in this module goes through :meth:`CheckovRunner._run`,
which performs ``os.chdir(env_dir)`` inside a ``try`` and restores the
saved CWD in the matching ``finally``. The restore therefore happens
even when Checkov raises.

Because the CWD is process-global and mutated here, this class is **not
safe to call concurrently from multiple threads** in the same process.

The Checkov API note
--------------------
``checkov.main.Checkov`` takes its configuration as a CLI-style argv
list (``Checkov(argv=[...])``) and exposes ``run()`` with no keyword
configuration — it does *not* accept ``framework=``/``output=`` kwargs.
Arguments are therefore built as argv lists that mirror the bash flags
one-for-one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Allow both `python -m scanner.checkov_runner` and direct execution.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.frameworks import detect_frameworks as _detect_frameworks  # noqa: E402
from scanner.frameworks import is_terraform_family  # noqa: E402
from scanner.url_rewrite import rewrite_sarif_file  # noqa: E402

# Checkov always names its SARIF artifact this, inside --output-file-path.
_SARIF_BASENAME = "results_sarif.sarif"

# aztfexport-generated files are machine-authored and intentionally not
# scanned (mirrors `find_aztfexport_files` in scan.sh). We do not mutate
# them; they are passed to Checkov as --skip-path.
AZTFEXPORT_FILES: tuple[str, ...] = (
    "terraform.aztfexport.tf",
    "provider.aztfexport.tf",
    "main.aztfexport.tf",
    "aztfexportResourceMapping.json",
    "aztfexportSkippedResources.txt",
)

# Default location of the custom policy-as-code checks.
DEFAULT_CHECKS_DIR = Path(__file__).resolve().parent / "checks"


class CheckovRunner:
    """Runs the layered Checkov passes against one environment directory.

    Args:
        mode: ``"gate"`` adds ``--hard-fail-on HIGH,CRITICAL`` so a
            HIGH/CRITICAL finding produces a non-zero exit code.
            Anything else (``"report"``) adds ``--soft-fail``, matching
            the bash scanner's MODE semantics.
        checks_dir: Directory of custom checks for :meth:`run_paac`.
            Defaults to ``scanner/checks/``.
        frameworks: Optional iterable of framework names to expose via
            :attr:`frameworks`. When ``None`` (the default), the set is
            auto-detected per call to :meth:`run_framework` via
            :func:`scanner.frameworks.detect_frameworks`. The constructor
            itself does NOT run detection — the parameter is a hint for
            callers that want to know the resolved set without running
            a scan. The single source of truth for framework identity is
            :mod:`scanner.frameworks`; this runner does not maintain a
            parallel list.
    """

    def __init__(
        self,
        mode: str = "report",
        checks_dir: Path | None = None,
        frameworks: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self.mode = mode
        self.checks_dir = Path(checks_dir) if checks_dir else DEFAULT_CHECKS_DIR
        # ``frameworks`` is stored verbatim when supplied — the caller may
        # use it to short-circuit or sanity-check. When ``None``, each
        # ``run_framework`` call performs its own detection; we do NOT
        # auto-detect at __init__ time because the env_dir differs per
        # call.
        self.frameworks: tuple[str, ...] | None = (
            tuple(frameworks) if frameworks is not None else None
        )

    # -- internals --------------------------------------------------

    def _fail_flags(self) -> list[str]:
        """Return the mode-dependent failure flags."""
        if self.mode == "gate":
            return ["--hard-fail-on", "HIGH,CRITICAL"]
        return ["--soft-fail"]

    @staticmethod
    def _skip_path_flags(env_dir: Path) -> list[str]:
        """Return ``--skip-path`` flags for aztfexport files present in env_dir."""
        flags: list[str] = []
        for name in AZTFEXPORT_FILES:
            if (env_dir / name).exists():
                flags += ["--skip-path", name]
        return flags

    def _build_framework_argv(
        self,
        env_dir: Path,
        framework: str,
        input_arg: tuple[str, str],
    ) -> list[str]:
        """Build the per-framework argv tail (before ``--output``/fail flags).

        Shared between :meth:`run_framework` (directory mode) and
        :meth:`run_plan` (file mode). Adding ``--external-checks-dir``
        is gated on :func:`scanner.frameworks.is_terraform_family` —
        the custom PaaC checks subclass Terraform's BaseResourceCheck.

        Args:
            env_dir: Directory used to discover aztfexport files.
            framework: Checkov framework name (``--framework <value>``).
            input_arg: ``("-d", "<dir>")`` for directory mode or
                ``("-f", "<file>")`` for file mode (terraform_plan).

        Returns:
            argv tail list — does NOT include ``--output``/``--output-file-path``
            or the fail-mode flags; those are appended by :meth:`_run`.
        """
        argv = [input_arg[0], input_arg[1], "--framework", framework]
        if is_terraform_family(framework) and self.checks_dir.is_dir():
            argv += ["--external-checks-dir", str(self.checks_dir.resolve())]
        argv += self._skip_path_flags(env_dir)
        return argv

    def _run(self, env_dir: Path, args: list[str], sarif_out: Path) -> int:
        """Invoke Checkov in a fresh subprocess from inside ``env_dir``.

        Each scan runs as ``python -m checkov.main <args>`` with
        ``cwd=env_dir``. Subprocess isolation is MANDATORY: Checkov 3.3.9
        caches its scan results in module-level state, so calling
        ``Checkov(argv=...).run()`` twice from the same Python process
        returns the SARIF from the FIRST scan regardless of the second
        scan's ``-d`` target or CWD. Reproduced locally with a minimal
        4-scan sequence on alternating env_dirs; all 4 SARIFs were
        byte-identical.

        Subprocess isolation also obsoletes the previous Windows
        relpath workaround (the os.chdir dance) — the child process
        starts in ``env_dir`` natively. The runner is therefore
        thread-safe again (no process-global CWD mutation).

        Args:
            env_dir: Directory to run Checkov from (becomes the CWD
                of the child process).
            args: argv tail, excluding output/fail flags.
            sarif_out: Final path for the SARIF file.

        Returns:
            Checkov's exit code (``0`` on a clean run).
        """
        env_dir = Path(env_dir).resolve()
        sarif_out = Path(sarif_out).resolve()
        sarif_out.parent.mkdir(parents=True, exist_ok=True)

        # Checkov writes <output-file-path>/results_sarif.sarif. Use a
        # scratch dir so a partial/failed run never clobbers an existing
        # SARIF at the destination. The scratch dir sits next to the
        # final SARIF so the cross-drive move at the end is impossible
        # (sarif_out.parent is the scratch parent).
        tmp_dir = Path(tempfile.mkdtemp(prefix="pacioli_ckv_", dir=sarif_out.parent))
        try:
            argv = [sys.executable, "-m", "checkov.main", *args,
                    "--output", "sarif",
                    "--output-file-path", str(tmp_dir),
                    *self._fail_flags()]

            # Capture stderr for diagnostics on non-zero exit. Checkov
            # writes progress lines (and the failure summary) to stderr;
            # the SARIF artifact is the only thing we care about, and it
            # is on disk regardless of exit code.
            completed = subprocess.run(
                argv,
                cwd=str(env_dir),
                capture_output=True,
                text=True,
                timeout=900,  # 15 min hard cap per scan; scan.sh uses no cap but
                              # a stuck subprocess shouldn't wedge the orchestrator.
                check=False,
            )

            produced = tmp_dir / _SARIF_BASENAME
            if produced.is_file():
                shutil.move(str(produced), str(sarif_out))
                rewrite_sarif_file(sarif_out)
            elif completed.returncode != 0:
                # Surface Checkov's own error output so the operator can
                # diagnose without re-running the scan manually.
                sys.stderr.write(
                    f"checkov exited with rc={completed.returncode} and produced "
                    f"no SARIF in {tmp_dir}; stderr tail:\n"
                    f"{completed.stderr[-2000:]}\n"
                )

            return int(completed.returncode)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # -- public passes ----------------------------------------------

    def run_framework(
        self,
        env_dir: Path,
        sarif_out: Path,
        framework: str,
    ) -> int:
        """Single generic Checkov pass for any supported framework.

        Builds the argv with ``--framework <framework>`` and delegates
        to :meth:`_run`. Adds ``--external-checks-dir`` only when the
        framework is terraform-family — the custom PaaC checks subclass
        :class:`checkov.terraform.checks.resource.azure.BaseResourceCheck`
        (and friends), so they apply only to terraform/terraform_plan.

        Args:
            env_dir: Directory to scan (``-d .``). The CWD chdir to this
                path (Windows relpath workaround) happens inside
                :meth:`_run`.
            sarif_out: Final destination for the SARIF artifact.
            framework: Checkov framework name. Any value accepted by
                ``--framework`` is allowed; Pacioli does NOT validate
                the name — Checkov itself raises on unknown values.

        Returns:
            Checkov's exit code (``0`` on a clean run).
        """
        env_dir = Path(env_dir)
        args = self._build_framework_argv(env_dir, framework, ("-d", "."))
        return self._run(env_dir, args, sarif_out)

    def run_paac(self, env_dir: Path, sarif_out: Path) -> int:
        """Custom policy-as-code pass over the ``.tf`` source.

        Thin delegate over :meth:`run_framework` with ``framework="terraform"``.
        Mirrors scan.sh step 1: ``--framework terraform`` plus
        ``--external-checks-dir <checks_dir>``. If the checks directory
        does not exist the pass is skipped and ``0`` is returned, which
        matches the bash guard ``if [[ -d "$PCI_CHECKS_DIR" ]]``.
        """
        # Preserve the historical "skip when checks dir absent" early
        # return — keeps run_paac's contract identical to the bash scanner.
        if not self.checks_dir.is_dir():
            return 0
        return self.run_framework(env_dir, sarif_out, framework="terraform")

    def run_source(
        self,
        env_dir: Path,
        sarif_out: Path,
        framework: str = "terraform",
    ) -> int:
        """Built-in ``<framework>`` source pass over the env tree.

        Thin delegate over :meth:`run_framework`. Mirrors scan.sh step 2
        — the deepest source-only layer.

        .. note::

            ``framework`` defaults to ``"terraform"`` for backward
            compatibility — the prior hard-coded literal. Callers
            (notably :meth:`scanner.orchestrator.Orchestrator._emit_source`)
            now pass through the operator-supplied ``--framework`` flag
            so a non-Terraform stack (``cloudformation``, ``kubernetes``,
            ``dockerfile``, etc.) actually exercises the corresponding
            Checkov framework instead of scanning Terraform-shaped
            files that may not be present (yielding 0 findings and
            bogus terraform remediation blocks).

        Args:
            env_dir: Directory to scan (``-d .``). The CWD chdir to this
                path (Windows relpath workaround) happens inside
                :meth:`_run`.
            sarif_out: Final destination for the SARIF artifact.
            framework: Checkov framework name. Defaults to
                ``"terraform"`` for backward compatibility.
        """
        return self.run_framework(env_dir, sarif_out, framework=framework)

    def run_plan(
        self,
        plan_json: Path,
        sarif_out: Path,
        env_dir: Path | None = None,
    ) -> int:
        """``terraform_plan`` framework pass over a plan JSON document.

        Builds its argv via the shared :meth:`_build_framework_argv`
        helper, which encodes the ``--external-checks-dir`` gate in one
        place.

        Args:
            plan_json: A ``terraform show -json`` output file.
            sarif_out: Final path for the SARIF file.
            env_dir: Directory to run from. Defaults to the plan file's
                parent, which keeps the two-argument call form working.
        """
        plan_json = Path(plan_json).resolve()
        run_dir = Path(env_dir) if env_dir is not None else plan_json.parent
        args = self._build_framework_argv(
            Path(run_dir), "terraform_plan", ("-f", str(plan_json))
        )
        return self._run(run_dir, args, sarif_out)

    def run_secrets(self, env_dir: Path, sarif_out: Path) -> int:
        """``secrets`` framework pass over the source tree.

        Thin delegate over :meth:`run_framework`. Mirrors scan.sh step 4.
        Always safe to run — purely static. ``secrets`` is not in the
        terraform family, so :meth:`run_framework` correctly omits
        ``--external-checks-dir`` (custom PaaC checks target terraform
        resources only).
        """
        return self.run_framework(env_dir, sarif_out, framework="secrets")

    def detect_frameworks(self, env_dir: Path) -> set[str]:
        """Return frameworks detected in ``env_dir`` via the shared helper.

        Thin pass-through to :func:`scanner.frameworks.detect_frameworks`
        so callers do not need to import :mod:`scanner.frameworks`
        directly. Kept as an instance method for API ergonomics only —
        no runner state is involved.
        """
        return _detect_frameworks(Path(env_dir))


def _smoke() -> int:
    """Smoke test: run_source over a minimal .tf and assert SARIF is written."""
    import json

    with tempfile.TemporaryDirectory(prefix="pacioli_smoke_") as td:
        tmp_path = Path(td)
        env_dir = tmp_path / "env"
        env_dir.mkdir()
        (env_dir / "main.tf").write_text(
            'resource "null_resource" "x" {}\n', encoding="utf-8"
        )

        sarif_out = tmp_path / "out" / "results_terraform_source.sarif"
        saved_cwd = os.getcwd()
        rc = CheckovRunner(mode="report").run_source(env_dir, sarif_out)

        assert os.getcwd() == saved_cwd, f"CWD not restored: {os.getcwd()}"
        assert sarif_out.is_file(), f"SARIF not written to {sarif_out}"

        data = json.loads(sarif_out.read_text(encoding="utf-8"))
        assert isinstance(data.get("runs"), list), "SARIF has no 'runs' array"

        print(f"SMOKE_OK rc={rc} sarif={sarif_out.name} runs={len(data['runs'])}")
    return 0


if __name__ == "__main__":
    sys.exit(_smoke())
