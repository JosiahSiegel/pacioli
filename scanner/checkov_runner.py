"""checkov_runner.py — Python wrapper for the layered Checkov passes.

Ports the four Checkov invocations from ``scanner/scan.sh`` (lines
461-597) to the Checkov Python API, so the standalone CLI can run the
scan without shelling out:

  * ``run_paac``   — ``--framework terraform`` + ``--external-checks-dir``
                     (the custom policy-as-code checks under
                     ``scanner/checks/``).
  * ``run_source`` — ``--framework terraform`` built-in source scan.
  * ``run_plan``   — ``--framework terraform_plan`` over a
                     ``terraform show -json`` document.
  * ``run_secrets``— ``--framework secrets`` over the same source tree.

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
import sys
import tempfile
from pathlib import Path

# Allow both `python -m scanner.checkov_runner` and direct execution.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
    """

    def __init__(self, mode: str = "report", checks_dir: Path | None = None) -> None:
        self.mode = mode
        self.checks_dir = Path(checks_dir) if checks_dir else DEFAULT_CHECKS_DIR

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

    def _run(self, env_dir: Path, args: list[str], sarif_out: Path) -> int:
        """Invoke Checkov from inside ``env_dir`` and place SARIF at ``sarif_out``.

        This is the single choke point for the Windows relpath
        workaround: the ``os.chdir(env_dir)`` happens inside the ``try``
        and the ``finally`` restores the saved CWD unconditionally, so
        an exception from Checkov cannot leave the process in the
        scanned directory.

        Args:
            env_dir: Directory to run Checkov from (becomes the CWD).
            args: argv tail, excluding output/fail flags.
            sarif_out: Final path for the SARIF file.

        Returns:
            Checkov's exit code (``0`` when ``run()`` returns ``None``).
        """
        env_dir = Path(env_dir).resolve()
        sarif_out = Path(sarif_out).resolve()
        sarif_out.parent.mkdir(parents=True, exist_ok=True)

        # Import lazily: importing checkov is slow (~1s) and pulls in a
        # large dependency tree, so a caller that only imports this
        # module does not pay for it.
        from checkov.main import Checkov

        # Checkov writes <output-file-path>/results_sarif.sarif. Use a
        # scratch dir so a partial/failed run never clobbers an existing
        # SARIF at the destination.
        tmp_dir = Path(tempfile.mkdtemp(prefix="pacioli_ckv_", dir=sarif_out.parent))
        try:
            argv = list(args) + [
                "--output", "sarif",
                "--output-file-path", str(tmp_dir),
            ] + self._fail_flags()

            saved_cwd = os.getcwd()
            try:
                # --- Windows relpath workaround (see module docstring) ---
                os.chdir(env_dir)
                rc = Checkov(argv=argv).run()
            finally:
                os.chdir(saved_cwd)

            produced = tmp_dir / _SARIF_BASENAME
            if produced.is_file():
                shutil.move(str(produced), str(sarif_out))
                rewrite_sarif_file(sarif_out)

            # Checkov returns None on a clean run; normalize to 0.
            return 0 if rc is None else int(rc)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # -- public passes ----------------------------------------------

    def run_paac(self, env_dir: Path, sarif_out: Path) -> int:
        """Custom policy-as-code pass over the ``.tf`` source.

        Mirrors scan.sh step 1: ``--framework terraform`` plus
        ``--external-checks-dir <checks_dir>``. If the checks directory
        does not exist the pass is skipped and ``0`` is returned, which
        matches the bash guard ``if [[ -d "$PCI_CHECKS_DIR" ]]``.
        """
        env_dir = Path(env_dir)
        if not self.checks_dir.is_dir():
            return 0
        args = [
            "-d", ".",
            "--framework", "terraform",
            "--external-checks-dir", str(self.checks_dir.resolve()),
        ] + self._skip_path_flags(env_dir)
        return self._run(env_dir, args, sarif_out)

    def run_source(self, env_dir: Path, sarif_out: Path) -> int:
        """Built-in ``terraform`` framework pass over the ``.tf`` source.

        Mirrors scan.sh step 2 — the deepest source-only layer.
        """
        env_dir = Path(env_dir)
        args = [
            "-d", ".",
            "--framework", "terraform",
        ] + self._skip_path_flags(env_dir)
        return self._run(env_dir, args, sarif_out)

    def run_plan(
        self,
        plan_json: Path,
        sarif_out: Path,
        env_dir: Path | None = None,
    ) -> int:
        """``terraform_plan`` framework pass over a plan JSON document.

        Mirrors scan.sh step 3.

        Args:
            plan_json: A ``terraform show -json`` output file.
            sarif_out: Final path for the SARIF file.
            env_dir: Directory to run from. Defaults to the plan file's
                parent, which keeps the two-argument call form working.
        """
        plan_json = Path(plan_json).resolve()
        run_dir = Path(env_dir) if env_dir is not None else plan_json.parent
        args = [
            "-f", str(plan_json),
            "--framework", "terraform_plan",
        ] + self._skip_path_flags(Path(run_dir))
        if self.checks_dir.is_dir():
            args += ["--external-checks-dir", str(self.checks_dir.resolve())]
        return self._run(run_dir, args, sarif_out)

    def run_secrets(self, env_dir: Path, sarif_out: Path) -> int:
        """``secrets`` framework pass over the source tree.

        Mirrors scan.sh step 4. Always safe to run — purely static.
        """
        env_dir = Path(env_dir)
        args = [
            "-d", ".",
            "--framework", "secrets",
        ] + self._skip_path_flags(env_dir)
        if self.checks_dir.is_dir():
            args += ["--external-checks-dir", str(self.checks_dir.resolve())]
        return self._run(env_dir, args, sarif_out)


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
