"""scanner/tests/test_cli.py — pytest cases for the standalone ``pacioli`` CLI.

Exercises the top-level dispatcher in ``scanner/cli.py`` by invoking it as
a subprocess (``python -m scanner.cli ...``) so the orchestrator's
``--mode`` argument parsing is exercised end-to-end (rather than via an
in-process call). The suite is hermetic: every test uses ``tmp_path``
for both the consumer Terraform repo and the run-dir, so the real
``~/.pacioli/runs/`` is never touched.

Test inventory (mirrors the plan's MUST-DO contract for this file):

  * ``--help`` exits 0 for every subcommand (``scan``, ``gate``,
    ``aggregate``, ``audit``, ``baseline init``).
  * End-to-end ``pacioli scan <tmpdir>`` produces
    ``<output-dir>/aggregate/report.html``.
  * ``pacioli gate <nonexistent>`` exits non-zero.
  * ``pacioli aggregate <run-dir>`` re-emits the aggregate report.

NOTE on the aggregate bug
-------------------------
The ``pacioli aggregate <run-dir>`` subcommand now falls back to the
install-bundled mapping via ``importlib.resources`` when the default
``pci_mapping.yaml`` is not found alongside the run-dir. This test
runs without ``--mapping`` to exercise that fallback as a regression
guard.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

# Make ``import scanner`` resolve the worktree's scanner/ package.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(*args: str, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    """Invoke the standalone ``pacioli`` CLI as a child process.

    Returns the :class:`subprocess.CompletedProcess` so callers can
    inspect ``returncode`` / ``stdout`` / ``stderr``. The child runs
    from the worktree root (so ``scanner`` is importable) and inherits
    the caller's environment plus any overrides.
    """
    cmd = [sys.executable, "-m", "scanner.cli", *args]
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env=merged_env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _make_minimal_tf_repo(root: Path) -> Path:
    """Materialise a minimal consumer Terraform repo at ``root``.

    Returns the consumer repo path. The repo contains a single
    ``null_resource`` under ``env/myapp/prod/main.tf`` so the scan has
    something to discover without producing HIGH/CRITICAL findings
    (which would force the gate-mode rc != 0).
    """
    env_dir = root / "env" / "myapp" / "prod"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / "main.tf").write_text(
        'resource "null_resource" "smoke" {}\n',
        encoding="utf-8",
    )
    return root


# ---------------------------------------------------------------------------
# 1-5. --help exits 0 for every subcommand
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "subcommand_args",
    [
        ["scan", "--help"],
        ["gate", "--help"],
        ["aggregate", "--help"],
        ["audit", "--help"],
        ["baseline", "init", "--help"],
    ],
    ids=["scan-help", "gate-help", "aggregate-help", "audit-help", "baseline-init-help"],
)
def test_subcommand_help_exits_zero(subcommand_args: list[str]) -> None:
    """Every subcommand's ``--help`` exits 0 and emits a usage banner.

    argparse prints help to stdout and returns 0 — this catches any
    future regression where a subcommand loses its parser wiring
    (e.g. someone forgets to register the subparser under
    ``add_subparsers``).
    """
    result = _run_cli(*subcommand_args)
    assert result.returncode == 0, (
        f"subcommand {' '.join(subcommand_args)} returned rc={result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    # argparse prints ``usage:`` at the top of every --help banner.
    assert "usage:" in result.stdout, (
        f"unexpected --help output for {' '.join(subcommand_args)}: "
        f"{result.stdout[:200]!r}"
    )


# ---------------------------------------------------------------------------
# 6. End-to-end pacioli scan produces report.html
# ---------------------------------------------------------------------------


def test_pacioli_scan_end_to_end_produces_report(tmp_path: Path) -> None:
    """End-to-end ``pacioli scan <tmpdir>`` produces ``report.html``.

    Exercises the full pipeline: discovery → checkov passes → aggregate
    → HTML report. Uses ``null_resource`` (zero findings) so the scan
    returns rc=0 in --mode report and the gate auto-promotion does not
    trigger (we don't set ``CI=1``).
    """
    target_repo = _make_minimal_tf_repo(tmp_path / "repo")
    output_dir = tmp_path / "runs"

    result = _run_cli(
        "scan",
        str(target_repo),
        "--output-dir",
        str(output_dir),
        "--non-interactive",
        timeout=180,
    )

    assert result.returncode == 0, (
        f"pacioli scan returned rc={result.returncode}; "
        f"stdout={result.stdout[-1000:]!r} "
        f"stderr={result.stderr[-1000:]!r}"
    )

    # The aggregate step writes report.html under <output-dir>/aggregate/.
    report = output_dir / "aggregate" / "report.html"
    assert report.is_file(), (
        f"scan did not produce aggregate/report.html under {output_dir}; "
        f"contents of {output_dir}: {sorted(p.name for p in output_dir.rglob('*'))}"
    )
    # Sanity-check the report is non-trivial HTML (checkov SARIFs alone
    # are <2 KB; the rendered HTML report is much larger).
    assert report.stat().st_size > 1024, (
        f"report.html suspiciously small ({report.stat().st_size} bytes); "
        "check whether the HTML renderer ran end-to-end"
    )


# ---------------------------------------------------------------------------
# 7. pacioli gate <nonexistent> exits non-zero
# ---------------------------------------------------------------------------


def test_pacioli_gate_nonexistent_target_exits_nonzero(tmp_path: Path) -> None:
    """``pacioli gate <nonexistent>`` exits non-zero with an ERROR log.

    Mirrors the dispatcher's PathResolutionError branch: when the
    target repo doesn't exist, ``scanner.cli._handle_gate`` resolves
    ``--target-repo`` from the positional, the orchestrator's
    ``resolve_paths`` raises :class:`PathResolutionError`, and the
    orchestrator's ``main()`` catches it and returns rc=2.
    """
    nonexistent = tmp_path / "definitely_not_a_repo_xyz"
    assert not nonexistent.exists(), "pre-condition: path must not exist"

    result = _run_cli("gate", str(nonexistent), "--non-interactive", timeout=30)

    assert result.returncode != 0, (
        f"pacioli gate <nonexistent> returned rc=0; "
        f"stderr={result.stderr!r}"
    )
    # The orchestrator logs the path-resolution error to stderr before
    # returning 2 — verify it surfaced so operators see the cause.
    assert "does not exist" in result.stderr or "ERROR" in result.stderr, (
        f"expected an ERROR log on stderr; got {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# 8. pacioli aggregate <run-dir> re-emits the report
# ---------------------------------------------------------------------------


def test_pacioli_aggregate_reemits_report(tmp_path: Path) -> None:
    """``pacioli aggregate <run-dir>`` re-emits ``aggregate/report.html``.

    Builds a run-dir via the scan, deletes the produced
    ``aggregate/report.html``, then runs ``pacioli aggregate`` (no
    ``--mapping``) to confirm it re-emits the HTML report without
    re-running checkov. Exercises the install-bundled fallback path:
    when the run-dir is in a tmpdir there's no ``.git`` ancestor and
    no ``pci_mapping.yaml`` alongside, so the aggregator must fall
    back to the mapping shipped via ``importlib.resources``.
    """
    target_repo = _make_minimal_tf_repo(tmp_path / "repo")
    output_dir = tmp_path / "runs"

    # Build the run-dir via scan (rc=0; produces per-pair SARIFs +
    # aggregate/report.html).
    scan_result = _run_cli(
        "scan",
        str(target_repo),
        "--output-dir",
        str(output_dir),
        "--non-interactive",
        timeout=180,
    )
    assert scan_result.returncode == 0, (
        f"setup scan failed rc={scan_result.returncode}; "
        f"stderr={scan_result.stderr[-500:]!r}"
    )

    report_path = output_dir / "aggregate" / "report.html"
    assert report_path.is_file(), (
        f"setup: scan did not produce {report_path}"
    )

    # Snapshot the existing report, delete it, then re-aggregate.
    pre_bytes = report_path.read_bytes()
    report_path.unlink()
    assert not report_path.exists(), "setup: failed to delete report.html"

    # No --mapping flag — exercises the install-bundled fallback in
    # scanner/aggregate.py main() (the default must resolve to the
    # mapping shipped via importlib.resources.files("scanner")).
    agg_result = _run_cli(
        "aggregate", str(output_dir),
        timeout=60,
    )
    assert agg_result.returncode == 0, (
        f"pacioli aggregate returned rc={agg_result.returncode}; "
        f"stdout={agg_result.stdout[-1000:]!r} "
        f"stderr={agg_result.stderr[-1000:]!r}"
    )

    assert report_path.is_file(), (
        f"pacioli aggregate did not re-emit {report_path}; "
        f"contents of aggregate/: {sorted(p.name for p in (output_dir / 'aggregate').iterdir())}"
    )
    # The aggregator rebuilds the report from scratch — the new bytes
    # don't have to match the prior report (timestamps etc.), but they
    # must be non-trivial HTML.
    assert report_path.stat().st_size > 1024, (
        f"re-emitted report.html suspiciously small "
        f"({report_path.stat().st_size} bytes)"
    )
    assert b"<html" in report_path.read_bytes()[:4096].lower(), (
        "re-emitted report.html does not look like HTML"
    )
    # Belt-and-suspenders: the prior and re-emitted reports must
    # differ (otherwise we silently re-emitted an identical file, which
    # could mask a no-op aggregate path).
    post_bytes = report_path.read_bytes()
    assert pre_bytes != post_bytes or len(pre_bytes) == 0, (
        "re-emitted report.html is byte-identical to the prior report; "
        "the aggregator likely no-op'd"
    )
