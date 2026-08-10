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

import argparse
import os
import subprocess
import sys
import warnings
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


# ---------------------------------------------------------------------------
# Direct unit tests for the handler helpers in scanner/cli.py
# ---------------------------------------------------------------------------
#
# These tests bypass subprocess invocation and exercise each handler
# in-process. Downstream calls (orchestrator.main, aggregate.main,
# baseline_init.main, _az_blob_download, _resolve_latest_remote_run_id)
# are mocked via ``monkeypatch.setattr`` so we never touch Azure.
#
# The original 8 tests above are unchanged; this section adds 10
# direct unit tests as required by the full-pr test-coverage plan.


def _make_args(**kwargs: object) -> argparse.Namespace:
    """Build an ``argparse.Namespace`` seeded with safe defaults.

    Centralised so the unit tests below don't all repeat the same
    ``Namespace(...)`` boilerplate. Only overrides the keys that the
    handler reads, leaving everything else at ``None`` / ``False``.
    """
    base: dict[str, object] = {
        "target_dir": None,
        "target_repo": None,
        "tier": "source",
        "mode": "report",
        "mapping": None,
        "baseline": None,
        "output_dir": None,
        "project": None,
        "env": None,
        "label": None,
        "state_account": None,
        "source_value": None,
        "dry_run": False,
        "verbose": False,
        "non_interactive": False,
        "scan_state": False,
        "scan_plan": False,
        "scope": None,
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# 9. _apply_backcompat order-of-precedence
# ---------------------------------------------------------------------------


def test_apply_backcompat_state_wins_over_plan() -> None:
    """``--scan-state`` > ``--scan-plan``: final tier must be ``state``.

    Mirrors scanner/cli.py:262-273: when both aliases are set, the
    state branch fires first and escalates to ``tier='state'``. The
    subsequent plan branch sees ``tier != 'source'`` and bails out,
    so the final tier is ``state`` — never ``plan``.
    """
    from scanner.cli import _apply_backcompat

    args = _make_args(scan_state=True, scan_plan=True)
    with warnings.catch_warnings():
        # _apply_backcompat calls _emit_deprecation which calls
        # warnings.simplefilter("always", DeprecationWarning); the
        # catch block keeps the test output clean and still records
        # the warning so we can assert it was emitted.
        warnings.simplefilter("always")
        out = _apply_backcompat(args)

    assert out.tier == "state", (
        f"--scan-state should win over --scan-plan; got tier={out.tier!r}"
    )


def test_apply_backcompat_plan_only_escalates_to_plan() -> None:
    """``--scan-plan`` alone escalates ``tier`` from ``source`` to ``plan``."""
    from scanner.cli import _apply_backcompat

    args = _make_args(scan_plan=True)
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        out = _apply_backcompat(args)

    assert out.tier == "plan", (
        f"--scan-plan alone should set tier=plan; got tier={out.tier!r}"
    )


def test_apply_backcompat_scope_alias_only_when_baseline_unset() -> None:
    """``--scope`` translates to ``--baseline`` only when ``--baseline`` is unset.

    Mirrors scanner/cli.py:275-281: explicit ``--baseline`` wins over
    the deprecated ``--scope`` alias (so a user opting into the new
    flag gets a deterministic override).
    """
    from scanner.cli import _apply_backcompat

    # Scope fills baseline when baseline is None
    args = _make_args(scope="scope.yaml")
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        out = _apply_backcompat(args)
    assert out.baseline == "scope.yaml", (
        f"--scope should populate baseline; got baseline={out.baseline!r}"
    )

    # Explicit --baseline wins over --scope
    args = _make_args(scope="scope.yaml", baseline="real.yaml")
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        out = _apply_backcompat(args)
    assert out.baseline == "real.yaml", (
        f"--baseline should win over --scope; got baseline={out.baseline!r}"
    )


# ---------------------------------------------------------------------------
# 10. _emit_deprecation emits both a DeprecationWarning and a stderr line
# ---------------------------------------------------------------------------


def test_emit_deprecation_warns_and_prints(capsys: pytest.CaptureFixture[str]) -> None:
    """``_emit_deprecation`` raises a DeprecationWarning AND prints to stderr.

    The handler has belt-and-suspenders output: the warnings module so
    Python tooling (``-W error::DeprecationWarning``) sees it, and a
    direct stderr write so operators tailing stderr see it even when
    warnings are filtered.
    """
    from scanner.cli import _emit_deprecation

    with pytest.warns(DeprecationWarning, match=r"--scan-state"):
        _emit_deprecation("--scan-state", "--tier state")

    captured = capsys.readouterr()
    assert "WARNING:" in captured.err, (
        f"_emit_deprecation should also print to stderr; got err={captured.err!r}"
    )
    assert "--scan-state" in captured.err, (
        f"stderr line should mention the deprecated flag; got err={captured.err!r}"
    )


# ---------------------------------------------------------------------------
# 11. _handle_scan delegates to orchestrator.main with the right argv
# ---------------------------------------------------------------------------


def test_handle_scan_passes_args_to_orchestrator_main(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_scan`` translates the namespace into orchestrator argv.

    Mocks ``scanner.orchestrator.main`` to capture the argv it
    receives. Asserts the positional ``target_repo`` is passed via
    ``--target-repo`` (orchestrator uses a flag, not a positional)
    and that ``--tier`` / ``--mode`` defaults propagate.
    """
    from scanner import cli

    captured: dict[str, object] = {}

    def fake_main(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 0

    # The handler does ``from scanner import orchestrator as _orchestrator``
    # then calls ``_orchestrator.main(argv)``. We patch
    # ``scanner.orchestrator.main`` so the late-bound import picks up
    # the fake.
    import scanner.orchestrator as orchestrator_mod
    monkeypatch.setattr(orchestrator_mod, "main", fake_main)

    repo = tmp_path / "repo"
    repo.mkdir()
    args = _make_args(
        target_dir=str(repo),
        tier="plan",
        mode="report",
        state_account="mystorageacct",
    )
    rc = cli._handle_scan(args)
    assert rc == 0, f"_handle_scan returned {rc}; expected 0"
    argv = captured["argv"]
    assert "--target-repo" in argv, f"missing --target-repo in argv={argv!r}"
    assert "--tier" in argv and argv[argv.index("--tier") + 1] == "plan"
    assert "--mode" in argv and argv[argv.index("--mode") + 1] == "report"
    assert "--state-account" in argv, (
        f"--state-account missing in argv={argv!r}"
    )


# ---------------------------------------------------------------------------
# 12. _handle_gate forces --mode gate
# ---------------------------------------------------------------------------


def test_handle_gate_forces_mode_gate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_gate`` overrides whatever ``--mode`` the user passed.

    Mirrors scanner/cli.py:353: ``args.mode = "gate"`` is unconditional.
    """
    from scanner import cli

    captured: dict[str, object] = {}

    def fake_main(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 0

    import scanner.orchestrator as orchestrator_mod
    monkeypatch.setattr(orchestrator_mod, "main", fake_main)

    repo = tmp_path / "repo"
    repo.mkdir()
    # User passed --mode report (the default). Gate must override.
    args = _make_args(target_dir=str(repo), mode="report")
    rc = cli._handle_gate(args)
    assert rc == 0, f"_handle_gate returned {rc}; expected 0"
    argv = captured["argv"]
    assert argv[argv.index("--mode") + 1] == "gate", (
        f"_handle_gate must force --mode gate; got argv={argv!r}"
    )


# ---------------------------------------------------------------------------
# 13. _handle_aggregate argv wiring preserves --emit-fix-list
# ---------------------------------------------------------------------------


def test_handle_aggregate_preserves_emit_fix_list(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_aggregate`` passes ``--emit-fix-list`` to ``aggregate.main``.

    The handler swaps ``sys.argv`` for the call and restores it on
    exit (mirrors the orchestrator's argv-swap pattern). Mocks
    ``scanner.aggregate.main`` to capture the argv it sees.
    """
    from scanner import cli

    captured: dict[str, object] = {}

    def fake_main() -> int:
        # aggregate.main reads sys.argv directly (line 395 in cli.py:
        # ``sys.argv = aggregate_argv`` before the call).
        captured["argv"] = list(sys.argv)
        return 0

    import scanner.aggregate as aggregate_mod
    monkeypatch.setattr(aggregate_mod, "main", fake_main)

    run_dir = tmp_path / "rundir"
    run_dir.mkdir()
    saved_argv = sys.argv
    try:
        args = argparse.Namespace(
            run_dir=str(run_dir),
            mapping="m.yaml",
            baseline="b.yaml",
            out="/tmp/o",
            emit_fix_list=True,
        )
        rc = cli._handle_aggregate(args)
    finally:
        sys.argv = saved_argv

    assert rc == 0, f"_handle_aggregate returned {rc}; expected 0"
    argv = captured["argv"]
    assert "--emit-fix-list" in argv, (
        f"--emit-fix-list missing from aggregate argv={argv!r}"
    )
    assert "--run-dir" in argv, f"--run-dir missing from argv={argv!r}"
    assert "--mapping" in argv, f"--mapping missing from argv={argv!r}"
    assert "--baseline" in argv, f"--baseline missing from argv={argv!r}"
    # Belt-and-suspenders: sys.argv must be restored after the call.
    assert sys.argv == saved_argv, (
        f"_handle_aggregate must restore sys.argv; got {sys.argv!r}"
    )


def test_handle_aggregate_without_run_dir_returns_2() -> None:
    """``_handle_aggregate`` with no ``run_dir`` returns 2 and skips the call."""
    from scanner import cli

    args = argparse.Namespace(
        run_dir=None,
        mapping=None,
        baseline=None,
        out=None,
        emit_fix_list=False,
    )
    rc = cli._handle_aggregate(args)
    assert rc == 2, f"expected rc=2 for missing run_dir; got rc={rc}"


# ---------------------------------------------------------------------------
# 14. _resolve_latest_run_dir returns None / freshest
# ---------------------------------------------------------------------------


def test_resolve_latest_run_dir_returns_none_on_empty_root(tmp_path: Path) -> None:
    """``_resolve_latest_run_dir`` returns ``None`` when no candidates exist."""
    from scanner.cli import _resolve_latest_run_dir

    empty_runs = tmp_path / "runs"
    empty_runs.mkdir()
    assert _resolve_latest_run_dir(empty_runs) is None, (
        "expected None for empty runs root"
    )


def test_resolve_latest_run_dir_returns_freshest_mtime(tmp_path: Path) -> None:
    """``_resolve_latest_run_dir`` returns the most-recently-modified subdir.

    Creates three subdirs with distinct mtimes (oldest first, freshest
    last) and asserts the freshest is returned.
    """
    from scanner.cli import _resolve_latest_run_dir

    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    a = runs_root / "run-old"
    b = runs_root / "run-mid"
    c = runs_root / "run-new"
    for d in (a, b, c):
        d.mkdir()

    # Force distinct mtimes by walking forward in 1-second steps; on
    # Windows mtime resolution is ~2s so we use larger deltas.
    import time

    base_mtime = time.time() - 10_000
    os.utime(a, (base_mtime, base_mtime))
    os.utime(b, (base_mtime + 100, base_mtime + 100))
    os.utime(c, (base_mtime + 200, base_mtime + 200))

    latest = _resolve_latest_run_dir(runs_root)
    assert latest == c, (
        f"expected freshest dir (run-new); got {latest!r}"
    )


def test_resolve_latest_run_dir_returns_none_when_root_missing(tmp_path: Path) -> None:
    """``_resolve_latest_run_dir`` returns ``None`` when the root itself is absent."""
    from scanner.cli import _resolve_latest_run_dir

    missing = tmp_path / "does_not_exist_runs_root"
    assert not missing.exists(), "pre-condition: root must not exist"
    assert _resolve_latest_run_dir(missing) is None, (
        "expected None for missing runs root"
    )


# ---------------------------------------------------------------------------
# 15. _resolve_report_html is a silent no-op when source HTML is missing
# ---------------------------------------------------------------------------


def test_resolve_report_html_noop_when_source_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``_resolve_report_html`` logs a WARN and does nothing if ``report.html`` is absent.

    Mirrors scanner/cli.py:438-451: when the source report.html is
    missing the handler must not crash, must not create the dest
    file, and must emit a WARN log so operators see what happened.
    """
    from scanner.cli import _resolve_report_html

    aggregate_dir = tmp_path / "aggregate"
    aggregate_dir.mkdir()
    out_path = tmp_path / "out" / "report.html"
    # Pre-condition: out_path must NOT exist so we can prove no-op.
    assert not out_path.exists()
    assert not (aggregate_dir / "report.html").exists()

    _resolve_report_html(aggregate_dir, str(out_path))

    assert not out_path.exists(), (
        f"_resolve_report_html should be a no-op; created {out_path!r}"
    )
    captured = capsys.readouterr()
    assert "WARN" in captured.err, (
        f"expected a WARN log on stderr; got {captured.err!r}"
    )
    assert "report.html" in captured.err, (
        f"WARN should mention report.html; got {captured.err!r}"
    )


def test_resolve_report_html_copies_when_source_present(tmp_path: Path) -> None:
    """``_resolve_report_html`` copies ``report.html`` when source exists."""
    from scanner.cli import REPORT_FILENAME, _resolve_report_html

    aggregate_dir = tmp_path / "aggregate"
    aggregate_dir.mkdir()
    src = aggregate_dir / REPORT_FILENAME
    src.write_bytes(b"<html>ok</html>\n")

    out_path = tmp_path / "out" / "report.html"
    _resolve_report_html(aggregate_dir, str(out_path))

    assert out_path.is_file(), f"expected {out_path} to exist"
    assert out_path.read_bytes() == b"<html>ok</html>\n", (
        "copied bytes should match source verbatim"
    )


# ---------------------------------------------------------------------------
# 16. _handle_audit_local in --latest mode uses _resolve_latest_run_dir
# ---------------------------------------------------------------------------


def test_handle_audit_local_with_run_id_copies_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_audit_local --run-id <id>`` reads ``report.html`` from <runs>/<id>/aggregate/.

    Patches ``Path.home`` so the handler looks under ``tmp_path``
    instead of the real ``~/.pacioli/runs/`` (hermetic test).
    """
    from scanner import cli

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)

    runs_root = tmp_path / ".pacioli" / "runs"
    run_id = "20260804T153407Z-2455"
    aggregate_dir = runs_root / run_id / "aggregate"
    aggregate_dir.mkdir(parents=True)
    (aggregate_dir / "report.html").write_bytes(b"<html>audit</html>\n")

    args = argparse.Namespace(
        latest=False,
        run_id=run_id,
        out=str(tmp_path / "out" / "report.html"),
    )
    rc = cli._handle_audit_local(args)
    assert rc == 0, f"_handle_audit_local returned {rc}; expected 0"
    assert (tmp_path / "out" / "report.html").is_file(), (
        f"expected report.html copied to {(tmp_path / 'out' / 'report.html')!r}"
    )


def test_handle_audit_local_without_run_id_or_latest_returns_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_audit_local`` without ``--latest`` or ``--run-id`` returns 2."""
    from scanner import cli

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)

    args = argparse.Namespace(latest=False, run_id=None, out=None)
    rc = cli._handle_audit_local(args)
    assert rc == 2, f"expected rc=2; got rc={rc}"


# ---------------------------------------------------------------------------
# 17. _handle_audit_remote returns 2 when PACIOLI_STATE_STORAGE_ACCOUNT is unset
# ---------------------------------------------------------------------------


def test_handle_audit_remote_returns_2_when_storage_account_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_handle_audit_remote`` refuses with rc=2 when storage account is unset.

    Defense in depth: mirrors scan_audit.sh lines 74-81. The handler
    must NOT contact Azure; it must short-circuit before invoking
    ``_resolve_latest_remote_run_id`` or ``_az_blob_download``.
    """
    from scanner import cli

    # Clear the env var. ``monkeypatch.delenv`` raises if the var
    # isn't set in the test process — use ``raising=False`` so the
    # test works regardless of host environment.
    monkeypatch.delenv("PACIOLI_STATE_STORAGE_ACCOUNT", raising=False)
    # Also force args.state_account to None in case the host has it
    # set (defensive — the handler checks args.state_account first).
    args = argparse.Namespace(
        latest=True,
        run_id=None,
        out=None,
        state_account=None,
        dry_run=True,
    )

    # Spy on the would-be Azure-touching helpers; they MUST NOT run.
    called: dict[str, int] = {"resolve_latest": 0, "az_download": 0}

    def fake_resolve_latest(
        *, storage_account: str, container_name: str, dry_run: bool
    ) -> str | None:
        called["resolve_latest"] += 1
        return "DRYRUN-LATEST"

    def fake_az_download(
        *,
        storage_account: str,
        container_name: str,
        blob_name: str,
        dest: Path,
        dry_run: bool,
    ) -> bool:
        called["az_download"] += 1
        return True

    monkeypatch.setattr(cli, "_resolve_latest_remote_run_id", fake_resolve_latest)
    monkeypatch.setattr(cli, "_az_blob_download", fake_az_download)

    rc = cli._handle_audit_remote(args)

    assert rc == 2, (
        f"_handle_audit_remote must refuse without storage account; got rc={rc}"
    )
    assert called["resolve_latest"] == 0, (
        "_resolve_latest_remote_run_id must NOT be called when storage account is unset"
    )
    assert called["az_download"] == 0, (
        "_az_blob_download must NOT be called when storage account is unset"
    )


# ---------------------------------------------------------------------------
# 18. _handle_audit_remote dry-run path uses DRYRUN-LATEST and prints
# ---------------------------------------------------------------------------


def test_handle_audit_remote_dry_run_skips_azure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--dry-run`` mode contacts no Azure: the latest-run-id is faked and prints to stdout.

    Patches both ``_resolve_latest_remote_run_id`` and
    ``_az_blob_download`` to record their invocations. Verifies the
    handler does call them (in dry-run mode it short-circuits before
    any real ``az storage blob ...`` subprocess), and that the
    download print prefix is "[dry-run]".
    """
    from scanner import cli

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("PACIOLI_STATE_STORAGE_ACCOUNT", "fakeacct")

    downloaded: list[dict[str, object]] = []

    def fake_resolve_latest(
        *, storage_account: str, container_name: str, dry_run: bool
    ) -> str | None:
        assert dry_run is True, "dry_run flag must propagate"
        assert storage_account == "fakeacct"
        return "DRYRUN-LATEST"

    def fake_az_download(
        *,
        storage_account: str,
        container_name: str,
        blob_name: str,
        dest: Path,
        dry_run: bool,
    ) -> bool:
        downloaded.append(
            {
                "storage_account": storage_account,
                "container_name": container_name,
                "blob_name": blob_name,
                "dest": str(dest),
                "dry_run": dry_run,
            }
        )
        # Mirror the real handler's dry-run print so we exercise the
        # branch even though no subprocess ran.
        print(
            f"[dry-run] az storage blob download "
            f"--account-name {storage_account} "
            f"--container-name {container_name} "
            f"--name {blob_name} --file {dest}"
        )
        return True

    monkeypatch.setattr(cli, "_resolve_latest_remote_run_id", fake_resolve_latest)
    monkeypatch.setattr(cli, "_az_blob_download", fake_az_download)

    args = argparse.Namespace(
        latest=True,
        run_id=None,
        out=None,
        state_account=None,
        dry_run=True,
    )
    rc = cli._handle_audit_remote(args)
    assert rc == 0, f"_handle_audit_remote dry-run returned {rc}; expected 0"

    # Four artifacts downloaded: coverage_matrix.csv, combined.sarif,
    # junit.xml, report.html.
    assert len(downloaded) == 4, (
        f"expected 4 dry-run downloads; got {len(downloaded)}: {downloaded!r}"
    )
    expected_blobs = {
        "coverage_matrix.csv",
        "combined.sarif",
        "junit.xml",
        "report.html",
    }
    assert {d["blob_name"].rsplit("/", 1)[-1] for d in downloaded} == expected_blobs, (
        f"unexpected blob names: {[d['blob_name'] for d in downloaded]!r}"
    )
    for d in downloaded:
        assert d["dry_run"] is True, (
            f"all downloads should be dry-run; got {d['dry_run']!r}"
        )
    captured = capsys.readouterr()
    assert "[dry-run]" in captured.out, (
        f"dry-run downloads should print [dry-run] markers; got {captured.out!r}"
    )


# ---------------------------------------------------------------------------
# 19. _handle_baseline argv wiring preserves --append / --top / --dry-run
# ---------------------------------------------------------------------------


def test_handle_baseline_passes_append_top_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_handle_baseline`` translates the namespace into baseline_init argv.

    Mocks ``scanner.baseline_init.main`` to capture the argv it
    receives. Asserts ``--run-dir`` (positional -> flag translation),
    ``--append``, ``--top``, and ``--dry-run`` all propagate.
    """
    from scanner import cli

    captured: dict[str, object] = {}

    def fake_main(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 0

    import scanner.baseline_init as baseline_init_mod
    monkeypatch.setattr(baseline_init_mod, "main", fake_main)

    args = argparse.Namespace(
        run_dir="/tmp/some/run-dir",
        baseline="b.yaml",
        top=25,
        append=True,
        dry_run=True,
    )
    rc = cli._handle_baseline(args)
    assert rc == 0, f"_handle_baseline returned {rc}; expected 0"
    argv = captured["argv"]
    assert "--run-dir" in argv, f"--run-dir missing; argv={argv!r}"
    assert "--baseline" in argv, f"--baseline missing; argv={argv!r}"
    assert "--top" in argv and argv[argv.index("--top") + 1] == "25", (
        f"--top value should be '25'; argv={argv!r}"
    )
    assert "--append" in argv, f"--append missing; argv={argv!r}"
    assert "--dry-run" in argv, f"--dry-run missing; argv={argv!r}"


# ---------------------------------------------------------------------------
# Section E (--no-open flag + _maybe_open_report helper coverage)
# ---------------------------------------------------------------------------
#
# These tests cover the ``--no-open`` CLI flag (added by Section A) and
# the module-level ``_maybe_open_report`` helper (added by Section C,
# invoked by the audit handlers). Mirrors scanner/tests/test_orchestrator.py
# additions for ``Orchestrator._open_report``.


def test_no_open_flag_accepted_on_scan_and_gate() -> None:
    """``--no-open`` parses cleanly on both ``pacioli scan`` and ``pacioli gate``.

    Regression guard: argparse strips any flag it does not recognise,
    so the only way the option text reaches stdout is if the subparser
    registered it.
    """
    for sub in ("scan", "gate"):
        result = _run_cli(sub, "--help")
        assert result.returncode == 0, (
            f"{sub} --help failed; rc={result.returncode}; stderr={result.stderr!r}"
        )
        assert "--no-open" in result.stdout, (
            f"{sub} --help should advertise --no-open; got stdout={result.stdout!r}"
        )


def test_audit_accepts_no_open_flag() -> None:
    """``--no-open`` parses cleanly on ``pacioli audit``.

    Mirrors :func:`test_no_open_flag_accepted_on_scan_and_gate` but for
    the audit subcommand. The audit subparser is built independently
    of scan/gate, so it gets its own acceptance test.
    """
    result = _run_cli("audit", "--help")
    assert result.returncode == 0, (
        f"audit --help failed; rc={result.returncode}; stderr={result.stderr!r}"
    )
    assert "--no-open" in result.stdout, (
        f"audit --help should advertise --no-open; got stdout={result.stdout!r}"
    )


def test_audit_local_out_triggers_maybe_open_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_audit_local --out`` calls ``_maybe_open_report`` with the resolved path.

    Builds a hermetic run-dir under ``tmp_path / ".pacioli" / "runs" /
    test-run / aggregate / report.html`` and patches ``cli.Path.home``
    so the handler reads from ``tmp_path`` instead of the real ``~``.
    ``_maybe_open_report`` is replaced with a capturing fake so we can
    assert on its (positional ``path``, keyword ``no_open``) without
    touching any real browser.

    Also exercises the parallel ``no_open=True`` case to prove the
    flag propagates from args all the way to the helper.
    """
    from scanner import cli

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)

    runs_root = tmp_path / ".pacioli" / "runs" / "test-run"
    (runs_root / "aggregate").mkdir(parents=True)
    (runs_root / "aggregate" / "report.html").write_bytes(b"<html>x</html>\n")

    captured: list[tuple[Path, bool]] = []

    def fake_maybe_open_report(path: Path, *, no_open: bool) -> None:
        captured.append((path, no_open))

    monkeypatch.setattr(cli, "_maybe_open_report", fake_maybe_open_report)

    out_path = tmp_path / "out" / "report.html"

    # Case A: ``no_open=False`` (default) — the helper is invoked with
    # ``no_open=False`` so an operator running interactively gets the
    # auto-open behaviour.
    args_default = argparse.Namespace(
        latest=False,
        run_id="test-run",
        out=str(out_path),
        no_open=False,
    )
    rc = cli._handle_audit_local(args_default)
    assert rc == 0, f"_handle_audit_local(no_open=False) returned {rc}; expected 0"
    assert len(captured) == 1, (
        f"_maybe_open_report should be called exactly once; got {captured!r}"
    )
    path_a, no_open_a = captured[0]
    assert path_a == Path(str(out_path)), (
        f"_maybe_open_report path arg mismatch; expected {out_path!r}, got {path_a!r}"
    )
    assert no_open_a is False, (
        f"_maybe_open_report no_open kwarg should be False; got {no_open_a!r}"
    )

    # Case B: ``no_open=True`` — same flow, helper receives
    # ``no_open=True`` so a CI / scripted invocation stays quiet.
    captured.clear()
    args_quiet = argparse.Namespace(
        latest=False,
        run_id="test-run",
        out=str(out_path),
        no_open=True,
    )
    rc = cli._handle_audit_local(args_quiet)
    assert rc == 0, f"_handle_audit_local(no_open=True) returned {rc}; expected 0"
    assert len(captured) == 1, (
        f"_maybe_open_report should be called exactly once; got {captured!r}"
    )
    path_b, no_open_b = captured[0]
    assert path_b == Path(str(out_path)), (
        f"_maybe_open_report path arg mismatch; expected {out_path!r}, got {path_b!r}"
    )
    assert no_open_b is True, (
        f"_maybe_open_report no_open kwarg should be True; got {no_open_b!r}"
    )


def test_audit_remote_out_triggers_maybe_open_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_audit_remote --out`` calls ``_maybe_open_report`` after download.

    Mirrors the local case but for the remote branch: pre-creates the
    run-dir under ``tmp_path / ".pacioli" / "runs" / <run_id> /
    aggregate / report.html`` so ``_resolve_report_html`` finds the
    source HTML on disk (the fake ``_az_blob_download`` is a no-op),
    then asserts the helper was called with the resolved ``--out``
    path.
    """
    from scanner import cli

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("PACIOLI_STATE_STORAGE_ACCOUNT", "fakeacct")

    run_id = "20260804T153407Z-2455"
    remote_aggregate_dir = tmp_path / ".pacioli" / "runs" / run_id / "aggregate"
    remote_aggregate_dir.mkdir(parents=True)
    (remote_aggregate_dir / "report.html").write_bytes(b"<html>remote</html>\n")
    # The four other artifacts are referenced by the handler; touch
    # them so the copy step (which calls ``_resolve_report_html``) finds
    # every input it expects from the same fake ``_az_blob_download``.
    for fname in ("coverage_matrix.csv", "combined.sarif", "junit.xml"):
        (remote_aggregate_dir / fname).write_text("stub", encoding="utf-8")

    def fake_resolve_latest(
        *, storage_account: str, container_name: str, dry_run: bool
    ) -> str:
        assert dry_run is True, "dry_run flag should propagate"
        assert storage_account == "fakeacct"
        return run_id

    def fake_az_blob_download(
        *,
        storage_account: str,
        container_name: str,
        blob_name: str,
        dest: Path,
        dry_run: bool,
    ) -> bool:
        assert dry_run is True
        # The handler expects each "downloaded" path to exist already
        # because the handler copies ``report.html`` from ``dest_dir``
        # later. Pre-create the file so the subsequent copy succeeds.
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            dest.write_bytes(b"<html>remote</html>\n")
        return True

    monkeypatch.setattr(cli, "_resolve_latest_remote_run_id", fake_resolve_latest)
    monkeypatch.setattr(cli, "_az_blob_download", fake_az_blob_download)

    captured: list[tuple[Path, bool]] = []

    def fake_maybe_open_report(path: Path, *, no_open: bool) -> None:
        captured.append((path, no_open))

    monkeypatch.setattr(cli, "_maybe_open_report", fake_maybe_open_report)

    out_path = tmp_path / "audit-out" / "report.html"
    args = argparse.Namespace(
        latest=True,
        run_id=None,
        out=str(out_path),
        state_account=None,
        no_open=False,
        dry_run=True,
    )
    rc = cli._handle_audit_remote(args)
    assert rc == 0, f"_handle_audit_remote returned {rc}; expected 0"

    assert len(captured) == 1, (
        f"_maybe_open_report should be called exactly once after remote download; "
        f"got {captured!r}"
    )
    path, no_open = captured[0]
    assert path == Path(str(out_path)), (
        f"_maybe_open_report path arg mismatch; expected {out_path!r}, got {path!r}"
    )
    assert no_open is False, (
        f"_maybe_open_report no_open kwarg should be False; got {no_open!r}"
    )

    # Verify the dest artifact actually landed in the local archive —
    # pre-condition for the report-copy + open step firing.
    assert (tmp_path / ".pacioli" / "runs" / run_id / "aggregate" / "report.html").is_file(), (
        "fake _az_blob_download should have materialised report.html locally"
    )


def test_maybe_open_report_skips_when_no_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_maybe_open_report`` is a silent no-op when ``no_open=True``.

    Mirrors the production behaviour: ``pacioli audit --no-open`` (or
    any operator who sets the flag explicitly) must NOT trigger a
    browser open. We patch ``webbrowser.open`` at the module level
    (where ``cli.py`` imported it) so the open never escapes.
    """
    from scanner import cli

    fake_target = tmp_path / "r.html"
    fake_target.write_text("<html></html>", encoding="utf-8")

    calls: list[str] = []

    def fake_open(url, *a, **k):
        calls.append(url)
        return True

    monkeypatch.setattr(cli.webbrowser, "open", fake_open)

    cli._maybe_open_report(fake_target, no_open=True)

    assert calls == [], (
        f"webbrowser.open should NOT be called when no_open=True; got calls={calls!r}"
    )


def test_maybe_open_report_calls_webbrowser(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_maybe_open_report`` opens the report when ``no_open=False``.

    Verifies the happy path: a real ``report.html`` on disk triggers
    exactly one ``webbrowser.open`` call with a URL that ends in
    ``r.html`` (the ``path.as_uri()`` representation).
    """
    from scanner import cli

    fake_target = tmp_path / "r.html"
    fake_target.write_text("<html></html>", encoding="utf-8")

    calls: list[str] = []

    def fake_open(url, *a, **k):
        calls.append(url)
        return True

    monkeypatch.setattr(cli.webbrowser, "open", fake_open)

    cli._maybe_open_report(fake_target, no_open=False)

    assert len(calls) == 1, (
        f"expected exactly one webbrowser.open call; got {len(calls)}: {calls!r}"
    )
    assert calls[0].endswith("r.html"), (
        f"webbrowser.open URL should end with 'r.html'; got {calls[0]!r}"
    )


def test_maybe_open_report_handles_webbrowser_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_maybe_open_report`` swallows ``webbrowser.open`` returning ``False``.

    No-browser-registered scenarios (headless containers, CI runners)
    cause ``webbrowser.open`` to return ``False`` rather than raise.
    The helper must not propagate this as an exception — failing to
    open the report must not mask the successful audit.
    """
    from scanner import cli

    fake_target = tmp_path / "r.html"
    fake_target.write_text("<html></html>", encoding="utf-8")

    def fake_open(*a, **k):
        return False

    monkeypatch.setattr(cli.webbrowser, "open", fake_open)

    # Assertion: no exception propagates out of the helper.
    cli._maybe_open_report(fake_target, no_open=False)
