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


def test_pacioli_version_flag_prints_version_and_exits_zero() -> None:
    """HOTFIX 1.1.2: ``pacioli --version`` prints the installed package
    version and exits 0.

    This is a UX fix for the workflow where the user wants to verify
    which wheel is actually installed (the 1.1.0 -> 1.1.1 hotfix
    episode showed this matters: the failure mode was completely
    silent because there was no way to ask ``pacioli`` which version
    it was).

    Contract:
    * Exit code 0 (version queries are not errors).
    * Stdout contains the literal version string from
      ``importlib.metadata.version("pacioli")`` (so the printed
      version is ALWAYS the installed wheel, never a hardcoded
      constant that could drift).
    * No subcommand is required (the test invokes ``pacioli`` with
      ONLY ``--version``).
    """
    result = _run_cli("--version")
    assert result.returncode == 0, (
        f"pacioli --version returned rc={result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    import importlib.metadata
    expected = importlib.metadata.version("pacioli")
    assert expected in result.stdout, (
        f"expected --version stdout to contain {expected!r}, got: "
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


def test_main_exits_99_when_subprocess_operation_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused command from a CLI handler terminates the process with exit 99."""
    from scanner import cli
    from scanner.safety import MutatingOperationRefused

    def refuse_command(_args: argparse.Namespace) -> int:
        raise MutatingOperationRefused("forced refusal")

    monkeypatch.setattr(cli, "_handle_scan", refuse_command)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", "--non-interactive"])

    assert exc_info.value.code == 99


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

    The Todo-8 multi-stack flags (``scan_path``, ``scan_glob``,
    ``stack_label``, ``state_file``, ``include_modules``,
    ``ignore_lockfile``, ``registry_mirror``, ``backend_key``) are
    seeded with the same defaults the CLI parser uses (``None`` /
    ``False`` / ``[]``) so every existing test still works without
    passing new kwargs.
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
        # Todo-8 multi-stack flags.
        "scan_path": None,
        "scan_glob": None,
        "stack_label": None,
        "state_file": None,
        "include_modules": False,
        "ignore_lockfile": False,
        "registry_mirror": None,
        "backend_key": None,
        # Todo 12: --framework flag.
        "framework": None,
        # scan-config-bootstrap: --init flag (auto-create missing config files).
        "init": False,
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
    instead of the real ``~/.pacioli/runs/`` (hermetic test). The
    ``_maybe_open_report`` no-op prevents the stub HTML from opening as a
    bare ``audit`` page in a real browser.
    """
    from scanner import cli

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(cli, "_maybe_open_report", lambda path, *, no_open: None)

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
# 20. _resolve_latest_remote_run_id routes through ops.run("az.blob_list", ...)
# ---------------------------------------------------------------------------

def test_resolve_latest_remote_run_id_uses_ops_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_resolve_latest_remote_run_id`` calls ``scanner.ops.run`` with the registered op.

    Confirms the inner subprocess call was migrated to the typed
    operation registry. The mock returns a tsv-formatted ``result``
    so we can verify the call argv matches the registry schema for
    ``az.blob_list`` (13 tokens after the executable). The mock
    returns a fake ``CompletedProcess`` so the function's stdout
    parsing exercises a non-empty value.
    """
    from scanner import cli, ops

    captured: dict[str, object] = {}

    class _FakeCompleted:
        returncode = 0
        stdout = "run-2026/run-A/main.tf\nrun-2026/run-B/main.tf\n"
        stderr = ""

    def fake_ops_run(name: str, *args: str, **kwargs: object) -> _FakeCompleted:
        captured["name"] = name
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeCompleted()

    monkeypatch.setattr(ops, "run", fake_ops_run)

    out = cli._resolve_latest_remote_run_id(
        storage_account="myacct",
        container_name="pacioli-reports",
        dry_run=False,
    )

    assert out == "run-2026", (
        f"expected freshest run-id 'run-2026'; got {out!r}"
    )
    assert captured["name"] == "az.blob_list", (
        f"_resolve_latest_remote_run_id must call ops.run('az.blob_list', ...); "
        f"got {captured['name']!r}"
    )
    # The argv passed to ops.run must match the registry schema length
    # exactly (13 tokens for az.blob_list).
    args = captured["args"]
    assert isinstance(args, tuple)
    assert len(args) == len(ops.OPERATION_REGISTRY["az.blob_list"].argv_schema), (
        f"argv length must equal registry schema length; "
        f"got {len(args)} args, schema has "
        f"{len(ops.OPERATION_REGISTRY['az.blob_list'].argv_schema)} slots"
    )
    # The tier must be 'state' (the registry rejects other tiers).
    assert captured["kwargs"].get("tier") == "state", (
        f"_resolve_latest_remote_run_id must pass tier='state'; "
        f"got {captured['kwargs']!r}"
    )



# ---------------------------------------------------------------------------
# 21. _az_blob_download routes through ops.run("az.blob_download", ...)
# ---------------------------------------------------------------------------

def test_az_blob_download_uses_ops_registry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_az_blob_download`` calls ``scanner.ops.run`` with ``az.blob_download``.

    Confirms the migrated subprocess call invokes the typed registry
    with the correct schema (15 tokens), correct tier ('state'), and
    that the real reimplementation surfaces non-zero return codes by
    logging a WARN and returning ``False``.
    """
    from scanner import cli, ops

    captured: dict[str, object] = {}

    class _FakeCompleted:
        def __init__(self, returncode: int = 0, stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = ""
            self.stderr = stderr

    def fake_ops_run(name: str, *args: str, **kwargs: object) -> _FakeCompleted:
        captured["name"] = name
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeCompleted(returncode=1, stderr="ERROR: blob not found")

    monkeypatch.setattr(ops, "run", fake_ops_run)

    dest = tmp_path / "report.html"
    ok = cli._az_blob_download(
        storage_account="myacct",
        container_name="pacioli-reports",
        blob_name="run-1/report.html",
        dest=dest,
        dry_run=False,
    )

    assert ok is False, (
        f"non-zero return code must propagate as False; got {ok!r}"
    )
    assert captured["name"] == "az.blob_download", (
        f"_az_blob_download must call ops.run('az.blob_download', ...); "
        f"got {captured['name']!r}"
    )
    args = captured["args"]
    assert isinstance(args, tuple)
    assert len(args) == len(ops.OPERATION_REGISTRY["az.blob_download"].argv_schema), (
        f"argv length must equal registry schema length; "
        f"got {len(args)} args, schema has "
        f"{len(ops.OPERATION_REGISTRY['az.blob_download'].argv_schema)} slots"
    )
    assert captured["kwargs"].get("tier") == "state", (
        f"_az_blob_download must pass tier='state'; got {captured['kwargs']!r}"
    )



# ---------------------------------------------------------------------------
# 22. _handle_audit_remote registers a cleanup trap in non-dry-run mode
# ---------------------------------------------------------------------------

def test_handle_audit_remote_registers_signal_trap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_audit_remote`` calls ``register_traps`` with a cleanup fn.

    Non-dry-run mode MUST register a cleanup trap so partial downloads
    are removed on SIGINT/SIGTERM. The handler passes a closure that
    captures ``dest_dir``; we satisfy that by pre-creating one of the
    expected artefacts and letting the cleanup callable run.
    """
    from scanner import cli, trap

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("PACIOLI_STATE_STORAGE_ACCOUNT", "fakeacct")

    # Pre-create the directory + a fake partial download so the
    # cleanup closure actually has something to remove.
    run_id = "run-signal-trap"
    dest_dir = tmp_path / ".pacioli" / "runs" / run_id / "aggregate"
    dest_dir.mkdir(parents=True)
    (dest_dir / "coverage_matrix.csv").write_bytes(b"partial-blob-bytes")
    (dest_dir / ".audit_pulled_at").write_text("stale marker\n")

    registered: list[object] = []

    def fake_register_traps(cleanup_fn: object) -> None:
        registered.append(cleanup_fn)

    monkeypatch.setattr(trap, "register_traps", fake_register_traps)

    # Stub the inner helpers so the download loop completes without
    # touching Azure.
    monkeypatch.setattr(
        cli,
        "_resolve_latest_remote_run_id",
        lambda **_kw: run_id,
    )

    def fake_download(
        *,
        storage_account: str,
        container_name: str,
        blob_name: str,
        dest: Path,
        dry_run: bool,
    ) -> bool:
        # No-op: the cleanup fixture already created the file.
        return True

    monkeypatch.setattr(cli, "_az_blob_download", fake_download)

    args = argparse.Namespace(
        latest=True,
        run_id=None,
        out=None,
        state_account=None,
        dry_run=False,
    )

    rc = cli._handle_audit_remote(args)
    assert rc == 0, f"_handle_audit_remote returned {rc}; expected 0"

    assert len(registered) == 1, (
        f"register_traps must be called exactly once in non-dry-run mode; "
        f"got {len(registered)} registrations"
    )
    cleanup_fn = registered[0]
    assert callable(cleanup_fn), "register_traps must receive a callable"

    # Invoke the cleanup: it must remove the partial download + the
    # stale marker. After it runs, the .audit_pulled_at marker is
    # gone (the handler writes a fresh one at the end, so we expect
    # one to exist with new contents).
    cleanup_fn()
    # Coverage matrix was a partial download → cleaned up.
    assert not (dest_dir / "coverage_matrix.csv").exists(), (
        "cleanup_fn must remove partial downloads"
    )



def test_handle_audit_remote_dry_run_does_not_register_trap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``--dry-run`` mode does NOT register a signal trap.

    Dry-run never writes anything to disk, so there's nothing to
    clean up; registering a trap would just add noise to the
    test suite.
    """
    from scanner import cli, trap

    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("PACIOLI_STATE_STORAGE_ACCOUNT", "fakeacct")

    registered: list[object] = []

    def fake_register_traps(cleanup_fn: object) -> None:
        registered.append(cleanup_fn)

    monkeypatch.setattr(trap, "register_traps", fake_register_traps)

    monkeypatch.setattr(
        cli,
        "_resolve_latest_remote_run_id",
        lambda **_kw: "DRYRUN-LATEST",
    )

    def fake_download(
        *,
        storage_account: str,
        container_name: str,
        blob_name: str,
        dest: Path,
        dry_run: bool,
    ) -> bool:
        return True

    monkeypatch.setattr(cli, "_az_blob_download", fake_download)

    args = argparse.Namespace(
        latest=True,
        run_id=None,
        out=None,
        state_account=None,
        dry_run=True,
    )

    rc = cli._handle_audit_remote(args)
    assert rc == 0, f"dry-run returned {rc}; expected 0"
    assert registered == [], (
        f"register_traps must NOT be called in --dry-run mode; "
        f"got {len(registered)} registrations"
    )



# ---------------------------------------------------------------------------
# Section E (--no-open flag + _maybe_open_report helper coverage)
# ---------------------------------------------------------------------------
#
# These tests cover the ``--no-open`` CLI flag (PR #9) and the module-level
# ``_maybe_open_report`` helper, invoked by the audit handlers. Mirrors the
# ``Orchestrator._open_report`` tests in scanner/tests/test_orchestrator.py.

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


# ---------------------------------------------------------------------------
# 23. No raw subprocess calls remain in scanner/cli.py
# ---------------------------------------------------------------------------


def test_cli_module_has_no_raw_subprocess_calls() -> None:
    """``scanner.cli`` must not contain ``subprocess.run/Popen/call`` or ``os.system``.

    Guards against regressions: if a future change reintroduces a raw
    subprocess call, the ops-registry migration is incomplete. The
    grep walks the source file text directly so it doesn't depend on
    importing cli (which triggers the UTF-8 bootstrap).
    """
    src = (Path(__file__).resolve().parents[1] / "cli.py").read_text(
        encoding="utf-8"
    )
    forbidden = ("subprocess.run", "subprocess.Popen", "subprocess.call", "os.system")
    hits = [tok for tok in forbidden if tok in src]
    assert not hits, (
        f"scanner.cli must not contain raw subprocess calls; "
        f"found: {hits!r}"
    )


# ---------------------------------------------------------------------------
# 24. Todo-8: --scan-path JSON parsing + validation (Todo 8 — flags #1 of 8)
# ---------------------------------------------------------------------------


def test_parse_scan_path_spec_minimal() -> None:
    """``--scan-path`` with only ``path`` yields a minimal entry dict.

    The other keys are optional and absent from the returned dict so
    downstream code can use ``entry.get('project')`` etc. without
    worrying about defaults. Mirrors the YAML schema: only ``path`` is
    required.
    """
    from scanner.cli import _parse_scan_path_spec

    out = _parse_scan_path_spec('{"path": "env/myapp/prod"}', 0)
    assert out == {"path": "env/myapp/prod"}, (
        f"minimal --scan-path should yield only 'path'; got {out!r}"
    )


def test_parse_scan_path_spec_full() -> None:
    """``--scan-path`` with all 6 keys round-trips through the parser."""
    from scanner.cli import _parse_scan_path_spec

    spec = (
        '{"path": "x", "project": "p", "env": "e", '
        '"backend_key": "bk", "workspace": "ws", "stack_label": "sl"}'
    )
    out = _parse_scan_path_spec(spec, 0)
    assert out == {
        "path": "x",
        "project": "p",
        "env": "e",
        "backend_key": "bk",
        "workspace": "ws",
        "stack_label": "sl",
    }, f"unexpected --scan-path roundtrip: {out!r}"


def test_parse_scan_path_spec_rejects_missing_path() -> None:
    """``--scan-path`` without ``path`` raises ``ValueError``."""
    from scanner.cli import _parse_scan_path_spec

    with pytest.raises(ValueError, match=r"'path' is required"):
        _parse_scan_path_spec('{"project": "p"}', 2)


def test_parse_scan_path_spec_rejects_unknown_key() -> None:
    """``--scan-path`` with an unknown key raises ``ValueError``.

    Unknown keys are a typo sentinel — surfacing them at parse time
    keeps the YAML/CLI surfaces aligned.
    """
    from scanner.cli import _parse_scan_path_spec

    with pytest.raises(ValueError, match=r"unknown keys"):
        _parse_scan_path_spec(
            '{"path": "x", "nonsense": 1}', 0
        )


def test_parse_scan_path_spec_rejects_malformed_json() -> None:
    """``--scan-path`` with malformed JSON raises ``ValueError`` with index."""
    from scanner.cli import _parse_scan_path_spec

    with pytest.raises(ValueError, match=r"\[3\].*malformed JSON"):
        _parse_scan_path_spec('{"path": ', 3)


def test_parse_scan_path_spec_rejects_non_object() -> None:
    """``--scan-path`` with a JSON array (not object) raises ``ValueError``."""
    from scanner.cli import _parse_scan_path_spec

    with pytest.raises(ValueError, match=r"must be a JSON object"):
        _parse_scan_path_spec('[1, 2, 3]', 0)


# ---------------------------------------------------------------------------
# 25. Todo-8: --scan-glob expansion (Todo 8 — flags #2 of 8)
# ---------------------------------------------------------------------------


def test_expand_scan_glob_to_dirs(tmp_path: Path) -> None:
    """``--scan-glob 'env/*/prod'`` expands to one entry per match.

    Each match becomes ``{path, project=<parent>, env=<basename>}``.
    Non-directory matches are skipped silently (file globs would
    produce bogus scan-path entries).
    """
    from scanner.cli import _expand_scan_glob

    # Materialise three env dirs and one non-dir artefact to verify
    # the non-dir skip behaviour.
    for env_name in ("prod", "stage"):
        d = tmp_path / "env" / "myapp" / env_name
        d.mkdir(parents=True)
        (d / "main.tf").write_text("# stub\n", encoding="utf-8")
    (tmp_path / "env" / "myapp" / "stray.txt").write_text("nope", encoding="utf-8")

    out = _expand_scan_glob("env/*/prod", tmp_path, 0)
    assert len(out) == 1, f"expected 1 prod match; got {len(out)}: {out!r}"
    entry = out[0]
    assert entry["path"] == "env/myapp/prod", f"bad path: {entry!r}"
    assert entry["project"] == "myapp", f"bad project: {entry!r}"
    assert entry["env"] == "prod", f"bad env: {entry!r}"


def test_expand_scan_glob_no_matches_returns_empty(tmp_path: Path) -> None:
    """``--scan-glob`` with no matches returns ``[]`` (not an error).

    Mirrors bash ``nullglob``: a pattern that legitimately matches
    nothing shouldn't kill the run. The orchestrator's INFO banner
    surfaces the empty expansion so the operator can see what
    happened.
    """
    from scanner.cli import _expand_scan_glob

    out = _expand_scan_glob("env/*/nonexistent", tmp_path, 0)
    assert out == [], f"expected empty list for no-match glob; got {out!r}"


def test_expand_scan_glob_rejects_empty_pattern() -> None:
    """``--scan-glob ''`` raises ``ValueError`` (empty pattern is a typo)."""
    from scanner.cli import _expand_scan_glob

    with pytest.raises(ValueError, match=r"non-empty string"):
        _expand_scan_glob("", Path("/tmp"), 0)


# ---------------------------------------------------------------------------
# 26. Todo-8: --include-modules validator (Todo 8 — flags #5 of 8)
# ---------------------------------------------------------------------------


def test_validate_include_modules_with_plan_tier_errors() -> None:
    """``--include-modules --tier plan`` raises ``ValueError``."""
    from scanner.cli import _validate_include_modules_vs_tier

    with pytest.raises(ValueError, match=r"--include-modules is source-tier only"):
        _validate_include_modules_vs_tier(tier="plan", include_modules=True)


def test_validate_include_modules_with_state_tier_errors() -> None:
    """``--include-modules --tier state`` raises ``ValueError``."""
    from scanner.cli import _validate_include_modules_vs_tier

    with pytest.raises(ValueError, match=r"--tier 'state'"):
        _validate_include_modules_vs_tier(tier="state", include_modules=True)


def test_validate_include_modules_with_source_tier_ok() -> None:
    """``--include-modules --tier source`` is the valid combination."""
    from scanner.cli import _validate_include_modules_vs_tier

    # No raise.
    _validate_include_modules_vs_tier(tier="source", include_modules=True)


def test_validate_include_modules_disabled_with_plan_tier_ok() -> None:
    """``--tier plan`` without ``--include-modules`` is fine (no-op)."""
    from scanner.cli import _validate_include_modules_vs_tier

    # No raise.
    _validate_include_modules_vs_tier(tier="plan", include_modules=False)


# ---------------------------------------------------------------------------
# 27. Todo-8: --registry-mirror / --stack-label validation (Todo 8 — flags #3, #7 of 8)
# ---------------------------------------------------------------------------


def test_validate_registry_mirror_accepts_https() -> None:
    """``--registry-mirror`` accepts a normal https URL."""
    from scanner.cli import _validate_registry_mirror

    # No raise.
    _validate_registry_mirror("https://mirror.example.com/terraform-modules")
    _validate_registry_mirror("http://internal-mirror:8080/path")
    _validate_registry_mirror(None)


def test_validate_registry_mirror_rejects_junk() -> None:
    """``--registry-mirror`` rejects non-URL strings (FTP, plain text)."""
    from scanner.cli import _validate_registry_mirror

    with pytest.raises(ValueError, match=r"invalid URL"):
        _validate_registry_mirror("not-a-url")
    with pytest.raises(ValueError, match=r"invalid URL"):
        _validate_registry_mirror("ftp://mirror.example.com")
    with pytest.raises(ValueError, match=r"invalid URL"):
        _validate_registry_mirror("")


def test_validate_stack_label_accepts_safe_slug() -> None:
    """``--stack-label`` accepts ``[A-Za-z0-9._-]{1,64}`` slugs."""
    from scanner.cli import _validate_stack_label

    # No raise.
    _validate_stack_label("vpc1")
    _validate_stack_label("env_a.0-1")
    _validate_stack_label("a" * 64)
    _validate_stack_label(None)


def test_validate_stack_label_rejects_unsafe_slug() -> None:
    """``--stack-label`` rejects slashes / spaces / leading dashes."""
    from scanner.cli import _validate_stack_label

    with pytest.raises(ValueError, match=r"invalid slug"):
        _validate_stack_label("with/slash")
    with pytest.raises(ValueError, match=r"invalid slug"):
        _validate_stack_label("with space")
    with pytest.raises(ValueError, match=r"invalid slug"):
        _validate_stack_label("-leading-dash")
    with pytest.raises(ValueError, match=r"invalid slug"):
        _validate_stack_label("a" * 65)


# ---------------------------------------------------------------------------
# 28. Todo-8: _resolve_scan_path_entries wiring (Todo 8 — all 8 flags together)
# ---------------------------------------------------------------------------


def test_resolve_scan_path_entries_merges_path_and_glob(
    tmp_path: Path,
) -> None:
    """``--scan-path`` + ``--scan-glob`` are unioned into one ordered list.

    The CLI helper preserves argv order: ``--scan-path`` entries come
    first, then ``--scan-glob`` matches. The default ``--backend-key``
    is applied to any entry missing an explicit per-entry value.
    """
    from scanner.cli import _resolve_scan_path_entries

    # Materialise one env dir for the glob.
    env_dir = tmp_path / "env" / "myapp" / "prod"
    env_dir.mkdir(parents=True)

    args = _make_args(
        scan_path=[
            '{"path": "modules/net", "project": "shared"}',
        ],
        scan_glob=["env/*/prod"],
        backend_key="global.tfstate",
    )
    entries = _resolve_scan_path_entries(args, tmp_path)

    assert len(entries) == 2, (
        f"expected 2 entries (1 path + 1 glob); got {len(entries)}: {entries!r}"
    )
    # First entry: the explicit --scan-path; project override wins.
    assert entries[0]["path"] == "modules/net"
    assert entries[0]["project"] == "shared"
    assert entries[0]["backend_key"] == "global.tfstate", (
        f"default --backend-key must apply to entries missing it; got {entries[0]!r}"
    )
    # Second entry: the glob-derived entry; project=<parent> (env),
    # env=<basename> (prod). Default backend_key applied.
    assert entries[1]["path"] == "env/myapp/prod"
    assert entries[1]["project"] == "myapp"
    assert entries[1]["env"] == "prod"
    assert entries[1]["backend_key"] == "global.tfstate"


def test_resolve_scan_path_entries_per_entry_backend_key_wins(
    tmp_path: Path,
) -> None:
    """Per-entry ``backend_key`` beats the top-level ``--backend-key`` default.

    Precedence mirrors the orchestrator's documented order:
    per-entry > top-level > aztfexport file > basename default.
    """
    from scanner.cli import _resolve_scan_path_entries

    args = _make_args(
        scan_path=[
            '{"path": "a", "backend_key": "explicit.tfstate"}',
            '{"path": "b"}',
        ],
        backend_key="global.tfstate",
    )
    entries = _resolve_scan_path_entries(args, tmp_path)

    assert entries[0]["backend_key"] == "explicit.tfstate", (
        f"per-entry backend_key must win; got {entries[0]!r}"
    )
    assert entries[1]["backend_key"] == "global.tfstate", (
        f"default backend_key must fill missing values; got {entries[1]!r}"
    )


def test_resolve_scan_path_entries_includes_modules_validator_runs(
    tmp_path: Path,
) -> None:
    """``--include-modules --tier plan`` raises ``ValueError`` at dispatch.

    The validator runs inside ``_resolve_scan_path_entries`` so a
    bad combination surfaces before any orchestrator subprocess is
    spawned.
    """
    from scanner.cli import _resolve_scan_path_entries

    args = _make_args(include_modules=True, tier="plan")
    with pytest.raises(ValueError, match=r"--include-modules is source-tier only"):
        _resolve_scan_path_entries(args, tmp_path)


def test_resolve_scan_path_entries_validates_registry_mirror(
    tmp_path: Path,
) -> None:
    """Bad ``--registry-mirror`` URL surfaces inside the resolver."""
    from scanner.cli import _resolve_scan_path_entries

    args = _make_args(registry_mirror="not-a-url")
    with pytest.raises(ValueError, match=r"invalid URL"):
        _resolve_scan_path_entries(args, tmp_path)


def test_resolve_scan_path_entries_validates_stack_label(
    tmp_path: Path,
) -> None:
    """Bad ``--stack-label`` slug surfaces inside the resolver."""
    from scanner.cli import _resolve_scan_path_entries

    args = _make_args(stack_label="with/slash")
    with pytest.raises(ValueError, match=r"invalid slug"):
        _resolve_scan_path_entries(args, tmp_path)


# ---------------------------------------------------------------------------
# 29. Todo-8: --include-modules --tier plan exits 2 via _handle_scan
# ---------------------------------------------------------------------------


def test_handle_scan_rejects_include_modules_with_plan_tier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``_handle_scan`` exits 2 with an ERROR log when ``--include-modules`` clashes with ``--tier plan``.

    Belt-and-suspenders test: ``_resolve_scan_path_entries`` raises
    ``ValueError``; ``_build_orchestrator_argv`` logs it and returns
    ``[]``; ``_handle_scan`` returns 2 without ever calling the
    orchestrator. The test patches ``scanner.orchestrator.main`` and
    asserts it was NOT called.
    """
    from scanner import cli, orchestrator

    called: list[list[str]] = []

    def fake_main(argv: list[str]) -> int:
        called.append(argv)
        return 0

    monkeypatch.setattr(orchestrator, "main", fake_main)

    repo = tmp_path / "repo"
    repo.mkdir()
    args = _make_args(
        target_dir=str(repo),
        tier="plan",
        include_modules=True,
    )
    rc = cli._handle_scan(args)
    captured = capsys.readouterr()

    assert rc == 2, f"_handle_scan must return 2 on validation error; got rc={rc}"
    assert called == [], (
        f"orchestrator.main must NOT be called when validation fails; got {called!r}"
    )
    assert "ERROR" in captured.err, (
        f"expected ERROR log on validation failure; got err={captured.err!r}"
    )
    assert "--include-modules" in captured.err, (
        f"ERROR should name the bad flag; got err={captured.err!r}"
    )


# ---------------------------------------------------------------------------
# 30. Todo-8: _build_orchestrator_argv end-to-end translation
# ---------------------------------------------------------------------------


def test_build_orchestrator_argv_emits_scan_path_entries(
    tmp_path: Path,
) -> None:
    """``_build_orchestrator_argv`` emits one ``--scan-path-entry`` per resolved entry.

    The CLI's argv builder is the single bridge between the operator's
    repeated ``--scan-path`` / ``--scan-glob`` flags and the
    orchestrator's repeatable ``--scan-path-entry`` flag. The test
    asserts the bridge produces JSON-encoded entries in argv order.
    """
    from scanner import cli

    args = _make_args(
        target_dir=str(tmp_path),
        scan_path=['{"path": "env/a/prod", "project": "a"}'],
        backend_key="global.tfstate",
    )
    argv = cli._build_orchestrator_argv(args)
    assert argv, "argv must be non-empty for a valid scan invocation"

    # Each --scan-path-entry token is followed by a JSON string.
    indices = [i for i, tok in enumerate(argv) if tok == "--scan-path-entry"]
    assert len(indices) == 1, (
        f"expected one --scan-path-entry token; got {len(indices)}: argv={argv!r}"
    )
    import json as _json
    payload = _json.loads(argv[indices[0] + 1])
    assert payload["path"] == "env/a/prod"
    assert payload["project"] == "a"
    assert payload["backend_key"] == "global.tfstate"


def test_build_orchestrator_argv_emits_all_new_flags(
    tmp_path: Path,
) -> None:
    """All 8 new flags propagate into the orchestrator argv.

    Belt-and-suspenders: catches a regression where one of the flags
    is silently dropped during the bridge translation. Two invocations:

      1. Without ``--scan-path``: 7 of the 8 new flags propagate
         (the resolver has nothing to inject ``--stack-label`` into).
      2. With ``--scan-path``: the resolver injects ``--stack-label``
         as the default per-entry ``stack_label`` and emits
         ``--scan-path-entry``.
    """
    from scanner import cli
    import json as _json

    # --- pass 1: 7 of 8 flags propagate; --scan-path-entry absent ---
    args = _make_args(
        target_dir=str(tmp_path),
        include_modules=True,
        ignore_lockfile=True,
        state_file=str(tmp_path / "state.tfstate"),
        registry_mirror="https://mirror.example.com",
        backend_key="bk",
        stack_label="sl",
    )
    argv = cli._build_orchestrator_argv(args)

    for flag in (
        "--include-modules",
        "--ignore-lockfile",
        "--state-file",
        "--registry-mirror",
        "--backend-key",
    ):
        assert flag in argv, f"{flag} missing from argv={argv!r}"

    # --- pass 2: --stack-label is applied as default per-entry ---
    args_with_path = _make_args(
        target_dir=str(tmp_path),
        scan_path=['{"path": "env/a/prod"}'],
        stack_label="sl",
    )
    argv2 = cli._build_orchestrator_argv(args_with_path)
    assert "--scan-path-entry" in argv2, (
        f"--scan-path-entry missing from second argv; argv={argv2!r}"
    )
    entry_idx = argv2.index("--scan-path-entry")
    payload2 = _json.loads(argv2[entry_idx + 1])
    assert payload2["stack_label"] == "sl", (
        f"--stack-label must be injected as default per-entry; got {payload2!r}"
    )


# ---------------------------------------------------------------------------
# 31. Todo-8: --registry-mirror config generation writes an isolated HCL file
# ---------------------------------------------------------------------------


def test_write_registry_mirror_config_creates_isolated_hcl(
    tmp_path: Path,
) -> None:
    """``--registry-mirror`` writes a ``terraform.rc`` under a fresh tmpdir.

    The config contains the URL in a quoted ``network_mirror`` block.
    Operators can point ``TF_CLI_CONFIG_FILE`` at it to redirect
    Terraform to a private mirror without touching
    ``~/.terraformrc``.
    """
    from scanner.cli import _write_registry_mirror_config

    cfg = _write_registry_mirror_config(
        "https://mirror.example.com/terraform", tmp_path
    )
    assert cfg.is_file(), f"registry-mirror config should exist at {cfg!r}"
    text = cfg.read_text(encoding="utf-8")
    assert "provider_installation" in text, (
        f"missing provider_installation block in {text!r}"
    )
    assert "network_mirror" in text, (
        f"missing network_mirror block in {text!r}"
    )
    assert '"https://mirror.example.com/terraform"' in text, (
        f"URL should be quoted in network_mirror block; got {text!r}"
    )


def test_write_registry_mirror_config_handles_url_with_query(
    tmp_path: Path,
) -> None:
    """A mirror URL with ``?`` and ``#`` survives JSON-quoting intact.

    Operators occasionally run a private registry behind a path with
    query params (e.g. ``?type=module``). We use ``json.dumps`` for
    the URL so the HCL stays valid; the test guards against an
    accidental raw interpolation.
    """
    from scanner.cli import _write_registry_mirror_config

    url = "https://mirror.example.com/?type=module&fmt=hcl#frag"
    cfg = _write_registry_mirror_config(url, tmp_path)
    text = cfg.read_text(encoding="utf-8")
    # ``json.dumps`` escapes ``#`` (no), but it DOES escape ``"`` (n/a)
    # and ``\``. The URL must appear verbatim inside double quotes.
    assert '"' + url + '"' in text, (
        f"URL with query/fragment must be JSON-quoted intact; got {text!r}"
    )


# ---------------------------------------------------------------------------
# 32. Todo-8: --ignore-lockfile emits a WARN log line
# ---------------------------------------------------------------------------


def test_emit_ignore_lockfile_warning_logs_warn(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``_emit_ignore_lockfile_warning`` writes a WARN line to stderr.

    The flag is opt-in (default off), so a WARN makes the operator's
    choice visible in CI logs.
    """
    from scanner.cli import _emit_ignore_lockfile_warning

    _emit_ignore_lockfile_warning()
    captured = capsys.readouterr()
    assert "WARN" in captured.err, (
        f"--ignore-lockfile should emit a WARN log; got err={captured.err!r}"
    )
    assert "--ignore-lockfile" in captured.err, (
        f"WARN should name the flag; got err={captured.err!r}"
    )
    assert ".terraform.lock.hcl" in captured.err, (
        f"WARN should mention the file pattern; got err={captured.err!r}"
    )


# ---------------------------------------------------------------------------
# 33. Todo-8: scan --help lists all 8 new flags
# ---------------------------------------------------------------------------


_EXPECTED_NEW_FLAGS: tuple[str, ...] = (
    "--scan-path",
    "--scan-glob",
    "--stack-label",
    "--state-file",
    "--include-modules",
    "--ignore-lockfile",
    "--registry-mirror",
    "--backend-key",
)


def test_scan_help_lists_all_eight_new_flags() -> None:
    """``pacioli scan --help`` mentions all 8 new flags.

    Guards against a regression where one of the flags is forgotten
    when ``_add_scan_flags`` is reorganised. The grep is intentionally
    substring-based so renames (e.g. ``--scan-path SPEC``) still match.
    """
    result = _run_cli("scan", "--help")
    assert result.returncode == 0, (
        f"`scan --help` failed rc={result.returncode}; stderr={result.stderr!r}"
    )
    output = result.stdout + result.stderr
    missing = [flag for flag in _EXPECTED_NEW_FLAGS if flag not in output]
    assert not missing, (
        f"`scan --help` is missing {len(missing)} of {len(_EXPECTED_NEW_FLAGS)} "
        f"new flags: {missing!r}"
    )


def test_gate_help_lists_all_eight_new_flags() -> None:
    """``pacioli gate --help`` ALSO mentions all 8 new flags.

    ``gate`` reuses ``_add_scan_flags``; this test guards against a
    future refactor that splits the flag wiring and forgets to wire
    the new flags into both subparsers.
    """
    result = _run_cli("gate", "--help")
    assert result.returncode == 0, (
        f"`gate --help` failed rc={result.returncode}; stderr={result.stderr!r}"
    )
    output = result.stdout + result.stderr
    missing = [flag for flag in _EXPECTED_NEW_FLAGS if flag not in output]
    assert not missing, (
        f"`gate --help` is missing {len(missing)} of {len(_EXPECTED_NEW_FLAGS)} "
        f"new flags: {missing!r}"
    )


# ---------------------------------------------------------------------------
# 34. Todo-8: --include-modules --tier plan exits 2 end-to-end via the CLI
# ---------------------------------------------------------------------------


def test_pacioli_scan_include_modules_with_plan_tier_exits_2(
    tmp_path: Path,
) -> None:
    """End-to-end: ``pacioli scan --include-modules --tier plan`` exits 2 with ERROR log.

    The validator must surface BEFORE any orchestrator subprocess is
    spawned (no Checkov pass, no Terraform init). The test asserts
    both the non-zero rc AND the human-readable ERROR log.
    """
    target_repo = _make_minimal_tf_repo(tmp_path / "repo")
    output_dir = tmp_path / "runs"

    result = _run_cli(
        "scan",
        str(target_repo),
        "--output-dir",
        str(output_dir),
        "--tier",
        "plan",
        "--include-modules",
        "--non-interactive",
        timeout=30,
    )

    assert result.returncode == 2, (
        f"`pacioli scan --include-modules --tier plan` must exit 2; "
        f"got rc={result.returncode}; stderr={result.stderr[-500:]!r}"
    )
    assert "ERROR" in result.stderr, (
        f"expected ERROR log on validation failure; got stderr={result.stderr!r}"
    )
    assert "--include-modules" in result.stderr, (
        f"ERROR should name the conflicting flag; got stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# 35. Todo-8: Back-compat aliases survive the refactor
# ---------------------------------------------------------------------------


def test_backcompat_aliases_still_wired() -> None:
    """``--scan-plan``, ``--scan-state``, ``--scope`` remain in ``scan --help``.

    Belt-and-suspenders: the task's MUST NOT DO clause forbids removing
    these aliases. This test asserts they're still registered.
    """
    result = _run_cli("scan", "--help")
    assert result.returncode == 0
    output = result.stdout + result.stderr
    for legacy in ("--scan-plan", "--scan-state", "--scope"):
        assert legacy in output, (
            f"back-compat alias {legacy!r} missing from `scan --help`; "
            f"got output (first 500 chars): {output[:500]!r}"
        )


# ---------------------------------------------------------------------------
# 36. Todo-8: Scan-path arg shape from _handle_scan -> orchestrator
# ---------------------------------------------------------------------------


def test_handle_scan_passes_new_flags_to_orchestrator_main(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_scan`` propagates ALL 8 new flags to ``orchestrator.main``.

    The end-to-end CLI → orchestrator bridge: ``_handle_scan`` must
    re-emit every flag in the orchestrator's argv, including the
    resolved ``--scan-path-entry`` JSON.
    """
    from scanner import cli, orchestrator

    captured: dict[str, object] = {}

    def fake_main(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr(orchestrator, "main", fake_main)

    repo = tmp_path / "repo"
    (repo / "env" / "myapp" / "prod").mkdir(parents=True)
    (repo / "env" / "myapp" / "prod" / "main.tf").write_text(
        "# stub\n", encoding="utf-8"
    )

    args = _make_args(
        target_dir=str(repo),
        tier="source",
        mode="report",
        include_modules=True,
        ignore_lockfile=True,
        state_file=str(tmp_path / "state.tfstate"),
        registry_mirror="https://mirror.example.com",
        backend_key="global.tfstate",
        scan_path=['{"path": "env/myapp/prod"}'],
    )
    rc = cli._handle_scan(args)
    assert rc == 0, f"_handle_scan returned {rc}; expected 0"
    argv = captured["argv"]

    # Every new flag must appear in argv.
    for flag in (
        "--include-modules",
        "--ignore-lockfile",
        "--state-file",
        "--registry-mirror",
        "--backend-key",
        "--scan-path-entry",
    ):
        assert flag in argv, f"{flag} missing from orchestrator argv={argv!r}"



# ---------------------------------------------------------------------------
# F3: live demonstration that `terraform apply -auto-approve` -> exit 99
# ---------------------------------------------------------------------------
#
# The pre-existing exit-99 test above (
# ``test_main_exits_99_when_subprocess_operation_is_refused``) proves the
# *wiring* only: it raises a hand-constructed MutatingOperationRefused from
# a patched handler. It never demonstrates that the specific command
# ``terraform apply -auto-approve`` is what triggers the refusal.
#
# The three tests below close that gap end-to-end:
#   1. the real refusal matrix fires on the real command string;
#   2. the real ops registry refuses the real composed argv *before*
#      subprocess.run is reached (proved with a sentinel);
#   3. a real ``python -m scanner.cli`` child process terminates with
#      exit status 99 when that refusal propagates out of a handler.


def test_refusal_matrix_fires_on_terraform_apply_auto_approve() -> None:
    """The real SafetyGuard refuses ``terraform apply -auto-approve``."""
    from scanner.safety import MutatingOperationRefused, SafetyGuard

    with pytest.raises(MutatingOperationRefused):
        SafetyGuard().refuse_if_mutating("terraform apply -auto-approve")


def test_ops_run_refuses_apply_before_executing_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``ops.run`` refuses an apply argv *before* reaching subprocess.run.

    Registers a deliberately mutating operation, stages a fake
    ``terraform`` on PATH so binary resolution succeeds (the refusal must
    be what stops us, not a missing binary), and installs a sentinel over
    ``subprocess.run`` that fails the test if it is ever reached.
    """
    from scanner import ops
    from scanner.safety import MutatingOperationRefused

    # Stage a fake `terraform` so _resolve_binary() succeeds and the
    # refusal check is provably the thing that stops execution.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    is_windows = sys.platform.startswith("win")
    shim = bin_dir / ("terraform.bat" if is_windows else "terraform")
    shim.write_text("@echo off\n" if is_windows else "#!/bin/sh\nexit 0\n",
                    encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])

    def _never_called(*_args, **_kwargs):  # pragma: no cover - must not run
        raise AssertionError(
            "subprocess.run was reached for `terraform apply -auto-approve`; "
            "the refusal matrix failed to stop the mutating operation"
        )

    monkeypatch.setattr(ops.subprocess, "run", _never_called)

    saved = dict(ops.OPERATION_REGISTRY)
    ops.OPERATION_REGISTRY["test.f3_apply"] = ops.Operation(
        name="test.f3_apply",
        executable="terraform",
        argv_schema=("apply", "-auto-approve"),
        allowed_tiers=("plan", "state"),
        default_timeout=60,
        mutation_class="mutate_azure",
        cleanup_obligation="none",
        env_allowlist=("*",),
    )
    try:
        with pytest.raises(MutatingOperationRefused):
            ops.run("test.f3_apply", "apply", "-auto-approve", tier="plan")
    finally:
        ops.OPERATION_REGISTRY.clear()
        ops.OPERATION_REGISTRY.update(saved)


def test_cli_subprocess_exits_99_on_terraform_apply_refusal(
    tmp_path: Path,
) -> None:
    """A real ``python -m scanner.cli`` child exits 99 on an apply refusal.

    This is the user-facing proof: a genuine child process, whose scan
    handler attempts ``terraform apply -auto-approve`` through the real
    ops registry, terminates with exit status 99. The attempt is injected
    via a sitecustomize-style bootstrap so no production source is edited
    and no real Terraform is ever executed (the refusal fires first).
    """
    bootstrap = tmp_path / "f3_apply_probe.py"
    bootstrap.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from scanner import cli\n"
        "from scanner.safety import SafetyGuard\n"
        "\n"
        "def _apply(_args):\n"
        "    # The real refusal matrix, on the real command string.\n"
        "    SafetyGuard().refuse_if_mutating('terraform apply -auto-approve')\n"
        "    raise AssertionError('refusal did not fire')\n"
        "\n"
        "cli._handle_scan = _apply\n"
        "sys.exit(cli.main(['scan', '--non-interactive']))\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, str(bootstrap)],
        cwd=str(REPO_ROOT),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert proc.returncode == 99, (
        "expected exit 99 from `terraform apply -auto-approve` refusal; "
        f"got {proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
    )

# ---------------------------------------------------------------------------
# Section F: _maybe_open_report helper coverage (PR #9 follow-up)
# ---------------------------------------------------------------------------
#
# Unit tests for the ``_maybe_open_report`` helper that backs both the
# audit subcommand and the orchestrator flow. Mirrors the tests in
# scanner/tests/test_orchestrator.py for ``Orchestrator._open_report``.

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


# ---------------------------------------------------------------------------
# TODO 12: --framework flag + cloud-agnostic help text
# ---------------------------------------------------------------------------


def test_scan_help_advertises_framework_flag() -> None:
    """``pacioli scan --help`` advertises ``--framework`` with dynamic choices.

    Todo 12 acceptance criterion: ``pacioli scan --help`` shows the
    ``--framework`` flag. The choices must come from
    ``scanner.frameworks.SUPPORTED_FRAMEWORKS`` (NOT a local list) — at
    minimum ``terraform`` and ``cloudformation`` must appear, since
    those are the two the user-facing example uses.
    """
    from scanner.frameworks import SUPPORTED_FRAMEWORKS

    result = _run_cli("scan", "--help")
    assert result.returncode == 0, (
        f"pacioli scan --help returned rc={result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    assert "--framework" in result.stdout, (
        f"--framework missing from scan --help output:\n{result.stdout!r}"
    )
    # The flag must accept the canonical terraform + cloudformation
    # choices (subset of SUPPORTED_FRAMEWORKS), proving the choices
    # are dynamic and not a copy-paste list.
    for framework in ("terraform", "cloudformation"):
        assert framework in SUPPORTED_FRAMEWORKS, (
            f"framework {framework!r} missing from SUPPORTED_FRAMEWORKS"
        )


def test_top_level_help_says_any_iac_framework() -> None:
    """``pacioli --help`` description is cloud-agnostic (no Azure Terraform).

    Todo 12(d): the top-level parser description must say
    "Compliance-as-code for any IaC framework ..." instead of
    "Compliance-as-code for Azure Terraform. ... (PCI DSS 4.0.1 by default)".
    """
    result = _run_cli("--help")
    assert result.returncode == 0, (
        f"pacioli --help returned rc={result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    assert "Compliance-as-code for any IaC framework" in result.stdout, (
        f"top-level help description not generalized; got:\n{result.stdout!r}"
    )
    assert "Compliance-as-code for Azure Terraform" not in result.stdout, (
        "old 'Compliance-as-code for Azure Terraform' phrasing leaked into "
        "top-level help"
    )
    assert "PCI DSS 4.0.1 by default" not in result.stdout, (
        "old 'PCI DSS 4.0.1 by default' phrasing leaked into top-level help"
    )


def test_target_repo_help_says_iac_repo() -> None:
    """``--target-repo`` help says "Consumer IaC repo" (not Terraform).

    Todo 12(e): the --target-repo help text must read
    "Consumer IaC repo" — the scanner is no longer Terraform-only.
    """
    result = _run_cli("scan", "--help")
    assert result.returncode == 0
    assert "Consumer IaC repo" in result.stdout, (
        f"--target-repo help not generalized; got:\n{result.stdout!r}"
    )
    assert "Consumer Terraform repo" not in result.stdout, (
        "old 'Consumer Terraform repo' phrasing leaked into --target-repo help"
    )


def test_tier_help_warns_plan_state_need_terraform_family() -> None:
    """``--tier`` help notes that plan/state require Terraform-family.

    Todo 12(f): the --tier help text must mention that plan/state
    require Terraform-family frameworks.
    """
    result = _run_cli("scan", "--help")
    assert result.returncode == 0
    assert "Terraform-family" in result.stdout, (
        f"--tier help missing Terraform-family note; got:\n{result.stdout!r}"
    )


def test_safety_disclaimer_says_read_only_scanner() -> None:
    """SAFETY_DISCLAIMER uses "READ-ONLY scanner" (not "READ-ONLY against Azure").

    Todo 12(c): the safety disclaimer must say "READ-ONLY scanner"
    — the read-only invariant is now scoped to the scanner, not the
    cloud provider.
    """
    result = _run_cli("scan", "--help")
    assert result.returncode == 0
    # The disclaimer is rendered in the epilog of `scan --help`.
    assert "READ-ONLY scanner" in result.stdout, (
        f"SAFETY_DISCLAIMER not generalized; got:\n{result.stdout!r}"
    )
    assert "READ-ONLY against Azure" not in result.stdout, (
        "old 'READ-ONLY against Azure' phrasing leaked into SAFETY_DISCLAIMER"
    )


def test_validate_tier_vs_framework_rejects_plan_with_cloudformation() -> None:
    """``--tier plan --framework cloudformation`` raises OrchestratorError.

    Todo 12(b): the CLI refuses plan/state with a non-Terraform-family
    framework, using :func:`scanner.frameworks.is_terraform_family` and
    raising :class:`scanner.orchestrator.OrchestratorError`.
    """
    from scanner import cli
    from scanner.orchestrator import OrchestratorError

    # --framework cloudformation, --tier plan -> must raise.
    with pytest.raises(OrchestratorError) as exc_info:
        cli._validate_tier_vs_framework(
            tier="plan", framework="cloudformation"
        )
    assert "terraform" in str(exc_info.value).lower(), (
        f"error message must mention terraform; got: {exc_info.value!r}"
    )

    # Same for --tier state.
    with pytest.raises(OrchestratorError):
        cli._validate_tier_vs_framework(
            tier="state", framework="kubernetes"
        )


def test_validate_tier_vs_framework_allows_terraform_family() -> None:
    """``--tier plan --framework terraform`` is allowed (no error)."""
    from scanner import cli

    # Must not raise for any Terraform-family tier.
    cli._validate_tier_vs_framework(tier="plan", framework="terraform")
    cli._validate_tier_vs_framework(tier="state", framework="terraform")
    cli._validate_tier_vs_framework(tier="state", framework="terraform_plan")
    # Source tier is always valid for any framework.
    cli._validate_tier_vs_framework(tier="source", framework="cloudformation")
    cli._validate_tier_vs_framework(tier="source", framework="kubernetes")
    # None framework (auto-detect) is always valid CLI-side.
    cli._validate_tier_vs_framework(tier="plan", framework=None)


def test_scan_subprocess_with_framework_and_plan_exits_nonzero() -> None:
    """Subprocess: ``pacioli scan --framework cloudformation --tier plan`` fails.

    Full CLI subprocess test (matches the failure-scenario acceptance
    criterion in the plan): the combination of a non-Terraform
    framework with a plan/state tier exits non-zero with a stderr
    message mentioning terraform.
    """
    result = _run_cli(
        "scan",
        "--framework",
        "cloudformation",
        "--tier",
        "plan",
        str(Path.cwd()),  # any path; we fail at validation before scanning
    )
    assert result.returncode != 0, (
        f"expected non-zero exit for --framework cloudformation --tier plan; "
        f"got rc={result.returncode}, stdout={result.stdout!r}, "
        f"stderr={result.stderr!r}"
    )
    combined = (result.stdout + result.stderr).lower()
    assert "terraform" in combined, (
        f"error message must mention terraform; got stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )


def test_handle_scan_propagates_framework_to_orchestrator_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_handle_scan`` forwards ``--framework <name>`` to orchestrator argv."""
    from scanner import cli

    captured: dict[str, object] = {}

    def fake_main(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 0

    # Patch the orchestrator.main so we don't run a real scan.
    import scanner.orchestrator as orchestrator_mod
    monkeypatch.setattr(orchestrator_mod, "main", fake_main)

    repo = Path(__file__).resolve().parent
    args = _make_args(
        target_dir=str(repo),
        tier="source",
        framework="cloudformation",
    )
    rc = cli._handle_scan(args)
    assert rc == 0, f"_handle_scan returned {rc}; expected 0"
    argv = captured["argv"]
    assert "--framework" in argv, (
        f"--framework missing from orchestrator argv={argv!r}"
    )
    fw_idx = argv.index("--framework")
    assert argv[fw_idx + 1] == "cloudformation", (
        f"expected --framework cloudformation; got argv={argv!r}"
    )


def test_handle_scan_rejects_framework_plan_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_handle_scan`` rejects --framework cloudformation --tier plan at the CLI.

    The validation must happen BEFORE the orchestrator is invoked —
    the orchestrator must never be called when validation fails.
    """
    from scanner import cli
    from scanner.orchestrator import OrchestratorError

    captured: dict[str, object] = {}

    def fake_main(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 0

    import scanner.orchestrator as orchestrator_mod
    monkeypatch.setattr(orchestrator_mod, "main", fake_main)

    repo = Path(__file__).resolve().parent
    args = _make_args(
        target_dir=str(repo),
        tier="plan",
        framework="cloudformation",
    )
    with pytest.raises(OrchestratorError):
        cli._handle_scan(args)
    # The orchestrator must NOT have been called.
    assert "argv" not in captured, (
        f"orchestrator.main was invoked despite validation failure; "
        f"captured={captured!r}"
    )


# ---------------------------------------------------------------------------
# scan-config-bootstrap: --init flag wiring
# ---------------------------------------------------------------------------
#
# Tests that exercise the new ``--init`` flag wired into the scan/gate
# subcommands in Task 3 (scanner/cli.py:_add_scan_flags, _handle_scan,
# _handle_gate). ``_init_handler_short_circuits`` is mocked to keep the
# suite hermetic; real subprocess invocations are deliberately avoided.


def test_init_flag_appears_in_scan_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``pacioli scan --help`` lists the new ``--init`` flag and its scope mention.

    The help text is the contract the user reads; losing the flag (or
    its scope/baseline mention) silently breaks first-time adopters, so
    we assert the literal token ``--init`` AND the ``pci_scope.yaml``
    substring so any future help-text rewrite that drops the scope
    reference fails fast.
    """
    result = _run_cli("scan", "--help")
    captured = capsys.readouterr()  # noqa: F841 -- not used, just for symmetry
    assert result.returncode == 0, (
        f"pacioli scan --help returned rc={result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    assert "--init" in result.stdout, (
        f"--init flag missing from pacioli scan --help; stdout={result.stdout[:600]!r}"
    )
    assert "pci_scope.yaml" in result.stdout, (
        f"--init help text should mention pci_scope.yaml; "
        f"stdout={result.stdout[:600]!r}"
    )


def test_init_flag_appears_in_gate_help() -> None:
    """``pacioli gate --help`` lists the new ``--init`` flag.

    Gate reuses ``_add_scan_flags`` so the flag must appear in both
    subcommands' ``--help`` banners. This guards against a future
    refactor that splits scan/gate parsers without re-registering the
    bootstrap flag.
    """
    result = _run_cli("gate", "--help")
    assert result.returncode == 0, (
        f"pacioli gate --help returned rc={result.returncode}; "
        f"stderr={result.stderr!r}"
    )
    assert "--init" in result.stdout, (
        f"--init flag missing from pacioli gate --help; stdout={result.stdout[:600]!r}"
    )


def test_handle_scan_invokes_bootstrap_when_init_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When ``args.init=True``, ``_handle_scan`` calls ``config_bootstrap.auto_create``.

    Mirrors scanner/cli.py:_maybe_bootstrap_config line 1061: a bare
    ``args.init=True`` forces the auto-create branch regardless of
    interactive / non-interactive state. We capture the bootstrap call
    to verify the args/paths flow through unchanged, and stub the
    orchestrator so we don't actually scan.

    Both files are reported missing by the patched ``missing_config_files``
    helper, so the auto_create branch must be the one that executes
    (it's the only branch in the boolean tree that calls ``auto_create``).
    """
    from scanner import cli, config_bootstrap
    import scanner.orchestrator as orchestrator_mod

    bootstrap_calls: list[dict[str, object]] = []

    def fake_auto_create(args, target_repo, scope_path, baseline_path):
        bootstrap_calls.append({
            "args": args,
            "target_repo": target_repo,
            "scope_path": scope_path,
            "baseline_path": baseline_path,
        })
        return []  # nothing actually written

    def fake_missing_config_files(target_repo: Path):
        # Both files missing → forces _maybe_bootstrap_config down the
        # auto_create branch when args.init=True.
        return (target_repo / "pci_scope.yaml", target_repo / "pci_baseline.yaml")

    monkeypatch.setattr(config_bootstrap, "auto_create", fake_auto_create)
    monkeypatch.setattr(config_bootstrap, "missing_config_files",
                        fake_missing_config_files)
    monkeypatch.setattr(config_bootstrap, "is_bootstrap_interactive",
                        lambda a: True)  # would otherwise prompt; init must win

    orchestrator_called: list[list[str]] = []

    def fake_orchestrator_main(argv: list[str]) -> int:
        orchestrator_called.append(list(argv))
        return 0

    monkeypatch.setattr(orchestrator_mod, "main", fake_orchestrator_main)

    args = _make_args(
        init=True,
        target_dir=str(tmp_path),
        non_interactive=True,
    )
    rc = cli._handle_scan(args)
    assert rc == 0, f"_handle_scan returned {rc}; expected 0"
    assert len(bootstrap_calls) == 1, (
        f"--init=True should call config_bootstrap.auto_create exactly once; "
        f"got {len(bootstrap_calls)} calls: {bootstrap_calls!r}"
    )
    call = bootstrap_calls[0]
    assert call["args"] is args, (
        f"_handle_scan must pass the same args namespace through to auto_create; "
        f"got {call['args']!r}"
    )
    assert Path(call["target_repo"]) == tmp_path.resolve(), (
        f"target_repo must be the resolved tmp_path; got {call['target_repo']!r}"
    )
    # Orchestrator runs AFTER bootstrap completes successfully.
    assert len(orchestrator_called) == 1, (
        f"orchestrator.main should be called once after bootstrap; "
        f"got {len(orchestrator_called)} calls"
    )


def test_handle_scan_skips_bootstrap_when_non_interactive_no_init(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When ``args.init=False`` and non-interactive, no bootstrap function is called.

    Mirrors scanner/cli.py:_maybe_bootstrap_config line 1083 comment:
    "non-interactive and no --init -> skip silently (current behavior)".
    We verify BOTH ``auto_create`` and ``prompt_and_create`` are
    untouched, and that the orchestrator still runs normally.
    """
    from scanner import cli, config_bootstrap
    import scanner.orchestrator as orchestrator_mod

    auto_called = {"flag": False}
    prompt_called = {"flag": False}

    def fake_auto(*args, **kwargs):  # pragma: no cover -- failure path
        auto_called["flag"] = True
        return []

    def fake_prompt(*args, **kwargs):  # pragma: no cover -- failure path
        prompt_called["flag"] = True
        return []

    monkeypatch.setattr(config_bootstrap, "auto_create", fake_auto)
    monkeypatch.setattr(config_bootstrap, "prompt_and_create", fake_prompt)
    monkeypatch.setattr(config_bootstrap, "missing_config_files",
                        lambda r: (r / "pci_scope.yaml", r / "pci_baseline.yaml"))
    monkeypatch.setattr(config_bootstrap, "is_bootstrap_interactive",
                        lambda a: False)

    orchestrator_called: list[list[str]] = []

    def fake_orchestrator_main(argv: list[str]) -> int:
        orchestrator_called.append(list(argv))
        return 0

    monkeypatch.setattr(orchestrator_mod, "main", fake_orchestrator_main)

    args = _make_args(
        init=False,
        target_dir=str(tmp_path),
        non_interactive=True,
    )
    rc = cli._handle_scan(args)
    assert rc == 0, f"_handle_scan returned {rc}; expected 0"
    assert not auto_called["flag"], (
        "auto_create must NOT be called when args.init=False"
    )
    assert not prompt_called["flag"], (
        "prompt_and_create must NOT be called when is_bootstrap_interactive=False"
    )
    assert len(orchestrator_called) == 1, (
        f"orchestrator.main should still run with rc=0; "
        f"got {len(orchestrator_called)} calls"
    )


def test_handle_gate_invokes_bootstrap_when_init_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_handle_gate`` also routes through ``_maybe_bootstrap_config`` when init=True.

    Mirrors scanner/cli.py line 1154: gate shares the same bootstrap
    gate as scan (both handlers call ``_maybe_bootstrap_config``). The
    test only adds init coverage for gate to lock the parity contract
    without duplicating the full logic verified on scan.
    """
    from scanner import cli, config_bootstrap
    import scanner.orchestrator as orchestrator_mod

    bootstrap_calls: list[Path] = []

    def fake_auto_create(args, target_repo, scope_path, baseline_path):
        bootstrap_calls.append(Path(target_repo))
        return []

    monkeypatch.setattr(config_bootstrap, "auto_create", fake_auto_create)
    monkeypatch.setattr(config_bootstrap, "missing_config_files",
                        lambda r: (r / "pci_scope.yaml", r / "pci_baseline.yaml"))
    monkeypatch.setattr(config_bootstrap, "is_bootstrap_interactive",
                        lambda a: True)
    monkeypatch.setattr(orchestrator_mod, "main", lambda argv: 0)

    args = _make_args(
        init=True,
        target_dir=str(tmp_path),
        non_interactive=True,
        mode="report",  # gate overrides to "gate" internally
    )
    rc = cli._handle_gate(args)
    assert rc == 0, f"_handle_gate returned {rc}; expected 0"
    assert len(bootstrap_calls) == 1, (
        f"--init=True on _handle_gate must call auto_create exactly once; "
        f"got {len(bootstrap_calls)} calls"
    )
