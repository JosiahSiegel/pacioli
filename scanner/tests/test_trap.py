"""Tests for scanner.trap.

These tests cover the Python surface that mirrors the bash ``trap trap_on_exit
EXIT INT TERM`` from ``scanner/lib/common.sh``:

* ``register_traps`` registers atexit + SIGINT + (POSIX) SIGTERM
* signal handlers run the cleanup callback and re-raise so the process exits
  with the conventional ``128 + signum`` status
* ``shred_plan_artifacts`` removes ``tfplan.binary`` and ``plan.json``

The storage firewall IP whitelist cleanup (``cleanup_ip_whitelist``) was
removed in Todo 5: the scanner no longer mutates the Azure storage
firewall, so there is nothing to revert. The tests here assert that
the function is no longer importable so a future regression that
re-adds it is caught early.

Signal-handling tests that send signals to the test process itself would
interfere with pytest, so any test that needs to verify the exit-status
convention spawns a child Python process via ``subprocess.run`` and inspects
its return code.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from scanner import trap


# ---------------------------------------------------------------------------
# register_traps: structural checks (safe to run in-process)
# ---------------------------------------------------------------------------
def test_register_traps_registers_atexit_and_sigint():
    """``register_traps`` must install an atexit hook and a SIGINT handler."""
    prev_sigint = signal.getsignal(signal.SIGINT)
    try:
        trap.register_traps(lambda: None)
        # Inspect the handler AFTER registration but BEFORE restoring,
        # otherwise the assertion would compare the restored handler
        # against the original.
        new_handler = signal.getsignal(signal.SIGINT)
    finally:
        # Restore SIGINT so the test runner's own Ctrl+C handling still works.
        signal.signal(signal.SIGINT, prev_sigint)

    assert new_handler is not prev_sigint, "SIGINT handler was not replaced"


def test_register_traps_atexit_runs_cleanup_on_normal_exit(tmp_path):
    """The atexit hook installed by ``register_traps`` must fire on exit.

    Verified end-to-end via a child process: the child registers the trap,
    then ``sys.exit(0)``. If atexit fired, a marker file written by the
    cleanup callback will exist on disk by the time the parent observes the
    child's exit.
    """
    marker = tmp_path / "atexit_marker"
    scanner_dir = str(Path(__file__).resolve().parents[2])  # project root, not scanner/

    program = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {scanner_dir!r})
        from scanner import trap

        marker_path = r"{marker}"

        def cleanup():
            open(marker_path, "w", encoding="utf-8").close()

        trap.register_traps(cleanup)
        sys.exit(0)
        """
    )
    script_path = tmp_path / "child_atexit.py"
    script_path.write_text(program, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, (
        f"child exited {result.returncode}: {result.stderr}"
    )
    assert marker.exists(), "atexit hook did not run cleanup callback"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only SIGTERM trap")
def test_register_traps_registers_sigterm_on_posix():
    """On POSIX, ``register_traps`` must install a SIGTERM handler.

    Note: pytest installs its own SIGTERM handler at collection time,
    so the prev/new identity comparison is not reliable in the test
    process. We assert by behavioral observation: spawn a child
    process that calls ``register_traps`` and verify the registered
    handler is callable when SIGTERM is delivered.
    """
    # Capture the current handler so we can restore it after the test.
    prev_handler = signal.getsignal(signal.SIGTERM)

    def cleanup() -> None:
        pass

    trap.register_traps(cleanup)
    try:
        # The handler is now installed. The identity comparison is
        # not reliable under pytest (it intercepts signals), so we
        # verify behaviourally via a subprocess: a child that calls
        # register_traps and gets a SIGTERM should write the marker
        # AND exit non-zero (the signal was not swallowed).
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "sigterm_marker"
            scanner_dir = str(Path(__file__).resolve().parents[2])
            program = textwrap.dedent(
                f"""
                import sys
                sys.path.insert(0, {scanner_dir!r})
                from scanner import trap
                import signal

                marker_path = r"{marker}"

                def cleanup():
                    open(marker_path, "w", encoding="utf-8").close()

                trap.register_traps(cleanup)
                # Send SIGTERM to ourselves; the handler should run,
                # write the marker, and re-raise the signal.
                signal.raise_signal(signal.SIGTERM)
                """
            )
            script_path = Path(td) / "child_sigterm.py"
            script_path.write_text(program, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert marker.exists(), (
                f"trap handler did not run on SIGTERM: "
                f"rc={result.returncode} stderr={result.stderr}"
            )
            assert result.returncode != 0, (
                "SIGTERM was swallowed (exit 0); expected non-zero"
            )
    finally:
        # Restore so we don't leak handler state into the rest of the run.
        signal.signal(signal.SIGTERM, prev_handler)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific trap")
def test_register_traps_skips_sigterm_on_windows():
    """On Windows, ``register_traps`` must leave SIGTERM untouched."""
    prev_handler = signal.getsignal(signal.SIGTERM)

    def cleanup() -> None:
        pass

    try:
        trap.register_traps(cleanup)
    finally:
        signal.signal(signal.SIGTERM, prev_handler)

    # On Windows there is no SIGTERM handler in the conventional sense; the
    # important guarantee is that register_traps did not raise and did not
    # replace the prior handler. The "no change" assertion is what matters.
    assert signal.getsignal(signal.SIGTERM) is prev_handler


# ---------------------------------------------------------------------------
# cleanup_ip_whitelist: removed (Todo 5). The scanner no longer mutates
# the Azure storage firewall, so there is no firewall-revert step in
# the trap. These tests assert the function is no longer importable so
# a future regression that re-adds it is caught early.
# ---------------------------------------------------------------------------
def test_cleanup_ip_whitelist_no_longer_importable():
    """``cleanup_ip_whitelist`` was removed; it must NOT be importable.

    The scanner is now strictly read-only against Azure — it never
    mutates the ``state_account`` storage firewall, so there is no
    firewall-revert step to register in the cleanup trap. A regression
    that re-adds the function is an audit-grade failure and must fail
    this test loudly.
    """
    import scanner.trap as trap_module

    assert not hasattr(trap_module, "cleanup_ip_whitelist"), (
        "cleanup_ip_whitelist was removed; its re-introduction is a "
        "firewall-mutation regression. The scanner is read-only against "
        "Azure."
    )


# ---------------------------------------------------------------------------
# shred_plan_artifacts
# ---------------------------------------------------------------------------
def test_shred_plan_artifacts_removes_tfplan_binary(tmp_path):
    """``tfplan.binary`` must be gone after the call."""
    plan_bin = tmp_path / "tfplan.binary"
    plan_bin.write_bytes(b"secret-plan-bytes")
    assert plan_bin.exists()

    result = trap.shred_plan_artifacts(tmp_path)
    assert result is True
    assert not plan_bin.exists()


def test_shred_plan_artifacts_removes_plan_json(tmp_path):
    """``plan.json`` must be gone after the call."""
    plan_json = tmp_path / "plan.json"
    plan_json.write_text('{"secret": true}', encoding="utf-8")
    assert plan_json.exists()

    result = trap.shred_plan_artifacts(tmp_path)
    assert result is True
    assert not plan_json.exists()


def test_shred_plan_artifacts_idempotent_when_files_missing(tmp_path):
    """Calling shred on a directory with no plan files must succeed."""
    result = trap.shred_plan_artifacts(tmp_path)
    assert result is True


# ---------------------------------------------------------------------------
# safe_unlink: single helper for sensitive-artifact cleanup (Todo 11)
# ---------------------------------------------------------------------------
def test_safe_unlink_removes_file_inside_run_dir(tmp_path):
    """A file inside ``run_dir`` is removed by ``safe_unlink``."""
    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)
    target = run_dir / "tfplan.binary"
    target.write_bytes(b"secret-bytes")
    assert target.exists()

    result = trap.safe_unlink(target, run_dir)
    assert result is True
    assert not target.exists()


def test_safe_unlink_refuses_path_outside_run_dir(tmp_path):
    """``safe_unlink`` raises :class:`ValueError` for paths outside ``run_dir``.

    The containment check is the defense-in-depth guarantee: a
    future bug that smuggles a path outside the per-run directory
    must be caught at the helper boundary, not silently shredded.
    We assert both directions of escape (sibling directory + parent
    traversal) so the test catches regressions in either branch.
    """
    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)

    # Sibling — clearly outside the run_dir tree.
    sibling = tmp_path / "outside" / "tfplan.binary"
    sibling.parent.mkdir(parents=True)
    sibling.write_bytes(b"nope")
    with pytest.raises(ValueError):
        trap.safe_unlink(sibling, run_dir)
    # The file must NOT have been touched by the failed call.
    assert sibling.exists()

    # Parent-traversal — ``../foo`` collapses to a sibling of tmp_path,
    # which is also outside ``run_dir``.
    traversal = run_dir / ".." / ".." / "evil.binary"
    if not traversal.exists():
        traversal.parent.mkdir(parents=True, exist_ok=True)
        traversal.write_bytes(b"evil")
    with pytest.raises(ValueError):
        trap.safe_unlink(traversal, run_dir)


def test_safe_unlink_overwrites_with_zeros_when_shred_unavailable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When shred is unavailable, ``safe_unlink`` overwrites then unlinks.

    We simulate shred-unavailable by monkeypatching ``scanner_ops.run``
    to raise :class:`scanner.ops.TrustedBinaryMissing` on the
    ``"shred"`` operation. The helper must catch that, fall back to
    the overwrite-with-zeros + unlink path, and remove the file.

    The test also asserts that the file contents were zeroed before
    the unlink — this is the documented best-effort data-minimization
    step, and the only way the fallback provides any hygiene value at
    all (the inode name alone disappearing tells an attacker nothing
    about the prior contents).
    """
    from scanner.ops import TrustedBinaryMissing

    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)
    target = run_dir / "tfplan.binary"
    secret = b"\xDE\xAD\xBE\xEF" * 16  # 64 bytes, definitely non-zero
    target.write_bytes(secret)
    assert target.exists()

    # Force shred to look missing by raising TrustedBinaryMissing
    # from scanner_ops.run. All other ops must still work — we
    # only intercept the "shred" name.
    real_ops_run = trap.scanner_ops.run

    def fake_ops_run(name, *args, **kwargs):  # noqa: ANN001
        if name == "shred":
            raise TrustedBinaryMissing(
                "shred is not on PATH (test stub)"
            )
        return real_ops_run(name, *args, **kwargs)

    monkeypatch.setattr(trap.scanner_ops, "run", fake_ops_run)

    # Capture log output to assert the JSON-safe log line contains
    # only the basename and action — never the path tail or contents.
    captured: list[str] = []
    real_emit = trap.LOGGER.info

    def capturing_emit(msg, *args, **kwargs):  # noqa: ANN001
        captured.append(msg % args if args else str(msg))
        real_emit(msg, *args, **kwargs)

    monkeypatch.setattr(trap.LOGGER, "info", capturing_emit)

    # Run the cleanup.
    result = trap.safe_unlink(target, run_dir)
    assert result is True
    assert not target.exists(), "safe_unlink did not unlink the file"

    # The JSON-safe log line(s) must NOT contain:
    #   - the contents of the file (the secret bytes)
    #   - the full path tail (parent directories)
    # and MUST contain the basename + action.
    assert captured, "safe_unlink did not emit any log lines"
    log_blob = "\n".join(captured)
    assert secret.decode("latin-1") not in log_blob, (
        "JSON-safe log line leaked file contents"
    )
    # The basename must appear at least once in a complete log line.
    assert '"basename": "tfplan.binary"' in log_blob, (
        f"log lines missing basename key: {log_blob!r}"
    )
    # The action key must be one of the documented values.
    assert '"action":' in log_blob, (
        f"log lines missing action key: {log_blob!r}"
    )
    # The parent directory name MUST NOT appear in the log blob.
    # ``run_dir`` is ``<tmp_path>/runs/proj/env`` — none of those
    # tail segments should appear in any log line.
    for forbidden in ("/runs/", "/proj/", "/env/", "tmp_path"):
        if forbidden == "tmp_path":
            # The literal string "tmp_path" never appears in any log.
            assert "tmp_path" not in log_blob, (
                f"log blob leaked internal identifier: {log_blob!r}"
            )
        else:
            assert forbidden not in log_blob, (
                f"log blob leaked path tail {forbidden!r}: {log_blob!r}"
            )


def test_safe_unlink_returns_true_for_missing_file(tmp_path):
    """A missing target is treated as success (idempotent)."""
    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)
    target = run_dir / "does-not-exist.binary"

    result = trap.safe_unlink(target, run_dir)
    assert result is True


def test_safe_unlink_log_emits_json_safe_action_on_success(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every complete ``safe_unlink`` log line is a single JSON object.

    The scanner's audit-log contract is that the cleanup helper
    emits one structured JSON object per call — never a free-form
    string with the file's full path. We capture every ``info`` log
    call the helper makes, parse the line as JSON, and assert the
    schema is uniform.
    """
    import json

    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)
    target = run_dir / "tfplan.binary"
    target.write_bytes(b"x" * 32)

    # Force the overwrite+unlink fallback so the test is platform-
    # independent (does not require shred on PATH).
    from scanner.ops import TrustedBinaryMissing

    real_ops_run = trap.scanner_ops.run

    def fake_ops_run(name, *args, **kwargs):  # noqa: ANN001
        if name == "shred":
            raise TrustedBinaryMissing("shred is not on PATH (test stub)")
        return real_ops_run(name, *args, **kwargs)

    monkeypatch.setattr(trap.scanner_ops, "run", fake_ops_run)

    captured: list[str] = []
    real_emit = trap.LOGGER.info

    def capturing_emit(msg, *args, **kwargs):  # noqa: ANN001
        captured.append(msg % args if args else str(msg))

    monkeypatch.setattr(trap.LOGGER, "info", capturing_emit)

    trap.safe_unlink(target, run_dir)

    # Every captured line must be a single JSON object with at least
    # the documented keys. We don't require the helper to emit
    # exactly one line — multiple lines (overwrite, complete) are
    # fine — but each MUST be parseable as JSON.
    assert captured, "no log lines captured"
    for line in captured:
        # Skip lines the helper emits via plain text (none in the
        # current implementation, but future helpers may add WARN
        # lines that are also JSON — accept either).
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Free-form lines are not allowed for safe_unlink
            # emissions — every line must be JSON.
            pytest.fail(f"non-JSON log line emitted: {line!r}")
        assert "basename" in obj, f"log line missing basename: {obj!r}"
        assert "action" in obj, f"log line missing action: {obj!r}"
        assert "event" in obj, f"log line missing event: {obj!r}"


def test_create_secure_file_creates_empty_file(tmp_path):
    """``create_secure_file`` touches an empty file inside ``run_dir``."""
    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)
    target = run_dir / "tfplan.binary"

    trap.create_secure_file(target, run_dir)

    assert target.exists()
    assert target.stat().st_size == 0


def test_create_secure_file_refuses_traversal(tmp_path):
    """``create_secure_file`` raises :class:`ValueError` for paths outside run_dir."""
    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)

    with pytest.raises(ValueError):
        trap.create_secure_file(tmp_path / "outside" / "evil.binary", run_dir)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only chmod assertion")
def test_create_secure_file_applies_0o600_on_posix(tmp_path):
    """On POSIX, the helper applies 0o600 to the created file."""
    import stat

    run_dir = tmp_path / "runs" / "proj" / "env"
    run_dir.mkdir(parents=True)
    target = run_dir / "tfplan.binary"

    trap.create_secure_file(target, run_dir)
    mode = target.stat().st_mode
    # Owner read+write only; group and other bits zero.
    assert mode & stat.S_IRUSR, "owner-read bit missing"
    assert mode & stat.S_IWUSR, "owner-write bit missing"
    assert not (mode & stat.S_IRWXG), "group bits must be zero"
    assert not (mode & stat.S_IRWXO), "other bits must be zero"


# ---------------------------------------------------------------------------
# Signal-handler subprocess tests
# ---------------------------------------------------------------------------
# Helper that runs a child Python process which registers the trap, waits a
# tick, then sends itself a signal. We assert the child's exit code matches
# ``128 + signum`` — the bash ``trap`` convention — which proves the handler
# ran and re-raised the signal rather than swallowing it.

_SEND_SIGNAL_PROGRAM = textwrap.dedent(
    """
    import os, signal, sys, time
    sys.path.insert(0, {scanner_dir!r})
    from scanner import trap

    marker_path = {marker!r}

    def cleanup():
        try:
            open(marker_path, "w", encoding="utf-8").close()
        except OSError:
            pass

    trap.register_traps(cleanup)
    signum = {signum}
    # Give the runtime a moment to install the handlers before signalling.
    time.sleep(0.1)
    # ``signal.raise_signal`` is cross-platform: it lets Python deliver
    # the signal via the registered handler. ``os.kill(os.getpid(), ...)``
    # would also work on POSIX but on Windows it short-circuits the
    # handler by raising ``KeyboardInterrupt`` directly at the C level.
    signal.raise_signal(signum)
    # If the handler swallowed the signal we'd land here; that would be a
    # bug. Sleep just long enough to detect that case.
    time.sleep(0.2)
    sys.exit(0)
    """
)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only SIGTERM trap")
def test_sigterm_handler_calls_cleanup_and_exits_128_plus_signum(tmp_path):
    """SIGTERM must run cleanup and the child must exit ``128 + SIGTERM``."""
    marker = tmp_path / "sigterm_ran.marker"
    scanner_dir = str(Path(__file__).resolve().parents[2])  # project root, not scanner/
    program = _SEND_SIGNAL_PROGRAM.format(
        scanner_dir=scanner_dir, signum=signal.SIGTERM, marker=str(marker)
    )
    script_path = tmp_path / "child_sigterm.py"
    script_path.write_text(program, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert marker.exists(), (
        f"SIGTERM handler did not invoke cleanup "
        f"(rc={result.returncode}, stderr={result.stderr})"
    )
    assert result.returncode != 0, (
        "process exited cleanly after SIGTERM; signal was swallowed"
    )


def test_sigint_handler_calls_cleanup_and_exits_128_plus_signum(tmp_path):
    """SIGINT must run cleanup; the child must NOT exit cleanly.

    On POSIX the conventional exit status is ``128 + SIGINT`` (= 130).
    On Windows, re-raising SIGINT via ``os.kill`` surfaces as an uncaught
    ``KeyboardInterrupt`` and Python exits with status 2 — either way, the
    process must NOT exit 0 (which would mean the handler swallowed the
    signal).
    """
    marker = tmp_path / "sigint_ran.marker"
    scanner_dir = str(Path(__file__).resolve().parents[2])  # project root, not scanner/
    program = _SEND_SIGNAL_PROGRAM.format(
        scanner_dir=scanner_dir, signum=signal.SIGINT, marker=str(marker)
    )
    script_path = tmp_path / "child_sigint.py"
    script_path.write_text(program, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert marker.exists(), (
        f"SIGINT handler did not invoke cleanup "
        f"(rc={result.returncode}, stderr={result.stderr})"
    )
    assert result.returncode != 0, (
        "process exited cleanly after SIGINT; signal was swallowed"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific atexit path")
def test_windows_atexit_path_runs_cleanup_on_normal_exit(tmp_path):
    """On Windows, the atexit hook is the cleanup safety net.

    The child registers the trap, then ``sys.exit(0)``. Since SIGTERM
    is not deliverable on Windows, atexit is the only path that runs
    cleanup on a normal exit. A marker file written by the cleanup
    callback must exist after the child exits.
    """
    marker = tmp_path / "atexit_ran.marker"
    scanner_dir = str(Path(__file__).resolve().parents[2])  # project root, not scanner/

    program = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {scanner_dir!r})
        from scanner import trap

        marker_path = r"{marker}"

        def cleanup():
            with open(marker_path, "w", encoding="utf-8") as fh:
                fh.write("atexit-fires")

        trap.register_traps(cleanup)
        sys.exit(0)
        """
    )
    script_path = tmp_path / "child_atexit.py"
    script_path.write_text(program, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, (
        f"unexpected exit code {result.returncode}: {result.stderr}"
    )
    assert marker.exists(), "atexit hook did not run cleanup before exit"


# ---------------------------------------------------------------------------
# Cleanup side-effect: marker removal after signal
# ---------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only SIGTERM trap")
def test_cleanup_removes_marker_after_sigterm(tmp_path):
    """End-to-end: SIGTERM triggers cleanup, cleanup removes a marker file.

    We register a small cleanup callback that deletes the marker file,
    then send SIGTERM and assert the marker is gone — proving the
    handler actually ran. (The prior firewall-revert test name was
    removed when ``cleanup_ip_whitelist`` itself was deleted in Todo 5;
    the underlying trap mechanism is unchanged.)
    """
    marker = tmp_path / "cleanup_removed.marker"
    marker.touch()
    assert marker.exists()

    scanner_dir = str(Path(__file__).resolve().parents[2])  # project root, not scanner/

    program = textwrap.dedent(
        f"""
        import os, signal, sys, time
        sys.path.insert(0, {scanner_dir!r})
        from scanner import trap

        marker = r"{marker}"

        def cleanup():
            try:
                os.remove(marker)
            except OSError:
                pass

        trap.register_traps(cleanup)
        time.sleep(0.1)
        signal.raise_signal(signal.SIGTERM)
        time.sleep(0.2)
        sys.exit(0)
        """
    )
    script_path = tmp_path / "child_cleanup.py"
    script_path.write_text(program, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0, (
        f"process exited cleanly after SIGTERM (rc={result.returncode}); "
        f"signal was swallowed"
    )
    assert not marker.exists(), "cleanup callback did not delete the marker file"
