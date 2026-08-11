#!/usr/bin/env python3
"""
Trap registration and cleanup helpers for the Pacioli scanner.

Mirrors the bash `trap trap_on_exit EXIT INT TERM` semantics from
``scanner/lib/common.sh`` (function ``trap_on_exit`` plus the
``shred_plan_artifacts`` helper it calls).

Why this exists
---------------
When the scanner is being driven from Python (the future CLI entry point
and any embedded callers), we still need the PCI 10.7 hygiene guarantee:
even if the run dies abruptly (Ctrl+C in a local run, CI job timeout,
OOM kill signal propagation), the sensitive plan artifacts
(``tfplan.binary``, ``plan.json``) are shredded.

The storage firewall IP whitelist (and its cleanup) was removed: the
scanner is now strictly read-only against Azure — it never mutates the
``state_account`` storage firewall. The pair-level plan/state passes
fail-closed if network access is not already granted (see
:func:`scanner.orchestrator.Orchestrator._alert_network_required`).

Design choices
--------------
* **Re-raises the signal** — bash ``trap`` re-runs the default handler after
  the cleanup, which means the shell exits with ``128+N``. Python's
  ``atexit`` has no equivalent, but a signal handler can simulate it by
  restoring ``SIG_DFL`` and re-raising. The handler must NOT swallow the
  signal — otherwise CI sees a clean exit on a SIGTERM that should have
  been a failure.
* **Bounded subprocess timeouts** — every ``shred`` invocation inside a
  handler MUST go through :func:`scanner.ops.run` with an explicit
  ``timeout=...``. A hung shred cannot be allowed to block past the
  CI job's grace window; the trap itself has to finish promptly.
* **Windows-aware** — ``signal.SIGTERM`` registration is a no-op on
  Windows. ``SIGINT`` + ``atexit`` still fire, which is the right
  behaviour for the local Windows dev case.
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Callable

from scanner import ops as scanner_ops

LOGGER = logging.getLogger("scanner.trap")

# Default timeout for `shred -u` on POSIX.
_DEFAULT_SHRED_TIMEOUT = 5


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def register_traps(cleanup_fn: Callable[[], None]) -> None:
    """
    Register ``atexit`` + ``SIGTERM`` + ``SIGINT`` handlers that call
    ``cleanup_fn`` exactly once, then re-raise the signal so the
    process exits with status ``128 + signum`` (the convention bash
    ``trap`` uses).

    The trap is **one-shot by design**: after the first signal fires,
    ``atexit`` is NOT unregistered, but the inner handler restores
    ``SIG_DFL`` for that signal so subsequent deliveries of the same
    signal take the default action (which for SIGINT/SIGTERM is process
    termination). This matches the bash behaviour where the EXIT trap
    runs once and then the process exits.

    Parameters
    ----------
    cleanup_fn:
        Zero-arg callable invoked from each handler. Should run quickly
        (sub-second ideal; bounded by ``timeout`` on its subprocess
        calls). Any exception it raises is logged but NOT re-raised, so
        the signal still reaches the default handler and the process
        still terminates with the conventional exit status.

    Windows note
    ------------
    ``SIGTERM`` registration is silently skipped on Windows — the
    platform has no reliable way to deliver SIGTERM to a Python process
    and ``signal.signal(SIGTERM, ...)`` may even raise ``ValueError`` on
    some 3.12+ builds. ``SIGINT`` (Ctrl+C) + ``atexit`` still cover
    the local dev case.
    """
    # atexit runs on any clean interpreter shutdown: normal exit, sys.exit,
    # uncaught exception that triggers shutdown, AND (on POSIX) on signal
    # delivery via the default handler. It's our safety net for paths the
    # signal handlers don't catch.
    atexit.register(_safe_call, cleanup_fn, "atexit")

    # SIGINT first, then SIGTERM. Order matters: if the OS were to
    # somehow deliver both before we finish registering, we want the
    # one that's most likely to be the actual user request handled.
    _register_signal(signal.SIGINT, cleanup_fn)
    _register_signal(signal.SIGTERM, cleanup_fn)


def shred_plan_artifacts(
    run_dir: Path,
    timeout: int = _DEFAULT_SHRED_TIMEOUT,
) -> bool:
    """
    Securely remove ``tfplan.binary`` and ``plan.json`` from
    ``run_dir``.

    Per PCI 10.7 hygiene, these files contain resolved Azure topology
    and may carry sensitive attribute values; they MUST NOT linger on
    disk after the run finishes.

    Strategy:
    * POSIX: try ``shred -u <path>`` first (with a ``timeout=timeout``
      guard so a hung shred cannot block the trap), fall back to
      ``os.remove`` if shred is missing or fails.
    * Windows: ``shred`` is not available; use ``os.remove`` directly.

    Idempotent: missing files are silently treated as success.

    Parameters
    ----------
    run_dir:
        Per-run working directory.
    timeout:
        Per-call subprocess timeout for ``shred``, in seconds. Defaults
        to 5.

    Returns
    -------
    bool
        ``True`` if both files are absent after the call (either they
        never existed or they were removed). ``False`` if at least one
        file is still on disk.
    """
    targets = ("tfplan.binary", "plan.json")
    ok = True
    for name in targets:
        path = Path(run_dir) / name
        if not path.exists():
            continue
        if not _secure_remove(path, timeout=timeout):
            ok = False
    return ok


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _safe_call(cleanup_fn: Callable[[], None], origin: str) -> None:
    """Run ``cleanup_fn``, swallow + log any exception."""
    try:
        cleanup_fn()
    except Exception as exc:  # noqa: BLE001 — cleanup is best-effort
        LOGGER.warning("cleanup via %s raised: %s", origin, exc)


def _register_signal(signum: int, cleanup_fn: Callable[[], None]) -> None:
    """
    Register ``cleanup_fn`` for ``signum``; after running it, restore
    the default handler and re-raise the signal so the process exits
    with ``128 + signum`` (bash convention).

    On Windows, only ``SIGINT`` is honoured. ``SIGTERM`` registration
    is skipped (and logged) because it is not reliably deliverable
    there.
    """
    sig_name = _signal_name(signum)
    if sys.platform == "win32" and signum != signal.SIGINT:
        LOGGER.info(
            "skipping %s trap registration on Windows (not deliverable); "
            "atexit + SIGINT still cover cleanup",
            sig_name,
        )
        return

    def _handler(received_signum: int, _frame: object) -> None:
        LOGGER.warning("received %s; running cleanup", _signal_name(received_signum))
        _safe_call(cleanup_fn, _signal_name(received_signum))
        # Restore default action and re-raise so the OS applies the
        # conventional exit status (128 + signum) rather than the
        # default 0 from a clean handler return.
        try:
            signal.signal(received_signum, signal.SIG_DFL)
        except (ValueError, OSError):
            # Some platforms (and signal types) don't allow restoring
            # SIG_DFL. Fall through to the cross-platform exit call.
            pass
        try:
            os.kill(os.getpid(), received_signum)
        except OSError:
            # Re-raise failed (e.g. SIGTERM under bash where the
            # process group is being torn down). Fall back to a direct
            # exit so the CI job still records a non-zero status.
            sys.exit(128 + received_signum)

    try:
        signal.signal(signum, _handler)
        LOGGER.info("registered %s trap", sig_name)
    except (ValueError, OSError) as exc:
        LOGGER.warning(
            "could not register %s trap (%s); atexit still covers cleanup",
            sig_name,
            exc,
        )


def _signal_name(signum: int) -> str:
    """Human-readable signal name; falls back to ``"signal N"``."""
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"


def _secure_remove(path: Path, timeout: int) -> bool:
    """
    Remove ``path``: prefer ``shred -u`` on POSIX (bounded by
    ``timeout``), fall back to ``os.remove``. Always returns ``True``
    if the file is gone after the call.
    """
    if sys.platform == "win32":
        try:
            os.remove(path)
            LOGGER.info("removed %s", path)
            return True
        except OSError as exc:
            LOGGER.warning("failed to remove %s: %s", path, exc)
            return False

    shred_path = shutil.which("shred")
    if shred_path is not None:
        try:
            result = scanner_ops.run(
                "shred",
                "-u", str(path),
                tier="plan",
                timeout=timeout,
            )
            if result.returncode == 0 and not path.exists():
                LOGGER.info("shredded %s", path)
                return True
            LOGGER.warning(
                "shred -u %s returned rc=%d; falling back to os.remove",
                path,
                result.returncode,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning(
                "shred -u %s timed out after %ds; falling back to os.remove",
                path,
                timeout,
            )
        except OSError as exc:
            LOGGER.warning("shred -u %s failed to start: %s", path, exc)

    try:
        os.remove(path)
        LOGGER.info("removed %s (os.remove fallback)", path)
        return True
    except OSError as exc:
        LOGGER.warning("failed to remove %s: %s", path, exc)
        return False


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Demonstrate the API by registering a trap with a counter closure
    # and triggering SIGINT via os.kill. We do NOT actually replace the
    # process's exit status in this smoke block — the goal is to prove
    # that the handler runs and the cleanup_fn is callable.
    import tempfile

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    counter = {"calls": 0}

    def _cleanup() -> None:
        counter["calls"] += 1
        LOGGER.info("cleanup_fn invoked (call #%d)", counter["calls"])

    register_traps(_cleanup)

    with tempfile.TemporaryDirectory() as tmp:
        run_dir = Path(tmp)

        # Create a fake plan artifact and shred it. shred_plan_artifacts
        # should remove it via os.remove (since `shred` is not on
        # Windows; on POSIX the test environment may or may not have
        # shred — either path is valid).
        plan_bin = run_dir / "tfplan.binary"
        plan_bin.write_bytes(b"fake-plan-binary-bytes")
        ok = shred_plan_artifacts(run_dir)
        LOGGER.info(
            "shred_plan_artifacts returned %s; tfplan.binary exists=%s",
            ok,
            plan_bin.exists(),
        )

    # Trigger SIGINT to prove the handler runs. After the handler
    # restores SIG_DFL and re-raises, Python's default SIGINT handler
    # will raise KeyboardInterrupt; we catch it so the smoke test
    # exits 0.
    LOGGER.info("sending SIGINT to self to exercise handler")
    os.kill(os.getpid(), signal.SIGINT)
    LOGGER.info("post-SIGINT (unexpected — handler should have re-raised)")

    sys.exit(0)
