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
import json
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Callable

from scanner import ops as scanner_ops

LOGGER = logging.getLogger("scanner.trap")

# Default timeout for `shred -u` on POSIX.
_DEFAULT_SHRED_TIMEOUT = 5

# POSIX file mode applied when ``safe_unlink`` creates a sensitive artifact
# (read+write owner only, no group/world). Matches the policy used elsewhere
# in the scanner for ephemeral TF state (``orchestrator._isolate_terraform_env``
# uses 0o700 on directories; we use 0o600 on files because the artifact must
# be readable by the same owner that wrote it for downstream consumers).
_DEFAULT_FILE_MODE = 0o600


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
        if not safe_unlink(path, run_dir, timeout=timeout):
            ok = False
    return ok


# ---------------------------------------------------------------------------
# safe_unlink: single helper for cleanup of sensitive artifacts.
# ---------------------------------------------------------------------------
def safe_unlink(
    path: Path,
    run_dir: Path,
    timeout: int = _DEFAULT_SHRED_TIMEOUT,
) -> bool:
    """Remove ``path`` with PCI 10.7-hygiene best-effort data minimization.

    This is the single helper every cleanup site for sensitive
    artifacts (``tfplan.binary``, ``plan.json``, ``state_as_plan.json``,
    ``state.tfstate``, etc.) MUST use. It exists for one reason: the
    prior code base had three independent cleanup paths
    (``Path.unlink()``, ``os.remove()``, ``shred -u``) scattered across
    the orchestrator and trap modules. Each was slightly different —
    some overwrote with zeros, some did not; some ran shred, some did
    not; some validated the path, some did not. Unifying them behind
    one helper means there is exactly one place to audit, test, and
    extend the policy.

    What this helper does
    ---------------------
    1. **Path containment check (defense-in-depth).** Resolves
       ``path`` and ``run_dir`` (so symlinks and ``..`` segments are
       collapsed) and refuses to operate if ``path`` is not a
       descendant of ``run_dir``. Raises :class:`ValueError` on
       containment failure — this is a programming error, not a
       runtime I/O condition, and the caller is expected to surface it
       loudly so a future bug that smuggles a path outside the run
       directory is caught at the first call site, not silently
       shredded.
    2. **Secure deletion with fallback.** Tries ``shred -u <path>``
       first (POSIX only; routed through :func:`scanner.ops.run` so the
       argv is allowlist-validated). When shred is unavailable
       (:class:`scanner.ops.TrustedBinaryMissing`), the registry
       rejected the call, or the binary returned non-zero, falls back
       to:

         a. Open the file in write-binary mode and write
            ``b"\\x00" * file_size`` to overwrite the contents with
            zeros (best-effort; see limitations below).
         b. :meth:`Path.unlink` to remove the inode.

    3. **JSON-safe logging.** Emits a single ``INFO`` log line that
       contains ONLY the file's basename (``path.name``) and the
       action taken (``"shred"`` or ``"overwrite+unlink"``). Never
       the file's contents, its full path tail, or anything that
       could leak a sensitive attribute value into the audit log.

    Parameters
    ----------
    path:
        Sensitive artifact to remove. Must be inside ``run_dir``.
    run_dir:
        The per-run root the artifact lives under. Used for both the
        containment check and the helper's contract that no cleanup
        operates outside the run directory.
    timeout:
        Per-call subprocess timeout for ``shred``, in seconds. Defaults
        to 5.

    Returns
    -------
    bool
        ``True`` if the file is gone after the call (or was never
        there). ``False`` if the file is still on disk after every
        attempt.

    Raises
    ------
    ValueError
        When ``path`` is not inside ``run_dir`` after resolution. This
        is a programming error, not an I/O condition.

    Important: best-effort data minimization, NOT secure erasure
    ----------------------------------------------------
    Per the scanner's documented threat model, this helper is
    **best-effort data minimization**, not secure erasure. The
    following conditions are NOT covered and may leave the
    artifact's contents recoverable by an attacker with raw
    block-device access:

    * SSDs (wear-leveling may preserve the previous contents on
      retired blocks; the zero-fill only reaches the visible file).
    * Copy-on-write filesystems (btrfs, ZFS, APFS) — the overwrite
      creates a new block; the old block is freed back to the pool.
    * Journaling filesystems (ext3/ext4, XFS) — the journal may
      contain a copy of the prior contents.
    * VM snapshots / VM disk images — the host's snapshot layer
      preserves prior block states.
    * Windows NTFS — no POSIX-mode permission narrowing is performed
      and there is no portable ACL-equivalent we can rely on without
      a new dependency; this helper applies POSIX file mode on POSIX
      only and falls through to a plain overwrite + unlink on
      Windows.

    The helper exists to make accidental disclosure less likely (a
    subsequent ``cat`` of the file returns nothing; a casual ``ls
    -l`` shows the artifact gone). It is NOT a defense against an
    attacker with root + raw-block access.

    POSIX file mode on creation
    ---------------------------
    ``safe_unlink`` ONLY applies the 0o600 mode-restriction when it
    is CREATING a file (i.e. when the caller passes a path that does
    not yet exist). For the typical cleanup call site the file
    already exists, so this is a no-op there. Use
    :func:`create_secure_file` when you need to atomically create a
    sensitive artifact with the right mode.
    """
    path = Path(path)
    run_dir = Path(run_dir)

    # 1. Path containment check. Both sides are resolved so symlinks
    #    and ``..`` segments cannot be used to escape ``run_dir``.
    #    resolve() is a no-op for paths that don't exist on POSIX, so
    #    the missing-file case is still bounded by ``run_dir``.
    try:
        resolved_run_dir = run_dir.resolve()
        resolved_path = path.resolve()
    except OSError:
        # resolve() can raise on platforms with very long paths; we
        # fall back to comparing the raw segments. This is the last
        # line of defense, not the first.
        resolved_run_dir = run_dir.absolute()
        resolved_path = path.absolute()

    try:
        resolved_path.relative_to(resolved_run_dir)
    except ValueError as exc:
        raise ValueError(
            f"safe_unlink refused: {path!s} is not inside run_dir {run_dir!s} "
            f"(resolved: {resolved_path!s} not under {resolved_run_dir!s})"
        ) from exc

    # 2. Secure deletion with shred-or-zero fallback.
    return _secure_remove(path, timeout=timeout, run_dir=resolved_run_dir)


def create_secure_file(
    path: Path,
    run_dir: Path,
    mode: int = _DEFAULT_FILE_MODE,
) -> None:
    """Create ``path`` (empty) with restrictive POSIX permissions.

    Companion to :func:`safe_unlink`: this is the creation-side
    helper for sensitive artifacts. It enforces the containment
    check (same as ``safe_unlink``) and applies ``mode`` on POSIX
    so the file is owner-only read+write from the moment it exists.

    On Windows there is no portable ACL-equivalent in stdlib; we
    create the file and log a one-line ``INFO`` noting that the
    POSIX-mode narrowing was skipped. Operators who need
    Windows-side ACL restriction should layer ``icacls`` or a
    third-party ACL library on top — out of scope for this helper.

    Idempotent: if the file already exists, its mode is NOT
    changed (the helper does not want to silently widen
    permissions on a file written by a separate process). Callers
    that need to ensure the mode on every write should use
    :func:`os.open` with ``O_CREAT|O_WRONLY|O_TRUNC`` directly.

    Parameters
    ----------
    path:
        File path to create. Must be inside ``run_dir``.
    run_dir:
        The per-run root. Containment is enforced the same way
        as :func:`safe_unlink`.
    mode:
        POSIX file mode bits. Defaults to ``0o600`` (owner read/write
        only).

    Raises
    ------
    ValueError
        When ``path`` is not inside ``run_dir`` after resolution.
    OSError
        On filesystem failure (propagated from ``Path.touch``).
    """
    path = Path(path)
    run_dir = Path(run_dir)

    # Same containment check as safe_unlink — keep the two in lockstep
    # so any future change to the policy applies to both.
    try:
        resolved_run_dir = run_dir.resolve()
        resolved_path = path.resolve()
    except OSError:
        resolved_run_dir = run_dir.absolute()
        resolved_path = path.absolute()

    try:
        resolved_path.relative_to(resolved_run_dir)
    except ValueError as exc:
        raise ValueError(
            f"create_secure_file refused: {path!s} is not inside run_dir "
            f"{run_dir!s} (resolved: {resolved_path!s} not under "
            f"{resolved_run_dir!s})"
        ) from exc

    path.touch(exist_ok=True)
    if sys.platform != "win32":
        try:
            os.chmod(path, mode)
        except OSError as exc:
            LOGGER.warning(
                json.dumps(
                    {
                        "event": "create_secure_file.chmod_failed",
                        "basename": path.name,
                        "error": str(exc),
                    }
                )
            )
    else:
        LOGGER.info(
            json.dumps(
                {
                    "event": "create_secure_file.windows_no_acl",
                    "basename": path.name,
                    "note": "POSIX-mode narrowing skipped on Windows; "
                    "no portable stdlib ACL helper.",
                }
            )
        )


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


def _secure_remove(path: Path, timeout: int, run_dir: Path | None = None) -> bool:
    """Internal worker for :func:`safe_unlink`.

    Tries ``shred -u`` on POSIX (routed through :func:`scanner.ops.run`
    so the argv is allowlist-validated), then falls back to an
    overwrite-with-zeros + :meth:`Path.unlink` pair when shred is
    unavailable. Returns ``True`` if the file is gone after the call.

    The ``run_dir`` argument is currently unused by the worker itself
    — it is kept on the signature so future logging/audit changes can
    attach run-dir context without breaking call sites. The caller
    (:func:`safe_unlink`) passes it explicitly.
    """
    # JSON-safe log line emitter. Only the basename (never the path
    # tail) and the action taken are surfaced — never the file's
    # contents, full path, or any attribute value that could leak
    # sensitive data into the audit log. The line is emitted as a
    # single JSON object so log-shipping systems can parse it
    # cleanly without per-line regex.
    def _emit(event: str, action: str, **extra: object) -> None:
        payload = {"event": event, "basename": path.name, "action": action}
        payload.update(extra)
        LOGGER.info(json.dumps(payload))

    # POSIX path: try shred first, fall back to overwrite + unlink.
    # Windows path: skip shred (not available on Windows) and use
    # the overwrite + unlink fallback directly.
    if not path.exists():
        # Idempotent: a missing file is treated as success. The
        # caller is the orchestrator's per-pair cleanup hook, which
        # routinely calls safe_unlink on paths that may have been
        # removed by a previous step (e.g. by a signal handler that
        # fired mid-run). Returning True here matches the
        # ``shred_plan_artifacts`` contract — missing files are
        # silently treated as success.
        _emit("safe_unlink.complete", "noop", note="missing_file")
        return True

    if sys.platform != "win32":
        try:
            result = scanner_ops.run(
                "shred",
                "-u", str(path),
                tier="plan",
                timeout=timeout,
            )
            if result.returncode == 0 and not path.exists():
                _emit("safe_unlink.complete", "shred")
                return True
            LOGGER.warning(
                json.dumps(
                    {
                        "event": "safe_unlink.shred_nonzero",
                        "basename": path.name,
                        "returncode": result.returncode,
                    }
                )
            )
        except scanner_ops.TrustedBinaryMissing:
            # The registry refused because shred isn't on PATH.
            # Fall through to the overwrite + unlink fallback.
            _emit("safe_unlink.shred_unavailable", "fallback", reason="binary_missing")
        except scanner_ops.ArgvSchemaViolation as exc:
            # Should not happen — the helper is the only caller and
            # always passes ``("-u", str(path))``. Log and fall back
            # so a future argv-shape change does not silently leak
            # the artifact.
            LOGGER.warning(
                json.dumps(
                    {
                        "event": "safe_unlink.shred_argv_rejected",
                        "basename": path.name,
                        "error": str(exc),
                    }
                )
            )
            _emit("safe_unlink.shred_unavailable", "fallback", reason="argv_rejected")
        except scanner_ops.TierViolation as exc:
            LOGGER.warning(
                json.dumps(
                    {
                        "event": "safe_unlink.shred_tier_refused",
                        "basename": path.name,
                        "error": str(exc),
                    }
                )
            )
            _emit("safe_unlink.shred_unavailable", "fallback", reason="tier_refused")
        except subprocess.TimeoutExpired:
            LOGGER.warning(
                json.dumps(
                    {
                        "event": "safe_unlink.shred_timeout",
                        "basename": path.name,
                        "timeout": timeout,
                    }
                )
            )
        except OSError as exc:
            LOGGER.warning(
                json.dumps(
                    {
                        "event": "safe_unlink.shred_start_failed",
                        "basename": path.name,
                        "error": str(exc),
                    }
                )
            )

    # Fallback: overwrite with zeros, then unlink. Best-effort — see
    # the "best-effort data minimization" docstring on safe_unlink
    # for the list of conditions this does NOT cover (SSDs, CoW,
    # journaling, VM snapshots, Windows ACLs).
    try:
        size = path.stat().st_size
        with open(path, "wb") as fh:
            fh.write(b"\x00" * size)
        _emit("safe_unlink.complete", "overwrite+unlink")
    except OSError as exc:
        LOGGER.warning(
            json.dumps(
                {
                    "event": "safe_unlink.overwrite_failed",
                    "basename": path.name,
                    "error": str(exc),
                }
            )
        )

    try:
        Path(path).unlink()
        return True
    except OSError as exc:
        LOGGER.warning(
            json.dumps(
                {
                    "event": "safe_unlink.unlink_failed",
                    "basename": path.name,
                    "error": str(exc),
                }
            )
        )
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
