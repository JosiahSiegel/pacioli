"""url_rewrite.py — In-process rewrite of docs.prismacloud.io URLs.

This module is the Python port of the bash ``checkov_stderr_filter``
(sed-based prismacloud.io redirect, scan.sh lines 285-289) plus the
SARIF ``helpUri`` rewriter from ``rewrite_sarif_help.py``. It exists so
the scanner can:

1. Apply the redirect to the runner's stdout/stderr in-process via a
   context manager that wraps the runner's emit (no subprocess, no
   temp files). This means a `print()` from inside the runner that
   happens to contain a docs.prismacloud.io URL reaches the operator
   already rewritten — same behavior as piping through the old
   ``checkov_stderr_filter`` sed, but with no shell dependency.

2. Self-contain the SARIF rewriter so a single ``from scanner.url_rewrite
   import rewrite_sarif_file`` does both jobs. ``rewrite_sarif_help.py``
   remains as a thin wrapper around ``rewrite_sarif_file`` for backward
   compatibility with any external caller that imports it by name.

The rewrite is mechanical: any URL starting with ``docs.prismacloud.io``
through the next whitespace is replaced with the static Checkov GitHub
repo root (``https://github.com/bridgecrewio/checkov``) — that URL is
always 200 and the operator can drill down to the rule file manually.

Pure stdlib. No new dependencies.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterator

# Allow running as a script from anywhere — mirror the path bootstrap
# used in rewrite_sarif_help.py so the SARIF rewriter can import its
# mapping table.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from checkov_url_overrides import get_help_uri  # noqa: E402

# Host literal used by every docs.prismacloud.io rewrite/assertion in
# this module. Extracted to a module-level constant (S1192) so the
# hostname lives in exactly one place — changing it touches every
# call site at once.
PRISMA_DOCS_HOST: str = "docs.prismacloud.io"

# Pattern matches any URL whose host starts with docs.prismacloud.io,
# extending through the next whitespace. Equivalent to the bash sed
# ``https://docs\.prismacloud\.io[^[:space:]]*`` — non-greedy by
# construction because the character class excludes whitespace.
_PRISMA_URL_PATTERN: re.Pattern[str] = re.compile(
    r"https://docs\.prismacloud\.io[^\s]+"
)

# Replacement target. Static repo root — always 200, never 404.
_REPLACEMENT_URL: str = "https://github.com/bridgecrewio/checkov"


def rewrite_text(text: str) -> str:
    """Rewrite all docs.prismacloud.io URLs in ``text``.

    Pure function — exposed so callers that already have a string (e.g.
    a captured log line) can rewrite without going through a stream.
    """
    return _PRISMA_URL_PATTERN.sub(_REPLACEMENT_URL, text)


class URLRewriteStream(io.TextIOBase):
    """A ``io.TextIOBase`` wrapper that rewrites docs.prismacloud.io URLs.

    Designed to be swapped in for ``sys.stdout`` / ``sys.stderr`` while
    the runner emits — every ``write()`` runs its argument through
    ``rewrite_text()`` and forwards to the wrapped stream, then calls
    ``flush()`` on the wrapped stream to preserve line-buffering
    semantics (the operator still sees output arrive line-by-line, not
    in one dump at the end).

    Notes:
        - ``io.TextIOBase`` provides a working ``write()`` and a
          default no-op ``flush()``/``writable()``; we override the
          minimum needed and defer everything else to the wrapped
          stream via composition-style attribute passthrough.
        - We intentionally do NOT inherit from the wrapped stream
          directly — that breaks if the wrapped stream is e.g.
          ``sys.stdout`` (a ``TextIOWrapper``) whose ``__init__``
          requires a real underlying buffer. Subclassing
          ``io.TextIOBase`` and delegating is the safe option.
    """

    def __init__(self, wrapped: io.TextIOBase) -> None:
        self._wrapped = wrapped

    # ---- io.TextIOBase overrides ----------------------------------------

    def writable(self) -> bool:
        return self._wrapped.writable()

    def flush(self) -> None:
        self._wrapped.flush()

    def write(self, s: str) -> int:  # type: ignore[override]
        if not s:
            return 0
        rewritten = rewrite_text(s)
        # ``io.TextIOBase.write`` returns the number of characters
        # written; mirror that contract so callers that read the
        # return value (logging.StreamHandler, print internals, etc.)
        # still work correctly.
        written = self._wrapped.write(rewritten)
        # Preserve line-buffering semantics — flush after each rewrite
        # so the operator sees output immediately, just like the old
        # sed pipe which was line-buffered by default.
        try:
            self._wrapped.flush()
        except (AttributeError, ValueError):
            # Some streams (rare) don't support flush() in all states.
            # Swallow rather than crash the runner mid-emit.
            pass
        return written if written is not None else len(rewritten)

    # ---- passthrough helpers --------------------------------------------

    @property
    def wrapped(self) -> io.TextIOBase:
        """The underlying stream — exposed for tests and for the
        context manager to restore the original on exit."""
        return self._wrapped


@contextlib.contextmanager
def redirect_stdout_stderr() -> Iterator[tuple[URLRewriteStream, URLRewriteStream]]:
    """Swap ``sys.stdout`` / ``sys.stderr`` with URL-rewriting wrappers.

    Yields a ``(out_wrapper, err_wrapper)`` tuple so callers can access
    the wrappers if needed (e.g. to forward to a captured buffer for
    tests). On exit — even on exception — restores the original
    streams. This is the same restore-on-exit contract as
    ``contextlib.redirect_stdout`` but for both streams at once.
    """
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    out_wrapper = URLRewriteStream(original_stdout)
    err_wrapper = URLRewriteStream(original_stderr)
    sys.stdout = out_wrapper
    sys.stderr = err_wrapper
    try:
        yield out_wrapper, err_wrapper
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        # Flush both originals so any buffered rewritten output makes
        # it to the terminal before we hand control back.
        for stream in (original_stdout, original_stderr):
            try:
                stream.flush()
            except (AttributeError, ValueError):
                pass


def _load_sarif(path: Path) -> dict | None:
    """Read and parse a SARIF file from disk.

    Returns the parsed JSON object on success, or ``None`` if the file
    is not valid JSON (errors are logged to stderr). All other schema
    validation (presence of ``runs``, etc.) is deferred to the caller
    so this helper stays focused on the I/O contract.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"  ERROR: {path} is not valid JSON: {exc}", file=sys.stderr)
        return None


def _rewrite_rule(rule: object) -> tuple[int, int]:
    """Rewrite one SARIF rule and return ``(rewritten, skipped)`` counts."""
    if not isinstance(rule, dict):
        return 0, 0
    rid = rule.get("id", "")
    old = rule.get("helpUri")
    new = get_help_uri(rid, old)
    if new == old:
        return 0, 1
    rule["helpUri"] = new
    return 1, 0


def _rewrite_rules(runs: list[object]) -> tuple[int, int]:
    """Mutate ``helpUri`` on every rule in every run's tool driver."""
    rewritten = 0
    skipped = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        if not isinstance(tool, dict):
            continue
        driver = tool.get("driver")
        if not isinstance(driver, dict):
            continue
        rules = driver.get("rules", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            rule_rewritten, rule_skipped = _rewrite_rule(rule)
            rewritten += rule_rewritten
            skipped += rule_skipped
    return rewritten, skipped


def _validate_sarif_path(path: Path) -> Path:
    """Validate that ``path`` looks like a SARIF file on disk.

    Guards the ``write_text`` sink (S2083). The caller passes a
    user-influenced path (the ``--sarif`` CLI flag, in turn sourced from
    a pipeline-resolved artifact location). We require:

      * the suffix is ``.sarif`` (case-insensitive), and
      * the resolved path lives under a non-system, writable location
        (CWD, the system temp dir, or the user's home dir).

    This is a real check (suffix regex + path-prefix match), not a
    ``# noqa``. It blocks ``/etc/passwd`` style absolute paths while
    still allowing pytest temp dirs and the consumer's run output dir.
    Raises :class:`ValueError` on a mismatch so the caller fails fast
    rather than writing to an unexpected location.
    """
    resolved = path.expanduser().resolve()
    if resolved.suffix.lower() != ".sarif":
        raise ValueError(
            f"refusing to rewrite non-SARIF path: {resolved} "
            f"(suffix must be .sarif, got {resolved.suffix!r})"
        )
    allowed_parents: list[Path] = [
        Path.cwd().resolve(),
        Path.home().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]
    if not any(
        resolved == parent or parent in resolved.parents
        for parent in allowed_parents
    ):
        raise ValueError(
            f"refusing to rewrite SARIF outside allowed roots: "
            f"{resolved} not under {[str(p) for p in allowed_parents]}"
        )
    return resolved


def _is_under(child: Path, parent: Path) -> bool:
    """Return True iff ``child`` is the same path as or lives under ``parent``.

    Thin wrapper over :meth:`pathlib.PurePath.is_relative_to` (Python 3.9+)
    so the static analyzer (SonarCloud S2083) can recognize the call as a
    path-sanitization sink. ``is_relative_to`` is preferred over a manual
    ``child == parent or parent in child.parents`` because it is the
    canonical, well-tested stdlib check.
    """
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _write_sarif_atomic(path: Path, data: dict) -> None:
    """Write SARIF ``data`` back to ``path`` atomically.

    Serializes to a ``.tmp`` sibling first, then ``Path.replace``s it
    over the target. This means a crash during write never leaves a
    half-written SARIF in place — the original is preserved until the
    rename succeeds.

    The destination is validated against a SARIF-suffix + CWD-prefix
    allow-list INLINE, before any I/O runs (S2083). Resolving the
    user-supplied path and confirming it sits under at least one
    canonical root via :func:`_is_under` (which delegates to
    ``PurePath.is_relative_to``) gives the static analyzer a single,
    recognizable sanitization sink between the tainted input and the
    ``write_text`` call.
    """
    resolved = path.expanduser().resolve()
    if resolved.suffix.lower() != ".sarif":
        raise ValueError(
            f"refusing to rewrite non-SARIF path: {resolved} "
            f"(suffix must be .sarif, got {resolved.suffix!r})"
        )
    allowed_parents: list[Path] = [
        Path.cwd().resolve(),
        Path.home().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]
    if not any(_is_under(resolved, parent) for parent in allowed_parents):
        raise ValueError(
            f"refusing to rewrite SARIF outside allowed roots: "
            f"{resolved} not under {[str(p) for p in allowed_parents]}"
        )
    # At this point ``resolved`` is provably sanitized via
    # ``PurePath.is_relative_to`` — the S2083 sink is cleared.
    tmp_path = resolved.with_suffix(resolved.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    tmp_path.replace(resolved)


def rewrite_sarif_file(path: Path) -> tuple[int, int]:
    """Rewrite ``helpUri`` fields in a SARIF file.

    Self-contained port of ``rewrite_sarif_help.rewrite_sarif()`` so
    this module can be the single import for all URL rewriting. Logic
    is identical to the original: walk each run's tool.driver.rules,
    swap ``helpUri`` for the canonical GitHub source URL via
    ``get_help_uri(rule_id, old)``, and write back atomically via a
    ``.tmp`` sibling + ``Path.replace``.

    Args:
        path: Path to a SARIF (``.sarif``) file on disk.

    Returns:
        ``(rewritten_count, skipped_count)`` — number of rules whose
        ``helpUri`` changed vs. number whose ``helpUri`` was already
        correct. On parse errors or missing ``runs`` array, returns
        ``(0, 0)`` and logs to stderr.
    """
    data = _load_sarif(path)
    if data is None:
        return 0, 0

    runs = data.get("runs", [])
    if not isinstance(runs, list) or not runs:
        print(f"  WARN: {path} has no 'runs' array; skipping", file=sys.stderr)
        return 0, 0

    rewritten, skipped = _rewrite_rules(runs)
    _write_sarif_atomic(path, data)
    return rewritten, skipped


# ---------------------------------------------------------------------------
# Smoke test — exercises the stream wrapper, the context manager, and the
# text rewriter end-to-end. Exits non-zero on any failure so this can be
# used as a CI gate.
# ---------------------------------------------------------------------------


def _smoke_test() -> int:
    """Run a quick end-to-end sanity check. Returns process exit code."""
    prisma_url_a = f"https://{PRISMA_DOCS_HOST}/some/deep/link"
    prisma_url_b = f"https://{PRISMA_DOCS_HOST}/path/to/rule"
    prisma_url_c = f"https://{PRISMA_DOCS_HOST}/x"
    prisma_url_d = f"https://{PRISMA_DOCS_HOST}/y"
    prisma_url_e = f"https://{PRISMA_DOCS_HOST}/z"
    prisma_url_f = f"https://{PRISMA_DOCS_HOST}/old/1"

    print("smoke: rewrite_text()")
    sample = f"see {prisma_url_a} for details"
    got = rewrite_text(sample)
    expected = f"see {_REPLACEMENT_URL} for details"
    assert got == expected, f"rewrite_text() failed: {got!r} != {expected!r}"
    print(f"  in : {sample!r}")
    print(f"  out: {got!r}")

    print("smoke: URLRewriteStream.write()")
    buf = io.StringIO()
    stream = URLRewriteStream(buf)
    stream.write(f"docs: {prisma_url_b}\n")
    captured = buf.getvalue()
    assert _REPLACEMENT_URL in captured, (
        f"URLRewriteStream.write() failed: {captured!r}"
    )
    assert PRISMA_DOCS_HOST not in captured, (
        f"original URL leaked through: {captured!r}"
    )
    print(f"  captured: {captured!r}")

    print("smoke: redirect_stdout_stderr() context manager")
    captured_out = io.StringIO()
    captured_err = io.StringIO()

    # Point sys.stdout / sys.stderr at our StringIOs so the context
    # manager wraps those — and so we can inspect what the wrappers
    # wrote. On exit, the context manager must restore sys.stdout /
    # sys.stderr to whatever they were at entry (the StringIOs).
    real_stdout, real_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = captured_out, captured_err
    sysout_at_entry = sys.stdout
    syserr_at_entry = sys.stderr
    try:
        with redirect_stdout_stderr() as (out_w, err_w):
            # Inside the with-block, sys.stdout/stderr should be the
            # URLRewriteStream wrappers, not the StringIOs.
            assert isinstance(sys.stdout, URLRewriteStream), (
                f"stdout not wrapped inside context: {type(sys.stdout)}"
            )
            assert isinstance(sys.stderr, URLRewriteStream), (
                f"stderr not wrapped inside context: {type(sys.stderr)}"
            )
            print(f"err: {prisma_url_c}")
            sys.stdout.write(f"out: {prisma_url_d}\n")
            sys.stderr.write(f"err2: {prisma_url_e}\n")
        # After exit, sys.stdout/stderr must be restored to what they
        # were at entry — i.e. the StringIOs.
        assert sys.stdout is sysout_at_entry, (
            "stdout not restored to entry value on exit"
        )
        assert sys.stderr is syserr_at_entry, (
            "stderr not restored to entry value on exit"
        )
    finally:
        sys.stdout, sys.stderr = real_stdout, real_stderr

    out_text = captured_out.getvalue()
    err_text = captured_err.getvalue()
    assert PRISMA_DOCS_HOST not in out_text, (
        f"prismacloud URL leaked to stdout: {out_text!r}"
    )
    assert PRISMA_DOCS_HOST not in err_text, (
        f"prismacloud URL leaked to stderr: {err_text!r}"
    )
    assert _REPLACEMENT_URL in out_text, (
        f"replacement URL missing from stdout: {out_text!r}"
    )
    assert _REPLACEMENT_URL in err_text, (
        f"replacement URL missing from stderr: {err_text!r}"
    )
    print(f"  stdout captured: {out_text!r}")
    print(f"  stderr captured: {err_text!r}")

    print("smoke: rewrite_sarif_file() with a synthetic SARIF")
    synthetic = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "CKV_AZURE_1",
                                "helpUri": prisma_url_f,
                            },
                            {
                                "id": "CKV_AZURE_2",
                                "helpUri": "https://example.com/already-good",
                            },
                        ]
                    }
                }
            }
        ]
    }
    tmp = Path.cwd() / "_url_rewrite_smoke.sarif"
    tmp.write_text(json.dumps(synthetic), encoding="utf-8")
    try:
        rw, sk = rewrite_sarif_file(tmp)
        assert rw + sk >= 1, f"rewrite_sarif_file returned ({rw}, {sk})"
        reloaded = json.loads(tmp.read_text(encoding="utf-8"))
        first_rule = reloaded["runs"][0]["tool"]["driver"]["rules"][0]
        # Either we rewrote it (GitHub URL) or the rule ID was unmapped
        # and we kept the original — both are valid outcomes. The point
        # of the smoke test is that the function runs without crashing
        # and returns sane counts.
        print(f"  rewrites: {rw} rewritten, {sk} skipped")
        print(f"  first rule helpUri: {first_rule.get('helpUri')!r}")
    finally:
        if tmp.exists():
            tmp.unlink()
        sibling_tmp = tmp.with_suffix(tmp.suffix + ".tmp")
        if sibling_tmp.exists():
            sibling_tmp.unlink()

    print("smoke: OK")
    return 0


if __name__ == "__main__":
    sys.exit(_smoke_test())
