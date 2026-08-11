"""scanner/tests/test_subprocess_surface.py — Static enforcement of the subprocess surface.

Why this exists
---------------
The Pacioli scanner is **read-only against Azure by design** (see
``docs/SAFETY_MODEL.md``). Every mutating shell call in the production
code path goes through ``scanner.ops.run`` (or, in the past, a
dedicated ``SafetyGuard.refuse_if_mutating`` guard) so the allowlist +
refusal matrix can audit and block it.

A *raw* ``subprocess.run`` / ``subprocess.Popen`` / ``subprocess.call``
/ ``os.system`` call in production code would bypass the registry
entirely. CI must catch any regression at PR time, BEFORE the new code
runs in a sandbox where ``terraform apply`` is real.

How this plugin works
---------------------
This module parses ``scanner/cli.py``, ``scanner/orchestrator.py``, and
``scanner/trap.py`` with the stdlib :mod:`ast` module and walks each
file's function bodies looking for raw subprocess invocations. For
every one it finds, it walks **backwards** within the enclosing
function (or within an enclosing ``try`` block) to confirm an
``ops.run(...)`` or ``refuse_if_mutating(...)`` call precedes it. If no
guard is found, the test fails with a clear message naming the file,
line, and call name.

The plugin only scans the three production files listed above; the
test files themselves (which legitimately use ``subprocess.run`` for
fixtures and harnesses) are excluded by design.

Adding a new prohibited call
----------------------------
If a future change legitimately needs a NEW kind of raw subprocess
call outside the registry — DON'T. Instead route it through
``scanner.ops.register(...)``. The plugin is the safety net; the
registry is the policy.

If a guarded form is required (e.g. an interactive subprocess that
must bypass argv allowlisting), add it to the production file AND
the guard walker's accepted-guard list below.
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from typing import Iterable, NamedTuple

import pytest


# ---------------------------------------------------------------------------
# Production files the plugin enforces against
# ---------------------------------------------------------------------------
# These three files own the entire read-only invariant:
#   - cli.py          : top-level entry points
#   - orchestrator.py : per-tier scan loop, terraform invocations
#   - trap.py         : atexit / signal-driven cleanup
# Any new subprocess-facing module must be appended here.
SCANNER_ROOT = Path(__file__).resolve().parent.parent
PRODUCTION_FILES: tuple[Path, ...] = (
    SCANNER_ROOT / "cli.py",
    SCANNER_ROOT / "orchestrator.py",
    SCANNER_ROOT / "trap.py",
)


# ---------------------------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------------------------
# Raw subprocess calls the plugin treats as bypasses of the ops registry.
# These are the four names an unguarded call could carry: any other name
# (e.g. ``subprocess.getoutput``) is a separate hazard tracked elsewhere.
RAW_CALL_NAMES: frozenset[str] = frozenset({
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "os.system",
})

# Guards that protect a subprocess call. For each guard we accept any
# call whose dotted name ENDS with one of these suffixes. This handles
# the three name forms the codebase actually uses:
#   - ``ops.run(...)``             -> suffix ``".run"`` (UNBOUND; in
#     practice the codebase imports ops as ``_ops`` / ``scanner_ops``
#     and only calls ``.run(...)`` via ``_ops.run(...)`` / ``scanner_ops.run(...)``.
#     Both resolve to suffix ``".run"``.
#   - ``refuse_if_mutating(...)``  -> suffix ``"refuse_if_mutating"``.
#     The codebase uses ``self.refuse_if_mutating(...)`` via the
#     ``SafetyGuard`` instance, so a method call on a non-self callee
#     also resolves to the same suffix.
#   - ``safety.check(...)``        -> legacy synonym for the refusal
#     matrix (kept for backwards-compat with the bash scanner's
#     ``safety_check`` symbol). Accept the suffix ``"safety.check"``.
GUARD_CALL_SUFFIXES: tuple[str, ...] = (
    ".run",
    "refuse_if_mutating",
    "safety.check",
)


# ---------------------------------------------------------------------------
# Findings model
# ---------------------------------------------------------------------------
class _Finding(NamedTuple):
    """A single raw subprocess call that needs guarding."""

    file: Path
    line: int
    call_name: str
    enclosing_function: str
    raw_source: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_raw_subprocess_call(node: ast.Call) -> str | None:
    """Return the dotted call name if ``node`` is a raw subprocess call.

    Recognises the four ``RAW_CALL_NAMES`` patterns:
      * ``subprocess.run(...)``, ``subprocess.Popen(...)``,
        ``subprocess.call(...)``, ``os.system(...)`` as bare names.
      * ``from subprocess import run; run(...)`` resolves to the bare
        name ``"run"`` — we don't try to resolve imports; the plugin
        deliberately restricts itself to the well-known dotted names.
        A future change that adds a new raw call pattern must extend
        this function AND update ``RAW_CALL_NAMES``.
    """
    func = node.func
    # Bare ``name(...)``.
    if isinstance(func, ast.Name):
        # Handle dotted ``module.func`` form (the common case in this
        # codebase: ``subprocess.run``, ``os.system``).
        return func.id if func.id in RAW_CALL_NAMES else None
    # Dotted ``module.func(...)`` form.
    if isinstance(func, ast.Attribute):
        # Reconstruct ``a.b.c(...)`` by walking ``func.value`` until we
        # hit an ``ast.Name``. Module prefixes matter because
        # ``some_helper.run(...)`` is NOT a subprocess call.
        parts: list[str] = []
        cur: ast.expr = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        dotted = ".".join(reversed(parts))
        if dotted in RAW_CALL_NAMES:
            return dotted
    return None


def _call_suffix(call: ast.Call) -> str | None:
    """Return the trailing suffix of a call's dotted name, or ``None``.

    Used to match guard calls against ``GUARD_CALL_SUFFIXES``. We walk
    both ``ast.Name`` (``foo``) and ``ast.Attribute`` (``a.b.c``) forms
    and return the longest dotted tail that ends in a useful token.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _is_guard_call(call: ast.Call) -> bool:
    """Return True if ``call`` matches any known guard suffix.

    Match strategy (most-specific first):
      * Exact match against any guard suffix.
      * For guards that begin with ``.``: the call's dotted name ends
        in ``"<.suffix>"`` AND the call's receiver (leftmost segment)
        is NOT ``subprocess`` / ``os`` / ``sys`` (any of which would
        be a raw-subprocess facade, not a guard). This excludes
        ``subprocess.run`` and ``os.system`` from the guard set even
        though their dotted names end in ``.run`` / ``.system``.
      * Bare-name fallback for ``run`` only: a call to ``run(...)``
        with no qualifier matches ``.run``. Tolerated (rare false
        positive: ``some_helper.run(...)``); production-only scanning
        keeps the surface small.
      * Tail-segment match for guards that don't begin with ``.``
        (e.g. ``refuse_if_mutating``): any call whose last dotted
        segment equals the guard suffix matches. Handles
        ``sg.refuse_if_mutating(...)`` and ``self.refuse_if_mutating(...)``.

    The receiver is computed by :func:`_call_receiver`, which extracts
    the leftmost ``Name`` node from a chained ``Attribute`` tree.
    """
    suffix = _call_suffix(call) or ""
    receiver = _call_receiver(call) or ""
    # Raw-subprocess facades are NEVER guards, even if they share a
    # trailing segment (``.run``, ``.system``). Filter them here so
    # the bottom test below doesn't accidentally match
    # ``subprocess.run``.
    forbidden_receivers: frozenset[str] = frozenset({"subprocess", "os", "sys"})

    for g in GUARD_CALL_SUFFIXES:
        # Exact match.
        if suffix == g:
            return True
        # ``.run`` style guards (or any future ``.suffix`` style).
        # Excluded when the call's receiver is a raw-subprocess
        # facade (the matching name on a non-guard module).
        if g.startswith(".") and suffix.endswith(g):
            if receiver not in forbidden_receivers:
                return True
            continue
        # Bare ``run`` matches the ``.run`` guard when the receiver
        # (none, in this case) is not a forbidden facade.
        if g == ".run" and suffix == "run":
            if receiver not in forbidden_receivers:
                return True
            continue
        # Tail-segment match for non-dot guards:
        # ``sg.refuse_if_mutating`` ends with ``refuse_if_mutating``.
        if not g.startswith(".") and suffix.endswith("." + g):
            if receiver not in forbidden_receivers:
                return True
            continue
    return False


def _call_receiver(call: ast.Call) -> str | None:
    """Return the leftmost ``Name`` in a chained attribute call, or ``None``.

    For ``ops.run(...)`` returns ``"ops"``. For ``sg.refuse_if_mutating(...)``
    returns ``"sg"``. For bare ``foo(...)`` returns ``"foo"``. For
    ``subprocess.run(...)`` returns ``"subprocess"``. Used by
    :func:`_is_guard_call` to exclude raw-subprocess facades from the
    guard-walker false-positive surface.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        cur: ast.expr = func.value
        while isinstance(cur, ast.Attribute):
            cur = cur.value
        if isinstance(cur, ast.Name):
            return cur.id
    return None


def _line_offset(source_lines: list[str], lineno: int) -> str:
    """Return the trimmed source line for ``lineno`` (1-indexed)."""
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()
    return ""


def _enclosing_function(
    func_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef],
    target_line: int,
) -> str:
    """Return the dotted name of the innermost function wrapping ``target_line``.

    Falls back to ``"<module>"`` when the target lives at module
    top-level (e.g. an ``if __name__ == "__main__":`` smoke block).
    """
    for node in sorted(
        func_nodes,
        key=lambda n: (n.lineno, -(n.end_lineno or n.lineno)),
    ):
        start = node.lineno
        end = node.end_lineno or start
        if start <= target_line <= end:
            return node.name
    return "<module>"


def _block_has_preceding_guard(
    body: list[ast.stmt],
    target_line: int,
) -> bool:
    """Walk ``body`` in source order; return True if a guard precedes ``target_line``.

    Statement-order traversal matters: a guard that lives in a
    statement AFTER the target — even in the same block — is too
    late. We track ``seen_target`` and only count guard calls before
    that point. Compound statements (``if``/``for``/``while``/
    ``with``/``try``) are recursed into so a guard nested inside an
    early arm is still treated as preceding the target.
    """
    for stmt in body:
        # If this statement STARTS at or after the target, nothing
        # earlier in the body can satisfy the rule. Exit early.
        if stmt.lineno > target_line:
            return False
        # If this statement CONTAINS the target line, recurse into its
        # sub-bodies — a guard nested inside the same ``if`` or
        # ``with`` is still considered "preceding" the target if it
        # appears on a prior line.
        stmt_end = getattr(stmt, "end_lineno", None) or stmt.lineno
        if stmt.lineno <= target_line <= stmt_end:
            # Direct guard call inside an ``Expr`` statement?
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                if _is_guard_call(stmt.value):
                    return True
            # Compound statements: search every sub-body for a guard on
            # a line strictly less than ``target_line``.
            sub_bodies: list[list[ast.stmt]] = []
            for field_name in ("body", "orelse", "finalbody"):
                val = getattr(stmt, field_name, None)
                if isinstance(val, list):
                    sub_bodies.append(val)
            # Try handlers: each handler has its own ``body``.
            if isinstance(stmt, ast.Try):
                for handler in stmt.handlers:
                    if handler is not None:
                        sub_bodies.append(handler.body)
            for sub in sub_bodies:
                if _block_has_preceding_guard(sub, target_line):
                    return True
            # Otherwise the target lives inside this statement but we
            # couldn't find a guard — that branch failed; we cannot
            # claim "guarded" without one, so return False from this
            # walk. Higher-level ``_walk_with_guard`` may still find a
            # guard in an enclosing ``try`` block.
            return False
        # Statement is strictly BEFORE the target. A guard call here
        # satisfies the rule.
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            if _is_guard_call(stmt.value):
                return True
    return False


def _walk_with_guard(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    target_line: int,
) -> bool:
    """Walk backward through ``func_node`` to find a preceding guard.

    Strategy: the enclosing ``try`` block — if any — is the tightest
    guard scope (the canonical pattern is ``try: ops.run(...);
    subprocess.run(...)``). Otherwise the whole function body is the
    scope. We search EACH scope in turn; if the guard lives in an
    enclosing try, fine. If it lives in the function body itself (and
    the raw call is NOT inside a try), also fine.

    We do NOT consider guards that live in an *outer* try when the
    target is in an *inner* try whose body lacks a guard — that's the
    whole reason the rule requires per-block auditing.
    """
    # 1. Locate the innermost enclosing ``try`` for ``target_line``.
    enclosing_try: ast.Try | None = None
    for child in ast.walk(func_node):
        if not isinstance(child, ast.Try):
            continue
        # ``Try`` spans its body + handlers + orelse + finalbody.
        # Approximate range as the union of body + handlers.
        start = child.lineno
        end = child.end_lineno or start
        # ``Try`` ranges aren't perfectly nested in source order, but
        # the well-formed structure this plugin targets is always
        # nested. Pick the deepest enclosing match.
        if start <= target_line <= end:
            if enclosing_try is None:
                enclosing_try = child
            else:
                # Narrower wins.
                e_start = enclosing_try.lineno
                e_end = enclosing_try.end_lineno or e_start
                if (start > e_start) and (end <= e_end):
                    enclosing_try = child

    if enclosing_try is not None:
        # Try bodies are the primary guard scope. Handlers + orelse +
        # finalbody contain EXCEPTION handling, not a guard. We
        # intentionally allow a guard in ``orelse`` because that's
        # the no-exception path of the try — but the rule says
        # "precede" the raw call, which the orelse branches do not
        # satisfy in source order (orelse runs after body). For
        # simplicity and safety we accept a guard in ``body`` only.
        if _block_has_preceding_guard(enclosing_try.body, target_line):
            return True
        # If the target is in a HANDLER (unlikely, but valid), the
        # handler body IS a separate block — recurse into it the
        # same way.
        for handler in enclosing_try.handlers:
            if handler is None:
                continue
            if (
                handler.lineno <= target_line
                <= (handler.end_lineno or handler.lineno)
            ):
                if _block_has_preceding_guard(handler.body, target_line):
                    return True
                # Handler body did not satisfy — fall through to the
                # function-body fallback below (defense in depth).
        # Try body alone could not satisfy. Fall through to the
        # whole-function fallback ONLY if the target is NOT inside
        # this try's body (i.e. it's in an except handler that
        # lacked a guard). Otherwise the try is the scope and we
        # failed.
        target_in_try_body = (
            enclosing_try.body
            and enclosing_try.body[0].lineno <= target_line
            <= (enclosing_try.end_lineno or enclosing_try.body[0].lineno)
            and not any(
                (
                    handler.lineno <= target_line
                    <= (handler.end_lineno or handler.lineno)
                )
                for handler in enclosing_try.handlers
                if handler is not None
            )
        )
        if target_in_try_body:
            return False

    # 2. Fallback: whole-function search. Acceptable when the target
    # is at function body level (NOT inside any try block).
    return _block_has_preceding_guard(func_node.body, target_line)


def _scan_file(path: Path) -> list[_Finding]:
    """Parse ``path`` and return every raw subprocess call unguarded at site.

    Raises ``SyntaxError`` if the file fails to parse (the plugin fails
    closed — a parse error is louder than a missed finding).
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    source_lines = source.splitlines()
    findings: list[_Finding] = []

    # Pre-collect every FunctionDef / AsyncFunctionDef so the
    # per-call enclosing-function lookup is constant-time.
    function_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _is_raw_subprocess_call(node)
        if call_name is None:
            continue
        # Determine the enclosing function. Top-level raw calls (e.g.
        # inside ``if __name__ == "__main__":``) are also caught —
        # those are still raw subprocess calls and must be guarded.
        enclosing = _enclosing_function(function_nodes, node.lineno)
        if enclosing == "<module>":
            # Module-level — search the module top-level body for a
            # preceding guard. The module body itself is just a
            # sequence of statements on ``tree.body``.
            if _block_has_preceding_guard(tree.body, node.lineno):
                continue
            findings.append(
                _Finding(
                    file=path,
                    line=node.lineno,
                    call_name=call_name,
                    enclosing_function=enclosing,
                    raw_source=_line_offset(source_lines, node.lineno),
                )
            )
            continue

        # Inside a function — find that function's node and search
        # backward for a guard within it.
        func_node = next(
            (
                fn for fn in function_nodes
                if fn.lineno <= node.lineno <= (fn.end_lineno or fn.lineno)
                and fn.name == enclosing
            ),
            None,
        )
        if func_node is None:
            # Couldn't locate the enclosing function (shouldn't
            # happen — defensive). Treat as unguarded.
            findings.append(
                _Finding(
                    file=path,
                    line=node.lineno,
                    call_name=call_name,
                    enclosing_function=enclosing,
                    raw_source=_line_offset(source_lines, node.lineno),
                )
            )
            continue

        if not _walk_with_guard(func_node, node.lineno):
            findings.append(
                _Finding(
                    file=path,
                    line=node.lineno,
                    call_name=call_name,
                    enclosing_function=enclosing,
                    raw_source=_line_offset(source_lines, node.lineno),
                )
            )

    return findings


def _format_findings(findings: Iterable[_Finding]) -> str:
    """Human-readable summary of every finding for the failure message."""
    rows = sorted(findings, key=lambda f: (str(f.file), f.line))
    lines = [f"  {f.file.name}:{f.line}  {f.call_name}(...)  in {f.enclosing_function}()"]
    for f in rows:
        if f.raw_source:
            lines[-1] += f"\n      | {f.raw_source}"
    return "\n".join(lines) if rows else "  (no findings)"


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def production_findings() -> list[_Finding]:
    """Scan the three production files once per test session."""
    all_findings: list[_Finding] = []
    for path in PRODUCTION_FILES:
        all_findings.extend(_scan_file(path))
    return all_findings


# ---------------------------------------------------------------------------
# Production enforcement — the contract this test exists to enforce
# ---------------------------------------------------------------------------
def test_no_unguarded_subprocess_calls_in_production(production_findings: list[_Finding]) -> None:
    """Every raw subprocess call in production code MUST be guard-wrapped.

    Each finding's failure message names the file, line, call site,
    and enclosing function so the developer can find and remediate it
    in one read of CI output.
    """
    if production_findings:
        names = ", ".join(
            f"{f.file.name}:{f.line} ({f.call_name} in {f.enclosing_function}())"
            for f in production_findings
        )
        pytest.fail(
            "Unguarded subprocess call at " + names
            + " — must be preceded by ops.run() or refuse_if_mutating() "
            "within the same function/try block\n\n"
            "Details:\n" + _format_findings(production_findings)
        )


# ---------------------------------------------------------------------------
# Happy-path self-tests — prove the detector catches what it claims to.
#
# These two tests construct tiny synthetic modules that exercise both
# the FAIL path (raw subprocess.run with no guard) and the PASS path
# (raw subprocess.run with a preceding ops.run guard). They exist so a
# future refactor of ``_scan_file`` / ``_walk_with_guard`` cannot
# silently regress to "always passes" without at least these self-tests
# catching it.
# ---------------------------------------------------------------------------
def _scan_source(source: str, tmp_path: Path) -> list[_Finding]:
    """Write ``source`` to a temp file and scan it as if it were a production file."""
    p = tmp_path / "synthetic_module.py"
    p.write_text(textwrap.dedent(source), encoding="utf-8")
    return _scan_file(p)


def test_detector_catches_unguarded_subprocess_run(tmp_path: Path) -> None:
    """A raw ``subprocess.run`` with no guard MUST be reported as unguarded."""
    src = """
        import subprocess
        def do_work():
            subprocess.run(["echo", "hello"])  # no ops.run / refuse_if_mutating ahead
    """
    findings = _scan_source(src, tmp_path)
    assert findings, "expected the detector to flag the unguarded subprocess.run"
    only = findings[0]
    assert only.call_name == "subprocess.run"
    assert only.enclosing_function == "do_work"
    assert "subprocess.run" in only.raw_source


def test_detector_passes_guarded_subprocess_run(tmp_path: Path) -> None:
    """A raw ``subprocess.run`` preceded by ``ops.run`` is allowed (zero findings)."""
    src = """
        import subprocess
        from scanner import ops

        def do_work():
            ops.run("terraform.init_local", "init", "-input=false")
            subprocess.run(["echo", "hello"])  # OK — ops.run above guards it
    """
    findings = _scan_source(src, tmp_path)
    assert not findings, (
        "expected zero findings for a guard-preceded subprocess.run; "
        f"got: {[f'{f.file}:{f.line} {f.call_name}' for f in findings]}"
    )


def test_detector_passes_guarded_via_refuse_if_mutating(tmp_path: Path) -> None:
    """A guard via ``refuse_if_mutating(...)`` also satisfies the rule."""
    src = """
        import os
        from scanner.safety import SafetyGuard

        def do_work():
            sg = SafetyGuard()
            sg.refuse_if_mutating("terraform apply")
            os.system("terraform apply")  # OK — refuse_if_mutating ahead
    """
    findings = _scan_source(src, tmp_path)
    assert not findings, (
        "expected zero findings for a refuse_if_mutating-guarded os.system; "
        f"got: {[f'{f.file}:{f.line} {f.call_name}' for f in findings]}"
    )


def test_detector_flags_top_level_unguarded_call(tmp_path: Path) -> None:
    """Module-level ``subprocess.run`` (outside any function) is still flagged."""
    src = """
        import subprocess
        subprocess.run(["echo", "hello"])  # at module level — still unguarded
    """
    findings = _scan_source(src, tmp_path)
    assert findings, "module-level raw subprocess.run must be flagged"
    assert findings[0].enclosing_function == "<module>"


def test_detector_passes_top_level_guarded_call(tmp_path: Path) -> None:
    """Module-level ``subprocess.run`` is allowed if a guard precedes it on a prior line."""
    src = """
        from scanner import ops
        import subprocess
        ops.run("echo.hello", "echo", "hello")
        subprocess.run(["echo", "hello"])  # OK — ops.run above guards it
    """
    findings = _scan_source(src, tmp_path)
    assert not findings, (
        "expected zero findings for module-level ops.run-guarded subprocess.run; "
        f"got: {[f'{f.file}:{f.line} {f.call_name}' for f in findings]}"
    )


def test_detector_flags_unguarded_inside_try_without_guard(tmp_path: Path) -> None:
    """A raw subprocess inside ``try`` with NO guard must be flagged.

    Ensures the per-try-block walk is actually consulted: a guard in
    a *different* try block earlier in the function does not satisfy
    the rule.
    """
    src = """
        import subprocess
        from scanner import ops

        def do_work():
            try:
                ops.run("terraform.init_local", "init", "-input=false")
            except Exception:
                pass
            try:
                subprocess.run(["echo", "hello"])  # UNGUARDED in this try
            except Exception:
                pass
    """
    findings = _scan_source(src, tmp_path)
    assert findings, "expected unguarded subprocess.run in second try block to be flagged"
    assert findings[0].call_name == "subprocess.run"


def test_detector_passes_guarded_inside_same_try(tmp_path: Path) -> None:
    """A raw subprocess inside ``try`` is OK if the guard is in the SAME try block."""
    src = """
        import subprocess
        from scanner import ops

        def do_work():
            try:
                ops.run("terraform.init_local", "init", "-input=false")
                subprocess.run(["echo", "hello"])  # OK — guard in same try
            except Exception:
                pass
    """
    findings = _scan_source(src, tmp_path)
    assert not findings, (
        "expected zero findings for guard+subprocess in same try; "
        f"got: {[f'{f.file}:{f.line} {f.call_name}' for f in findings]}"
    )


def test_detector_flags_subprocess_popen_and_call_and_os_system(tmp_path: Path) -> None:
    """All four prohibited names (``run``, ``Popen``, ``call``, ``os.system``) are caught."""
    src = """
        import subprocess
        import os

        def do_work():
            subprocess.Popen(["echo"])   # unguarded
            subprocess.call(["echo"])     # unguarded
            os.system("echo")             # unguarded
    """
    findings = _scan_source(src, tmp_path)
    names = sorted(f.call_name for f in findings)
    assert names == ["os.system", "subprocess.Popen", "subprocess.call"], (
        f"expected os.system + subprocess.Popen + subprocess.call findings; got {names}"
    )


# ---------------------------------------------------------------------------
# Sanity tests on the parser helpers themselves — these are unit-level
# guards so a typo in ``_is_raw_subprocess_call`` doesn't silently
# disable the whole plugin.
# ---------------------------------------------------------------------------
def test_is_raw_subprocess_call_recognises_known_names() -> None:
    tree = ast.parse("subprocess.run(['x']); os.system('y'); subprocess.Popen(['z']); subprocess.call(['w'])")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    detected = sorted(filter(None, (_is_raw_subprocess_call(c) for c in calls)))
    assert detected == ["os.system", "subprocess.Popen", "subprocess.call", "subprocess.run"]


def test_is_raw_subprocess_call_ignores_unrelated_names() -> None:
    """Methods on unrelated objects (``some_obj.run(...)``) must NOT be flagged."""
    tree = ast.parse("foo.run(['x']); self.do_thing(); Path.open('y')")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    for c in calls:
        assert _is_raw_subprocess_call(c) is None
