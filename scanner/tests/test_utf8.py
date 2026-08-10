"""Tests for scanner._utf8 — the UTF-8 environment bootstrap.

Covers every invariant asserted in scanner/_utf8.py:1-80:
  - (a) PYTHONUTF8 is forced to "1" on import
  - (b) PYTHONIOENCODING is forced to "utf-8" on import
  - (c) LC_ALL is preserved if set, otherwise defaulted to "C.UTF-8"
  - (d) LANG is preserved if set, otherwise defaulted to "C.UTF-8"
  - (e) sys.stdout.encoding is "utf-8" after reconfigure()
  - (f) sys.stderr.encoding is "utf-8" after reconfigure()
  - (g) `python -m scanner._utf8` exits 0 and prints all four env vars

Also covers the IDEMPOTENCY contract documented in scanner/_utf8.py:27-33:
importing the module a second time (after PYTHONUTF8 was explicitly set to
"0" in the child environment) must re-force PYTHONUTF8 back to "1".

Test style mirrors scanner/tests/test_url_rewrite.py — package-style import
(`from scanner._utf8 import ...`) since the project root is on sys.path via
scanner/tests/conftest.py.

NOTE on env restoration:
The fixture below is defined IN THIS FILE (not in conftest.py) per the
task contract. It uses pytest's `monkeypatch` fixture so env mutations are
restored automatically at test teardown — no try/finally needed.

NOTE on module re-import:
Python caches imported modules in `sys.modules`. Because `scanner._utf8` may
have been auto-imported earlier in this pytest session (by conftest, by
another test module, or by us), a plain `import scanner._utf8` in our test
is a no-op — the module body does NOT re-execute. To exercise the bootstrap
side effects we must evict the module from `sys.modules` first, then reload.
"""
from __future__ import annotations

import os
import subprocess
import sys
from importlib import reload

import pytest


# ---------------------------------------------------------------------------
# Test-local fixture (NOT in conftest.py — per task contract)
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_utf8_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str | None]:
    """Snapshot + restore the four UTF-8 env vars for the duration of one test.

    Saves the pre-test values of PYTHONUTF8, PYTHONIOENCODING, LC_ALL, LANG
    into a dict that the test can introspect, then deletes each var so the
    test starts from a known-clean slate. `monkeypatch` automatically restores
    the originals at teardown — no sibling test pollution.

    This fixture is `autouse=False` (explicit opt-in per test) so other
    scanner/tests/* files that don't care about these env vars are not
    affected.
    """
    saved: dict[str, str | None] = {
        key: os.environ.get(key) for key in ("PYTHONUTF8", "PYTHONIOENCODING", "LC_ALL", "LANG")
    }
    for key in saved:
        monkeypatch.delenv(key, raising=False)
    return saved


def _reload_utf8_module() -> object:
    """Re-execute scanner._utf8 from scratch so its side effects run again.

    Necessary because pytest may have auto-imported the module earlier in
    the session (via conftest, another test, or us). Plain `import` would
    hit the `sys.modules` cache and skip the module body.
    """
    sys.modules.pop("scanner._utf8", None)
    import scanner._utf8  # noqa: F401  -- side-effect import
    # `import` and `reload` both work after eviction, but reload gives us
    # the module handle explicitly. Belt-and-suspenders for any future
    # reader who doesn't see the pop above.
    return reload(scanner._utf8)


# ---------------------------------------------------------------------------
# (a)+(b) Forced env vars
# ---------------------------------------------------------------------------

def test_pythonutf8_is_forced_to_one(clean_utf8_env: dict[str, str | None]) -> None:
    """Importing scanner._utf8 must force PYTHONUTF8 to "1" regardless of the
    pre-test value (even if it was "0" or unset).
    """
    # Arrange: confirm we really did start from the saved value, not a leftover.
    assert "PYTHONUTF8" not in os.environ, (
        f"clean_utf8_env fixture failed to delete PYTHONUTF8 "
        f"(pre-snapshot was {clean_utf8_env['PYTHONUTF8']!r})"
    )

    # Act
    _reload_utf8_module()

    # Assert
    assert os.environ["PYTHONUTF8"] == "1"


def test_pythonioencoding_is_forced_to_utf8(clean_utf8_env: dict[str, str | None]) -> None:
    """Importing scanner._utf8 must force PYTHONIOENCODING to "utf-8"."""
    assert "PYTHONIOENCODING" not in os.environ

    _reload_utf8_module()

    assert os.environ["PYTHONIOENCODING"] == "utf-8"


def test_forced_env_vars_override_existing_bad_values(
    clean_utf8_env: dict[str, str | None],
) -> None:
    """Even if PYTHONUTF8 was pre-set to a wrong value, the bootstrap must
    overwrite it. This is the whole point of the 'force' semantics documented
    in scanner/_utf8.py:29-31.
    """
    os.environ["PYTHONUTF8"] = "0"
    os.environ["PYTHONIOENCODING"] = "ascii"

    _reload_utf8_module()

    assert os.environ["PYTHONUTF8"] == "1"
    assert os.environ["PYTHONIOENCODING"] == "utf-8"


# ---------------------------------------------------------------------------
# (c)+(d) Preserved-or-defaulted env vars
# ---------------------------------------------------------------------------

def test_lc_all_defaults_to_c_utf8_when_unset(clean_utf8_env: dict[str, str | None]) -> None:
    """When LC_ALL is unset, scanner._utf8 must default it to C.UTF-8."""
    assert "LC_ALL" not in os.environ

    _reload_utf8_module()

    assert os.environ["LC_ALL"] == "C.UTF-8"


def test_lc_all_is_preserved_when_already_set(clean_utf8_env: dict[str, str | None]) -> None:
    """When LC_ALL is already set (operator override), scanner._utf8 must
    NOT clobber it. This is the 'setdefault' semantics at _utf8.py:52.
    """
    os.environ["LC_ALL"] = "en_US.UTF-8"

    _reload_utf8_module()

    assert os.environ["LC_ALL"] == "en_US.UTF-8"


def test_lang_defaults_to_c_utf8_when_unset(clean_utf8_env: dict[str, str | None]) -> None:
    """When LANG is unset, scanner._utf8 must default it to C.UTF-8."""
    assert "LANG" not in os.environ

    _reload_utf8_module()

    assert os.environ["LANG"] == "C.UTF-8"


def test_lang_is_preserved_when_already_set(clean_utf8_env: dict[str, str | None]) -> None:
    """When LANG is already set, scanner._utf8 must NOT clobber it.
    This is the 'setdefault' semantics at _utf8.py:53.
    """
    os.environ["LANG"] = "fr_FR.UTF-8"

    _reload_utf8_module()

    assert os.environ["LANG"] == "fr_FR.UTF-8"


# ---------------------------------------------------------------------------
# (e)+(f) Stream reconfiguration
# ---------------------------------------------------------------------------

def test_stdout_reconfigured_to_utf8(clean_utf8_env: dict[str, str | None]) -> None:
    """sys.stdout.encoding must be utf-8 after importing scanner._utf8."""
    _reload_utf8_module()

    # In normal Python (3.7+) under PYTHONUTF8=1, encoding is 'utf-8'.
    # On very old Pythons or detached streams the try/except in _utf8.py
    # swallows the failure — in that case this assertion would still hold
    # because PYTHONUTF8=1 makes utf-8 the default encoding anyway.
    encoding = sys.stdout.encoding
    assert encoding is not None
    assert encoding.lower().replace("_", "-") in {"utf-8", "utf8"}


def test_stderr_reconfigured_to_utf8(clean_utf8_env: dict[str, str | None]) -> None:
    """sys.stderr.encoding must be utf-8 after importing scanner._utf8."""
    _reload_utf8_module()

    encoding = sys.stderr.encoding
    assert encoding is not None
    assert encoding.lower().replace("_", "-") in {"utf-8", "utf8"}


# ---------------------------------------------------------------------------
# (g) `python -m scanner._utf8` smoke test
# ---------------------------------------------------------------------------

def test_python_m_scanner_utf8_exits_zero_and_prints_all_four_env_vars() -> None:
    """Running `python -m scanner._utf8` as a subprocess must:
      - exit 0 (it's a diagnostic; never fails)
      - print all four env var lines: PYTHONUTF8, PYTHONIOENCODING, LC_ALL, LANG
    """
    # Use the current interpreter so we test the same Python that pytest runs on.
    # Do NOT override env — we want to verify the bootstrap handles a normal
    # child environment (PYTHONUTF8 may or may not be set by pytest's own env).
    result = subprocess.run(
        [sys.executable, "-m", "scanner._utf8"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, (
        f"`python -m scanner._utf8` exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    # All four env vars must appear in stdout, formatted as "KEY=value".
    stdout = result.stdout
    for key in ("PYTHONUTF8", "PYTHONIOENCODING", "LC_ALL", "LANG"):
        assert f"{key}=" in stdout, (
            f"Expected '{key}=' in subprocess stdout but got:\n{stdout}"
        )


# ---------------------------------------------------------------------------
# Idempotency contract
# ---------------------------------------------------------------------------

def test_idempotency_subprocess_with_pythonutf8_zero_pre_set() -> None:
    """IDEMPOTENCY contract from scanner/_utf8.py:27-33.

    Spawn a fresh subprocess with PYTHONUTF8 explicitly set to "0" in the
    child environment (simulating the failure mode where an operator or
    wrapper script has disabled UTF-8 mode), then have the child import
    scanner._utf8 and assert PYTHONUTF8 has been re-forced to "1".
    """
    # Build a child env from the current process env but with PYTHONUTF8=0
    # pre-set. We only override PYTHONUTF8; the rest of the env (including
    # PYTHONIOENCODING, LC_ALL, LANG) flows through unchanged.
    child_env = dict(os.environ)
    child_env["PYTHONUTF8"] = "0"

    # Inline Python program that the child will execute:
    #   1. assert PYTHONUTF8 really starts as "0" (sanity check on env passing)
    #   2. import scanner._utf8 (side-effect: bootstrap runs)
    #   3. assert PYTHONUTF8 is now "1" (the idempotency invariant)
    #   4. print IDEMPOTENCY_OK on success
    program = (
        "import os, sys\n"
        "assert os.environ.get('PYTHONUTF8') == '0', "
        "f'pre-import PYTHONUTF8={os.environ.get(\"PYTHONUTF8\")!r}'\n"
        "import scanner._utf8\n"
        "assert os.environ['PYTHONUTF8'] == '1', "
        "f'post-import PYTHONUTF8={os.environ[\"PYTHONUTF8\"]!r}'\n"
        "print('IDEMPOTENCY_OK')\n"
        "sys.exit(0)\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", program],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, (
        f"Idempotency subprocess failed (exit={result.returncode}).\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "IDEMPOTENCY_OK" in result.stdout, (
        f"Expected IDEMPOTENCY_OK marker in stdout.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# In-process invariant summary — passes regardless of import order
# ---------------------------------------------------------------------------

def test_all_invariants_hold_simultaneously(clean_utf8_env: dict[str, str | None]) -> None:
    """Final assertion: after a single re-import, every invariant (a)-(f) holds
    at once. This is the test that catches a partial regression — e.g. someone
    fixes LC_ALL preservation but accidentally drops the reconfigure() call.
    """
    _reload_utf8_module()

    # (a)
    assert os.environ["PYTHONUTF8"] == "1"
    # (b)
    assert os.environ["PYTHONIOENCODING"] == "utf-8"
    # (c) — LC_ALL is "C.UTF-8" because we started from a clean slate
    assert os.environ["LC_ALL"] == "C.UTF-8"
    # (d) — LANG is "C.UTF-8" because we started from a clean slate
    assert os.environ["LANG"] == "C.UTF-8"
    # (e)
    assert sys.stdout.encoding is not None
    assert sys.stdout.encoding.lower().replace("_", "-") in {"utf-8", "utf8"}
    # (f)
    assert sys.stderr.encoding is not None
    assert sys.stderr.encoding.lower().replace("_", "-") in {"utf-8", "utf8"}
