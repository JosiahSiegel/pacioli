#!/usr/bin/env python3
"""
UTF-8 environment bootstrap for the scanner.

Why this exists
---------------
Pacioli scans Azure Terraform on every platform, including Windows + non-UTF-8
code pages (cp1252). Some Azure .tf files contain non-ASCII metadata --
strings with emoji glyphs (KQL workbook titles, ADF dashboard panels) whose
UTF-8 multi-byte sequences include the byte 0x8F -- which cp1252 cannot decode.
This bootstrap makes every file open() (default), stdout, and stderr use UTF-8
so we can ingest those files and emit them again without crashing or mojibake.

This is the Python equivalent of the bash bootstrap in scanner/lib/common.sh
lines 34-37:

    export PYTHONIOENCODING=utf-8
    export PYTHONUTF8=1
    export LC_ALL="${LC_ALL:-C.UTF-8}"
    export LANG="${LANG:-C.UTF-8}"

Import this module FIRST in any entry-point (cli.py, aggregate.py, future
entry points) -- before any checkov import -- so the env vars and stream
reconfiguration land before any third-party code reads from stdin or opens
a file with the default encoding.

Idempotency
-----------
This module is safe to import multiple times. For the two Python-specific
encodings (PYTHONUTF8, PYTHONIOENCODING) we FORCE the value to "1"/"utf-8"
because if those are wrong, the Windows emoji-byte failure mode returns.
For LC_ALL / LANG we use setdefault so an operator's deliberate locale
override (e.g. "en_US.UTF-8" for date formatting) is preserved.
"""

from __future__ import annotations

import os
import sys

# PYTHONUTF8=1 enables CPython's UTF-8 mode for the default text encoding
# (open() with no encoding arg) and the default I/O encoding. Without this,
# Windows Python defaults to cp1252 and crashes on 0x8F.
os.environ["PYTHONUTF8"] = "1"

# PYTHONIOENCODING=utf-8 covers stdout/stderr encoding for child processes
# and as a belt-and-suspenders for our own reconfigure() below.
os.environ["PYTHONIOENCODING"] = "utf-8"

# LC_ALL / LANG: respect an operator override if set, otherwise default to
# C.UTF-8 so child processes (terraform, checkov subprocesses) inherit UTF-8.
os.environ.setdefault("LC_ALL", "C.UTF-8")
os.environ.setdefault("LANG", "C.UTF-8")

# Reconfigure stdout/stderr to UTF-8 with errors="replace" so a stray non-UTF8
# byte from a child process or library doesn't raise UnicodeEncodeError on
# print(). This mirrors scanner/aggregate.py lines 65-72.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, OSError):
    # Python <3.7 or stream already detached; the env vars above are enough.
    pass

# Sanity-check that PYTHONUTF8 actually took effect. sys.flags.utf8_mode is
# set when -X utf8 or PYTHONUTF8=1 is on. AttributeError on very old Pythons.
try:
    sys.flags.utf8_mode  # noqa: B018 -- true if -X utf8 or PYTHONUTF8=1 is on
except AttributeError:
    pass


if __name__ == "__main__":
    # Smoke test: print the four env vars so an operator can verify the
    # bootstrap landed. Exit 0 always -- this is a diagnostic.
    print(f"PYTHONUTF8={os.environ.get('PYTHONUTF8', '<unset>')}")
    print(f"PYTHONIOENCODING={os.environ.get('PYTHONIOENCODING', '<unset>')}")
    print(f"LC_ALL={os.environ.get('LC_ALL', '<unset>')}")
    print(f"LANG={os.environ.get('LANG', '<unset>')}")
    sys.exit(0)
