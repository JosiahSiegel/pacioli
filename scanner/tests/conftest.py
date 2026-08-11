"""pytest configuration for the Pacioli scanner tests.

Adds the project root to sys.path so:
  - `import scanner.foo` works (scanner is a real package)
  - `import baseline_init` works (legacy flat-system imports from the
    pre-port baseline_init.py are tolerated, but the new style is
    `from scanner.aggregate import ...`)

This is intentionally the project root, NOT the scanner/ directory, so
both forms work without conflict.

Static-enforcement plugin (Todo 12)
----------------------------------
``test_subprocess_surface`` is registered as an explicit plugin module so
it is GUARANTEED to run as part of the standard test collection — a
future ``--ignore`` or ``-k`` filter cannot silently skip the
subprocess-surface enforcement that protects the read-only invariant.
Both forms are used:

  * ``pytest_plugins`` ensures the test module is collected (belt).
  * The test module is also discoverable by name and can be run
    explicitly with ``pytest scanner/tests/test_subprocess_surface.py``
    (suspenders).

If you intentionally need to suppress the surface check (e.g. for a
local red build), do so via ``-k`` filtering AND surface the
suppression in the PR description — never via ``--ignore``.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Static subprocess-surface enforcement plugin (Todo 12). Registered
# explicitly so it runs as part of the standard test suite regardless
# of test selection filters. See scanner/tests/test_subprocess_surface.py
# for the enforcement contract.
pytest_plugins = ["test_subprocess_surface"]  # noqa: E501 — relative import via pytest_plugins
