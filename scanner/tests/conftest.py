"""pytest configuration for the Pacioli scanner tests.

Adds the project root to sys.path so:
  - `import scanner.foo` works (scanner is a real package)
  - `import baseline_init` works (legacy flat-system imports from the
    pre-port baseline_init.py are tolerated, but the new style is
    `from scanner.aggregate import ...`)

This is intentionally the project root, NOT the scanner/ directory, so
both forms work without conflict.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
