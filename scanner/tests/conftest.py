"""pytest configuration for the Pacioli scanner tests.

Adds .scripts/checkov to sys.path so test files can `import` the
scanner modules directly without needing an installable package.
"""
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
