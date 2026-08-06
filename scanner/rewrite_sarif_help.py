"""rewrite_sarif_help.py — Rewrite helpUri in Checkov SARIF files.

Usage:
    python rewrite_sarif_help.py <sarif_path> [<sarif_path> ...]

Walks each SARIF file, replaces the `helpUri` field on every rule with
the canonical GitHub source URL from checkov_url_overrides.RULE_SOURCE_URLS.

Why this exists:
    Checkov OSS populates `helpUri` from docs.prismacloud.io. That
    domain was acquired by Palo Alto in 2026 and the per-rule deep-links
    redirect to the generic cortex-docs.paloaltonetworks.com landing
    page. We override the URLs to the canonical GitHub source files
    (where the rule logic actually lives) so any tooling that ingests
    the SARIF (Azure DevOps, GitHub Code Scanning, custom CI scripts)
    sees a URL that resolves to the rule definition.

    Aggregate_pci.py also does this rewrite when it builds the HTML
    report, but the SARIF files on disk still carry the broken URLs.
    This script fixes them in place so the SARIF artifacts are correct
    on their own.

    Idempotent: re-running on an already-rewritten SARIF is a no-op.

Failure modes:
    - Non-SARIF JSON: error, no changes.
    - Missing 'runs' array: error, no changes.
    - Unmapped rule IDs: keep the upstream helpUri (better than nothing).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running as a script from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from checkov_url_overrides import get_help_uri  # noqa: E402


def rewrite_sarif(path: Path) -> tuple[int, int]:
    """Rewrite helpUri in a SARIF file. Returns (rewritten_count, skipped_count)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"  ERROR: {path} is not valid JSON: {exc}", file=sys.stderr)
        return 0, 0

    runs = data.get("runs", [])
    if not isinstance(runs, list) or not runs:
        print(f"  WARN: {path} has no 'runs' array; skipping", file=sys.stderr)
        return 0, 0

    rewritten = 0
    skipped = 0
    for run in runs:
        # Rewrite per-rule helpUri in the tool driver rules array.
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rid = rule.get("id", "")
                old = rule.get("helpUri")
                new = get_help_uri(rid, old)
                if new != old:
                    rule["helpUri"] = new
                    rewritten += 1
                else:
                    skipped += 1

    # Write back atomically: write to .tmp, then rename.
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp_path.replace(path)
    return rewritten, skipped


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sarif_path> [<sarif_path> ...]", file=sys.stderr)
        return 64

    total_rewritten = 0
    total_skipped = 0
    for arg in sys.argv[1:]:
        path = Path(arg)
        if not path.exists():
            print(f"  ERROR: {path} does not exist", file=sys.stderr)
            continue
        if not path.is_file():
            print(f"  ERROR: {path} is not a file", file=sys.stderr)
            continue
        rewritten, skipped = rewrite_sarif(path)
        total_rewritten += rewritten
        total_skipped += skipped
        print(f"  {path}: {rewritten} rewritten, {skipped} unchanged")

    print(f"Total: {total_rewritten} rewritten, {total_skipped} unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
