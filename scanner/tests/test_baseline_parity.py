"""Round-trip parity tests for `pacioli baseline init`.

These tests prove that the YAML emitted by ``scanner.baseline_init``
is loadable by ``scanner.aggregate.load_baseline`` (formerly named
``load_baseline``) and that every stub entry exposes the fields
the aggregation rule depends on.

The 7 fields the producer (``baseline_init._build_stub_entries``) writes
AND that the consumer (``load_baseline``) round-trips are:

    check_id
    resource_pattern
    justification
    compensating_control
    owner
    ticket_id
    expires_on

The aggregator's suppression rule is

    suppress iff (owner != "TBD") AND (expires_on >= today)

so stubs are *discoverable* in report.html (under a "requires triage"
banner) but never silently mask findings. The parity test exists
to catch a regression where the emitted YAML drifts from the loader's
expected schema — that would break the triage → suppression workflow
without anyone noticing until production.

Note: A broader audit contract mentions 9 fields (adding ``approved_by``
and ``approved_on``). Neither ``baseline_init`` nor ``aggregate.py``
currently produces or consumes those fields; they're tracked separately
outside the scanner's baseline format. This test pins the *actual*
schema, not the aspirational one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

# conftest.py (in this directory) adds the project root to sys.path so
# `from scanner.foo import ...` resolves cleanly.
from scanner import baseline_init
from scanner.aggregate import load_baseline
from scanner.frameworks import SARIF_PROPERTY_ENV, SARIF_PROPERTY_PROJECT


REQUIRED_FIELDS: tuple[str, ...] = (
    "check_id",
    "resource_pattern",
    "justification",
    "compensating_control",
    "owner",
    "ticket_id",
    "expires_on",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_combined_sarif(run_dir: Path, runs: list[dict]) -> Path:
    """Write a synthetic combined.sarif under ``<run_dir>/aggregate``.

    Args:
        run_dir: Root run directory (e.g. ``tmp_path``).
        runs: List of run objects to embed. Each run is a SARIF run
            with optional ``properties`` (project, env, both names
            imported from ``scanner.frameworks``) and ``results``
            (each result has ``ruleId`` and ``locations``).

    Returns:
        Path to the written combined.sarif.
    """
    aggregate_dir = run_dir / "aggregate"
    aggregate_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = aggregate_dir / "combined.sarif"
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    sarif_path.write_text(json.dumps(payload), encoding="utf-8")
    return sarif_path


def _make_run(project: str, env: str, results: list[dict]) -> dict:
    """Build a minimal SARIF run with project/env properties."""
    return {
        "tool": {"driver": {"name": "checkov", "version": "3.0.0"}},
        "properties": {
            SARIF_PROPERTY_PROJECT: project,
            SARIF_PROPERTY_ENV: env,
        },
        "results": results,
    }


def _make_result(rule_id: str, resource_uri: str) -> dict:
    """Build a minimal SARIF result with a single physicalLocation."""
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": f"finding {rule_id} at {resource_uri}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": resource_uri},
                }
            }
        ],
    }


@pytest.fixture
def run_dir_with_two_findings(tmp_path: Path) -> Path:
    """Synthetic SARIF with two distinct (check_id, resource) pairs.

    Chosen to exercise the dedup logic in ``_build_stub_entries``:
        - CKV_AZURE_206 on /subscriptions/sub-1/resourceGroups/rg1 (project=pci, env=prod)
        - CKV_AZURE_3   on /subscriptions/sub-1/resourceGroups/rg1/storageAccounts/sa1
            (project=pci, env=prod)
    Both run under the same project+env so the second stub gets a
    hit_count of 1 (one project × one env).

    We also add a *duplicate* finding (same ruleId, same resource) in
    a second run to prove dedup works: only one stub per pair.
    """
    dup_result = _make_result(
        "CKV_AZURE_206",
        "/subscriptions/sub-1/resourceGroups/rg1",
    )
    runs = [
        _make_run(
            project="pci",
            env="prod",
            results=[
                _make_result(
                    "CKV_AZURE_206",
                    "/subscriptions/sub-1/resourceGroups/rg1",
                ),
                _make_result(
                    "CKV_AZURE_3",
                    "/subscriptions/sub-1/resourceGroups/rg1/storageAccounts/sa1",
                ),
                dup_result,  # duplicate of the first — should be deduped
            ],
        ),
    ]
    _write_combined_sarif(tmp_path, runs)
    return tmp_path


@pytest.fixture
def baseline_path(tmp_path: Path) -> Path:
    """Destination path for the generated baseline YAML."""
    return tmp_path / "pci_baseline.yaml"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_baseline_init_yaml_loads_via_load_baseline(
    run_dir_with_two_findings: Path, baseline_path: Path
) -> None:
    """Round-trip: emitted YAML must be accepted by ``load_baseline``.

    This is the headline parity test. It runs the CLI against a
    synthetic SARIF and asserts that the resulting YAML parses back
    into a list of dicts via the same loader the aggregator uses.
    """
    rc = baseline_init.main(
        [
            "--run-dir", str(run_dir_with_two_findings),
            "--baseline", str(baseline_path),
        ]
    )
    assert rc == 0, "baseline init exited non-zero"
    assert baseline_path.is_file(), "baseline file was not written"

    # The same loader the aggregator uses at scan time.
    entries = load_baseline(baseline_path)
    assert isinstance(entries, list)
    # Synthetic SARIF had 2 distinct (check_id, resource) pairs; the
    # duplicate was deduped.
    assert len(entries) == 2


def test_baseline_init_emits_all_required_fields(
    run_dir_with_two_findings: Path, baseline_path: Path
) -> None:
    """Every stub entry must carry all 7 fields the round-trip contract requires.

    The producer (``baseline_init``) and the consumer
    (``load_baseline``) both honor the same field set. The
    suppression rule is gated on owner + expires_on. If those drift
    to a different key name, the rule silently breaks. This test
    pins the field set so a producer-side regression is caught here
    rather than at scan time in production.
    """
    rc = baseline_init.main(
        [
            "--run-dir", str(run_dir_with_two_findings),
            "--baseline", str(baseline_path),
        ]
    )
    assert rc == 0

    entries = load_baseline(baseline_path)
    assert len(entries) == 2

    for entry in entries:
        assert isinstance(entry, dict), f"entry is not a dict: {entry!r}"
        missing = [f for f in REQUIRED_FIELDS if f not in entry]
        assert not missing, (
            f"entry missing required fields {missing}: {entry!r}"
        )

    # Stubs should also have the bonus metadata fields the runbook
    # documents (first_seen, hit_count, generated_at). These are not
    # strictly required by the loader but downstream tools rely on them.
    for entry in entries:
        assert "first_seen" in entry
        assert "hit_count" in entry
        assert "generated_at" in entry


def test_baseline_init_append_merges_with_existing(
    tmp_path: Path, baseline_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """``--append`` merges new stubs with an existing pci_baseline.yaml.

    Setup: pre-seed the baseline with a *promoted* entry (owner/person,
    future expiry → would actually suppress). Then run baseline_init
    with --append using a fresh SARIF that contains a *different*
    check_id. The promoted entry must survive; the new stub must be
    added.
    """
    # Pre-seed baseline with one promoted entry (real owner, future expiry).
    promoted = {
        "version": 1,
        "verified_against": "2099-12-31",
        "suppressions": [
            {
                "check_id": "CKV_AZURE_50",
                "resource_pattern": "/subscriptions/sub-x/storageAccounts/legacy",
                "justification": "Legacy storage account; covered by compensating control.",
                "compensating_control": "Network ACL + private endpoint.",
                "owner": "alice@example.com",
                "ticket_id": "SEC-1234",
                "approved_by": "alice@example.com",
                "approved_on": "2025-01-15",
                "expires_on": "2099-12-31",
            }
        ],
    }
    baseline_path.write_text(
        "# Pre-existing header — should be preserved by --append.\n"
        + yaml.safe_dump(promoted, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    # New SARIF: a *different* (check_id, resource) pair.
    runs = [
        _make_run(
            project="pci",
            env="prod",
            results=[
                _make_result(
                    "CKV_AZURE_206",
                    "/subscriptions/sub-1/resourceGroups/rg1",
                ),
            ],
        ),
    ]
    _write_combined_sarif(tmp_path, runs)

    # Run with --append.
    rc = baseline_init.main(
        [
            "--run-dir", str(tmp_path),
            "--baseline", str(baseline_path),
            "--append",
        ]
    )
    assert rc == 0, "baseline init --append exited non-zero"

    entries = load_baseline(baseline_path)
    check_ids = {e["check_id"] for e in entries}
    assert "CKV_AZURE_50" in check_ids, "promoted entry was lost on --append"
    assert "CKV_AZURE_206" in check_ids, "new stub was not added on --append"
    assert len(entries) == 2

    # The promoted entry's *values* must be unchanged (we did not
    # overwrite the human-populated fields).
    promoted_after = next(e for e in entries if e["check_id"] == "CKV_AZURE_50")
    assert promoted_after["owner"] == "alice@example.com"
    assert promoted_after["expires_on"] == "2099-12-31"


def test_baseline_init_replaces_without_append(
    run_dir_with_two_findings: Path, baseline_path: Path
) -> None:
    """Without ``--append``, a new baseline-init replaces prior content.

    Mirrors the bash script's default behavior. Documents the contract
    so a future change to default-append won't break the workflow.
    """
    # Pre-seed with a single entry that must NOT survive.
    pre_existing = {
        "version": 1,
        "verified_against": "2020-01-01",
        "suppressions": [
            {
                "check_id": "CKV_AZURE_OLD",
                "resource_pattern": "/subscriptions/legacy",
                "justification": "legacy",
                "compensating_control": "n/a",
                "owner": "bob@example.com",
                "ticket_id": "SEC-9999",
                "approved_by": "bob@example.com",
                "approved_on": "2020-01-01",
                "expires_on": "2020-12-31",
            }
        ],
    }
    baseline_path.write_text(
        yaml.safe_dump(pre_existing, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    rc = baseline_init.main(
        [
            "--run-dir", str(run_dir_with_two_findings),
            "--baseline", str(baseline_path),
        ]
    )
    assert rc == 0

    entries = load_baseline(baseline_path)
    check_ids = {e["check_id"] for e in entries}
    assert "CKV_AZURE_OLD" not in check_ids, (
        "pre-existing entry should have been replaced by default-init"
    )
    # The two stubs from our fixture should be present.
    assert "CKV_AZURE_206" in check_ids
    assert "CKV_AZURE_3" in check_ids
