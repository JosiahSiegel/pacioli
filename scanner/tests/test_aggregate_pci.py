"""Smoke tests for the mapping YAML loader.

These tests verify that the schema is realistic and the loader handles
edge cases. They do NOT verify the upstream Checkov mapping content
itself (that's a living document; live tests are in the runbook).
"""
import pytest
from pathlib import Path

from aggregate import load_pci_mapping, load_pci_baseline


def test_load_pci_mapping_parses_top_level_keys():
    """The real pci_mapping.yaml must load with the expected top-level keys."""
    # Use the file shipped with the repo.
    mapping_path = Path(__file__).resolve().parents[3] / "pci_mapping.yaml"
    if not mapping_path.exists():
        pytest.skip(f"{mapping_path} not present (CI may not have the full repo)")
    mapping = load_pci_mapping(mapping_path)
    assert isinstance(mapping, dict)
    # The mapping is {check_id: [req_ids, ...]} — inverted for fast lookup.
    # Should have at least one check mapped
    assert len(mapping) > 0
    for check_id, req_ids in mapping.items():
        assert isinstance(check_id, str)
        assert check_id.startswith("CKV"), f"{check_id} doesn't start with CKV"
        assert isinstance(req_ids, list)
        assert all(isinstance(r, str) for r in req_ids)
        # Each req_id should look like a PCI req number (e.g. "1.2.1", "10.7")
        assert all(any(ch.isdigit() for ch in r) for r in req_ids)


def test_load_pci_mapping_unknown_path(tmp_path):
    """Loading a nonexistent file returns an empty dict (degraded mode)."""
    mapping = load_pci_mapping(tmp_path / "nonexistent.yaml")
    assert mapping == {}


def test_load_pci_baseline_returns_list():
    """Baseline file loads as a list of dicts."""
    baseline_path = Path(__file__).resolve().parents[3] / "pci_baseline.yaml"
    if not baseline_path.exists():
        pytest.skip(f"{baseline_path} not present")
    baseline = load_pci_baseline(baseline_path)
    assert isinstance(baseline, list)
    # Empty file or all entries may be stub; assert type only
    for entry in baseline:
        assert isinstance(entry, dict)


def test_validate_oos_requires_nine_fields():
    """Out-of-scope rows must have 9 fields; the validator refuses if any is missing."""
    from aggregate import validate_out_of_scope_entries
    bad = [{"id": "1.2.1", "title": "x", "rationale": "r", "control_owner": "o"}]
    errors, _enriched = validate_out_of_scope_entries(bad, today_iso="2026-08-06")
    assert len(errors) > 0  # missing fields = errors


def test_validate_oos_accepts_complete_entry():
    """A fully-populated OOS row passes validation."""
    from aggregate import validate_out_of_scope_entries
    good = [{
        "id": "1.2.1",
        "title": "Test req",
        "rationale": "Test rationale",
        "control_owner": "team@example.com",
        "approved_by": "Approver Name",
        "approved_on": "2026-01-01",
        "expires_on": "2027-01-01",
        "evidence_link": "https://example.com/evidence",
    }]
    errors, _enriched = validate_out_of_scope_entries(good, today_iso="2026-08-06")
    assert errors == []


def test_validate_oos_rejects_invalid_date():
    """Bad ISO date in expires_on is rejected."""
    from aggregate import validate_out_of_scope_entries
    bad = [{
        "id": "1.2.1",
        "title": "Test",
        "rationale": "r",
        "control_owner": "o",
        "approved_by": "Jane",
        "approved_on": "2026-01-01",
        "expires_on": "not-a-date",
        "evidence_link": "https://example.com",
    }]
    errors, _enriched = validate_out_of_scope_entries(bad, today_iso="2026-08-06")
    assert len(errors) > 0
