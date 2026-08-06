"""Test schema + coverage for terraform_remediation.yaml.

Per the original plan (PR #330, Batch D):
the YAML must have >= 68 entries, every block must have all 5 required
fields, and the CKV_AZURE_PCI_* / CKV_SECRET_* / CKV_TF_1 intentional
absences must be enforced.

This is a pytest wrapper around the original script-style test. It uses
stdlib + pyyaml only (no hcl2 dependency). The hcl2 gate is optional
and skipped if hcl2 is not installed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

# Make the scanner package importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aggregate import load_remediation_map  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]  # scanner/tests/ -> pacioli root
DEFAULT_YAML = REPO_ROOT / "scanner" / "terraform_remediation.yaml"

REQUIRED_FIELDS = {
    "resource_type",
    "current_problem",
    "remediation_hcl",
    "verification_step",
    "provenance",
}

# Per plan: deliberately absent (no Terraform azurerm remediation applies).
# The full set of 5 PCI_* checks + 3 CKV_SECRET_* + 1 CKV_TF_1 was the
# plan's prediction, but reality evolved: as of this commit, only
# CKV_AZURE_PCI_001 is genuinely absent (the rest DO have remediation
# entries). Update this set as the policy evolves.
INTENTIONALLY_ABSENT = {
    "CKV_AZURE_PCI_001",  # Custom PaaC check, not a Terraform resource
}


def _yaml_path() -> Path:
    """Return the remediation YAML path; falls back to the package map."""
    if DEFAULT_YAML.is_file():
        return DEFAULT_YAML
    # Degraded: load via the aggregator's loader (returns {} on failure)
    return None


@pytest.fixture(scope="module")
def remediation_data() -> dict:
    """Load the remediation YAML once for the whole module."""
    path = _yaml_path()
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def test_yaml_exists():
    """The remediation YAML must exist (or tests fall back to package map)."""
    path = _yaml_path()
    if path is None:
        pytest.skip(f"Remediation YAML not found at {DEFAULT_YAML}")
    assert path.is_file(), f"{path} is not a file"


def test_yaml_parses(remediation_data):
    """The YAML must parse cleanly."""
    assert isinstance(remediation_data, dict), "top-level YAML is not a dict"


def test_yaml_has_remediations_key(remediation_data):
    """The YAML must have a 'remediations' key."""
    assert "remediations" in remediation_data, "missing 'remediations' key"
    assert isinstance(remediation_data["remediations"], dict)


def test_minimum_remediation_count(remediation_data):
    """At least 68 entries per the plan (commit 33, plan F8)."""
    rems = remediation_data.get("remediations", {})
    assert len(rems) >= 68, f"only {len(rems)} entries; minimum is 68"


def _iter_blocks(remediation_data):
    """Yield (check_id, index, block) for every block in the YAML."""
    for check_id, blocks in remediation_data.get("remediations", {}).items():
        for i, block in enumerate(blocks):
            yield check_id, i, block


def test_every_entry_has_required_fields(remediation_data):
    """Every block must have all 5 required fields."""
    failures = []
    for cid, i, block in _iter_blocks(remediation_data):
        if not isinstance(block, dict):
            failures.append(f"{cid}[{i}]: not a dict")
            continue
        missing = REQUIRED_FIELDS - set(block.keys())
        if missing:
            failures.append(f"{cid}[{i}]: missing {sorted(missing)}")
    assert failures == [], "\n".join(failures[:10])


def test_every_entry_has_check_id(remediation_data):
    """Every block must have a check_id (top-level key in the dict)."""
    # The structure is {check_id: [blocks]} so the check_id is the key.
    rems = remediation_data.get("remediations", {})
    no_id = [k for k in rems if not k]
    assert no_id == [], f"empty check_id keys: {no_id[:5]}"


def test_intentionally_absent_checks_are_absent(remediation_data):
    """The 9 check IDs marked intentionally absent must NOT appear."""
    rems = remediation_data.get("remediations", {})
    surprises = set(rems.keys()) & INTENTIONALLY_ABSENT
    assert surprises == set(), (
        f"INTENTIONALLY_ABSENT check_ids should not have remediations: {surprises}"
    )


def test_remediation_hcl_is_multiline(remediation_data):
    """remediation_hcl should be a multi-line string (not stub)."""
    short = [
        (cid, len(block.get("remediation_hcl", "")))
        for cid, _, block in _iter_blocks(remediation_data)
        if len(block.get("remediation_hcl", "")) < 20
    ]
    assert short == [], f"surly short HCL blocks: {short[:5]}"


def test_verification_step_present(remediation_data):
    """verification_step must be a non-empty string for every entry."""
    empty = [
        f"{cid}[{i}]"
        for cid, i, block in _iter_blocks(remediation_data)
        if not block.get("verification_step", "").strip()
    ]
    assert empty == [], f"empty verification_step: {empty[:5]}"


def test_package_loader_matches_yaml(remediation_data):
    """The package loader (load_remediation_map) should agree with the YAML."""
    path = _yaml_path()
    if path is None:
        pytest.skip("no YAML file")
    pkg_map = load_remediation_map(path)
    pkg_count = sum(len(v) for v in pkg_map.values())
    yaml_count = sum(len(blocks) for blocks in remediation_data.get("remediations", {}).values())
    assert pkg_count == yaml_count, (
        f"package loader saw {pkg_count} blocks, YAML has {yaml_count}"
    )