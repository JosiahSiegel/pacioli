"""Cross-reference tests for the PCI mapping pack and scanner rule tables."""
from __future__ import annotations

from pathlib import Path
from typing import Final

import yaml

from scanner.checkov_url_overrides import RULE_SOURCE_URLS

REPO_ROOT = Path(__file__).resolve().parents[2]
MAPPING_PATH = REPO_ROOT / "mappings" / "pci_dss_4.0.1.yaml"
REMEDIATION_PATH = REPO_ROOT / "scanner" / "terraform_remediation.yaml"

# These are note-only, custom, or otherwise not-yet-overridden controls without
# canonical Checkov source URLs. Keep each exception documented here; this set
# is intentionally distinct from test_terraform_remediation_yaml.INTENTIONALLY_ABSENT.
INTENTIONALLY_ABSENT_FROM_RULE_SOURCE_URLS: Final[set[str]] = {
    "CKV_AZURE_1",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_3",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_9",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_10",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_15",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_19",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_41",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_57",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_109",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_111",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_207",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_208",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_214",  # Existing mapping coverage; URL override is future work.
    "CKV_AZURE_PCI_001",  # Custom PaaC check; no canonical Checkov source.
    "CKV_AZURE_PCI_002",  # Custom PaaC check; no canonical Checkov source.
    "CKV_AZURE_PCI_003",  # Custom PaaC check; no canonical Checkov source.
    "CKV_AZURE_PCI_004",  # Custom PaaC check; no canonical Checkov source.
    "CKV_AZURE_PCI_005",  # Custom PaaC check; no canonical Checkov source.
    # NOTE tokens (renamed CKV_AZURE_PCI_NOTE_* -> PACIOLI_NOTE_* in T7) are
    # symbolic placeholders with no canonical Checkov source URL. Each one
    # is a documented exception; the mapping pack declares them in the
    # top-level ``note_tokens`` allow-list.
    "PACIOLI_NOTE_3_4",  # Procedural PAN-display control; note token only.
    "PACIOLI_NOTE_3_5_1_1",  # Follow-up custom PaaC control; note token only.
    "PACIOLI_NOTE_8_3_1",  # Procedural strong-authentication control.
    "PACIOLI_NOTE_8_3_10",  # Custom MFA control; note token only.
    "PACIOLI_NOTE_10_7",  # Audit-retention note token; no working Checkov rule.
    "PACIOLI_NOTE_11_4_5",  # Follow-up custom PaaC control; note token only.
}


def _mapping_check_ids() -> set[str]:
    """Load and collect every check ID referenced by the mapping requirements."""
    mapping = yaml.safe_load(MAPPING_PATH.read_text(encoding="utf-8"))
    return {
        check_id
        for requirement in mapping["requirements"]
        for check_id in requirement["checks"]
    }


def _remediation_check_ids() -> set[str]:
    """Load and collect top-level remediation check IDs."""
    remediation = yaml.safe_load(REMEDIATION_PATH.read_text(encoding="utf-8"))
    return set(remediation["remediations"])


def test_mapping_checks_have_rule_source_urls_or_documented_absences() -> None:
    """Every mapped check has a URL override or an explicit documented exception."""
    mapping_check_ids = _mapping_check_ids()
    missing_urls = mapping_check_ids - set(RULE_SOURCE_URLS) - INTENTIONALLY_ABSENT_FROM_RULE_SOURCE_URLS
    assert missing_urls == set(), f"Mapped checks missing URL overrides: {sorted(missing_urls)}"


# The remediation artifact currently contains a few forward-looking entries
# that are intentionally not yet anchored in this mapping pack.
INTENTIONALLY_UNMAPPED_REMEDIATIONS: Final[set[str]] = {
    "CKV_AZURE_35",  # Remediation exists ahead of mapping coverage.
    "CKV_AZURE_80",  # Remediation exists ahead of mapping coverage.
    "CKV_AZURE_244",  # Remediation exists ahead of mapping coverage.
}


def test_remediation_checks_are_referenced_by_mapping() -> None:
    """Every non-forward-looking remediation entry is anchored by the mapping."""
    orphaned_checks = (
        _remediation_check_ids() - _mapping_check_ids() - INTENTIONALLY_UNMAPPED_REMEDIATIONS
    )
    assert orphaned_checks == set(), f"Remediation checks absent from mapping: {sorted(orphaned_checks)}"
