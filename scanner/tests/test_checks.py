"""Unit coverage for Pacioli's custom Azure PCI resource checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from scanner.checks.CKV_AZURE_PCI_001__lifecycle_ignore_changes import (
    LifecycleIgnoreChanges,
)
from scanner.checks.CKV_AZURE_PCI_002__storage_default_deny import StorageDefaultDeny
from scanner.checks.CKV_AZURE_PCI_003__tls_min_version import TLSMinVersion
from scanner.checks.CKV_AZURE_PCI_004__cmk_required import CMKRequired
from scanner.checks.CKV_AZURE_PCI_005__kv_purge_protection import KVPurgeProtection


@dataclass(frozen=True)
class CheckCase:
    check_class: type[BaseResourceCheck]
    resource_type: str
    check_id: str
    category: CheckCategories
    bad_conf: dict[str, Any]
    good_conf: dict[str, Any]


CHECK_CASES = [
    CheckCase(
        check_class=LifecycleIgnoreChanges,
        resource_type="azurerm_storage_account",
        check_id="CKV_AZURE_PCI_001",
        category=CheckCategories.GENERAL_SECURITY,
        bad_conf={"lifecycle": {"ignore_changes": [["min_tls_version"]]}},
        good_conf={"lifecycle": {"ignore_changes": [["tags"]]}},
    ),
    CheckCase(
        check_class=StorageDefaultDeny,
        resource_type="azurerm_storage_account",
        check_id="CKV_AZURE_PCI_002",
        category=CheckCategories.NETWORKING,
        bad_conf={"network_rules": [{"default_action": ["Allow"]}]},
        good_conf={"network_rules": [{"default_action": ["Deny"]}]},
    ),
    CheckCase(
        check_class=TLSMinVersion,
        resource_type="azurerm_storage_account",
        check_id="CKV_AZURE_PCI_003",
        category=CheckCategories.ENCRYPTION,
        bad_conf={"min_tls_version": ["TLS1_1"]},
        good_conf={"min_tls_version": ["TLS1_2"]},
    ),
    CheckCase(
        check_class=CMKRequired,
        resource_type="azurerm_storage_account",
        check_id="CKV_AZURE_PCI_004",
        category=CheckCategories.ENCRYPTION,
        bad_conf={},
        good_conf={"customer_managed_key": [{"key_vault_key_id": ["example-key-id"]}]},
    ),
    CheckCase(
        check_class=KVPurgeProtection,
        resource_type="azurerm_key_vault",
        check_id="CKV_AZURE_PCI_005",
        category=CheckCategories.ENCRYPTION,
        bad_conf={"enable_purge_protection": [False]},
        good_conf={"enable_purge_protection": [True]},
    ),
]


@pytest.mark.parametrize("case", CHECK_CASES, ids=lambda case: case.check_id)
@pytest.mark.parametrize(
    ("conf_attribute", "expected_result"),
    [("bad_conf", CheckResult.FAILED), ("good_conf", CheckResult.PASSED)],
    ids=["bad", "good"],
)
def test_custom_pci_check(
    case: CheckCase,
    conf_attribute: str,
    expected_result: CheckResult,
) -> None:
    check = case.check_class()
    check.entity_type = case.resource_type

    assert check.scan_resource_conf(getattr(case, conf_attribute)) is expected_result
    assert check.entity_type in check.supported_resources
    assert check.id == case.check_id
    assert case.category in check.categories
