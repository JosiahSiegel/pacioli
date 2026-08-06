"""CKV_AZURE_PCI_002 — Storage account without explicit network_rules.

PCI DSS 1.2.1 / 1.3 require that CDE-bearing resources have explicit
network access controls. A storage account without a network_rules block
defaults to 'Allow' from any VNet/IP not on a deny list — non-compliant.
"""
from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _flatten(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class StorageDefaultDeny(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Storage account without default Deny network ACL",
            id="CKV_AZURE_PCI_002",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_storage_account"],
            guideline="https://www.pcisecuritystandards.org/document_library/?category=pcidss#",
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        rules = _flatten(conf.get("network_rules"))
        if rules is None:
            self.evaluated_keys = ["network_rules"]
            return CheckResult.FAILED
        default_action = _flatten(rules.get("default_action"))
        if default_action != "Deny":
            self.evaluated_keys = ["network_rules/default_action"]
            return CheckResult.FAILED
        return CheckResult.PASSED


check = StorageDefaultDeny()
