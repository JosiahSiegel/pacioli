"""CKV_AZURE_PCI_004 — Customer-managed key (CMK) missing on encryption-bearing resource.

PCI DSS 3.5.1 requires procedures for protecting cryptographic keys.
Customer-managed keys (BYOK) ensure the customer controls key lifecycle
and rotation, rather than relying on platform-managed defaults.
"""
from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.common.graph.graph_builder import CustomAttributes
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _flatten(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class CMKRequired(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Customer-managed key (CMK) missing on encryption-bearing resource",
            id="CKV_AZURE_PCI_004",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=[
                "azurerm_storage_account",
                "azurerm_storage_account_customer_managed_key",
                "azurerm_mssql_database",
                "azurerm_mssql_managed_instance",
                "azurerm_cosmosdb_account",
            ],
            guideline="https://www.pcisecuritystandards.org/document_library/?category=pcidss#",
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        rtype = self.entity_type
        if rtype == "azurerm_storage_account":
            if _flatten(conf.get("customer_managed_key")) is None:
                parent_address = _flatten(conf.get("__address__"))
                if self.graph is not None and parent_address:
                    for _, attributes in self.graph.nodes():
                        if (
                            attributes.get(CustomAttributes.RESOURCE_TYPE)
                            == "azurerm_storage_account_customer_managed_key"
                            and attributes.get("storage_account_id", "").removesuffix(".id")
                            == parent_address
                        ):
                            self.evaluated_keys = ["customer_managed_key (standalone)"]
                            return CheckResult.PASSED
                self.evaluated_keys = ["customer_managed_key"]
                return CheckResult.FAILED
        elif rtype == "azurerm_storage_account_customer_managed_key":
            if conf.get("storage_account_id") is None or conf.get("key_vault_key_id") is None:
                self.evaluated_keys = ["storage_account_id", "key_vault_key_id"]
                return CheckResult.FAILED
        elif rtype in ("azurerm_mssql_database", "azurerm_mssql_managed_instance"):
            if _flatten(conf.get("identity")) is None:
                self.evaluated_keys = ["identity"]
                return CheckResult.FAILED
        elif rtype == "azurerm_cosmosdb_account":
            if _flatten(conf.get("identity")) is None:
                self.evaluated_keys = ["identity"]
                return CheckResult.FAILED
        return CheckResult.PASSED


check = CMKRequired()
