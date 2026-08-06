"""CKV_AZURE_PCI_003 — min_tls_version below 1.2.

PCI DSS 4.2.1 requires strong cryptography for transmission of cardholder
data. TLS 1.0 / 1.1 are non-compliant.
"""
from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


UNACCEPTABLE = {"TLS1_0", "TLS1_1", "TLS10", "TLS11"}

SUPPORTED = [
    "azurerm_storage_account",
    "azurerm_mssql_server",
    "azurerm_mssql_managed_instance",
    "azurerm_app_service",
    "azurerm_linux_web_app",
    "azurerm_windows_web_app",
]


def _flatten(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class TLSMinVersion(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="min_tls_version below 1.2",
            id="CKV_AZURE_PCI_003",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=SUPPORTED,
            guideline="https://www.pcisecuritystandards.org/document_library/?category=pcidss#",
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        v = _flatten(conf.get("min_tls_version"))
        if v is None:
            return CheckResult.PASSED
        if v in UNACCEPTABLE:
            self.evaluated_keys = ["min_tls_version"]
            return CheckResult.FAILED
        return CheckResult.PASSED


check = TLSMinVersion()
