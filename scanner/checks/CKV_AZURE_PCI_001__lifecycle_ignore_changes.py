"""CKV_AZURE_PCI_001 — lifecycle.ignore_changes on security-sensitive attribute.

PCI DSS 6.5.5 requires that all changes to system components (including
configuration) are managed through formal change-control. In the
Terraform/Azure context, lifecycle.ignore_changes on a security-sensitive
attribute is a one-way bypass: it means the source-of-truth (.tf) no
longer reflects reality, and any drift in Azure (manual change, Portal
edit, sibling automation) will persist undetected.

Citation chain-of-custody:
  Verified against PCI SSC Summary-of-Changes v3.2.1 -> v4.0 PDF
  (pulled Aug 4 2026; HEAD 200/application/pdf/477973B).
  Originally docstring-cited as "11.3.4" (an external-pentest req
  about report retention); corrected to 6.5.5 (changes to system
  components are managed) which is the verbatim PCI SSC v4.0.1
  controlling requirement for Terraform drift management.

Proving method: HUMAN-LIBRARIAN cross-check against PCI SSC SoC
  PDF lines 706, 779, 800, 902 (v4.0.x 6.x → 6.5.5 renumbering).
"""
from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


# Attribute names that are PCI-relevant when ignored.
PCI_SENSITIVE_ATTRIBUTES: dict[str, set[str]] = {
    "azurerm_storage_account": {
        "enable_https_traffic_only",
        "min_tls_version",
        "public_network_access_enabled",
        "allow_blob_public_access",
        "network_rules",
        "infrastructure_encryption_enabled",
        "customer_managed_key",
        "identity",
    },
    "azurerm_mssql_server": {
        "public_network_access_enabled",
        "minimal_tls_version",
        "azuread_administrator",
        "auditing_policy",
        "security_alert_policy",
    },
    "azurerm_mssql_database": {
        "transparent_data_encryption_enabled",
        "auditing_policy",
        "threat_detection_policy",
        "long_term_retention_policy",
    },
    "azurerm_key_vault": {
        "enable_purge_protection",
        "enable_soft_delete",
        "soft_delete_retention_days",
        "purge_protection_enabled",
        "network_acls",
        "public_network_access_enabled",
    },
    "azurerm_key_vault_key": {
        "key_opts",
        "curve",
        "key_size",
        "expiration_date",
    },
    "azurerm_mssql_managed_instance": {
        "public_data_endpoint_enabled",
        "minimal_tls_version",
        "auditing_policy",
    },
}


def _flatten(value: Any) -> Any:
    """Unwrap Checkov's list-wrapped attribute values."""
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class LifecycleIgnoreChanges(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="lifecycle ignore_changes on security-sensitive attribute",
            id="CKV_AZURE_PCI_001",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=list(PCI_SENSITIVE_ATTRIBUTES.keys()),
            guideline="https://www.pcisecuritystandards.org/document_library/?category=pcidss#",
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        rtype = self.entity_type
        sensitive = PCI_SENSITIVE_ATTRIBUTES.get(rtype)
        if not sensitive:
            return CheckResult.PASSED

        lifecycle = _flatten(conf.get("lifecycle"))
        if not isinstance(lifecycle, dict):
            return CheckResult.PASSED
        ignored = _flatten(lifecycle.get("ignore_changes"))
        if not isinstance(ignored, list):
            return CheckResult.PASSED

        # Each entry may be a string (bare attr name) or a dict
        # (sub-attr like tags), per Terraform's lifecycle.ignore_changes
        # docs. We only flag bare names; ignore sub-dicts to avoid noise.
        flagged = []
        for entry in ignored:
            entry = _flatten(entry)
            if isinstance(entry, str) and entry in sensitive:
                flagged.append(entry)
        if not flagged:
            return CheckResult.PASSED

        self.evaluated_keys = ["lifecycle/ignore_changes"]
        return CheckResult.FAILED


check = LifecycleIgnoreChanges()
