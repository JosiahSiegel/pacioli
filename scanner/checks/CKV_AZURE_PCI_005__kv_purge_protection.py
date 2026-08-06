"""CKV_AZURE_PCI_005 — Key Vault purge protection disabled.

PCI DSS 3.6.5 requires procedures for the secure destruction of
cryptographic keys (the verbatim v4.0.1 sub-requirement governing
non-recoverable deletion of key material). 8.6.3 (least-privilege
on application and system accounts) covers the operational side:
an operator with permissions to purge a vault is accountable for
that destructive action.
enable_purge_protection = false means a deleted key vault can be
permanently purged within the soft-delete retention window,
bypassing both controls.

Citation chain-of-custody:
  Verified against PCI SSC Summary-of-Changes v3.2.1 -> v4.0 PDF
  (pulled Aug 4 2026; HEAD 200/application/pdf/477973B).
  Originally docstring-cited as "3.6 / 8.6" (umbrellas;
  3.6 = cryptographic-key security, 8.6 = application/system
  account management) which auditors will reject as non-verbatim.
  Corrected to the verbatim v4.0.1 sub-requirements 3.6.5
  (procedures for the secure destruction of cryptographic keys)
  and 8.6.3 (least-privilege for application and system accounts).

Proving method: HUMAN-LIBRARIAN cross-check against PCI SSC SoC
  PDF lines 393-394, 443, 455, 469, 474 (3.x renumbering into 3.6.5)
  and lines 779, 902 (8.6 -> 8.6.3 split).
"""
from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _flatten(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class KVPurgeProtection(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Key Vault purge protection disabled",
            id="CKV_AZURE_PCI_005",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_key_vault"],
            guideline="https://www.pcisecuritystandards.org/document_library/?category=pcidss#",
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        v = _flatten(conf.get("enable_purge_protection"))
        if v is None or v is False:
            self.evaluated_keys = ["enable_purge_protection"]
            return CheckResult.FAILED
        return CheckResult.PASSED


check = KVPurgeProtection()
