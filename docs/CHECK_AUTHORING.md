# Pacioli — Check Authoring

> **How to add a custom Checkov check** to the `scanner/checks/`
> directory. Use this when the framework requires a control that
> Checkov OSS does not cover, or when the existing Checkov check
> has the wrong severity / wrong framing for the audit.

The custom checks are loaded by Checkov at scan time via the
`--external-checks-dir` flag. Each check is a self-contained Python
file that inherits from `BaseResourceCheck` and implements
`scan_resource_conf(conf)`.

## The five checks that ship today

| ID | Resource types | PCI req | Pattern |
|---|---|---|---|
| `CKV_AZURE_PCI_001` | storage account, mssql server/db, key vault, key vault key, mssql managed instance | 6.5.5 | `lifecycle.ignore_changes` on a security-sensitive attribute |
| `CKV_AZURE_PCI_002` | storage account | 1.2.1 / 1.3 | Storage account without explicit `network_rules.default_action = "Deny"` |
| `CKV_AZURE_PCI_003` | storage account, mssql server/managed instance, app service / linux_web_app / windows_web_app | 4.2.1 | `min_tls_version` below 1.2 |
| `CKV_AZURE_PCI_004` | storage account, storage account CMK, mssql database, mssql managed instance, cosmosdb account | 3.5.1 | Customer-managed key (CMK) missing on encryption-bearing resource |
| `CKV_AZURE_PCI_005` | key vault | 3.6.5 / 8.6.3 | Key Vault purge protection disabled |

## The base template

```python
"""CKV_AZURE_PCI_<NNN> — <one-line description>.

<Why this check exists, what it catches, and the PCI requirement
that motivates it.>

PCI DSS <X.Y> requires <one-sentence verbatim from the standard>.

Citation chain-of-custody (when applicable):
  Verified against <framework doc + date + verification result>.
  Originally docstring-cited as "<old>" (<reason>); corrected to
  "<new>" which is the verbatim <framework> <version> controlling
  requirement.
"""
from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _flatten(value: Any) -> Any:
    """Unwrap Checkov's list-wrapped attribute values.

    Checkov's parser sometimes emits attribute values as a single-item
    list. Real-world .tf files always have a single value, so flattening
    to the unwrapped value is safe.
    """
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class MyNewCheck(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="<human-readable rule name (matches checkov --list output)>",
            id="CKV_AZURE_PCI_<NNN>",
            categories=[CheckCategories.<CATEGORY>],
            supported_resources=["azurerm_<service>"],
            guideline="https://www.pcisecuritystandards.org/document_library/?category=pcidss#",
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        # ... inspection logic ...
        if <violation>:
            self.evaluated_keys = ["<attribute_path>"]
            return CheckResult.FAILED
        return CheckResult.PASSED


check = MyNewCheck()
```

The module-level `check = MyNewCheck()` line is what Checkov
auto-discovers. The class name is internal; the `id` is the
public-facing rule ID.

## The `id` field

- Must start with `CKV_AZURE_PCI_` (the `CKV_AZURE_` prefix
  prevents collisions with Checkov's built-in rule IDs).
- Must be unique across all checks in the directory.
- Must match the file name: a check with `id="CKV_AZURE_PCI_006"`
  lives in `CKV_AZURE_PCI_006__<name>.py`.

When you add a new check, pick the next available integer. Today
the highest is `005`, so `006` is the next slot.

## The `supported_resources` field

A list of Terraform resource types the check applies to. Checkov
only invokes `scan_resource_conf` for resources in this list. The
five shipped checks cover:

- `azurerm_storage_account`
- `azurerm_storage_account_customer_managed_key`
- `azurerm_mssql_server`
- `azurerm_mssql_database`
- `azurerm_mssql_managed_instance`
- `azurerm_key_vault`
- `azurerm_key_vault_key`
- `azurerm_app_service`
- `azurerm_linux_web_app`
- `azurerm_windows_web_app`
- `azurerm_cosmosdb_account`

When adding a new check, pick the narrowest set of resources that
makes sense. A check that fires on a storage account but is
written against `azurerm_*` (all resources) will produce
meaningless noise.

## The `categories` field

Checkov's built-in categories. Use the one that most closely
matches the check:

- `CheckCategories.GENERAL_SECURITY` — catch-all
- `CheckCategories.NETWORKING` — network controls
- `CheckCategories.ENCRYPTION` — encryption / key management
- `CheckCategories.LOGGING` — audit / logging
- `CheckCategories.IAM` — identity / access
- `CheckCategories.SECRETS` — secret management
- `CheckCategories.KUBERNETES` — AKS / k8s
- `CheckCategories.SUPPLY_CHAIN` — image / dependency controls

## The `evaluated_keys` attribute

Set this on the `FAILED` path to declare which attribute(s) the
check inspected. This is what Checkov reports in the SARIF
`properties.evaluated_keys` field. Operators reading the SARIF see
exactly which attribute triggered the failure; auditors
verifying in the Azure Portal know where to look.

```python
self.evaluated_keys = ["min_tls_version"]
self.evaluated_keys = ["network_rules/default_action"]  # nested
self.evaluated_keys = ["customer_managed_key (standalone)"]  # for a graph-aware check
```

## The `guideline` field

A URL to the framework's authoritative document. For PCI checks,
this is the PCI SSC document library. The aggregator does NOT use
this URL — the per-finding `helpUri` is taken from
`checkov_url_overrides.py` instead. The field is here because
Checkov's SARIF requires it.

If the URL has to be a specific rule anchor (a deep-link to the
PCI SSC v4.0.1 standard PDF at the line of the requirement), use
the archived/Wayback mirror — the live PCI SSC site is sometimes
unavailable to scraping clients.

## The `_flatten` helper

Checkov's `scan_resource_conf` receives a `conf` dict whose values
are sometimes wrapped in single-item lists (a quirk of the HCL
parser). The `_flatten` helper unwraps the list to the bare value.
Use it at the entry of every attribute access:

```python
v = _flatten(conf.get("min_tls_version"))
if v in UNACCEPTABLE:
    self.evaluated_keys = ["min_tls_version"]
    return CheckResult.FAILED
```

If you have nested attributes (`network_rules.default_action`):

```python
rules = _flatten(conf.get("network_rules"))
if isinstance(rules, dict):
    default_action = _flatten(rules.get("default_action"))
```

## Graph-aware checks

For checks that need to look at related resources (e.g.
"this storage account has no `customer_managed_key` block, but is
it linked to a `azurerm_storage_account_customer_managed_key`
resource?"), use `self.graph`:

```python
def scan_resource_conf(self, conf: dict) -> CheckResult:
    rtype = self.entity_type
    if rtype == "azurerm_storage_account":
        if _flatten(conf.get("customer_managed_key")) is None:
            # No inline CMK block. Check the graph for a standalone
            # azurerm_storage_account_customer_managed_key that
            # links to this storage account.
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
```

`CKV_AZURE_PCI_004` is the shipped example of a graph-aware
check. The pattern is: if the inline attribute is missing, walk
the graph for a standalone resource that links to the parent.

## Registering the check

The check is auto-loaded by Checkov via the
`--external-checks-dir` flag in `scanner/orchestrator.py`. No
registration step is needed beyond dropping the file in the
right directory.

```bash
# Verify the file is loadable
python -c "
import sys
sys.path.insert(0, 'scanner/checks')
from CKV_AZURE_PCI_006__my_check import check
print(check.id, check.name)
"
```

## Mapping the check to a PCI requirement

After the file is in place, add the check to
`mappings/pci_dss_4.0.1.yaml`:

```yaml
- id: 1.2.1
  title: Configuration standards for NSCs are defined and implemented
  checks:
    - CKV_AZURE_9
    - CKV_AZURE_10
    - CKV_AZURE_PCI_006   # <-- new
  note: CKV_AZURE_PCI_006 (one-line rationale).
```

The aggregator will:

- Count it in `expected_count` for that req.
- Mark the cell `non_compliant` if any env has a finding.
- Mark the cell `compliant` if all envs pass.
- List it in `missing_check_ids` if it never fires.

## Setting severity

The aggregator's `SEVERITY_OVERRIDE` table in
`scanner/aggregate.py` is the local source of truth for severity
(Checkov OSS does not populate SARIF `properties.severity`).
Add an entry:

```python
SEVERITY_OVERRIDE = {
    ...
    "CKV_AZURE_PCI_006": "HIGH",  # new check
}
```

If you do not add an entry, the default `MEDIUM` is used.

## Adding a remediation block

If the check has a canonical fix, add a row to
`scanner/terraform_remediation.yaml`:

```yaml
- check_id: CKV_AZURE_PCI_006
  resource_type: azurerm_<service>
  current_problem: <one-line verbatim from checkov --list>
  remediation_hcl: |
    resource "azurerm_<service>" "example" {
      ...
    }
  verification_step: <one-line command + expected outcome>
  provenance: <registry.terraform.io URL for the canonical attribute docs>
```

The pytest test `test_terraform_remediation_yaml.py` enforces the
schema. If your check genuinely has no HCL remediation (e.g. it's
a process check, not a configuration check), add the check ID to
`INTENTIONALLY_ABSENT` in the test file.

## Adding tests

The pytest suite does not currently have per-check unit tests
(Checkov's own test harness is hard to wire up in isolation). The
end-to-end behavior is tested by running the scanner against a
fixture env with a known violation. This is a known gap; future
work is to add a `scanner/tests/checks/` subdir with per-check
fixtures.

For now, the validation is:

1. The check loads without error (`python -c "from checks import CKV_AZURE_PCI_006__my_check"`).
2. The check fires on a fixture .tf (manual test).
3. The check produces a SARIF result with the correct `ruleId`.
4. The aggregator maps the ruleId to the correct PCI requirement.
5. The report HTML shows the finding under the right PCI req.
6. `make test` and `make selftest` both pass.

## File-name convention

`CKV_AZURE_PCI_<NNN>__<short_snake_name>.py`:

- `CKV_AZURE_PCI_006__tls_13_required.py`
- `CKV_AZURE_PCI_007__vnet_peering_no_gateway_transit.py`

Two underscores separate the ID from the name. The name is a
short snake_case phrase describing the pattern (NOT the resource
type — that's already in the check body).

## Commit message

- New check: `feat: add CKV_AZURE_PCI_006__<name>`
- Severity change: `severity: <check_id> <HIGH|MEDIUM|LOW>`
- Mapping change: `mapping: <check_id> -> <req_id>`

## See also

- [Architecture](ARCHITECTURE.md) — how the custom checks fit in
- [Mapping Schema](MAPPING_SCHEMA.md) — how the check maps to a req
- [Developer Guide](DEVELOPER_GUIDE.md) — extending the scanner
- [Operator Guide → Five layers](OPERATOR_GUIDE.md#what-the-scanner-checks--five-layers)
