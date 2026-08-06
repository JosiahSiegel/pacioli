---
name: Mapping suggestion
about: Suggest adding a Checkov rule to a framework mapping
title: "[Mapping] "
labels: mapping
assignees: ''
---

## Framework

Which framework? (PCI DSS, SOC 2, CIS Azure, NIST 800-53, ISO
27001, ...)

If a new framework, also describe:

- The framework's canonical public document URL.
- How req IDs are formatted (e.g. `1.2.1` for PCI, `CC6.1` for
  SOC 2, `2.1.1` for CIS).

## Requirement ID

The framework requirement ID (e.g., `PCI DSS 1.2.1`, `SOC 2
CC6.1`, `CIS Azure 2.1.1`).

## Checkov rule ID

The Checkov rule ID (e.g., `CKV_AZURE_212`).

If multiple rules, list them in a YAML list:

```yaml
- CKV_AZURE_212
- CKV_AZURE_214
```

## Rationale

Why does this rule (or set of rules) satisfy the requirement? A
short explanation.

## Verified citation

URL of the framework requirement. The `doc_anchor` must be a
live URL (HEAD 200) that points to the requirement itself, not a
generic landing page.

## Severity

HIGH / MEDIUM / LOW

## Related

- [docs/MAPPING_SCHEMA.md](docs/MAPPING_SCHEMA.md) — mapping YAML
  format.
- [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) — workflow.
