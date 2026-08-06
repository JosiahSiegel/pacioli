# Contributing to Pacioli

Thanks for your interest in improving Pacioli. This document covers how to
file issues, submit pull requests, and add new mappings/remediations.

## Project structure

```
scanner/                 # The scanner itself (driver + aggregator + helpers)
  scan.sh                # Driver: orchestrates Checkov invocations
  scan_audit.sh          # Audit: re-emit a prior report from archive
  scan_baseline_init.sh  # Bulk-generate baseline stubs from a scan
  aggregate.py           # Aggregator: SARIF → HTML/CSV/JUnit
  rewrite_sarif_help.py  # Post-processor: rewrites Checkov helpUri links
  checkov_url_overrides.py # Single source of truth for rule URLs
  terraform_remediation.yaml # Canonical azurerm 4.x fix snippets
  checks/                # Custom policy-as-code checks (5 Python files)
  lib/                   # Shared bash helpers (common + safety)
  tests/                 # Test suite (pytest)
mappings/                # Framework mapping packs (PCI DSS v4.0.1, etc.)
examples/                # scope.yaml, baseline.yaml, Makefile.consumer templates
docs/                    # Operator-facing documentation
.github/                 # Issue templates, workflows, community health
```

## Adding a new Checkov rule → framework mapping

Most contributions happen in `pci_mapping.yaml` (or whatever your framework
file is named). The schema is:

```yaml
version: 2
framework_name: PCI DSS         # Shown in the HTML title
framework_version: '4.0.1'
requirements:
  - id: 1.2.1                   # Framework requirement ID
    title: Configuration standards for NSCs are defined and implemented
    checks:
      - CKV_AZURE_59
      - CKV_AZURE_212
    doc_anchor: <URL>           # Required for the per-req citation
    doc_anchor_wayback: <URL>   # Optional; verifier checks both
```

Workflow:
1. Identify the Checkov rule ID (e.g. `CKV_AZURE_212`) from a failed scan.
2. Find the framework requirement the rule satisfies. Cross-reference the
   linked standards document (PCI SSC, NIST 800-53, CIS, etc.).
3. Add the entry to `pci_mapping.yaml` under the right requirement.
4. Verify the doc_anchor URL is live (HEAD request).
5. Run `make scan-pci-selftest` to make sure nothing broke.

## Adding a canonical remediation

Every finding should have an actionable fix block in the HTML report. The
remediation library lives in `terraform_remediation.yaml`. To add one:

```yaml
- check_id: CKV_AZURE_<n>
  resource_type: azurerm_<service>
  current_problem: <one-line verbatim from checkov --list>
  remediation_hcl: |
    resource "azurerm_<service>" "example" {
      ...
    }
  verification_step: <one-line command + expected outcome>
```

Style:
- One snippet per check_id. Multiple snippets per check_id are OK when
  there are multiple resource types.
- HCL must be the canonical azurerm 4.x form (no deprecated `enable_*`).
- Always include the `verification_step` so the operator can confirm
  the fix landed.

## Adding a new framework pack (SOC 2, CIS Azure, NIST 800-53, …)

1. Copy `pci_mapping.yaml` to `<framework>_mapping.yaml`.
2. Change the top-level `framework_name` and `framework_version`.
3. Replace the `requirements:` list with the new framework's controls.
4. Re-run the scanner with `--mapping <framework>_mapping.yaml`.
5. The HTML title and subtitle will reflect the new framework name.

For the custom checks in `pci_checks/`, you can either:
- Keep them (they're general Azure hygiene checks that apply to any
  compliance framework), or
- Move them to a framework-specific subdirectory and update the
  `--external-checks-dir` flag in Make.

## Running tests

```bash
make scan-pci-selftest    # Bash unit tests (safety invariants)
pytest scanner/tests/  # Python unit tests
```

## Style guide

- Python: 3.12+ syntax. Type hints on every public function.
- Bash: `set -uo pipefail`. Always go through `run_cmd` for external
  commands so the safety invariant is enforced.
- Commits: present tense imperative ("add", not "added"). Body should
  reference the issue or the ADR if one exists.
- Branches: `feature/*`, `fix/*`, `docs/*`, `chore/*`.

## Security reports

See `SECURITY.md`. Do not file security issues as public GitHub issues.
