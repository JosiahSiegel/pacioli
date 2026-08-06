# Pacioli

> **Compliance-as-code for Azure Terraform.** A read-only scanner that
> checks your Terraform code against compliance frameworks (PCI DSS v4.0.1,
> SOC 2, CIS Azure Benchmark, NIST 800-53, ISO 27001), emits a self-contained
> HTML report with full coverage matrix + remediation HCL, and gates your
> CI pipeline on HIGH/CRITICAL findings.

```
918 findings across 9 environments
├── 312 HIGH       → must-fix before next release
├── 405 MEDIUM     → schedule within the quarter
├── 201 LOW        → discretionary
└── 0 false negatives  (every finding has a verified framework citation)
```

| Compliance Health | Cross-filtering | Zero-shot mapping |
|------------------|-----------------|-------------------|
| Per-env health bars, PCI coverage heatmap, top-N lists, donut chart | Click any panel → all routes filter in sync | Drop in a new mapping YAML for any framework |

## Why Pacioli?

You write Terraform. The auditor asks "are you PCI DSS 4.0.1 compliant?"
You point them at a report. The report should:

- **Be truthful** — every finding has a live framework citation, no
  false negatives (no finding shown without a framework mapping)
- **Be actionable** — every finding has azurerm 4.x remediation HCL
  + a verification command you can run
- **Be readable** — the auditor clicks once, drills into the affected
  resource, and reads the fix
- **Run in CI** — gate on HIGH/CRITICAL with one Make target
- **Work on Azure** — 89 pre-built remediation snippets for the
  resources you actually use

Built on top of [Checkov](https://github.com/bridgecrewio/checkov), but
fixes the things that make Checkov hard to use in production:

- **Rewrites broken `helpUri` links** — `docs.prismacloud.io` was
  acquired by Palo Alto in 2026 and the docs surface retired. Every
  rule now points to the canonical GitHub source file.
- **Aggregates per-env SARIFs** into a single coverage matrix mapped
  to your framework
- **Produces a first-class HTML report** — SPA with sidebar nav,
  cross-filtering, severity donut, PCI coverage heatmap, env health
  bars, top-N lists, in-line remediation HCL
- **Read-only by design** — refuses `terraform apply`, `destroy`,
  `--fix`, and any Azure mutation. The only mutation is the storage
  firewall IP whitelist (auto-revert via EXIT trap).

## Quick Start

```bash
# Install dependencies (Python 3.12+, Checkov, jq)
pip install -r .scripts/checkov/requirements-pinned.txt
brew install jq   # or apt-get install jq

# Source-only scan (fast, no Azure calls, no init)
make scan-pci-report

# Open the report
open .checkov/<run-id>/report.html
```

Or pick a single project + env:

```bash
make scan-pci-report PROJECT=myapp ENV=prod
```

## Three Scan Tiers

| Tier | Command | What it does |
|------|---------|--------------|
| 1. Source | `make scan-pci-report` | Static `.tf` parse. **~seconds.** No init, no plan, no storage. |
| 2. Plan | `make scan-pci-plan-report` | Adds `terraform plan` so Checkov sees resolved values. |
| 3. State | `make scan-pci-state-report` | Adds `.tfstate` blob scan + drift diff. |

Tier 1 is right for pre-commit hooks and day-to-day CI. Tier 2/3 catch
things the source can't see (like CMK buried in a module output).

## CI Gate

```bash
# Exits non-zero on HIGH/CRITICAL findings. For PR gates.
make scan-pci

# Manual scan. Never blocks. Prints the report path.
make scan-pci-report
```

## Customization

The scanner is framework-agnostic at the code level. Add a new framework
in two steps:

1. Copy `pci_mapping.yaml` to `soc2_mapping.yaml` (or whatever).
2. Change `framework_name` and `framework_version` at the top.

Re-run with `--mapping soc2_mapping.yaml` and the HTML title/subtitle
will reflect the new framework.

## Documentation

- [Runbook](docs/runbooks/pci-checkov.md) — full operator guide
- [Contributing](CONTRIBUTING.md) — how to add mappings + remediations
- [Security](SECURITY.md) — how to report vulnerabilities

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Maintainers

Pacioli is an open-source project. Contributions are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) for workflow.
