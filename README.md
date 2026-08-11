# Pacioli

> **Compliance-as-code for Azure Terraform.** A read-only scanner
> that checks your Terraform code against compliance frameworks
> (PCI DSS v4.0.1 by default; SOC 2, CIS Azure, NIST 800-53, ISO
> 27001 via custom mapping packs), emits a self-contained HTML
> report with full coverage matrix and remediation HCL, and gates
> your CI pipeline on HIGH/CRITICAL findings.

```
                Findings in a typical multi-env Azure repo
                ┌─────────────────────────────────────┐
                │ HIGH       → must-fix before merge  │
                │ MEDIUM     → schedule this quarter   │
                │ LOW        → discretionary          │
                └─────────────────────────────────────┘
                Every finding has a verified framework citation.
                Zero false negatives.
```

| Compliance health | Cross-filtering | Zero-shot mapping |
|---|---|---|
| Per-env health bars, PCI coverage heatmap, top-N lists, severity donut | Click any panel → all routes filter in sync | Drop in a new mapping YAML for any framework |

## Standalone usage

Pacioli installs as a single Python CLI. Point it at any Terraform
repo and it emits a self-contained HTML report.

```bash
# Install (Python 3.13+)
pip install https://github.com/JosiahSiegel/pacioli/releases/download/vX.Y.Z/pacioli-X.Y.Z-py3-none-any.whl

# Replace X.Y.Z with the desired release tag.

# Scan any Terraform repo
pacioli scan /path/to/target-repo
```

The report is written under `~/.pacioli/runs/<run-id>/aggregate/report.html` (or `~/.pacioli/runs/current/` for the most recent run; override with `--output-dir <path>`).

### From source (dev only)

For local development against this checkout:

```bash
pip install -e .
```

## Why Pacioli?

You write Terraform. The auditor asks "are you PCI DSS 4.0.1
compliant?" You point them at a report. The report should:

- **Be truthful** — every finding has a live framework citation,
  no false negatives (no finding shown without a framework
  mapping).
- **Be actionable** — every finding has azurerm 4.x remediation
  HCL plus a verification command you can run.
- **Be readable** — the auditor clicks once, drills into the
  affected resource, and reads the fix.
- **Run in CI** — gate on HIGH/CRITICAL with one command.
- **Work on Azure** — 89 pre-built remediation snippets for the
  resources you actually use.

Built on top of [Checkov](https://github.com/bridgecrewio/checkov),
but fixes the things that make Checkov hard to use in production:

- **Rewrites broken `helpUri` links** — `docs.prismacloud.io` was
  acquired by Palo Alto in 2026 and the docs surface was retired.
  Every rule now points to the canonical GitHub source file.
- **Aggregates per-env SARIFs** into a single coverage matrix
  mapped to your framework.
- **Produces a first-class HTML report** — SPA with sidebar nav,
  cross-filtering, severity donut, PCI coverage heatmap, env health
  bars, top-N lists, in-line remediation HCL.
- **Read-only by design** — refuses Terraform mutations, Checkov `--fix`,
  and Azure mutations through the typed operation registry. If a tier needs
  access that is unavailable, Pacioli emits an `ACCESS REQUIRED` alert and
  skips the dependent layer. It does not change Azure firewall rules.

Pacioli reports findings for the files and inputs it can discover and verify.
It makes no universal safety or coverage claim. See
[Safety Model](docs/SAFETY_MODEL.md) for the operation registry, alert-only
access behavior, constrained Terraform plan, and residual risks.

| Tier | Command | What it does | When |
|---|---|---|---|
| 1. Source | `pacioli scan <target-repo>` | Static `.tf` parse. **~seconds.** No init, no plan, no storage. | Pre-commit, day-to-day CI. |
| 2. Plan | `pacioli scan --tier plan <target-repo>` | Adds `terraform plan` so Checkov sees resolved values. | Monthly deep reviews, audit prep. |
| 3. State | `pacioli scan --tier state <target-repo>` | Adds `.tfstate` blob scan + drift diff. | Drift triage, after manual Azure changes. |

Tier 1 is right for pre-commit hooks and day-to-day CI. Tier 2/3
catch things the source can't see (like CMK buried in a module
output, or `ignore_changes` drift between plan and state).

## CI gate

```bash
# Exits non-zero on HIGH/CRITICAL findings. For PR gates.
pacioli gate <target-repo>

# Manual scan. Never blocks. Prints the report path.
pacioli scan <target-repo>
```

## Documentation

**Start here:**

- [docs/CONSUMING_GUIDE.md](docs/CONSUMING_GUIDE.md) — first-time
  setup for adding the scanner to a Terraform repo.
- [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) — full operator
  runbook.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the pieces fit
  together.
- [docs/INDEX.md](docs/INDEX.md) — master table of contents.

**Reference:**

- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) — every argument
  and env var.
- [docs/MAPPING_SCHEMA.md](docs/MAPPING_SCHEMA.md) — mapping YAML
  format.
- [docs/CHECK_AUTHORING.md](docs/CHECK_AUTHORING.md) — adding a
  custom check.
- [docs/REPORT_FORMAT.md](docs/REPORT_FORMAT.md) — every output
  file.
- [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) — the read-only
  invariant.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — common
  failures.

**Project:**

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability.
- [SUPPORT.md](SUPPORT.md) — where to get help.
- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) — extending
  the scanner.

## Customization

The scanner is framework-agnostic at the code level. Add a new
framework in three steps:

1. Copy `mappings/pci_dss_4.0.1.yaml` to
   `mappings/<framework>_<version>.yaml`.
2. Change `framework_name` and `framework_version` at the top.
3. Replace `requirements:` with the new framework's controls.

Re-run with `--mapping mappings/<framework>_<version>.yaml` and
the HTML title and sidebar will reflect the new framework.

## Optional: enterprise wrapper

If you maintain a Terraform monorepo and want a self-contained
wrapper checked in next to your code, the consumer Makefile is
still available:

```bash
# Copy the wrapper Makefile into your repo
cp examples/Makefile.consumer ./Makefile.pacioli

# Edit PACIOLI_DIR to point at your Pacioli checkout
# (../pacioli by default; override with `make PACIOLI_DIR=...`)

# Copy the scope + baseline templates
cp examples/scope.yaml.example ./pci_scope.yaml
cp examples/baseline.yaml.example ./pci_baseline.yaml

# Run your first scan
make -f Makefile.pacioli scan PROJECT=myapp ENV=prod
```

Most teams won't need this — `pip install https://github.com/JosiahSiegel/pacioli/releases/download/vX.Y.Z/pacioli-X.Y.Z-py3-none-any.whl` + `pacioli scan` is the supported path. The full step-by-step for the wrapper
flow lives in
[docs/CONSUMING_GUIDE.md](docs/CONSUMING_GUIDE.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Maintainers

Pacioli is an open-source project. Contributions are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) for workflow and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community norms.