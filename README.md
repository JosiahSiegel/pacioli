# Pacioli

> **Compliance-as-code for Azure Terraform.**

Compliance-as-code for Azure Terraform. Read-only scanner. Emits a self-contained HTML report.

## Install

```bash
pip install https://github.com/JosiahSiegel/pacioli/releases/download/vX.Y.Z/pacioli-X.Y.Z-py3-none-any.whl
```

Replace `X.Y.Z` with the desired release tag.

## Quick start

```bash
pacioli scan .
pacioli scan . --output-dir .
pacioli scan . --no-open
```

The report is written under `~/.pacioli/runs/<run-id>/aggregate/report.html`. Use `--output-dir` to save it in the repository.

### From source

```bash
pip install -e .
```

## Safety model

Pacioli refuses Terraform mutations, Checkov `--fix`, and Azure mutations through a typed operation registry. If a scan tier needs access that is unavailable, Pacioli emits an `ACCESS REQUIRED` alert and skips the dependent layer; it never modifies Azure state or firewall rules. A refused mutation exits with code `99` so CI can distinguish it from a finding-driven gate failure. Pacioli reports findings only for the files and inputs it can discover and verify, and makes no universal safety or coverage claim. See [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) for the operation registry, alert-only access behavior, constrained Terraform plan, and residual risks.

## Three scan tiers

| Tier | Command | Description |
|---|---|---|
| 1. Source | `pacioli scan <target-repo>` | Static `.tf` parse, with no init, plan, or storage access. |
| 2. Plan | `pacioli scan --tier plan <target-repo>` | Adds `terraform plan` so Checkov sees resolved values. |
| 3. State | `pacioli scan --tier state <target-repo>` | Adds `.tfstate` blob scanning and drift comparison. |

## CI gate

```bash
# Exits non-zero on HIGH/CRITICAL findings.
pacioli gate <target-repo>

# Manual scan. Never blocks.
pacioli scan <target-repo>
```

## Documentation

**Start here:**

- [docs/CONSUMING_GUIDE.md](docs/CONSUMING_GUIDE.md) — first-time setup for adding the scanner to a Terraform repo.
- [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) — full operator runbook.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the pieces fit together.
- [docs/INDEX.md](docs/INDEX.md) — master table of contents.

**Reference:**

- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) — every argument and environment variable.
- [docs/MAPPING_SCHEMA.md](docs/MAPPING_SCHEMA.md) — mapping YAML format.
- [docs/CHECK_AUTHORING.md](docs/CHECK_AUTHORING.md) — adding a custom check.
- [docs/REPORT_FORMAT.md](docs/REPORT_FORMAT.md) — every output file.
- [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) — the read-only invariant.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — common failures.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Maintainers

Pacioli is an open-source project. Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for workflow and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community norms.
