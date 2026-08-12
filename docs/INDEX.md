# Pacioli Documentation

Welcome to Pacioli. This is the master table of contents for everything
in this repository. Read in the order shown for first-time orientation;
jump directly to the section that matches your role.

## First-time orientation

| You are… | Read this first |
|---|---|
| **An operator** running a scan against your Terraform repo | [Consuming Pacioli](CONSUMING_GUIDE.md) → [Operator Guide](OPERATOR_GUIDE.md) |
| **A developer** extending the scanner, adding checks, or adding mappings | [Developer Guide](DEVELOPER_GUIDE.md) → [Architecture](ARCHITECTURE.md) |
| **A security auditor** reviewing an emitted report | [Report Format](REPORT_FORMAT.md) → [Operator Guide § Mapping schema](MAPPING_SCHEMA.md) |
| **Someone debugging a failure** | [Troubleshooting](TROUBLESHOOTING.md) |
| **A maintainer** reviewing or extending the safety model | [Safety Model](SAFETY_MODEL.md) |
| **A maintainer** cutting or debugging a release | [Releasing Pacioli](RELEASING.md) |

## Reference

- **[CLI Reference](CLI_REFERENCE.md)** — every command-line argument and
  environment variable, in one place.
- **[Mapping Schema](MAPPING_SCHEMA.md)** — how to write a `mappings/*.yaml`
  file, including the `out_of_scope_requirements` block.
- **[Check Authoring](CHECK_AUTHORING.md)** — how to add a custom
  `CKV_AZURE_PCI_*` Checkov check.
- **[Report Format](REPORT_FORMAT.md)** — every file in
  `~/.pacioli/runs/<run-id>/`, the HTML report routes, and the SARIF/CSV
  schemas.

## Project documents

- **[Operator Guide](OPERATOR_GUIDE.md)** — full runbook for running,
  configuring, and interpreting scans.
- **[Consuming Pacioli](CONSUMING_GUIDE.md)** — first-time setup for
  someone whose Terraform repo will consume the scanner.
- **[Architecture](ARCHITECTURE.md)** — how the scanner is put together
  (driver, aggregator, safety guard, helpers, custom checks).
- **[Developer Guide](DEVELOPER_GUIDE.md)** — extending the scanner,
  contributing back, running the test suite.
- **[Safety Model](SAFETY_MODEL.md)** — read-only invariant,
  `refuse_if_mutating` rule list, and how to add new patterns.
- **[Releasing Pacioli](RELEASING.md)** — how the release-please
  pipeline works, what triggers a release PR, what doesn't, and how to
  force a release with `Release-As:` when needed.
- **[Troubleshooting](TROUBLESHOOTING.md)** — common failure modes and
  their resolution.
- **[../CONTRIBUTING.md](../CONTRIBUTING.md)** — workflow for filing
  issues and PRs.
- **[../SECURITY.md](../SECURITY.md)** — how to report a vulnerability.
- **[../SUPPORT.md](../SUPPORT.md)** — where to get help.

## Other places documentation lives

- The **per-module docstrings** in `scanner/aggregate.py`,
  `scanner/orchestrator.py`, `scanner/safety.py`, etc. carry detailed
  implementation notes. Read them; they explain *why* the code is the
  way it is.
- The **HTML report** itself (`report.html`) is self-documenting — hover
  tooltips and the "Filter" UI explain what each metric means.
- The **example files** under `examples/` (`scope.yaml.example`,
  `baseline.yaml.example`, `Makefile.consumer`) are runnable templates
  with inline comments.
