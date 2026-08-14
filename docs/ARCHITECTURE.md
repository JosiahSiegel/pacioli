# Pacioli Architecture

This document describes the internal structure of the Pacioli scanner and
identifies the files to read when changing a subsystem.

If you are running scans, see [Operator Guide](OPERATOR_GUIDE.md). If you are
extending the scanner, see [Developer Guide](DEVELOPER_GUIDE.md).

## Bird's-eye view

```text
Consumer Terraform repo
  .pacioli/scope.yaml, .pacioli/baseline.yaml, env/<project>/<env>/*.tf
          |
          v
Pacioli
  scanner/cli.py              CLI entry point
  scanner/orchestrator.py     per-scope driver
  scanner/ops.py              typed operation registry, canonical subprocess entry point
  scanner/safety.py           refusal rules and safety self-test
  scanner/trap.py             verified cleanup and data minimization
  scanner/aggregate.py        SARIF to HTML, CSV, and JUnit
          |
          v
~/.pacioli/runs/current/<run-id>/
  per-environment SARIF files, drift data, aggregate/report.html
```

## Layered design

### Layer 0, typed operations and safety

`scanner/ops.py` is the primary control for external commands. Each command
is a registered, typed operation with fixed executable and argument handling.
Callers must use the registry rather than assembling arbitrary subprocess
commands. Unregistered operations are rejected.

`scanner/safety.py` supplies defense in depth. Its refusal rules reject
Terraform mutations, `-auto-approve`, Azure resource mutations, and Checkov
`--fix` before execution. See [Safety Model](SAFETY_MODEL.md).

### Layer 1, orchestration

`scanner/orchestrator.py` parses scope, discovers paths, coordinates each
project and environment, and records SARIF output. Discovery supports
`scan_paths:` in `.pacioli/scope.yaml`, plus the `--scan-path` and `--scan-glob`
CLI flags.

Plan-tier execution uses the privileged read-only composition
`terraform init -backend=false` followed by
`terraform plan -lock=false -refresh=false`. This is not offline. Provider
and module resolution can contact `registry.terraform.io`. Use
`--registry-mirror` with an isolated `TF_CLI_CONFIG_FILE` to constrain that
resolution.

If a protected input is unavailable, the orchestrator emits an `ACCESS
REQUIRED` alert and skips the dependent layer. It does not mutate Azure
firewall rules.

### Layer 2, scan layers

The driver runs source, custom policy, secrets, plan, and state layers as
configured. Each layer writes a canonical SARIF file. State data is converted
for analysis, then temporary material is removed with `safe_unlink()`.
Cleanup is verified on the intended paths and is best-effort data
minimization, not a cryptographic erase claim.

### Layer 3, aggregation

`scanner/aggregate.py` joins SARIF findings with mapping, severity, baseline,
and suppression data. It writes coverage matrices, coverage gaps, combined
SARIF, JUnit, and the static HTML report.

### Layer 4, post-scan tools

`pacioli audit` re-emits a prior report from the reports archive.
`pacioli baseline init` reads combined SARIF and emits baseline stubs for
operator triage.

## File-by-file index

| File | Purpose |
|---|---|
| `scanner/cli.py` | CLI entry point and flags |
| `scanner/ops.py` | Typed operation registry and subprocess boundary |
| `scanner/orchestrator.py` | Scope discovery and scan driver |
| `scanner/aggregate.py` | SARIF to HTML, CSV, and JUnit |
| `scanner/safety.py` | Refusal rules and safety self-test |
| `scanner/trap.py` | Verified cleanup and data minimization |
| `scanner/tfstate_to_plan.py` | State to plan-shaped data |
| `scanner/drift_report.py` | Plan versus state comparison |
| `scanner/checks/*.py` | Custom policy checks |
| `scanner/tests/*.py` | Test suite |
| `mappings/*.yaml` | Framework mappings |

## Limits of the model

There is no universal safety guarantee. Claims are limited to what the
registry, refusal checks, configured discovery paths, and cleanup code can
verify. SSD behavior, copy-on-write, journaling, VM snapshots, Windows
filesystem semantics, external processes, and Azure administrators are
outside that verification boundary.

## See also

- [Operator Guide](OPERATOR_GUIDE.md)
- [Developer Guide](DEVELOPER_GUIDE.md)
- [Safety Model](SAFETY_MODEL.md)
- [CLI Reference](CLI_REFERENCE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
