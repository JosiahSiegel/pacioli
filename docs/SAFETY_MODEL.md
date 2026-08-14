# Pacioli Safety Model

> **The scanner is read-only against your cloud provider.** This document
> describes the controls that enforce that contract, the operations the
> scanner can run, and the limits of what those controls verify.

## Primary control: the typed operation registry

The primary safety control is the typed operation registry in
`scanner/ops.py`. Scanner code does not assemble arbitrary subprocess
commands. It selects a registered operation with a typed argument shape.
The registry owns the executable, fixed arguments, safety classification,
working directory, environment, and output handling for each operation.

The registry is the canonical subprocess entry point. New external commands
must be added there, with a narrow type and an explicit safety review. The
registry rejects operations that are not registered. `scanner/safety.py`
provides the refusal checks and `MutatingOperationRefused` error used by the
registry as defense in depth. A refusal is raised before the command runs and
causes the scanner to exit with code 99.

The refused command families include (the registry is currently
Azure-flavored because the state tier downloads the `.tfstate` blob
from Azure Storage; the structure is designed to be extended for other
providers as those tiers land):

- Terraform apply, destroy, import, state mutation, taint, and untaint.
- Terraform plans that disable locking when the operation is not the
  privileged read-only composition described below.
- Any command using `-auto-approve`.
- Cloud-provider resource, group, role-assignment, Key Vault, SQL,
  App Service, and storage-account deletion or update operations. The
  shipped refusal matrix is Azure (`az …`); equivalent AWS / GCP /
  Kubernetes providers will be added in the same shape when their
  state tiers ship.
- Checkov `--fix`.

The exact patterns and reasons live in `scanner/safety.py`; the typed
registry in `scanner/ops.py` is the control callers must use.

## Firewall behavior is alert-only

The scanner does not change cloud-provider storage firewall rules. It
never adds or removes network rules as part of a scan.

When a tier that needs remote state cannot access the configured storage
account, the scanner emits an access-required alert and skips the dependent
layer. Operators must arrange access outside the scanner, using their normal
network and identity controls. The scanner does not whitelist an IP, wait for
firewall propagation, or remove a rule during cleanup.

The alert has this shape:

```text
ACCESS REQUIRED: <operation> cannot reach <resource>.
  Required access: <access requirement>.
  Action: grant access outside Pacioli, then rerun the scan.
  No firewall changes were made by Pacioli.
```

The exact operation and resource are filled in at runtime. Treat this as an
operator action, not as evidence that access was granted or that the scan
covered the skipped layer.

## Privileged Terraform composition

Plan-tier execution uses a deliberately constrained Terraform composition:

```text
terraform init -backend=false
terraform plan -lock=false -refresh=false
```

`init -backend=false` prevents backend initialization. The plan uses
`-lock=false` because no backend lock is acquired, and `-refresh=false` so
Terraform does not refresh remote objects while producing the plan. This
composition is a privileged exception in the operation registry. It is not a
request to run arbitrary Terraform commands.

This plan is **not offline**. `terraform init` still contacts
`registry.terraform.io` to resolve providers and modules unless resolution is
constrained. The constraint mechanism is the `--registry-mirror` CLI flag,
which points resolution at an approved mirror, together with an isolated
`TF_CLI_CONFIG_FILE` containing the corresponding Terraform CLI
configuration. A mirror can reduce or block external registry access, but
operators must verify the network boundary and mirror contents themselves.

Because `refresh=false` prevents live refresh, the plan describes Terraform's
configured inputs and locally available state, not a current guarantee about
the cloud provider. The scanner reports when this layer cannot run rather than turning an
incomplete plan into a complete result.

## Discovery scope

Discovery is not limited to one hard-coded directory layout. Consumer scope
configuration can declare additional roots with `scan_paths:` in
`.pacioli/scope.yaml`. The CLI also accepts repeated `--scan-path` and
`--scan-glob` flags for explicit runs.

Use these mechanisms to identify the Terraform files that should be scanned:

```yaml
scan_paths:
  - env/platform
  - modules/shared
```

```bash
pacioli scan --scan-path env/platform --scan-glob 'services/*'
```

The scanner still reports only what it discovers under the supplied paths.
A path that is omitted, unreadable, or excluded by the configured glob is not
covered by the resulting report.

## Verified cleanup and data minimization

The lifecycle performs **verified cleanup**, not shredding. Temporary plan
and state material is removed with the `safe_unlink()` helper when the run
completes or receives a handled termination signal. Cleanup is best-effort
and intended to minimize retained data. It is not a cryptographic erase
claim.

Cleanup does not run after `SIGKILL`, process failure before registration, a
host crash, or storage outside the run directory. Operators should use normal
filesystem controls and retention policies for any remaining artifacts.

## No universal safety guarantee

There is no universal safety guarantee. Every claim in this document is
scoped to what the scanner can actually verify through its typed operation
registry, refusal checks, configured discovery paths, and cleanup code.
SSD behavior, copy-on-write storage, journaling, VM snapshots, and Windows
filesystem semantics are not covered by the cleanup claim. The scanner also
cannot prove that an external caller, credential, Terraform process, or
cloud-provider administrator will not make a change outside the scanner.

## Self-test and extension rules

`scanner/safety.py` exposes `safety_selftest()`, which is run by:

```bash
make selftest
```

The self-test checks representative refused and allowed command shapes. When
changing the registry or refusal rules:

1. Add or update the typed operation in `scanner/ops.py`.
2. Keep arguments narrow and reject unregistered operations.
3. Add a refusal or allowance case to the safety self-test as appropriate.
4. Confirm that the operation uses the constrained Terraform composition if
   it is a plan operation.
5. Run `make selftest` and the relevant test suite.
6. Document any residual risk in this file and in the change review.

Do not add a cloud-provider firewall mutation as an exception. Access failures must
remain alert-only.

## Worked examples

These examples condense common scan situations into ten representative
cases. They describe the boundary of the scanner, not a promise that every
case is safe or complete.

1. **Source-only repository scan.** `pacioli scan` reads the detected IaC
   source, runs source checks, and makes no privileged provider calls.
   Terraform source-tier and CloudFormation / Kubernetes / Bicep scans
   all fall in this bucket.
2. **Plan scan with local resolution.** A plan-tier run uses
   `terraform init -backend=false`, then
   `terraform plan -lock=false -refresh=false`. Provider and module
   resolution may still contact the registry unless a mirror is configured.
3. **Plan scan with a registry mirror.** The operator supplies
   `--registry-mirror` and an isolated `TF_CLI_CONFIG_FILE`. The scanner
   constrains resolution, but the operator remains responsible for validating
   the mirror and network boundary.
4. **Remote state access denied.** The state storage account rejects the
   request. Pacioli emits `ACCESS REQUIRED`, makes no firewall change, and
   skips the affected state-dependent layer.
5. **Multiple Terraform roots.** `scan_paths:` names several roots in
   `.pacioli/scope.yaml`, or the operator supplies repeated `--scan-path` flags.
   The report covers only the discovered roots.
6. **Glob-selected services.** `--scan-glob 'services/*'` selects matching
   directories. Unmatched directories are outside that run's coverage.
7. **Attempted apply.** A request to run `terraform apply` is rejected by the
   registry and safety guard before execution.
8. **Attempted Checkov fix.** A Checkov command containing `--fix` is refused;
   Pacioli reports the refusal rather than modifying source files.
9. **Normal completion cleanup.** Temporary plan or state files are removed
   through `safe_unlink()`, with best-effort data minimization and verification
   of the intended path.
10. **Interrupted or failed host.** Handled termination attempts cleanup,
    but `SIGKILL`, a host crash, snapshots, journaling, and other external
    retention mechanisms remain outside the scanner's guarantee.

## See also

- [Operator Guide](OPERATOR_GUIDE.md)
- [Architecture](ARCHITECTURE.md)
- [Developer Guide](DEVELOPER_GUIDE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
