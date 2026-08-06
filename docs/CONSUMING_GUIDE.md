# Pacioli — Consuming Guide

> **First-time setup for adding Pacioli to a Terraform repo.** If you
> already have a working `pci_scope.yaml` and `pci_baseline.yaml` and
> are just running scans, you want [Operator Guide](OPERATOR_GUIDE.md)
> instead.

This guide walks through, end to end, what you need to do to start
scanning your Terraform code with Pacioli.

## What you need

1. **A Terraform repo** with this layout (or close to it):
   ```
   your-terraform-repo/
   ├── env/
   │   ├── projectA/
   │   │   ├── prod/
   │   │   │   ├── main.tf
   │   │   │   ├── variables.tf
   │   │   │   └── ...
   │   │   └── staging/
   │   │       └── ...
   │   └── projectB/
   │       └── prod/
   │           └── ...
   ├── modules/
   │   └── ...
   ```
2. **Python 3.12+**.
3. **`jq`** (used by `scan.sh` for JSON queries).
4. **Azure CLI** (`az`) — only for tier 2 and tier 3 scans (where
   `terraform plan` or `.tfstate` download is required).
5. **A copy of Pacioli** — either:
   - As a sibling directory: `git clone https://github.com/ORG/pacioli.git ../pacioli`, or
   - As a git submodule: `git submodule add https://github.com/ORG/pacioli.git`, or
   - As a `pip install` (not yet published to PyPI — see [Developer
     Guide → Releasing](DEVELOPER_GUIDE.md#releasing) for the
     release plan).

## Step 1: install the scanner

If you cloned the repo:

```bash
cd pacioli
make install
```

This installs:

- `checkov==3.3.9` (pinned)
- `pyyaml` (>= 6.0, < 7.0)
- `requests` (>= 2.28, < 3.0)
- `jmespath` (>= 1.0)
- `pytest` (test-only)
- `pyyaml` (test-only — already in the runtime set)

Verify:

```bash
checkov --version
# 3.3.9
```

## Step 2: create the wrapper Makefile

Copy `examples/Makefile.consumer` to your Terraform repo as
`Makefile.pacioli`. The Makefile is the operator-facing entry point
for the scanner.

```bash
# In your Terraform repo
cp ../pacioli/examples/Makefile.consumer ./Makefile.pacioli
```

Update the `PACIOLI_DIR` variable to point at where you cloned
Pacioli:

```makefile
PACIOLI_DIR ?= ../pacioli
```

If you have a different layout, you can override `PACIOLI_DIR` on
the command line:

```bash
make -f Makefile.pacioli scan PACIOLI_DIR=/opt/pacioli
```

You can either keep `Makefile.pacioli` separate (and call it with
`-f Makefile.pacioli`) or merge its targets into your existing
`Makefile`.

## Step 3: create the scope file

`pci_scope.yaml` declares which `(project, env)` pairs are in PCI
audit scope. The scanner walks every entry under
`env/<project>/<env>/`.

```bash
cp ../pacioli/examples/scope.yaml.example ./pci_scope.yaml
```

Edit `pci_scope.yaml` for your project names:

```yaml
- project: myapp
  description: My application infrastructure
  envs:
    - prod
    - staging
- project: myapp-data
  description: Data layer for myapp
  envs:
    - prod
```

### Status field

Each project entry has a `status` field with three values:

| Status | Behavior |
|---|---|
| `in_scope` | Scanned on every run |
| `pending` | Skipped (data-classification attestation outstanding) |
| `excluded` | Skipped (not in PCI audit boundary) |

For your initial setup, set every project you want scanned to
`in_scope`. Use `pending` if you're staging a project for later
addition; use `excluded` only for permanent out-of-scope items
like a sandbox.

## Step 4: create the baseline file (initially empty)

`pci_baseline.yaml` lists per-finding suppressions. Initially it
should be an empty list — you populate it after the first scan.

```bash
cp ../pacioli/examples/baseline.yaml.example ./pci_baseline.yaml
```

Edit it down to:

```yaml
# PCI baseline — repo-wide suppressions for known/accepted findings.
# See docs/OPERATOR_GUIDE.md for the schema and triage workflow.
# Initially empty. After the first scan, run:
#   make -f Makefile.pacioli scan-baseline-init RUN_DIR=.checkov/<run_id>
# to generate stub entries for triage.
suppressions: []
```

You do NOT need to add any entries before the first scan. The
aggregator handles the empty-list case.

## Step 5: configure Azure (only for tier 2/3 scans)

Tier 1 (source-only) needs nothing beyond Checkov. Tier 2 (plan)
and tier 3 (state) need Azure authentication.

```bash
# Log in
az login

# Confirm you can see the storage account
az storage account show --name "$PACIOLI_STATE_STORAGE_ACCOUNT"
```

Set `PACIOLI_STATE_STORAGE_ACCOUNT` in your shell or in the
Makefile:

```bash
export PACIOLI_STATE_STORAGE_ACCOUNT=mystorageaccount
```

The storage account must contain a `iac` container with the
`.tfstate` blobs named `CR_<env-prefix>_<project>.tfstate` (e.g.
`CR_Prod_myapp.tfstate`). If yours are named differently, edit
the `backend_key` derivation in `scan.sh` (search for
`CR_$(echo "${env}"` — the prefix is built from the env name).

## Step 6: run your first scan

Tier 1 (no Azure calls):

```bash
make -f Makefile.pacioli scan PROJECT=myapp ENV=prod
```

You should see output ending in:

```
report: .checkov/myapp-prod-2026-08-06/aggregate/report.html
```

Open the report in a browser:

```bash
open .checkov/myapp-prod-2026-08-06/aggregate/report.html
```

## Step 7: triage the findings

1. Open the **Findings** route in the report.
2. Click each HIGH/CRITICAL finding:
   - Click the **file:line** link to jump to the `.tf` line.
   - Read the in-line remediation HCL block.
   - Either fix the `.tf` (preferred), add a `pci_baseline.yaml`
     entry (accepted risk with an owner and ticket), or use an
     inline `# checkov:skip=` comment (one-off).
3. Re-run the scan to confirm the finding is gone.

For accepted-risk findings, see the
[baseline schema in Operator Guide](OPERATOR_GUIDE.md#baseline-entry-schema).

## Step 8: wire into CI

In your CI pipeline (Azure DevOps, GitHub Actions, etc.), add a job
that runs:

```yaml
# GitHub Actions snippet
- name: Pacioli PCI scan (gate)
  run: |
    PACIOLI_DIR=${{ github.workspace }}/../pacioli
    make -f Makefile.pacioli scan-gate PROJECT=myapp ENV=prod
```

Or for the standard Azure DevOps pipeline:

```yaml
# azure-pipelines.yml snippet
- task: Bash@3
  inputs:
    targetType: 'inline'
    script: |
      make -f Makefile.pacioli scan-gate PROJECT=$(PROJECT) ENV=$(ENV)
  displayName: 'Pacioli PCI gate'
```

The `scan-gate` target calls `scan.sh --mode gate`, which exits
non-zero on HIGH/CRITICAL findings. SARIF artifacts are emitted per
env under `.checkov/<run-id>/<project>/<env>/*.sarif`; your CI
runner should upload these as build artifacts for the security team
to ingest.

## Step 9: set up the iac-reports archive (optional but recommended)

For audit prep and historical record, set up a second Azure
storage container called `iac-reports`. After each scan, the
aggregator's output (`coverage_matrix.csv`, `combined.sarif`,
`junit.xml`, `report.html`) should be uploaded to
`iac-reports/<run-id>/` in that container.

This is usually a separate pipeline step:

```bash
# After scan.sh completes, upload aggregate
az storage blob upload \
    --account-name "$PACIOLI_STATE_STORAGE_ACCOUNT" \
    --container-name iac-reports \
    --name "<run-id>/report.html" \
    --file ".checkov/<run-id>/aggregate/report.html"
```

With this archive in place, anyone with read access to the
container can re-emit a prior report at any time using
`scan_audit.sh --latest` or `scan_audit.sh --run-id <run-id>`.

## Step 10: commit your config

Commit `pci_scope.yaml`, `pci_baseline.yaml`, `Makefile.pacioli`
(or the merged `Makefile` targets), and the CI wiring to your
Terraform repo. Do NOT commit the `.checkov/` directory — it's
already in the standard `.gitignore` patterns.

```bash
git add pci_scope.yaml pci_baseline.yaml Makefile.pacioli .gitignore
git commit -m "feat: add pacioli PCI compliance scanning"
```

## What to do when…

### A new project joins the audit boundary

1. Add the project to `pci_scope.yaml` with `status: in_scope`.
2. Run the scan against the new project alone.
3. Triage findings.
4. Commit the scope change as a PR titled "PCI scope: add
   <project>".

### A project leaves the audit boundary

Set its `status` to `excluded` (permanent) or `pending` (temporary).
Do not delete the entry — the audit trail is in git.

### A new env is created for an existing in-scope project

Add the new env to the existing `envs:` list under that project.
No PR title convention is required.

### A finding is reported as a false positive

Verify in the Azure Portal. If it really is wrong:

- File a bug at <https://github.com/bridgecrewio/checkov/issues>
  (Pacioli is downstream of Checkov and inherits all Checkov bugs).
- If you can patch it in the local copy, add an entry to
  `pci_baseline.yaml` with the evidence (Azure Portal screenshot
  URL or ticket ID) in `justification`.

### A new Checkov version ships

Coordinate with the Pacioli maintainers (file an issue or watch the
release notes) for the mapping refresh PR. Do not bump the pin
in your local copy unilaterally — the mapping YAML must be
re-validated as a single coordinated change.

## See also

- [Operator Guide](OPERATOR_GUIDE.md) — full runbook
- [Architecture](ARCHITECTURE.md) — how it all fits together
- [CLI Reference](CLI_REFERENCE.md) — every argument
- [Report Format](REPORT_FORMAT.md) — every output file
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
