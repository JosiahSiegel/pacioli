# Pacioli — Consuming Guide

> **First-time setup for adding Pacioli to a Terraform repo.** If you
> already have a working `pci_scope.yaml` and `pci_baseline.yaml` and
> are just running scans, you want [Operator Guide](OPERATOR_GUIDE.md)
> instead.

This guide walks through, end to end, what you need to do to start
scanning your Terraform code with Pacioli.

## Quick start

From any Terraform repository, run the installed CLI against the repository:

```bash
pacioli scan .
```

To scan a specific project and environment:

```bash
pacioli scan . --project myapp --env prod
```

The command writes the report to `.checkov/<run-id>/aggregate/report.html`.
Open that file in a browser when the scan completes. See [CLI Reference](CLI_REFERENCE.md)
for all scan modes and options.

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
3. **`jq`** (used for JSON queries).
4. **Azure CLI** (`az`) — only for tier 2 and tier 3 scans (where
   `terraform plan` or `.tfstate` download is required). The
   scanner also requires the consumer to set
   `PACIOLI_STATE_STORAGE_ACCOUNT` and (for audit mode)
   `PACIOLI_REPORTS_CONTAINER` in the environment; there are no
   tenant-agnostic defaults.
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

## Step 2: create the scope file

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

## Step 3: create the baseline file (initially empty)

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
#   pacioli scan-baseline-init RUN_DIR=.checkov/<run_id>
# to generate stub entries for triage.
suppressions: []
```

You do NOT need to add any entries before the first scan. The
aggregator handles the empty-list case.

## Headless / CI

Use non-interactive mode in automation. `PACIOLI_MAPPING` selects a
mapping pack without prompting:

```bash
PACIOLI_MAPPING=/path/to/mapping.yaml \
  pacioli scan /path/to/terraform-repo --non-interactive
```

The equivalent environment-variable form is useful when a CI job
cannot add the flag to its command:

```bash
PACIOLI_MAPPING=/path/to/mapping.yaml \
PACIOLI_NON_INTERACTIVE=1 \
  pacioli scan /path/to/terraform-repo
```

For a PR gate, add `--mode gate`; the command exits non-zero on
HIGH/CRITICAL findings:

```bash
PACIOLI_MAPPING=/path/to/mapping.yaml \
  pacioli scan /path/to/terraform-repo --non-interactive --mode gate
```

## Step 4: configure Azure (only for tier 2/3 scans)

Tier 1 (source-only) needs nothing beyond Checkov. Tier 2 (plan)
and tier 3 (state) need Azure authentication.

```bash
# Log in
az login

# Confirm you can see the storage account
az storage account show --name "$PACIOLI_STATE_STORAGE_ACCOUNT"
```

Set `PACIOLI_STATE_STORAGE_ACCOUNT` in your shell or CI secret:

```bash
export PACIOLI_STATE_STORAGE_ACCOUNT=mystorageaccount
```

The storage account must contain a `iac` container with the
`.tfstate` blobs named `CR_<env-prefix>_<project>.tfstate` (e.g.
`CR_Prod_myapp.tfstate`). If yours are named differently, configure
the corresponding state key mapping in Pacioli (see
[CLI Reference](CLI_REFERENCE.md)).

## Step 5: run your first scan

Tier 1 (no Azure calls):

```bash
pacioli scan . --project myapp --env prod
```

You should see output ending in:

```
report: .checkov/myapp-prod-2026-08-06/aggregate/report.html
```

Open the report in a browser:

```bash
open .checkov/myapp-prod-2026-08-06/aggregate/report.html
```

## Step 6: triage the findings

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

## Step 7: wire into CI

In your CI pipeline (Azure DevOps, GitHub Actions, etc.), add a job
that runs:

```yaml
# GitHub Actions snippet
- name: Pacioli PCI scan (gate)
  run: |
    PACIOLI_MAPPING=${{ github.workspace }}/../pacioli/mappings/pci_dss_4.0.1.yaml \
      pacioli scan "${{ github.workspace }}" --non-interactive --mode gate \
      --project myapp --env prod
```

Or for the standard Azure DevOps pipeline:

```yaml
# azure-pipelines.yml snippet
- task: Bash@3
  inputs:
    targetType: 'inline'
    script: |
      pacioli scan "$(Build.SourcesDirectory)" --non-interactive --mode gate \
        --project $(PROJECT) --env $(ENV)
  displayName: 'Pacioli PCI gate'
```

The `--mode gate` option exits non-zero on HIGH/CRITICAL findings.
SARIF artifacts are emitted per env under
`.checkov/<run-id>/<project>/<env>/*.sarif`; your CI runner should
upload these as build artifacts for the security team to ingest.

## Step 8: set up the pacioli-reports archive (optional but recommended)

For audit prep and historical record, set up a second Azure storage
container called `pacioli-reports`. After each scan, the aggregator's
output (`coverage_matrix.csv`, `combined.sarif`, `junit.xml`,
`report.html`) should be uploaded to
`pacioli-reports/<run-id>/` in that container.

This is usually a separate pipeline step:

```bash
# After pacioli completes, upload aggregate
az storage blob upload \
    --account-name "$PACIOLI_STATE_STORAGE_ACCOUNT" \
    --container-name pacioli-reports \
    --name "<run-id>/report.html" \
    --file ".checkov/<run-id>/aggregate/report.html"
```

With this archive in place, anyone with read access to the
container can re-emit a prior report at any time using the Pacioli
archive command described in [CLI Reference](CLI_REFERENCE.md).

`PACIOLI_REPORTS_CONTAINER` must be set explicitly for archive/audit
operations; there is no tenant-agnostic default.

## Step 9: commit your config

Commit `pci_scope.yaml`, `pci_baseline.yaml`, and the CI wiring to
your Terraform repo. If you also use the legacy wrapper, commit
`Makefile.pacioli` (or the merged `Makefile` targets). Do NOT commit
the `.checkov/` directory — it's already in the standard `.gitignore`
patterns.

```bash
git add pci_scope.yaml pci_baseline.yaml .gitignore
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

## Appendix: legacy consumer wrapper

The copy-Makefile workflow remains available for repositories that
need a checked-in wrapper. Copy `examples/Makefile.consumer` from the
Pacioli checkout as `Makefile.pacioli`, then set `PACIOLI_DIR` to the
checkout location (default `../pacioli`):

```bash
cp ../pacioli/examples/Makefile.consumer ./Makefile.pacioli
make -f Makefile.pacioli scan PACIOLI_DIR=/opt/pacioli PROJECT=myapp ENV=prod
```

You may keep `Makefile.pacioli` separate or merge its targets into an
existing `Makefile`. The wrapper delegates to the `pacioli` CLI; use
`pacioli scan` directly for new integrations.
