# Pacioli — Consuming Guide

> **First-time setup for adding Pacioli to an IaC repo.** If you
> already have a working `.pacioli/scope.yaml` and `.pacioli/baseline.yaml`
> and are just running scans, you want [Operator Guide](OPERATOR_GUIDE.md)
> instead.

This guide walks through, end to end, what you need to do to start
scanning your IaC code with Pacioli. The worked example uses Terraform
+ Azure (the primary shipped mapping pack, `pci_dss_4.0.1.yaml`),
but the same flow applies to every framework listed in
[Mapping Schema → Supported frameworks](MAPPING_SCHEMA.md#supported-frameworks).

## Quick start

```bash
# Install (Python 3.13+)
pip install https://github.com/JosiahSiegel/pacioli/releases/download/vX.Y.Z/pacioli-X.Y.Z-py3-none-any.whl

# Scan a Terraform repo — report opens in your default browser
pacioli scan /path/to/tf-repo

# Save the report inside the scanned repo
pacioli scan /path/to/tf-repo --output-dir /path/to/tf-repo
# Report lands at /path/to/tf-repo/aggregate/report.html

# Suppress the auto-open (CI, scripts, headless)
pacioli scan /path/to/tf-repo --no-open
```

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
2. **Python 3.13+**.
3. **`jq`** (used for JSON queries).
4. **Azure CLI** (`az`) — only for tier 2 and tier 3 scans (where
   `terraform plan` or `.tfstate` download is required). The
   scanner also requires the consumer to set
   `PACIOLI_STATE_STORAGE_ACCOUNT` and (for audit mode)
   `PACIOLI_REPORTS_CONTAINER` in the environment; there are no
   tenant-agnostic defaults.
5. **A copy of Pacioli** — install the recommended release wheel:
   ```bash
   pip install https://github.com/JosiahSiegel/pacioli/releases/download/vX.Y.Z/pacioli-X.Y.Z-py3-none-any.whl
   ```
   For local development, you can instead clone Pacioli and run
   `make install` from the checkout.

## Step 1: install the scanner

### Recommended: from a GitHub Release

```bash
pip install https://github.com/JosiahSiegel/pacioli/releases/download/vX.Y.Z/pacioli-X.Y.Z-py3-none-any.whl
```

Replace `vX.Y.Z` and `X.Y.Z` with the desired release tag (e.g. `v0.1.0`, `0.1.0`).

### Development: from a clone (dev only)

For local development against this checkout:

```bash
cd pacioli
make install
```

### Future: from PyPI

```bash
pip install pacioli
```

Pacioli is not yet published to PyPI — see [Developer Guide →
Releasing](DEVELOPER_GUIDE.md#releasing) for the release plan.

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

`.pacioli/scope.yaml` declares **scan scope**, the version-controlled PCI audit
boundary. For `projects:` entries, the scanner walks
`env/<project>/<env>/` only when both the project and environment are
`in_scope`.

Instead of copying the example file by hand, run `pacioli scan --init`
from the repo root. The CLI auto-discovers your IaC projects and
environments and populates both `.pacioli/scope.yaml` and
`.pacioli/baseline.yaml` atomically:

```bash
pacioli scan --init .
```

Output:

```
INFO  created /path/to/repo/.pacioli/scope.yaml
INFO  created /path/to/repo/.pacioli/baseline.yaml
```

The generated `.pacioli/scope.yaml` includes one `project:` entry per
discovered stack, with every `envs:` set to `in_scope` by default. The
generated `.pacioli/baseline.yaml` starts with an empty `suppressions: []`
list plus a comment header documenting the schema and discovery
coverage. Existing files are never overwritten; if either already
exists, the bootstrap is skipped silently. **Note:** the bootstrap
regenerates with everything `in_scope` — curated `pending`/`excluded`
statuses from a previous file are **not** carried over and must be
re-marked after the bootstrap.

If you prefer to start from the curated example template instead of an
auto-discovered manifest:

```bash
mkdir -p .pacioli
cp ../pacioli/examples/scope.yaml.example ./.pacioli/scope.yaml
```

> **Breaking change:** legacy scalar environment names are rejected. Migrate
> each `envs:` item from `- prod` to `- name: prod` with its own `status:`.
> Wrap a legacy top-level project list in `projects:` and add a `status:` to
> every project. The parser rejects a manifest that does not use this
> structured schema.

Edit `.pacioli/scope.yaml` for your project names:

```yaml
projects:
  - project: myapp
    description: My application infrastructure
    status: in_scope
    envs:
      - name: prod
        status: in_scope
      - name: staging
        status: pending
        reason: Data-classification attestation is awaiting Security approval.
  - project: sandbox
    status: excluded
    reason: Sandbox is outside the PCI audit boundary.
    envs:
      - name: dev
        status: in_scope
```

### Scope schema and status semantics

The root accepts only `projects:` and `scan_paths:` and requires at least one
non-empty list. A project record permits only `project` (non-blank string),
optional `description` (string), `status`, optional `reason` (string), and
`envs` (list). Each environment record permits only `name` (non-blank string),
`status`, and optional `reason` (string). `status` must be `in_scope`,
`pending`, or `excluded`; `reason` is required and non-blank for `pending` and
`excluded`.

A `scan_paths:`-only manifest is also valid. Each item requires a non-blank
`path` string and may include non-blank string `project`, `env`, `backend_key`,
`workspace`, and `stack_label` values. Omitted `project` defaults to `default`;
omitted `env` defaults to the basename of `path`. `stack_label` is required to
disambiguate colliding `(project, env)` paths.

Project status gates every environment beneath it: a project marked `pending`
or `excluded` overrides an environment otherwise marked `in_scope`. Environment
status controls only that named environment when its project is `in_scope`.

| Status | Behavior |
|---|---|
| `in_scope` | Scanned on every run when both project and environment are `in_scope`. |
| `pending` | Never scanned; use while an attestation or approval is outstanding. |
| `excluded` | Never scanned; use for a workload outside the PCI audit boundary. |

`pending` and `excluded` projects or environments are omitted at scan time
and never enter a newly generated report. For your initial setup, make every
intended scan pair `in_scope`; retain pending or excluded declarations with
reasons so the audit boundary remains explicit in Git.

For temporary browser triage after a full scan, use the report's **Hide
environments** checkboxes. That separate **report view** is a client-side
report-view-only exclusion: it recomputes what is shown without changing scan
scope or generated files. SARIF, CSV, and JUnit evidence remains unchanged as
full-scan evidence. The report defaults to Dark and persists the chosen Dark,
Light, or System theme locally in the browser. See
[Report Format](REPORT_FORMAT.md#report-view-theme-and-evidence-boundaries).

## Step 3: create the baseline file (initially empty)

`.pacioli/baseline.yaml` lists per-finding suppressions. Initially it
should be an empty list — you populate it after the first scan.

If you used `pacioli scan --init` in Step 2, this file already exists
at `.pacioli/baseline.yaml` with an empty `suppressions: []` list and a
comment header. Skip to the **Headless / CI** section.

If you copied the example file by hand instead:

```bash
mkdir -p .pacioli
cp ../pacioli/examples/baseline.yaml.example ./.pacioli/baseline.yaml
```

Edit it down to:

```yaml
# PCI baseline — repo-wide suppressions for known/accepted findings.
# See docs/OPERATOR_GUIDE.md for the schema and triage workflow.
# Initially empty. After the first scan, run:
#   pacioli baseline init <run_dir>
# to generate stub entries for triage.
suppressions: []
```

You do NOT need to add any entries before the first scan. The
aggregator handles the empty-list case. After the first scan completes,
run `pacioli baseline init <run-dir>` against that run directory to
seed stub suppression entries for triage.

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
report: ~/.pacioli/runs/myapp-prod-2026-08-06/aggregate/report.html
```

Open the report in a browser:

```bash
open ~/.pacioli/runs/myapp-prod-2026-08-06/aggregate/report.html
```

## Step 6: triage the findings

1. Open the **Findings** route in the report.
2. Click each HIGH/CRITICAL finding:
   - Click the **file:line** link to jump to the `.tf` line.
   - Read the in-line remediation HCL block.
   - Either fix the `.tf` (preferred), add a `.pacioli/baseline.yaml`
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
`~/.pacioli/runs/<run-id>/<project>/<env>/*.sarif`; your CI runner should
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
    --file "~/.pacioli/runs/<run-id>/aggregate/report.html"
```

With this archive in place, anyone with read access to the
container can re-emit a prior report at any time using the Pacioli
archive command described in [CLI Reference](CLI_REFERENCE.md).

`PACIOLI_REPORTS_CONTAINER` must be set explicitly for archive/audit
operations; there is no tenant-agnostic default.

## Step 9: commit your config

Commit `.pacioli/scope.yaml`, `.pacioli/baseline.yaml`, and the CI wiring to
your Terraform repo. If you also use the legacy wrapper, commit
`Makefile.pacioli` (or the merged `Makefile` targets). Run outputs
live under `~/.pacioli/runs/` (outside the repo), so nothing in your
target repo needs to be gitignored.

```bash
git add .pacioli/scope.yaml .pacioli/baseline.yaml .gitignore
git commit -m "feat: add pacioli PCI compliance scanning"
```

## What to do when…

### A new project joins the audit boundary

1. Add the project as a structured `projects:` record with `status: in_scope`.
2. Add each scan-ready environment as `{name: <env>, status: in_scope}`.
3. Run the scan against the new project alone.
4. Triage findings.
5. Commit the scope change as a PR titled "PCI scope: add
   <project>".

### A project leaves the audit boundary

Set its project `status` to `excluded` (permanent) or `pending` (temporary)
and add the required reason. Do not delete the entry — the audit trail is in
Git.

### A new env is created for an existing in-scope project

Add a structured environment record under its `envs:` list. Give it
`status: in_scope` when ready to scan, or `pending`/`excluded` with a reason
when it must not enter the audit boundary. No PR title convention is required.

### A finding is reported as a false positive

Verify in the Azure Portal. If it really is wrong:

- File a bug at <https://github.com/bridgecrewio/checkov/issues>
  (Pacioli is downstream of Checkov and inherits all Checkov bugs).
- If you can patch it in the local copy, add an entry to
  `.pacioli/baseline.yaml` with the evidence (Azure Portal screenshot
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
