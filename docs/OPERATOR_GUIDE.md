# Pacioli — Operator Guide

> **Read [Consuming Pacioli](CONSUMING_GUIDE.md) first** if you are
> setting up the scanner in an IaC repo for the first time. This
> guide assumes that setup is already done and you have a working
> `pci_scope.yaml`, `pci_baseline.yaml`, and `pci_mapping.yaml` in your
> consumer repo.

## What Pacioli is

A read-only compliance scanner for any Checkov-supported IaC framework.
Built on top of [Checkov](https://github.com/bridgecrewio/checkov),
but with a focused purpose: produce a single, audit-ready HTML report
that maps every Checkov finding to a specific clause in a compliance
framework (the shipped `mappings/pci_dss_4.0.1.yaml` pack is the
primary worked example; SOC 2, CIS, NIST 800-53, ISO 27001 ship via
custom mapping packs — see
[Mapping Schema → Supported frameworks](MAPPING_SCHEMA.md#supported-frameworks)
for the authoritative framework list).

The scanner is **read-only against your cloud provider**. It does not
change storage firewall rules. If a tier needs access that is
unavailable, Pacioli emits an `ACCESS REQUIRED` alert and skips the
dependent layer. Arrange access outside Pacioli, then rerun the scan.
See [Safety Model](SAFETY_MODEL.md) for the complete invariant.

## Quick start

```bash
# Install dependencies
pip install -r scanner/requirements-pinned.txt

# Source-only scan — fastest, no Azure calls, no init, no plan
pacioli scan

# Open the report
open ~/.pacioli/runs/<run-id>/aggregate/report.html
```

For a single project + env:

```bash
pacioli scan --project myapp --env prod
```

## Three scan tiers

| Tier | Command | What it does | When to use | Framework scope |
|---|---|---|---|---|
| 1. Source | `pacioli scan` | Static parse of the detected IaC source. Runs Checkov's `terraform` + `secrets` framework + the custom `CKV_AZURE_PCI_*` checks for Terraform packs (other frameworks get the equivalent Checkov framework). **Seconds.** No init, no plan, no storage. | Pre-commit, day-to-day CI, fast feedback. | Any Checkov framework. |
| 2. Plan | `pacioli scan --tier plan` | Adds `terraform init` + `terraform plan -out=tfplan.binary` so Checkov can inspect *resolved* values (catches things the source can't see, like CMK buried in a module output). | Monthly deep reviews, audit prep. | **Terraform-family only.** Rejected for non-Terraform frameworks. |
| 3. State | `pacioli scan --tier state` | Adds `.tfstate` blob download from Azure Storage and emits a `drift_report.json` comparing source plan vs state plan. Catches `ignore_changes` drift. | Triage drift incidents, after manual Azure changes. | **Terraform-family only.** Rejected for non-Terraform frameworks. |

Tier 1 is the right default. Tier 2/3 may contact the Terraform registry
for provider and module resolution, and require the runner to have the
configured access needed for their inputs. Plan-tier execution uses
`terraform init -backend=false` and `terraform plan -lock=false -refresh=false`;
it is not offline. Use `--registry-mirror` with an isolated
`TF_CLI_CONFIG_FILE` when registry resolution must be constrained.

## CI gate

```bash
# CI gate. Exits non-zero on HIGH/CRITICAL findings. Use in PR checks.
pacioli gate
```

`pacioli gate` does **not** auto-aggregate. CI ingests the per-env SARIF
artifacts directly. For human runs and audit prep, prefer
`pacioli scan` (the default), which runs the aggregator at the end
and prints the `report.html` path.

The full argument list is in [CLI Reference](CLI_REFERENCE.md).

## Where do scan outputs live?

Run dirs are auto-named from the scan scope so past runs are easy to
find. The UTC calendar date is always suffixed for chronological
ordering. The default run-dir root is `~/.pacioli/runs/current/`
(overridable with `--output-dir`); individual run dirs are timestamped
subdirectories under it.

| Command | Run dir name (example) |
|---|---|
| `pacioli scan` (no filter) | `all-prod-2026-08-06/` |
| `pacioli scan --env prod` | `all-prod-2026-08-06/` |
| `pacioli scan --project myapp` | `myapp-prod-2026-08-06/` |
| `pacioli scan --project myapp --env prod` | `myapp-prod-2026-08-06/` |

Re-running the same scope the same day auto-appends `-HHMM`, then
`-2`, `-3`, etc. so previous reports are never overwritten.

### Tagging ad-hoc runs with `--label`

Use `--label <text>` to override the derived name. Useful for one-off
scans you want to find later:

```bash
# Memo-tag a pre-deploy check
pacioli scan --label pre-deploy --project myapp --env prod
# -> ~/.pacioli/runs/current/pre-deploy-2026-08-06/
```

The label is sanitized to `[A-Za-z0-9_.-]`. Illegal characters become
`-`; leading/trailing dashes and dots are stripped. An empty label
falls back to `x`.

### Finding past runs

```bash
# All runs today
ls ~/.pacioli/runs/current/*-2026-08-06/

# All "redis" runs ever
ls ~/.pacioli/runs/ | grep -i redis

# The 5 most recent runs (any scope)
ls -1t ~/.pacioli/runs/current/ | head -5

# The 5 most recent "all-prod" bulk runs
ls -1dt ~/.pacioli/runs/current/all-prod-* | head -5
```

## Run-dir layout

After a successful scan, the run dir contains:

```
~/.pacioli/runs/current/<run_id>/
  .scope_pairs.tsv                # Tab-separated (project TAB env) pairs scanned
  <project>/<env>/
    results_terraform_source.sarif   # Tier 1 (always, for source-layer)
    results_paac.sarif                # Custom PCI checks (always)
    results_secrets.sarif             # Hardcoded-secret scan (always)
    results_terraform_plan.sarif      # Tier 2/3 only
    results_state.sarif               # Tier 3 only
    drift_report.json                 # Tier 3 only
  aggregate/                     # Only present after aggregation
    coverage_matrix.csv
    coverage_gaps.csv
    combined.sarif
    junit.xml
    report.html
    fix_list.md                    # Only if --emit-fix-list was passed
```

See [Report Format](REPORT_FORMAT.md) for the schema of every file.

## Coverage gaps — `NO CHECKS FIRED` triage

A row in `coverage_matrix.csv` (or in the HTML report) marked
`NO CHECKS FIRED` or `not_applicable` means: of the check_ids mapped to
that PCI requirement in your `pci_mapping.yaml`, **none produced a
SARIF finding in this run**. There are three possible causes:

| Cause | How it happens | How to verify | How to remediate |
|---|---|---|---|
| **Stale check id** | `pci_mapping.yaml` lists a `CKV_AZURE_<n>` that no longer exists in this Checkov version (renumbered, removed, or in a different framework). The aggregator's `triage_hint` column flags this with "likely stale check id". | `checkov --list \| grep <id>` — if the id is missing, it's stale. | Replace the stale id in `pci_mapping.yaml` with the current correct id, or remove the row if no longer applicable. Bump `verified_against` and commit. |
| **No relevant resource of that type exists** in any scanned env | The Azure resource the check targets is not deployed in any of the scanned envs. Checkov SARIF omits rules that ran without findings, so absence from SARIF looks identical to "rule didn't run." | `grep -r "<resource_type>" env/<project>/<env>/*.tf` or `checkov -d env/<project>/<env> --check <id> --framework terraform` directly. | Usually correct as-is. Document in the `note:` field of the mapping entry if useful. |
| **Rule ran and produced no findings** (passed) | The relevant resource is deployed AND the rule ran. Checkov SARIF simply doesn't emit "passed" results. | Same direct invocation as above; expect 0 findings and a `Passed checks: N` line in Checkov's output. | None — already compliant. |

### Triage workflow

1. Open `coverage_gaps.csv` from the latest run dir.
2. For each row with `missing_count > 0`:
   - Run `checkov --list | grep <each missing check_id>`.
   - If the id is gone → stale; fix `pci_mapping.yaml`.
   - If the id exists → re-check whether the rule applies to any resource in the scanned envs.
3. Document the outcome in the `note:` field of `pci_mapping.yaml` if non-obvious.
4. Re-run the scan; `coverage_gaps.csv` should now show the resolved ids in `fired_count` instead of `missing_count`.

### Don't claim compliance based on `NO CHECKS FIRED`

A PCI req with status `NO CHECKS FIRED` and a non-empty
`missing_count` has **not been verified**. Treat it as
"unverified — needs operator review" until the triage above is
complete. Compliance evidence should be the SARIF findings (compliant
or non_compliant) or an explicit out-of-scope approval, NOT a
"no findings" stat.

## What the scanner checks — five layers

Each layer produces its own SARIF file; the aggregator walks all five
(and the `ruleIndex` map joins them).

1. **Source scan** (`--framework terraform` for the shipped pack;
   other Checkov frameworks are equally supported — see
   [Mapping Schema → Supported frameworks](MAPPING_SCHEMA.md#supported-frameworks)
   for the authoritative list, tier 1+)
   - Static parse of `.tf` files (or the matching source type for
     the chosen framework). No init, no plan, no provider mutation.
   - Output: `<env>/results_<framework>_source.sarif`.

2. **Custom policy-as-code** (`--framework terraform` with the
   custom checks in `scanner/checks/`, tier 1+)
   - Five custom checks: `CKV_AZURE_PCI_001..005`. The PaaC layer
     currently targets Terraform-family frameworks because the
     shipped custom checks are Terraform-shaped; non-Terraform
     packs rely on Checkov's built-in rules instead.
   - Catches patterns the source plan misses (lifecycle ignore_changes,
     default-deny, TLS min, CMK, KV purge).
   - Output: `<env>/results_paac.sarif`.

3. **Secrets scan** (`--framework secrets`, tier 1+)
   - Hardcoded-secret / Gitleaks-equivalent pass on `.tf` source.
   - Output: `<env>/results_secrets.sarif`.

4. **Source-as-plan scan** (`--framework terraform_plan` on
   `terraform show -json` output, tier 2+)
   - Catches Azure-side configuration that diverges from `.tf` because
     the plan reflects the *next-apply* state, including
     `terraform refresh`-reimported values.
   - Does NOT catch `ignore_changes` drift (see layer 5).
    - Does not require Pacioli to change firewall rules.
   - Output: `<env>/results_terraform_plan.sarif`.

5. **State-as-plan scan** (`--framework terraform_plan` on state JSON,
   tier 3 only)
   - Downloads the encrypted state blob from Azure Storage.
   - Converts to plan-JSON shape via `scanner/tfstate_to_plan.py`.
   - Runs Checkov against the post-attribute, post-`ignore_changes`
     view.
   - Generates `drift_report.json` comparing source-plan vs state-plan
     attribute values — this is the `ignore_changes` drift signal.
   - Output: `<env>/results_state.sarif`, `<env>/drift_report.json`.

### Why five layers?

A `.tf` file is the source of *intent*. A plan JSON is the source of
*what Terraform will do next*. A state JSON is the source of *what was
last deployed* (refreshed from Azure). The custom-PaaC and secrets
layers add policy-specific coverage at the source-of-truth view.

The differences between these views reveal:

- **Source ≠ plan**: a `lifecycle.ignore_changes` block is in effect.
- **Source ≠ state**: someone edited the Azure resource out-of-band.
- **Plan ≠ state**: a `terraform refresh` would change the plan.
- **Source WITH paac PASS ≠ source WITHOUT paac**: a custom rule
  fires even though Checkov's built-in `CKV_AZURE_*` passed it.
- **Source WITH secrets PASS ≠ source WITHOUT secrets**: a hardcoded
  credential is in a Terraform variable or local.

The CSV coverage matrix maps all five views to PCI requirements.

## Triage workflow

When a new HIGH/CRITICAL finding appears:

1. **Identify** the env and resource from `report.html` (or the
   `fix_list.md` if you want a developer-friendly list — see
   [Report Format](REPORT_FORMAT.md)).
2. **Validate** in Azure Portal — confirm the resource actually has
   the flagged configuration (false positives are common; verify
   before remediating).
3. **Decide**:
   - **Fix it**: update the `.tf` and run `terraform plan` (NOT apply)
     against the env to verify the change is what Terraform will do.
     Then re-run the scan to confirm the finding is gone.
   - **Accept the risk**: add a baseline entry to `pci_baseline.yaml`
     with `owner`, `ticket_id`, `expires_on` populated.
   - **Suppress inline**: use
     `# checkov:skip=CKV_AZURE_xxx:PR_OWNER=team:PR_EXPIRES=2027-01-01|justification="..."`
     on the `.tf` line. The `PR_OWNER` and `PR_EXPIRES` keys are
     enforced by the aggregator (the same way baseline entries are).

### Baseline entry schema

```yaml
- check_id: CKV_AZURE_206
  resource_pattern: "azurerm_storage_account.<your-resource-name>"
  justification: "<reason this is accepted risk>"
  compensating_control: "<reference to the compensating control>"
  owner: "<team-or-person-email>"
  ticket_id: "<ticket-id>"
  approved_by: "<approver-name>"
  approved_on: "<YYYY-MM-DD>"
  expires_on: "<YYYY-MM-DD>"
```

**Enforcement rules** (applied by `scanner/aggregate.py`):

| Field | Rule |
|---|---|
| `owner` | Must NOT be `TBD` or empty (otherwise the finding is NOT suppressed) |
| `expires_on` | Must be ≥ today (otherwise the finding is NOT suppressed) |
| `resource_pattern` | fnmatch glob, e.g. `azurerm_storage_account.*` |

Expired entries fall off automatically; the team should re-baseline
quarterly.

### Inline skip format

For one-off, single-resource suppressions, use a comment on the `.tf`
line:

```hcl
resource "azurerm_storage_account" "example" {
  enable_https_traffic_only = false  # checkov:skip=CKV_AZURE_206:PR_OWNER=<team>:PR_EXPIRES=<YYYY-MM-DD>|justification="<reason>"
}
```

Format: `<reason>` with `PR_OWNER`, `PR_EXPIRES`, and `justification`
keys separated by `|`. Owner/expiry are enforced by the aggregator
(just like baseline entries).

## Out-of-scope entries in `pci_mapping.yaml`

`out_of_scope_requirements` lists PCI requirement families that the
IaC scanner cannot evaluate — runtime scanning, policy/process, or
vendor-managed physical access. **Each entry is a compliance assertion
that an auditor can read directly off the HTML/CSV report**, so every
field is REQUIRED and the aggregator refuses to emit a report when any
are missing.

See [Mapping Schema → Out-of-scope](MAPPING_SCHEMA.md#out-of-scope-requirements)
for the full schema and validation rules.

## Initial baseline generation

After the first scan across all envs:

```bash
# Run the scan
pacioli scan --label initial-baseline

# Re-emit a fix list (no re-scan; reads the existing aggregate)
pacioli aggregate ~/.pacioli/runs/current/initial-baseline-2026-08-06 --emit-fix-list

# Bulk-generate stub baseline entries
pacioli baseline init ~/.pacioli/runs/current/initial-baseline-2026-08-06
```

The baseline init command reads `combined.sarif` and emits stub entries
(TBD for owner/ticket/expires) for every finding. The team then:

1. Sorts entries by `hit_count` desc.
2. For the top 50, populates `justification`, `owner`, `ticket_id`,
   `expires_on`.
3. Removes entries that are real bugs (fix in `.tf` instead).
4. Commits the new `pci_baseline.yaml` as a PR titled "PCI baseline:
   triage <date>".

## Golden env verification

Before declaring the pipeline production-ready, verify the scanner's
output matches Azure reality for the canonical golden env:

```bash
# 1. Run scan
pacioli scan --project myapp --env prod

# 2. Capture findings
RUN_DIR=$(ls -td ~/.pacioli/runs/current/*/ | head -1)
pacioli aggregate "$RUN_DIR"

# 3. For each HIGH/CRITICAL finding, verify against Azure Portal:
#    - Go to the resource
#    - Confirm the configured attribute matches Checkov's claim
#    - Note the verification in the run log
```

## Severity calibration

`scanner/aggregate.py` has a `SEVERITY_OVERRIDE` dict that maps Checkov
check IDs to `HIGH`/`MEDIUM`/`LOW`. Checkov OSS does not populate SARIF
rule severity without a Prisma Cloud API key; this is the local source
of truth.

To extend:

```python
# in scanner/aggregate.py
SEVERITY_OVERRIDE = {
    "CKV_AZURE_999": "HIGH",  # new check
    ...
}
```

Or file a PR titled `severity: add <check_id>` and the maintainers will
add it.

## Quarterly review

Every 90 days:

1. **Re-verify Checkov rule output** — pin in
   `scanner/requirements-pinned.txt` is intentional. If you bump
   Checkov, every `pci_mapping.yaml` row needs re-validation; treat
   the bump as a major change requiring a dedicated PR.
2. **Re-verify PCI source links** — the `doc_anchor` in
   `pci_mapping.yaml` must remain live. Bump `verified_against` after
   a clean pass.
3. **Audit `pci_baseline.yaml` for stale / TBD** — every entry with
   `expires_on < today` is auto-dropped from suppression. Every entry
   with `owner: TBD` is silently dropped. The aggregator never credits
   an unsigned waiver; an unsigned waiver is not a waiver.
4. **Audit `pci_mapping.yaml` `out_of_scope_requirements` for stale**
   — same as step 3. STALE entries carry a red badge in the report
   and require explicit renewal or removal.
5. **Re-run golden env smoke test** — confirm the report output for
   the canonical env is stable.
6. **Review new Checkov rules** — run
   `checkov -l 2>&1 | grep '^CKV' | sort > /tmp/checkov-snapshot.txt`
   and diff against the prior quarter's snapshot. The grep is
   intentionally cloud-agnostic (`^CKV` instead of the old
   `^CKV(_2)?_AZURE_`); the scanner ships one pack per framework
   family today, but the snapshot diff must cover every prefix
   (`CKV_AWS_*`, `CKV_AZURE_*`, `CKV_GCP_*`, `CKV_K8S_*`,
   `CKV2_*`, etc.). Any new rule id needs a row in the matching
   mapping pack and a `severity_overrides` entry if the resource
   type is in scope.

## Adding a new project to scope

`pci_scope.yaml` defines **scan scope**: the version-controlled PCI audit
boundary applied when Pacioli scans. It uses structured-only `envs` records.
This is a **breaking change** from legacy manifests: a scalar environment such
as `- prod` is rejected. Migrate every scalar item to `- name: prod` plus its
`status`, wrap legacy top-level project records beneath `projects:`, and add a
`status` to every project.

A `projects:` root admits only project records with `project` (non-blank
string), optional `description` (string), `status`, optional `reason`
(string), and `envs` (list). Each `envs` item admits only `name` (non-blank
string), `status`, and optional `reason` (string). Status is exactly
`in_scope`, `pending`, or `excluded`; `pending` and `excluded` require a
non-blank reason. The only other root key is `scan_paths:`. A scan-path item
requires `path` and may use `project`, `env`, `backend_key`, `workspace`, and
`stack_label`; omitted project/env values default to `default` and the path
basename respectively. Use `stack_label` to disambiguate duplicate
`(project, env)` scan paths.

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

1. Copy a structured project entry, change `project`, set `status: in_scope`,
   and add the data-classification attestation (cite a ticket).
2. Add each environment as a structured record and set its scan status.
3. Run `pacioli scan --project <new_proj> --env prod` to validate.
4. Verify against Azure Portal (Golden env workflow above).
5. Commit `pci_scope.yaml` as a PR titled "PCI scope: add <new_proj>".

### Status field semantics

A project status gates every environment underneath it. A `pending` or
`excluded` project overrides an otherwise `in_scope` environment. An
environment's status applies only to that environment when its project is
`in_scope`.

| Status | Behavior |
|---|---|
| `in_scope` | Scanned only when both the project and environment are `in_scope`. |
| `pending` | **Never scanned** — data-classification attestation or approval is still owed. Set to `in_scope` after the ticket is closed. |
| `excluded` | **Never scanned** — not in the PCI audit boundary (for example, a sandbox with no deployed resources). |

Pending and excluded environments are omitted at scan time and never enter a
newly generated report. To temporarily remove a project or a single
environment from scans while keeping its declaration, set the relevant status
to `pending` and record the reason. Use `excluded` only when that declared
audit target is permanently out of scope.

### Scan scope versus report view

`pci_scope.yaml` statuses are scan-scope decisions: they are permanent until
changed in version control and determine whether an environment is scanned at
all. They are not browser controls.

The static HTML report also offers a **report view** control, **Hide
environments**. It is a client-side report-view-only exclusion for temporary
triage: it hides selected environments and recomputes every report view from
the remaining full-scan data. Clear the checkbox or use **Full-report reset**
to restore the full report view.

A report view must not be used to redefine compliance scope. Its browser-local
preference neither omits an environment at scan time nor changes generated
scan artifacts: SARIF, CSV, and JUnit evidence remains unchanged as full-scan
evidence. See [Report Format](REPORT_FORMAT.md#report-view-theme-and-evidence-boundaries)
for the UI, theme, and empty-filter behavior.

## See also

- [Consuming Pacioli](CONSUMING_GUIDE.md) — first-time setup
- [Developer Guide](DEVELOPER_GUIDE.md) — adding checks and mappings
- [CLI Reference](CLI_REFERENCE.md) — every argument and env var
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
- [Safety Model](SAFETY_MODEL.md) — the read-only invariant
