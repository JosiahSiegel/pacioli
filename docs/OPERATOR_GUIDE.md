# Pacioli — Operator Guide

> **Read [Consuming Pacioli](CONSUMING_GUIDE.md) first** if you are
> setting up the scanner in a Terraform repo for the first time. This
> guide assumes that setup is already done and you have a working
> `pci_scope.yaml`, `pci_baseline.yaml`, and `pci_mapping.yaml` in your
> consumer repo.

## What Pacioli is

A read-only compliance scanner for Azure Terraform code. Built on top
of [Checkov](https://github.com/bridgecrewio/checkov), but with a
focused purpose: produce a single, audit-ready HTML report that maps
every Checkov finding to a specific clause in a compliance framework
(PCI DSS v4.0.1 by default; SOC 2, CIS Azure, NIST 800-53, ISO 27001
via custom mapping packs).

The scanner is **read-only against Azure**. The only Azure mutation
is adding the runner's public IP to a storage-account firewall
(so `terraform plan` can read remote state); the IP is removed
automatically on exit. See [Safety Model](SAFETY_MODEL.md) for the
complete invariant.

## Quick start

```bash
# Install dependencies
pip install -r scanner/requirements-pinned.txt
brew install jq   # or apt-get install jq

# Source-only scan — fastest, no Azure calls, no init, no plan
bash scanner/scan.sh --mode report

# Open the report
open .checkov/<run-id>/aggregate/report.html
```

For a single project + env:

```bash
bash scanner/scan.sh --mode report --project myapp --env prod
```

## Three scan tiers

| Tier | Command | What it does | When to use |
|---|---|---|---|
| 1. Source | `scan.sh --mode report` | Static `.tf` parse. Runs Checkov's `terraform` + `secrets` framework + the custom `CKV_AZURE_PCI_*` checks. **Seconds.** No init, no plan, no storage. | Pre-commit, day-to-day CI, fast feedback. |
| 2. Plan | `scan.sh --mode report --scan-plan` | Adds `terraform init` + `terraform plan -out=tfplan.binary` so Checkov can inspect *resolved* values (catches things the source can't see, like CMK buried in a module output). | Monthly deep reviews, audit prep. |
| 3. State | `scan.sh --mode report --scan-state` | Adds `.tfstate` blob download from Azure Storage and emits a `drift_report.json` comparing source plan vs state plan. Catches `ignore_changes` drift. | Triage drift incidents, after manual Azure changes. |

Tier 1 is the right default. Tier 2/3 cost minutes per env (provider
download + state refresh + storage firewall IP) and require the runner
to be authenticated to Azure.

## CI gate

```bash
# CI gate. Exits non-zero on HIGH/CRITICAL findings. Use in PR checks.
scan.sh --mode gate
```

`--mode gate` does **not** auto-aggregate. CI ingests the per-env SARIF
artifacts directly. For human runs and audit prep, prefer
`--mode report` (the default), which runs `aggregate.py` at the end
and prints the `report.html` path.

The full argument list is in [CLI Reference](CLI_REFERENCE.md).

## Where do scan outputs live?

Run dirs are auto-named from the scan scope so past runs are easy to
find. The UTC calendar date is always suffixed for chronological
ordering:

| Command | Run dir name (example) |
|---|---|
| `scan.sh --mode report` (no filter) | `all-prod-2026-08-06/` |
| `scan.sh --mode report --env prod` | `all-prod-2026-08-06/` |
| `scan.sh --mode report --project myapp` | `myapp-prod-2026-08-06/` |
| `scan.sh --mode report --project myapp --env prod` | `myapp-prod-2026-08-06/` |

Re-running the same scope the same day auto-appends `-HHMM`, then
`-2`, `-3`, etc. so previous reports are never overwritten.

### Tagging ad-hoc runs with `--label`

Use `--label <text>` to override the derived name. Useful for one-off
scans you want to find later:

```bash
# Memo-tag a pre-deploy check
bash scanner/scan.sh --mode report --label pre-deploy --project myapp --env prod
# -> .checkov/pre-deploy-2026-08-06/
```

The label is sanitized to `[A-Za-z0-9_.-]`. Illegal characters become
`-`; leading/trailing dashes and dots are stripped. An empty label
falls back to `x`.

### Finding past runs

```bash
# All runs today
ls .checkov/*-2026-08-06/

# All "redis" runs ever
ls .checkov/ | grep -i redis

# The 5 most recent runs (any scope)
ls -1t .checkov/ | head -5

# The 5 most recent "all-prod" bulk runs
ls -1dt .checkov/all-prod-* | head -5
```

## Run-dir layout

After a successful scan, the run dir contains:

```
.checkov/<run_id>/
  .scope_pairs.tsv                # Tab-separated (project TAB env) pairs scanned
  .whitelist_ip                  # IP added to the storage firewall (tier 2/3 only)
  <project>/<env>/
    results_terraform_source.sarif   # Tier 1 (always, for source-layer)
    results_paac.sarif                # Custom PCI checks (always)
    results_secrets.sarif             # Hardcoded-secret scan (always)
    results_terraform_plan.sarif      # Tier 2/3 only
    results_state.sarif               # Tier 3 only
    drift_report.json                 # Tier 3 only
  aggregate/                     # Only present in --mode report after aggregation
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

1. **Source scan** (`--framework terraform`, tier 1+)
   - Static parse of `.tf` files. No init, no plan, no Azure mutation.
   - Output: `<env>/results_terraform_source.sarif`.

2. **Custom policy-as-code** (`--framework terraform` with the
   custom checks in `scanner/checks/`, tier 1+)
   - Five custom checks: `CKV_AZURE_PCI_001..005`.
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
   - Requires storage firewall whitelist.
   - Output: `<env>/results_terraform_plan.sarif`.

5. **State-as-plan scan** (`--framework terraform_plan` on state JSON,
   tier 3 only)
   - Downloads the encrypted state blob from Azure Storage.
   - Converts to plan-JSON shape via `tfstate_to_plan.py`.
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
  resource_pattern: "azurerm_storage_account.EXAMPLE_NAME"
  justification: "REPLACE_ME: legacy storage; migration tracked in TICKET-123"
  compensating_control: "REPLACE_ME: WAF rule + private endpoint in transit"
  owner: "TEAM_EMAIL (e.g., security-team@example.org)"
  ticket_id: "TICKET-123"
  approved_by: "Approver Name"
  approved_on: "2026-01-15"
  expires_on: "2027-01-15"
```

**Enforcement rules** (applied by `aggregate.py`):

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
  enable_https_traffic_only = false  # checkov:skip=CKV_AZURE_206:PR_OWNER=team:PR_EXPIRES=2027-01-01|justification="legacy migration"
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
bash scanner/scan.sh --mode report --label initial-baseline

# Re-emit a fix list (no re-scan; reads the existing aggregate)
python scanner/aggregate.py --run-dir .checkov/initial-baseline-2026-08-06 --emit-fix-list

# Bulk-generate stub baseline entries
bash scanner/scan_baseline_init.sh --run-dir .checkov/initial-baseline-2026-08-06
```

The baseline init script reads `combined.sarif` and emits stub entries
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
bash scanner/scan.sh --mode report --project myapp --env prod

# 2. Capture findings
RUN_DIR=$(ls -td .checkov/*/ | head -1)
python scanner/aggregate.py --run-dir "$RUN_DIR"

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
   `checkov -l 2>&1 | grep '^CKV(_2)?_AZURE_' | sort > /tmp/checkov-snapshot.txt`
   and diff against the prior quarter's snapshot. Any new rule id
   needs a row in `pci_mapping.yaml` and a severity entry in
   `SEVERITY_OVERRIDE` if the resource type is in scope.

## Cleaning up stale storage-firewall IPs

The scanner is supposed to remove the runner's public IP from the
storage firewall on exit. If a run was killed mid-flight (SIGKILL,
OOM kill, network partition), the IP may have been left behind.
Manual cleanup:

```bash
# List IPs on the firewall
az storage account network-rule list \
    --account-name "$PACIOLI_STATE_STORAGE_ACCOUNT" \
    --query "ipRules[].ipAddressOrRange" -o tsv

# Remove a specific IP
az storage account network-rule remove \
    --account-name "$PACIOLI_STATE_STORAGE_ACCOUNT" \
    --ip-address "<stale-ip>" --output none
```

The storage account name is set via `PACIOLI_STATE_STORAGE_ACCOUNT`
(default: `iacsa`).

## Adding a new project to scope

1. Edit `pci_scope.yaml` — copy an existing entry, change `project` to
   the new one, set `status: in_scope`, add the data-classification
   attestation (cite a ticket).
2. Run `bash scanner/scan.sh --mode report --project <new_proj> --env prod` to validate.
3. Verify against Azure Portal (Golden env workflow above).
4. Commit `pci_scope.yaml` as a PR titled "PCI scope: add <new_proj>".

### Status field semantics

| Status | Behavior |
|---|---|
| `in_scope` | Scanned on every run |
| `pending` | **Skipped** — data-classification attestation still owed. Set to `in_scope` after the ticket is closed |
| `excluded` | **Skipped** — not in PCI audit boundary (e.g. sandbox, no deployed resources) |

To temporarily remove a project from scans while keeping its
declaration (e.g. while remediating findings), set its status to
`pending` and reopen once it's clean. Do not set to `excluded` unless
the project is permanently out of audit scope.

## See also

- [Consuming Pacioli](CONSUMING_GUIDE.md) — first-time setup
- [Developer Guide](DEVELOPER_GUIDE.md) — adding checks and mappings
- [CLI Reference](CLI_REFERENCE.md) — every argument and env var
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
- [Safety Model](SAFETY_MODEL.md) — the read-only invariant
