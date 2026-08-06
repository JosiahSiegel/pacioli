# PCI Scanner Runbook

## What this is

A read-only Checkov-based scanner for PCI DSS v4.0.1 compliance on `env/`
Terraform code. It produces SARIF, JUnit, HTML, and a CSV coverage matrix
mapping Checkov findings to PCI requirements.

The scanner is **read-only against Azure**. The only Azure mutation is the
storage firewall IP whitelist, paired with a cleanup trap. See
`.scripts/checkov/lib/safety.sh` for the full list of forbidden commands.

## Quick start

```bash
# Scan all in-scope prod envs (default mode: report, never blocks)
make scan-pci-report

# Scan a single project
make scan-pci-report PROJECT=CR_PROJECT_NAME

# Scan a single env
make scan-pci-report PROJECT=CR_PROJECT_NAME ENV=prod

# Source-only scan (default, Tier 1). No terraform, no init, no Azure
# storage access, no IP whitelist. Fast (seconds per env). Right for
# pre-commit hooks and day-to-day CI.
make scan-pci-report PROJECT=CR_PROJECT_NAME ENV=prod

# Source + plan scan (Tier 2). Adds `terraform init` + `terraform plan`
# so Checkov can inspect resolved values. Auto-handles storage-firewall
# IP whitelist for the duration of the run.
make scan-pci-plan-report PROJECT=CR_PROJECT_NAME ENV=prod

# Source + plan + state-drift scan (Tier 3, top). Downloads the .tfstate
# blob from Azure Storage and emits a drift_report.{json,md} comparing
# source plan and state plan. Catches `ignore_changes` drift.
 make scan-pci-state-report PROJECT=CR_PROJECT_NAME ENV=prod

# CI gate mode (blocks on HIGH/CRITICAL findings). Same three tiers.
# Gate mode does NOT auto-aggregate — CI ingests SARIF artifacts directly.
make scan-pci PROJECT=CR_PROJECT_NAME ENV=prod
make scan-pci-plan PROJECT=CR_PROJECT_NAME ENV=prod
make scan-pci-state PROJECT=CR_PROJECT_NAME ENV=prod

# (Optional) Re-aggregate an existing run dir into a single report.
# The scan-pci-report variants above already do this automatically.
python .scripts/checkov/aggregate_pci.py --run-dir .checkov/<run_id>

# Self-test (safety + common helpers)
make scan-pci-selftest
```

**Auto-aggregation behavior:**
- `make scan-pci-report` / `scan-pci-plan-report` / `scan-pci-state-report`
  (all `--mode report`) run `aggregate_pci.py` automatically at the end and
  print the resulting `report.html` path.
- `make scan-pci` / `scan-pci-plan` / `scan-pci-state` (gate mode) **do not**
  aggregate — CI uploads the raw per-env SARIF artifacts directly.
- Pass `--no-aggregate` to the script (or use `scan-pci-report-raw`) to skip
  the end-of-run aggregation in report mode. Useful for CI artifact uploads
  where SARIF-only is wanted.

## Where do scan outputs live?

Run dirs are auto-named from what you're scanning so past runs are easy to
find. The UTC calendar date is always suffixed for chronological ordering:

| Command | Run dir name (example) |
|---|---|
| `make scan-pci-report` (no filter) | `all-prod-2026-08-05/` |
| `make scan-pci-report ENV=prod` | `all-prod-2026-08-05/` |
| `make scan-pci-report PROJECT=CR_PROJECT_NAME` | `CR_PROJECT_NAME-prod-2026-08-05/` |
| `make scan-pci-report PROJECT=CR_PROJECT_NAME ENV=prod` | `CR_PROJECT_NAME-prod-2026-08-05/` |

Re-running the same scope the same day auto-appends `-HHMM` (and a `-N`
counter if that minute is also taken) so previous reports are never
overwritten. The collision handler logic is in
`init_pretty_run_dir()` and `resolve_collision_free_dir()` in
`.scripts/checkov/lib/common.sh`.

### Tagging ad-hoc runs with `LABEL=`

Use `LABEL=<text>` (in Make) or `--label <text>` (in bash) to override
the derived name. Useful for one-off scans you want to find later:

```bash
# Memo-tag a pre-deploy check
make scan-pci-report PROJECT=CR_PROJECT_NAME ENV=prod LABEL=pre-deploy
# -> .checkov/pre-deploy-2026-08-05/

# Equivalent direct invocation
bash .scripts/checkov/scan_pci.sh --mode report \
    --label audit-q4 --project CR_PROJECT_NAME --env prod
# -> .checkov/audit-q4-2026-08-05/
```

The label is sanitized to `[A-Za-z0-9_.-]` (illegal chars → `-`, leading
and trailing dashes/dots stripped). An empty label (after sanitizing)
falls back to `x`. The UTC date is still suffixed, so labels stay
chronologically ordered even when reused.

### Finding past runs

```bash
# All runs today
ls .checkov/*-2026-08-05/

# All "redis" runs ever
ls .checkov/ | grep -i redis

# The 5 most recent runs (any scope)
ls -1t .checkov/ | head -5

# The 5 most recent "all-prod" bulk runs
ls -1dt .checkov/all-prod-* | head -5
```

## Tier comparison

| Tier | Trigger | Network calls | Speed | Catches |
|---|---|---|---|---|
| 1 | `scan-pci-report` (default) | **None** (after checkov install) | Seconds/env | Static .tf violations, custom PCI patterns, hardcoded secrets |
| 2 | `scan-pci-plan-report` `--scan-plan` | terraform init + plan = provider download + remote state refresh + storage firewall IP | Minutes/env (first run) | + resolved values like CMK on encryption-bearing resources |
| 3 | `scan-pci-state-report` `--scan-state` | All of tier 2 + state blob download | Minutes/env | + `ignore_changes` drift |

**Use tier 1 by default.** Use tier 2 for monthly deep reviews. Use tier 3
when triaging drift incidents.

## Outputs

After a scan + aggregate, find the report at:

```
.checkov/<run_id>/<project>/<env>/
  results_terraform_source.sarif  # tier 1 (always)
  results_paac.sarif               # custom policy-as-code (always)
  results_secrets.sarif            # hardcoded-secret scan (always)
  results_terraform_plan.sarif     # tier 2/3 only
  results_state.sarif              # tier 3 only
  drift_report.json                # tier 3 only (ignore_changes drift)

.checkov/<run_id>/aggregate/
  coverage_matrix.csv             # PCI requirement x check_id x status;
                                    # in-scope rows carry missing_for_req;
                                    # out-of-scope rows carry full audit metadata
  coverage_gaps.csv                # one row per PCI req: expected_count,
                                    # fired_count, missing_count, missing_check_ids,
                                    # triage_hint. Start here when triaging
                                    # "NO CHECKS FIRED" status.
  combined.sarif                   # all 5 SARIFs merged (with run properties)
  junit.xml                        # one testcase per finding, FAIL = HIGH/CRITICAL
  report.html                      # human-readable single-page report with
                                    # tooltip on NO CHECKS FIRED rows and a
                                     # dedicated Coverage-gaps section
```

## Coverage gaps — `NO CHECKS FIRED` triage

A row in `coverage_matrix.csv` (or in the HTML report) marked `NO CHECKS
FIRED` or `not_applicable` means: of the check_ids mapped to that PCI
requirement in `pci_mapping.yaml`, **none produced a SARIF finding in
this run**. There are three possible causes, each with a different
remediation:

| Cause | How it happens | How to verify | How to remediate |
|---|---|---|---|
| **Stale check id** | `pci_mapping.yaml` lists a `CKV_AZURE_<n>` that no longer exists in this Checkov version (renumbered, removed, or in a different framework). The aggregator's `triage_hint` column flags this with "likely stale check id". | `checkov --list \| grep <id>` — if the id is missing, it's stale. | Replace the stale id in `pci_mapping.yaml` with the current correct id, or remove the row if no longer applicable. Bump `verified_against` and commit. |
| **No relevant resource of that type exists** in any scanned env | The Azure resource the check targets (e.g. App Service plan, storage account CMK config) is not deployed in any of the 10 prod envs. Checkov SARIF omits rules that ran without findings, so absence from SARIF looks identical to "rule didn't run." | grep the in-scope env dirs for the resource type, or run `checkov -d <env> --check <id> --framework terraform` directly against one env. If no resource exists, the rule has nothing to evaluate. | Usually correct as-is. Document in `pci_mapping.yaml` `notes:` field if useful, or add a baseline stub via `make scan-pci-baseline-init`. |
| **Rule ran and produced no findings** (passed) | The relevant resource is deployed AND the rule ran. Checkov SARIF simply doesn't emit "passed" results. | Same direct invocation as above; expect 0 findings and a "Passed checks: N" line in Checkov's output. | None — already compliant. The `coverage_gaps.csv` entry will show `fired_count > 0` once Checkov starts emitting pass-records (e.g. in a future version). |

### Triage workflow

1. Open `coverage_gaps.csv` from the latest run dir.
2. For each row with `missing_count > 0`:
   - Run `checkov --list | grep <each missing check_id>`.
   - If the id is gone → stale, fix `pci_mapping.yaml`.
   - If the id exists → re-check whether the rule applies to any resource in the in-scope envs. Use `find env/<project>/<env> -name '*.tf' -exec grep <resource_type> {} \;` or run `checkov -d env/<project>/<env> --check <id> --framework terraform` directly.
3. Document the outcome in `pci_mapping.yaml` `notes:` field if non-obvious, so the next operator doesn't redo your work.
4. Re-run the scan; `coverage_gaps.csv` should now show the resolved ids in `fired_count` instead of `missing_count`.

### Don't claim compliance based on `NO CHECKS FIRED`

A PCI req with status `NO CHECKS FIRED` and a non-empty `missing_count`
has **not been verified**. Treat it as "unverified — needs operator
review" until the triage above is complete. Compliance evidence should
be the SARIF findings (compliant or non_compliant) or an explicit
out-of-scope approval, NOT a "no findings" stat.

## What the scanner checks

Five layers, in order. Each layer produces its own SARIF file; the
aggregator walks all five (and the ruleIndex map joins them).

1. **Source scan** (`--framework terraform`, tier 1+)
   - Static parse of `.tf` files. No init, no plan, no Azure mutation.
   - Default layer; runs in tier 1.
   - Output: `<env>/results_terraform_source.sarif`.

2. **Custom policy-as-code** (`--framework terraform` via custom
   checks, tier 1+)
   - Five custom checks under `.scripts/checkov/pci_checks/`:
     `CKV_AZURE_PCI_001..005`.
   - Catches patterns the source-plan run misses because the .tf
     declaration is independent of the resolved plan attributes.
   - Highest-impact: `CKV_AZURE_PCI_001` (`lifecycle_ignore_changes`)
     anchored to PCI 6.5.5 (changes to system components are managed).
   - Output: `<env>/results_paac.sarif`.

3. **Secrets scan** (`--framework secrets`, tier 1+)
   - Hardcoded-secret / Gitleaks-equivalent pass on .tf source.
   - Runs against the same files as layers 1 and 2.
   - Output: `<env>/results_secrets.sarif`.

4. **Source-as-plan scan** (`--framework terraform_plan` on plan JSON,
   tier 2+)
   - Generated by `terraform plan -out=tfplan.binary && terraform show -json`.
   - Catches Azure-side configuration that diverges from `.tf`
     because the plan reflects the *next-apply* state, including
     `terraform refresh`-reimported values.
   - Does NOT catch ignore_changes drift (see layer 5).
   - Requires `storage firewall whitelist` for the runner IP.
     `lib/safety.sh` registers an EXIT trap to drop the IP on
     completion.
   - Output: `<env>/results_terraform_plan.sarif`.

5. **State-as-plan scan** (`--framework terraform_plan` on state JSON,
   tier 3 only)
   - Downloads the encrypted state blob from Azure Storage
     (`az storage blob download` is the ONLY `* download` operation
     permitted by `lib/safety.sh`).
   - Converts to plan JSON shape via `tfstate_to_plan.py`.
   - Runs Checkov against the POST-attribute, post-`ignore_changes`
     view.
   - Generates `drift_report.json` comparing source-plan vs state-plan
     attribute values — this is the ignore_changes drift signal.
   - Output: `<env>/results_state.sarif`, `<env>/drift_report.json`.

### Why five layers?

A `.tf` file is the source of *intent*. A plan JSON is the source of
*what Terraform will do next*. A state JSON is the source of *what was
last deployed* (refreshed from Azure). The custom-Paac and secrets
layers add policy-specific coverage at the source-of-truth view.

The differences between these views reveal:

- **Source != plan**: a `lifecycle.ignore_changes` block is in effect.
- **Source != state**: someone edited the Azure resource out-of-band.
- **Plan != state**: a `terraform refresh` would change the plan.
- **Source WITH paac PASS != source WITHOUT paac**: a custom rule
  (e.g., drift on security-sensitive attrs) fires even though Checkov's
  built-in CKV_AZURE_* passed it.
- **Source WITH secrets PASS != source WITHOUT secrets**: a hardcoded
  credential is in a Terraform variable or local.

The CSV coverage matrix maps all five views to PCI requirements.

## Triage workflow

When a new HIGH/CRITICAL finding appears:

1. **Identify** the env and resource from `report.html`
2. **Validate** in Azure Portal — confirm the resource actually has the
   flagged configuration (false positives are common; verify before
   remediating)
3. **Decide**:
   - **Fix it**: update the `.tf` and run `terraform plan` (NOT apply)
     against the env to verify the change is what Terraform will do
   - **Accept the risk**: add a baseline entry to `pci_baseline.yaml`
     with `owner`, `ticket_id`, `expires_on` populated
   - **Suppress inline**: use `# checkov:skip=CKV_AZURE_xxx:...` if
     it's a one-off (see baseline schema below)

### Baseline entry schema

```yaml
- check_id: CKV_AZURE_206
  resource_pattern: "azurerm_storage_account.EXAMPLE_NAME"
  justification: "REPLACE_ME: legacy storage; migration tracked in TICKET-123"
  compensating_control: "REPLACE_ME: WAF rule + private endpoint in transit"
  owner: "TEAM_EMAIL (e.g., security-team@example.org)"
  ticket_id: "TICKET-123"
  expires_on: "2027-01-01"
```

**Enforcement rules** (applied by `aggregate_pci.py`):

| Field | Rule |
|---|---|
| `owner` | Must NOT be `TBD` or empty (otherwise finding is NOT suppressed) |
| `expires_on` | Must be ≥ today (otherwise finding is NOT suppressed) |
| `resource_pattern` | fnmatch glob, e.g. `azurerm_storage_account.*` |

Expired entries fall off automatically; the team should re-baseline
quarterly.

### OUT OF SCOPE entries in `pci_mapping.yaml`

`out_of_scope_requirements` lists PCI requirement families that the
IaC scanner cannot evaluate — runtime scanning, policy/process, or
vendor-managed physical access. **Each entry is a compliance assertion
that an auditor can read directly off the HTML/CSV report**, so every
field is REQUIRED and the aggregator refuses to emit a report when any
are missing.

#### Schema

| Field | Required | Format | Why |
|---|---|---|---|
| `id` | yes | e.g. `"11.x"` | Stable req-family ID |
| `title` | yes | free text | Requirement title from PCI doc |
| `rationale` | yes | free text | WHY IaC scanning can't evaluate this. Must say concretely — "process," "runtime," "vendor-managed," etc. — not a tautology like "out of scope." |
| `control_owner` | yes | team / role | Who owns the control OUTSIDE the scanner. Answerable question: "If not us, then who?" |
| `approved_by` | no | `"Name, Role"` (optional) | Optional historical record of who approved the exclusion; not required. |
| `approved_on` | yes | ISO `YYYY-MM-DD` | Date of approval |
| `expires_on` | yes | ISO `YYYY-MM-DD` | Auto-expiry. Aggregator renders a red `STALE (expired Nd ago)` badge once `expires_on < today`. |
| `evidence_link` | yes | resolvable URL or ticket ID | Where an auditor verifies external proof. NOT a placeholder like "tbd" or "to be defined." |

#### Example entry

```yaml
- id: "11.x"
  title: "Test security of systems and networks regularly"
  rationale: "PCI 11.x covers runtime vulnerability scanning (internal/external scans, ASV, penetration testing). IaC scanners cannot evaluate running-system posture, so we exclude this family and rely on the runtime controls listed under evidence_link."
  control_owner: "Security team — runtime scans"
  approved_on: "2026-08-01"
  expires_on: "2027-08-01"
  evidence_link: "https://www.pcisecuritystandards.org/document_library/"
```

#### What the report shows

In `coverage_matrix.csv`, the row for an out-of-scope entry has all nine
fields as columns (`title`, `rationale`, `control_owner`, etc.) plus
`stale` (`true`/`false`) and `days_to_expiry`. No need to read the YAML
to audit it.

In `report.html`, each out-of-scope row expands into a definition list
with clickable `evidence_link`. Stale entries show a red
`OUT OF SCOPE — STALE (expired Nd ago)` badge.

#### Validation

`aggregate_pci.py` performs these checks on every out-of-scope entry,
every run, in every mode:

1. Every required field present and non-empty
2. No field still equal to literal `"TBD"` (placeholder trap)
3. `approved_on` and `expires_on` parse as ISO YYYY-MM-DD
4. `approved_on <= expires_on` (illogical if reversed)
5. `expires_on >= today` — surfaces as the `STALE` badge but does NOT
   block the run (a stale exclusion is informational, not invalid)

A missing-required field, TBD placeholder, or invalid date REFUSES the
run with return code `2` BEFORE any artifact is written. The operator
cannot produce a partial compliance report.

> **Note on `TBD` semantics across files** — the OOS path above is
> strict-refusal. The `pci_baseline.yaml` path is silent-skip: a baseline
> entry with `owner: TBD` (or empty `owner`) is treated as if no entry
> existed for that `check_id` + `resource_pattern` pair, and the
> finding surfaces un-suppressed. This is intentional — the
> aggregator never credits an unsigned waiver — but operators frequently
> confuse the two paths and wonder why a `pci_baseline.yaml` row seems
> not to "take." The compliance-correct answer is: fill in the `owner`
> field. The audit-correct answer is: until the `owner` field is filled,
> the waiver is not effective and the finding remains REPORTED.

#### Renewing stale exclusions

When the `STALE` badge appears:

1. Review with the control owner whether the exclusion is still valid.
2. If yes: bump `expires_on` (audit has been re-confirmed). Commit
   with a justification line in the commit message linking to the
   approval ticket.
3. If no: REMOVE the entry from `out_of_scope_requirements` and add the
   relevant checks to `requirements` (if any now apply) or document in
   `pci_baseline.yaml` (per-finding waivers).

### Inline skip format

For one-off, single-resource suppressions, use a comment on the .tf line:

```hcl
resource "azurerm_storage_account" "example" {
  enable_https_traffic_only = false  # checkov:skip=CKV_AZURE_206:PR_OWNER=team:PR_EXPIRES=2027-01-01|justification="legacy migration"
}
```

Format: `<reason>` with `PR_OWNER`, `PR_EXPIRES`, and `justification` keys
separated by `|`. Owner/expiry are enforced by the aggregator.

## Initial baseline generation

After the first scan across all envs:

```bash
make scan-pci-report                 # produces .checkov/<run_id>/
python .scripts/checkov/aggregate_pci.py --run-dir .checkov/<run_id>/
bash .scripts/checkov/scan_pci_baseline_init.sh --run-dir .checkov/<run_id>/
```

The baseline init script reads `combined.sarif` and emits stub entries
(TBD for owner/ticket/expires) for every finding. The team then:

1. Sorts entries by `hit_count` desc
2. For the top 50, populates `justification`, `owner`, `ticket_id`, `expires_on`
3. Removes entries that are real bugs (fix in `.tf` instead)
4. Commits the new `pci_baseline.yaml` as a PR titled "PCI baseline: triage <date>"

## Golden Env verification

Before declaring the pipeline production-ready, verify the scanner's
output matches Azure reality for the canonical golden env:

```bash
# 1. Run scan
make scan-pci-report PROJECT=CR_PROJECT_NAME ENV=prod

# 2. Capture findings
RUN_DIR=$(ls -td .checkov/*/ | head -1)
python .scripts/checkov/aggregate_pci.py --run-dir "$RUN_DIR"

# 3. For each HIGH/CRITICAL finding, verify against Azure Portal:
#    - Go to the resource
#    - Confirm the configured attribute matches Checkov's claim
#    - Note the verification in this runbook under "Golden Env Verification"
```

Update the "Golden Env Verification" section below after each verification.

### Last verified

| Date | Env | Findings | Verified | False Positives | Notes |
|---|---|---|---|---|---|
| 2026-08-04 | CR_PROJECT_NAME/prod | 53 | 0 | – | Initial smoke test; verification in progress |

## Out-of-band Azure mutations

The scanner itself never mutates Azure. But `--scan-state` reads the
remote state blob. If you used another tool to modify the storage
firewall (e.g. `az storage account network-rule add`), it will accumulate
stale entries. Manual cleanup:

```bash
make scan-pci-cleanup
```

This walks `~/.cache/global-tf-checkov/` (the legacy cache) and the
`.checkov/` directory, removing any whitelisted IPs that were added by
prior runs.

## Adding a new project to PCI scope

1. Edit `pci_scope.yaml` — copy an existing entry, change `project` to
   the new one, set `status: in_scope`, add the data-classification
   attestation (cite a ticket / SEC-xxxx)
2. Run `make scan-pci-report PROJECT=<new_proj> ENV=prod` to validate
3. Verify against Azure Portal (Golden Env workflow above)
4. Commit `pci_scope.yaml` as a PR titled "PCI scope: add <new_proj>"

### Status field semantics

| Status | Behavior |
|---|---|
| `in_scope` | Scanned on every run |
| `pending` | **Skipped** — data-classification attestation still owed. Set to `in_scope` after the ticket is closed |
| `excluded` | **Skipped** — not in PCI audit boundary (e.g. sandbox, no deployed resources) |

To temporarily remove a project from scans while keeping its declaration
(e.g. while remediating findings), set its status to `pending` and reopen
once it's clean. Do not set to `excluded` unless the project is permanently
out of audit scope.

## Adding a new custom check

`.scripts/checkov/pci_checks/` is auto-loaded by Checkov via
`--external-checks-dir`. New checks must:

1. Use a file naming convention starting with an ID, e.g.
   `CKV_AZURE_PCI_006__tls13_required.py`
2. Define `metadata` (id, name, category, severity, description,
   guideline URL)
3. Define `scope` (resource_types list)
4. Define `check(entity)` returning a string (failure message) or None
5. Verify URL is `https://www.pcisecuritystandards.org/...` (v4.0.1)
6. Add a row to `pci_mapping.yaml` requirements mapping if the check
   maps to a specific PCI requirement

## Severity calibration

`aggregate_pci.py` has a `SEVERITY_OVERRIDE` table that maps Checkov
check IDs to HIGH/MEDIUM/LOW. Checkov OSS does not populate SARIF rule
severity without a Prisma Cloud API key; this is the local source of
truth. To extend:

```python
# in aggregate_pci.py
SEVERITY_OVERRIDE = {
    "CKV_AZURE_999": "HIGH",  # new check
    ...
}
```

Or add it to the override table at the top of the file.

## File layout

```
pci_scope.yaml                        # in-scope projects (edit, never auto-generated)
pci_mapping.yaml                      # PCI req -> check_id mapping (curated)
pci_baseline.yaml                     # accepted-risk suppressions (audit trail)
.devops/run_checkov_pci.yml           # Azure DevOps pipeline
modules/iac_reports/v1/               # iac-reports blob container (bicep + tf)
.scripts/checkov/
    lib/safety.sh                     # refuse-if-mutating guard
    lib/common.sh                     # paths, run-id, redact, trap
    scan_pci.sh                       # orchestrator
    aggregate_pci.py                  # SARIF -> CSV/HTML/JUnit/combined
    scan_pci_baseline_init.sh         # bulk-generate stub baseline entries
    tfstate_to_plan.py                # state.json -> plan.json shape
    drift_report.py                   # source-vs-state diff
    pci_checks/                       # custom policy-as-code (Python .py)
        CKV_AZURE_PCI_001__lifecycle_ignore_changes.py
        CKV_AZURE_PCI_002__storage_default_deny.py
        CKV_AZURE_PCI_003__tls_min_version.py
        CKV_AZURE_PCI_004__cmk_required.py
        CKV_AZURE_PCI_005__kv_purge_protection.py
docs/runbooks/pci-checkov.md         # this file
.checkov/                             # run artifacts (gitignored)
```

## Safety invariants

The scanner is **read-only** against Azure. The list of forbidden
commands is in `.scripts/checkov/lib/safety.sh`. The most important
refusals:

| Command | Reason |
|---|---|
| `terraform apply` / `destroy` | Mutates Azure |
| `terraform state rm` / `mv` / `import` | Mutates state |
| `terraform plan -lock=false` | Defeats drift detection |
| `az <resource> delete` / `group delete` | Mutates Azure |
| `checkov --fix` | Auto-remediation forbidden |

Pen-test/exception: the only allowed mutation is `az storage account
network-rule add/remove` for the storage firewall IP whitelist, and
`az storage blob download blob` for the state scan. Both are required
operations for scan functionality, both are read-only against user
data, and both are paired with cleanup.

## Quarterly review

Every 90 days, the security team should run the following cadence and
file a summary in `iac-reports/quarterly/<YYYY-QN>.md` (use the
`modules/iac_reports/v1` storage for archive). Each item is
defect-class driven (see `audit-grade-bundle.md` defects P2-03).

1. **Re-verify PCI source links** — open the latest `report.html`
   and confirm every `pci_source_url` row resolves to a
   `pcisecuritystandards.org` / `docs.pcisecuritystandards.org`
   document, every `azure_doc_url` resolves on Microsoft Learn with
   a Mozilla-style User-Agent, and every `evidence_url` is a live
   internal link. Spot-check 5 URLs per category with `curl -sIL`
   (use `User-Agent: Mozilla/5.0` for `learn.microsoft.com`). Bump
   `verified_against` in `pci_mapping.yaml` after a clean pass.
2. **Re-verify public PCI SSC anchor** — `curl -sIL
   https://listings.pcisecuritystandards.org/documents/PCI-DSS-v3-2-1-to-v4-0-Summary-of-Changes-r1.pdf`
   must still return `200 application/pdf`. If the URL has migrated,
   update `pci_scope.yaml` and `pci_mapping.yaml` `doc_anchor` field;
   record the new digest in the quarterly summary.
3. **Audit `pci_baseline.yaml` for STALE / TBD** — every entry with
   `expires_on < today` is automatically flagged as STALE in the
   `report.html` and must be either renewed (bump `expires_on`) or
   removed. Every entry with `owner: TBD` is silently dropped from
   suppression (see "Note on `TBD` semantics across files" above) —
   fix the `owner` field to actually take effect.
4. **Audit `pci_mapping.yaml` `out_of_scope_requirements` for STALE**
   — same as step 3 for OOS rows. Each must have every schema field
   non-empty, ISO-parseable dates, `approved_on <= expires_on`, and
   `expires_on >= today`. STALE entries are NOT auto-removed; they
   carry the `STALE` badge in the report and require explicit
   renewal or removal.
5. **Re-confirm entity_type and merchant_level** — confirm
   `pci_scope.yaml` `metadata.entity_type` and `merchant_level` still
   match the entity's current PCI registration. A change (e.g.,
   merchant merged with a service provider) requires a new entry on
   the OOS section for any req that depended on the prior
   classification (10.4.1.1 SP-only, etc.).
6. **Re-run Golden Env smoke test** — follow the "Golden Env
   verification" section above against `CR_PROJECT_NAME/prod` and
   confirm the report output is byte-identical to the prior
   quarter (modulo date stamps and `verified_against`).
7. **Review new Checkov rules** — run
   `checkov -l 2>&1 | grep '^CKV(_2)?_AZURE_' | sort > /tmp/checkov-3.3.9.txt`
   and diff against the prior quarter's snapshot
   (`iac-reports/quarterly/checkov-snapshots/3.3.9/<YYYY-QN>.txt`).
   Any new rule id (`+` lines) needs a row in `pci_mapping.yaml`
   and a severity entry in `SEVERITY_OVERRIDE` if the resource
   type is in scope.
8. **Re-validate the 5 custom PCI checks** — run
   `make scan-pci-selftest` and confirm the five
   `CKV_AZURE_PCI_001..005` checks still anchor correctly (see
   commit 5: 001→2.2.6, 002→1.3, 003→4.2.1, 004→3.5.1, 005→8.6.3).
   Any custom-check modification must update the chain-of-custody
   block in the docstring (see commit 6).
9. **Operator rotate** — refresh the role-appropriate approvers in
   `pci_mapping.yaml` `out_of_scope_requirements`. Use a single-
   approver per family and keep `control_owner` expressed as team /
   role only (no personal names). If `approved_by` is preserved for
   historical record, ensure the value still matches the live
   OrgChart.


## Chain of custody

Every URL surfaced in `report.html` is traceable back to a
source-of-truth artifact in the run directory
(`combined.sarif`, `coverage_matrix.csv`, `report.html`,
`<env>/results_*.sarif`). The auditor can re-derive any URL
from the run-dir files: out-of-scope rows carry `evidence_link`
in `coverage_matrix.csv`; in-scope findings carry the SARIF
`helpUri` and the per-rule `MS_LEARN_URL_BY_CHECK_ID` lookup
table embedded in `aggregate_pci.py`.

The PCI requirement citation (the row that points to the
standard itself) is always `pcisecuritystandards.org` /
`docs.pcisecuritystandards.org`. Internal links (Confluence,
ticket trackers, internal docs) are valid only as
`evidence_link` for an out-of-scope entry — they are NEVER
substituted for a PCI SSC citation.

## Emitting a developer-friendly fix list

`report.html` is designed for auditors and security reviewers.
When the goal is to actually fix the findings, that surface is
noisy: per-finding color coding, six link slots, hover tooltips,
expandable out-of-scope panels. For the developer who just needs
"what do I change in `.tf` to make this go away," use the
`scan-pci-fix-list` target.

### Running it

```bash
# Emit fix_list.md from an existing run dir (no re-scan)
make scan-pci-fix-list RUN_DIR=.checkov/<run_id>

# Equivalent direct invocation
python .scripts/checkov/aggregate_pci.py \
    --run-dir .checkov/<run_id> \
    --emit-fix-list
```

The target works on any run dir produced by `make scan-pci-report`,
`scan-pci-plan-report`, or `scan-pci-state-report`. It does NOT
re-scan; it re-reads `combined.sarif` + `coverage_matrix.csv` from
the run dir and emits a single markdown file. The aggregator's
`--emit-fix-list` flag is the underlying mechanism (see
`aggregate_pci.py --help`).

### What the output looks like

The emitted file is `<run_dir>/fix_list.md`. It contains:

1. **Header** — run id, scope, scan tier, total finding count,
   severity breakdown (CRITICAL/HIGH/MEDIUM/LOW).
2. **Findings sorted by severity** — CRITICAL first, then HIGH,
   then MEDIUM, then LOW. Findings suppressed by
   `pci_baseline.yaml` are listed in a separate `## Suppressed`
   section at the bottom for visibility (so reviewers can spot
   waivers that may need renewal).
3. **One section per finding**, with:
   - check id (e.g. `CKV_AZURE_206`)
   - severity and PCI requirement mapping
   - resource address (`azurerm_storage_account.foo["primary"]`)
   - file + line range
   - the failing attribute
   - a **canonical remediation HCL block** pulled from
     `terraform_remediation.yaml` (rendered inline; no extra
     lookups)
   - a **verification command** — the same `terraform plan`
     or `checkov -d <env> --check <id>` invocation the operator
     would run to confirm the fix

### Why this is better than reading the SARIF directly

| Reading SARIF / CSV | Reading `fix_list.md` |
|---|---|
| 5 SARIF files per run, separate per-framework | Single markdown file |
| Findings ordered by resource path, not fix priority | Sorted by severity (CRITICAL first) |
| Each finding is a JSON object with `ruleId`, `message.text`, `locations[]` | Each finding is a heading with file/line, the failing attribute, and a copy-pasteable HCL fix |
| No severity in the SARIF (must cross-reference `SEVERITY_OVERRIDE`) | Severity in every section header |
| PCI requirement mapping is in `coverage_matrix.csv`, separate file | PCI req id printed alongside the finding |
| Operator must write the HCL fix themselves | Canonical HCL rendered inline from `terraform_remediation.yaml` |
| Operator must invent a verification command | Verification command printed per finding |

### Typical workflow

```bash
# 1. Scan
make scan-pci-report PROJECT=CR_PROJECT_NAME ENV=prod

# 2. Audit the HTML report (regulatory review)
start .checkov/<run_id>/report.html

# 3. Hand the fix list to the dev who will remediate
make scan-pci-fix-list RUN_DIR=.checkov/<run_id>
cp .checkov/<run_id>/fix_list.md /tmp/CR_PROJECT_NAME-fix-list.md

# 4. Dev applies the HCL blocks top-down (CRITICAL first),
#    runs the printed verification command after each one,
#    re-runs the scan to confirm.
make scan-pci-report PROJECT=CR_PROJECT_NAME ENV=prod
```

The fix list is regenerated from the same run dir without a
re-scan, so the dev can re-print it after the auditor requests
a different sort order or a focus on a single check_id without
paying the scan cost again.
