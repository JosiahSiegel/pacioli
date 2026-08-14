# Pacioli — Report Format

> **Every file the scanner writes, what it contains, and how to
> read it.** Use this as a reference when you have a run dir in hand
> and need to know what to do with it.

For the workflow-level narrative, see [Operator Guide](OPERATOR_GUIDE.md).
For HTML report routes and SPA behavior, see the [HTML Report
section below](#html-report-routes).

## Run dir layout

A run is everything under `~/.pacioli/runs/<run-id>/`. The run-id is
derived from the scope (project, env filters, `--label` value) plus
the UTC date and a collision-counter. See [Operator Guide → Where
do scan outputs live?](OPERATOR_GUIDE.md#where-do-scan-outputs-live).

```
~/.pacioli/runs/<run-id>/
├── .scope_pairs.tsv                    # (project TAB env) pairs scanned
├── <project>/<env>/                    # Per-scope outputs
├── <project>/<env>/
│   ├── results_terraform_source.sarif  # Tier 1 source scan
│   ├── results_paac.sarif              # Custom PaaC checks (CKV_AZURE_PCI_*)
│   ├── results_secrets.sarif           # Hardcoded-secret scan
│   ├── results_terraform_plan.sarif    # Tier 2 plan scan
│   ├── results_state.sarif             # Tier 3 state scan
│   └── drift_report.json               # Tier 3 drift
└── aggregate/                          # Only present after --mode report
    ├── coverage_matrix.csv
    ├── coverage_gaps.csv
    ├── combined.sarif
    ├── junit.xml
    ├── report.html
    └── fix_list.md                     # Only if --emit-fix-list
```

## Per-env SARIFs

Each per-env SARIF is a SARIF 2.1.0 document. Sarif = the
[Static Analysis Results Interchange Format](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
Pacioli:

- **Rewrites `helpUri`** on every rule to the canonical GitHub
  source URL via `rewrite_sarif_help.py`. CI tools that ingest
  SARIF directly (GitHub Code Scanning, Azure DevOps, custom SIEM
  rules) see URLs that actually resolve.
- **Tags every run with `pci_project` and `pci_env`** properties
  when `aggregate.py` builds `combined.sarif`. The per-env SARIFs
  on disk do not yet carry these — the aggregator adds them in
  the merge step.

The `runs[]` array contains one entry per layer scanned. The
`tool.driver.rules[]` array contains the rule definitions. The
`results[]` array contains the findings.

## `combined.sarif`

The aggregator's per-run merge of all per-env SARIFs. Use this
when a single SIEM integration is preferred over N per-env files.

Properties added by the aggregator (only the new fields are shown; the rest of the SARIF is unchanged):

```text
{
  "runs": [
    {
      "properties": {
        "pci_project": "myapp",
        "pci_env": "prod",
        "pci_source_sarif": "results_terraform_source.sarif"
      },
      "tool": { /* original SARIF tool.driver block */ },
      "results": [ /* original SARIF results array */ ]
    }
  ]
}
```

## `coverage_matrix.csv`

The per-(req, check) coverage matrix. One CSV file with one row
per (requirement, check) cell. Columns:

| Column | Description |
|---|---|
| `pci_requirement` | The framework requirement ID (e.g. `1.2.1`) |
| `check_id` | The Checkov rule ID (e.g. `CKV_AZURE_59`); `*` for an in-scope row with no findings |
| `status` | `compliant` \| `non_compliant` \| `not_applicable` \| `out_of_scope` |
| `missing_for_req` | (in-scope rows only) space-separated check_ids mapped to this req that never fired in any SARIF |
| `title` | Requirement title (OOS rows only) |
| `rationale` | OOS rows: why IaC scanning cannot evaluate |
| `control_owner` | OOS rows: team / role that owns the control outside the scanner |
| `approved_by` | (currently unused; reserved) |
| `approved_on` | OOS rows: ISO `YYYY-MM-DD` |
| `expires_on` | OOS rows: ISO `YYYY-MM-DD` |
| `evidence_link` | OOS rows: resolvable URL or ticket ID |
| `stale` | OOS rows: `true`/`false` (expired) |
| `days_to_expiry` | OOS rows: int |
| `chain_of_custody_complete` | in-scope rows: `True` if `pci_source_url` was live-verified at `PCI_SOURCE_VERIFIED_AT`; `partial` if historical-only; `""` for OOS rows |

OOS rows are emitted after the in-scope rows. The status column
for OOS rows is always `out_of_scope`. The full audit metadata
(7 fields) is on the OOS row, so a single CSV is a sufficient
evidence record.

A row with status `not_applicable` is an in-scope row with no
findings at all — the `missing_for_req` column carries the
operator-triage list of expected-but-not-fired check_ids.

## `coverage_gaps.csv`

The audit-traceability report. One row per in-scope PCI
requirement. Columns:

| Column | Description |
|---|---|
| `pci_requirement` | Requirement ID |
| `title` | Requirement title |
| `expected_count` | Check_ids mapped to this req in `pci_mapping.yaml` |
| `fired_count` | Check_ids that produced at least one SARIF finding in any env |
| `missing_count` | `expected_count - fired_count` |
| `missing_check_ids` | Space-separated missing IDs |
| `triage_hint` | Suggested next step (stale check id? no resource of that type? mixed?) |
| `librarian_verified_at` | The date the per-row verification probe ran (constant `LIBRARIAN_VERIFIED_AT`) |
| `pci_anchor_url` | The URL the probe fetched (single PCI SSC anchor for v4.0.1) |
| `evidence_byte_size` | HTTP response body bytes observed |
| `evidence_content_type` | HTTP response `Content-Type` |
| `link_pass` | `True` if fingerprint match; `False` otherwise |

The audit-traceability columns (`librarian_verified_at` and
onward) are emitted on **every** row so the CSV is a
self-contained reproducibility record. An auditor reading the
file in isolation can re-verify every URL without consulting the
runbook or the operator.

## `junit.xml`

One `<testcase>` per finding. Used by CI runners that ingest JUnit
for pass/fail reporting. The `<testcase>` has:

- `classname` = `<project>.<env>`
- `name` = `<check_id>.<resource>` (or `env:<env>` for a scan that
  didn't produce any findings)
- `time` = 0 (the scanner doesn't time individual findings)

A HIGH/CRITICAL finding becomes:

```xml
<failure type="HIGH" message="..." resource="..."/>
```

A MEDIUM/LOW finding is a passing `<testcase>` (no `<failure>`).

A suppressed finding is `<skipped message="suppressed by baseline"/>`.

A scan that failed for an env (e.g. `terraform plan` error) is
`<skipped message="scan did not run: ..."/>`.

`<system-out>` carries `N tests, F failures`.

## HTML report routes

The HTML report is a single static file (no build step, no
bundler, no framework). The full CSS and JS are emitted in-line
by `write_html_report` in `aggregate.py`. Open it in any modern
browser; no web server required.

### Report view, theme, and evidence boundaries

The static report is **Dark default**: its first paint uses the dark theme.
The sidebar selector offers **Dark, Light, and System**. The selected theme
uses browser-local persistence (`localStorage`); `System` follows the browser
or operating-system color preference. A missing, invalid, or unavailable
stored value falls back to Dark.

The sidebar's **Hide environments** controls define a **report view**, not a
scan-scope or compliance-scope decision. This is a client-side report-view-only
exclusion: checking an environment hides it from the browser view and
recomputes the dashboard KPIs, severity donut, findings, environment summary,
top lists, coverage, and drift views from the remaining environments. The
status reports either `Full scan: viewing all <N> environments.` or the
number excluded and visible.

Use **Full-report reset** to clear the report view exclusions and the
search/severity/requirement filters. If every environment is hidden, the
report shows an empty-filter state that directs the reader to reset
exclusions; the donut shows `No data` and finding-derived lists show `No
visible findings.` Clearing the exclusions restores the full report view.

A report view never changes the generated scan evidence. SARIF, CSV, and
JUnit evidence remains unchanged and represents the full scan, regardless of
the browser-local filter or stored theme choice. Use `.pacioli/scope.yaml` to make
a scan-scope decision instead; see [Operator Guide](OPERATOR_GUIDE.md#adding-a-new-project-to-scope).

### `#dashboard`

The default route. Contains:

- **KPI cards** for Total, High/Critical, Medium, Low, Suppressed.
- **Severity donut** (SVG) with legend.
- **Environment health bars** — one bar per env, color-coded by
  the count of HIGH findings. Click a bar to filter the Findings
  route to that env.
- **Top vulnerable resources** — Top 15 by finding count, with
  severity pill.
- **Top fired rules** — Top 15 by finding count.

### `#findings`

The filterable findings table. Filters:

- Free-text search (matches `resource`, `check_id`, `message`, `file_path`).
- Severity pills (`HIGH`, `MEDIUM`, `LOW`, `SUPPRESSED`).
- Environment exclusions (checkboxes for the full scanned environment set;
  this report view is client-side only and is not a `.pacioli/scope.yaml` scan
  scope control).
- PCI requirement picker (one entry per in-scope req from `pci_mapping.yaml`).

Each finding row shows:

- Severity (color-coded left border).
- `check_id` and the in-line `helpUri` link to the GitHub source.
- Resource address (e.g. `azurerm_storage_account.foo`).
- File + line (clickable to the `.tf` location if your editor
  supports it).
- The PCI requirement mapping (with the framework's doc_anchor).
- Inline remediation HCL block (from `terraform_remediation.yaml`).
- Chain-of-custody badge.
- "Suppressed" badge if a baseline entry applies.

Click a row to expand the full remediation block + the SARIF
result JSON.

### `#environments`

Per-env summary table. One row per `(project, env)` pair, with
project, env, status (ok / failed_to_plan / no_sarif), total
findings, HIGH / MEDIUM / LOW counts.

### `#coverage`

PCI requirement coverage. Two sections:

- **Coverage heatmap** — one cell per in-scope req. Color-coded
  by status (PASS / FAIL / PARTIAL / GAP). Click any cell to
  filter the Findings route to that req.
- **PCI requirement status table** — one row per in-scope req,
  with status and a tooltip on `NO CHECKS FIRED` rows.

### `#remediation`

Aggregated remediation library. One row per `check_id` in
`terraform_remediation.yaml`, with the canonical azurerm 4.x
HCL fix block. Expand the "Show HCL" disclosure to read the fix.

### `#oos`

Out-of-scope requirements. One row per entry in
`out_of_scope_requirements`. The full audit metadata
(`rationale`, `control_owner`, `approved_on`, `expires_on`,
`evidence_link`) is on the row. Stale entries (expires_on <
today) get a red `STALE` badge.

### `#drift`

Drift findings (tier 3 only). One row per drifted attribute, with
resource, attribute, source value, state value, severity, drift
type. Empty for tier 1/2 scans.

## `fix_list.md` (opt-in)

A developer-friendly markdown file, sorted by severity, with the
canonical HCL fix block inlined per finding. Useful when handing
the dev team a "what do I change in `.tf` to make this go away?"
list.

```bash
# Generate (or regenerate) without re-scanning
python scanner/aggregate.py --run-dir ~/.pacioli/runs/<run_id> --emit-fix-list
```

Sections:

- **Header** — run id, scope, scan tier, total finding count,
  severity breakdown.
- **CRITICAL** — one section per finding.
- **HIGH** — one section per finding.
- **MEDIUM** — one section per finding.
- **LOW** — one section per finding.
- **Suppressed** — one section per suppressed finding (so
  reviewers can spot waivers that may need renewal).

Each finding section contains:

- check id and severity.
- resource address.
- file + line.
- the failing attribute.
- the canonical HCL block.
- the verification command.

## `drift_report.json` (tier 3 only)

The plan-vs-state diff. JSON document with:

```json
{
  "summary": {
    "addresses_in_state_only": 0,
    "addresses_in_source_only": 0,
    "addresses_with_attribute_drift": 0,
    "sensitive_attribute_findings": 0,
    "interpretation": "no drift; source plan matches state"
  },
  "address_in_state_only": [],
  "address_in_source_only": [],
  "attribute_drift": [
    {
      "address": "module.foo.azurerm_storage_account.bar",
      "diffs": [
        {
          "attribute": "min_tls_version",
          "source": "TLS1_2",
          "state": "TLS1_0",
          "note": ""
        }
      ]
    }
  ],
  "sensitive_findings": []
}
```

See [Operator Guide → Drift](#drift-route) for interpretation.

## `coverage_matrix.csv` sample rows

In-scope row, in-scope findings:

```csv
pci_requirement,check_id,status,missing_for_req,...
1.2.1,CKV_AZURE_9,non_compliant,,...
1.2.1,CKV_AZURE_10,compliant,,...
1.2.1,CKV_AZURE_59,non_compliant,,...
```

In-scope row, no findings at all:

```csv
pci_requirement,check_id,status,missing_for_req,...
3.5.1,*,not_applicable,CKV_AZURE_2 CKV_AZURE_41,...
```

OOS row:

```csv
pci_requirement,check_id,status,...,rationale,control_owner,approved_on,expires_on,evidence_link,stale,days_to_expiry,...
11.x (excluding 11.6.1),*,out_of_scope,...,PCI 11.x covers runtime...,Security team -- Vulnerability Management,2026-08-01,2027-08-01,https://www.pcisecuritystandards.org/document_library/,false,360,...
```

## See also

- [Operator Guide](OPERATOR_GUIDE.md) — workflow-level narrative
- [Architecture](ARCHITECTURE.md) — how the aggregator fits in
- [CLI Reference](CLI_REFERENCE.md) — every argument
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
