# Pacioli Architecture

This document describes the internal structure of the Pacioli scanner:
how the pieces fit together, why they were built that way, and which
files to read when changing a specific subsystem.

If you are running scans, you want [Operator Guide](OPERATOR_GUIDE.md).
If you are extending the scanner, you want [Developer Guide](DEVELOPER_GUIDE.md).
This document is for both — read it once to understand the model.

## Bird's-eye view

```
                    ┌─────────────────────────────────────┐
                    │  Consumer Terraform repo (your code) │
                    │  ├── pci_scope.yaml                  │
                    │  ├── pci_baseline.yaml               │
                    │  └── env/<project>/<env>/*.tf        │
                    └─────────────────────────────────────┘
                                       │
                                       │  (path via PACIOLI_TARGET_REPO)
                                       ▼
    ┌────────────────────────────────────────────────────────────────┐
    │  Pacioli install (this repo)                                   │
    │  scanner/                                                      │
    │  ├── scan.sh          ◄── driver, orchestrates Checkov         │
    │  ├── scan_audit.sh        Re-emit a prior report from archive  │
    │  ├── scan_baseline_init.sh  Bulk-generate stub baselines       │
    │  ├── aggregate.py     ◄── aggregator (SARIF → HTML/CSV/JUnit)  │
    │  ├── rewrite_sarif_help.py  Post-processor: fixes helpUri      │
    │  ├── checkov_url_overrides.py  Canonical rule-URL table         │
    │  ├── tfstate_to_plan.py    .tfstate → plan-JSON shape          │
    │  ├── drift_report.py       Plan-vs-state diff                  │
    │  ├── terraform_remediation.yaml  Canonical azurerm 4.x fixes   │
    │  ├── checks/            CKV_AZURE_PCI_001..005 (custom PaaC)    │
    │  ├── lib/                                                      │
    │  │   ├── safety.sh    ◄── READ-ONLY invariant (refuse)         │
    │  │   └── common.sh    ◄── paths, run-id, IP whitelist helpers  │
    │  ├── tests/            pytest suite                            │
    │  └── requirements-pinned.txt  Pinned deps                      │
    │  mappings/                                                     │
    │  └── pci_dss_4.0.1.yaml   Framework requirement → check_id     │
    │  examples/                                                     │
    │  ├── scope.yaml.example                                       │
    │  ├── baseline.yaml.example                                     │
    │  └── Makefile.consumer                                         │
    └────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │  Output: .checkov/<run-id>/         │
                    │  ├── <project>/<env>/*_source.sarif │
                    │  ├── <project>/<env>/*_plan.sarif   │
                    │  ├── <project>/<env>/*_state.sarif  │
                    │  ├── <project>/<env>/*_secrets.sarif│
                    │  ├── <project>/<env>/*_paac.sarif   │
                    │  ├── <project>/<env>/drift_report.json
                    │  └── aggregate/                      │
                    │      ├── coverage_matrix.csv        │
                    │      ├── coverage_gaps.csv          │
                    │      ├── combined.sarif             │
                    │      ├── junit.xml                  │
                    │      ├── report.html                │
                    │      └── fix_list.md  (opt-in)      │
                    └─────────────────────────────────────┘
```

## Layered design

Pacioli is built in five layers, each with a single responsibility:

### Layer 0 — `lib/safety.sh` (read-only guard)

The first thing every Bash script sources is `lib/safety.sh`, which
defines the read-only invariant. Every external command the scanner
runs is gated through `refuse_if_mutating` (or `safe_run_exec`, which
calls it). The full pattern list and extension procedure are in
[Safety Model](SAFETY_MODEL.md).

### Layer 1 — `lib/common.sh` (paths + run-id + helpers)

Sourced by every driver script. Sets up:

- `PYTHONIOENCODING=utf-8` and `PYTHONUTF8=1` so Python child
  processes (Checkov, `aggregate.py`) don't crash on Windows cp1252
  encodings of multi-byte UTF-8 (the `⏳` / `⚠` glyphs embedded in KQL
  workbook titles).
- `PACIOLI_TARGET_REPO` (the consumer's Terraform repo; default: CWD).
- `PACIOLI_INSTALL_DIR` (this repo; resolved from the location of
  `lib/common.sh`).
- `PACIOLI_MAPPING` (default: `mappings/pci_dss_4.0.1.yaml`).
- `PCI_STATE_STORAGE_ACCOUNT` and `PCI_REPORTS_CONTAINER` (Azure
  storage for tier 2/3 and the `pacioli-reports` archive; both
  required — the scanner refuses tier 2/3 and audit-mode runs
  when either is unset).
- `pci_log` (timestamped logging; respects `PCI_VERBOSE`, `PCI_DEBUG`).
- `safe_run_exec` (gates external commands through the safety guard).
- `whitelist_my_ip` / `cleanup_ip_whitelist` (paired Azure mutation +
  removal, with a 5-retry verification).
- `shred_plan_artifacts` (PCI 10.7 hygiene for plan files).
- `yaml_to_json` / `load_pci_scope` (scope parsing).
- `init_pretty_run_dir` / `init_run_dir_labeled` (run-dir naming).
- `find_aztfexport_files` (returns the set of files that must be
  excluded from scanning because they are aztfexport-generated).

### Layer 2 — `scan.sh` (driver)

The driver is a per-(project, env) loop. For each env, it does, in
order:

1. **Validate the env dir** (`require_env_dir`).
2. **Whitelist the runner IP** if tier 2 or 3 (`whitelist_my_ip`).
3. **`terraform init -input=false`** (tier 2+).
4. **`terraform plan -out=tfplan.binary`** (tier 2+).
5. **`terraform show -json tfplan.binary > plan.json`** (tier 2+).
6. **Custom PCI checks** (always) — `checkov -d <env>
   --framework terraform --external-checks-dir scanner/checks`.
7. **Built-in source scan** (tier 1) — `checkov -d <env> --framework
   terraform`.
8. **Plan scan** (tier 2+) — `checkov -d <env> -f plan.json
   --framework terraform_plan`.
9. **Secrets scan** (always) — `checkov -d <env> --framework secrets`.
10. **State scan** (tier 3 only) — download `.tfstate` blob, convert
    to plan-JSON shape, run Checkov.
11. **Drift report** (tier 3 only) — diff source plan vs state plan.
12. **Shred plan artifacts** (PCI 10.7 hygiene).
13. **Rewrite `helpUri`** in every SARIF on disk so the artifacts
    themselves are correct (SIEM / GitHub code-scanning consumers
    don't need to re-apply our URL map).

Each step's SARIF output is renamed to a canonical filename
(`results_<layer>.sarif`) so the aggregator finds it without
per-tier logic.

The driver traps `EXIT INT TERM` to:

- Call `cleanup_ip_whitelist` (removes the IP we added in step 2).
- Call `shred_plan_artifacts` (destroys tfplan.binary + plan.json).
- Remove the staging dir for the pairs file.

### Layer 3 — `aggregate.py` (per-run → per-org → per-framework)

After the driver finishes, the aggregator:

1. **Walks the run dir** (`walk_run_dir`), finds every
   `results_*.sarif`, attaches the `(project, env)` tuple to each run
   via the `pci_project` / `pci_env` properties.
2. **Parses each SARIF** (`parse_sarif`), joining each result to its
   rule via SARIF 2.1.0's `ruleIndex` (or the legacy `ruleId`
   fallback). Resolves severity using `SEVERITY_OVERRIDE` (since
   Checkov OSS doesn't populate `properties.severity`).
3. **Loads `pci_mapping.yaml`** (`load_pci_mapping`), inverts the
   `requirement → checks` map to `check_id → requirements` for O(1)
   per-finding lookup.
4. **Loads `pci_baseline.yaml`** (`load_pci_baseline`) and the
   inline `# checkov:skip=` comments from every scanned `.tf` file.
5. **Marks findings as suppressed** if a matching baseline entry has
   `owner` populated AND `expires_on >= today` (`is_suppressed`,
   `is_inline_suppressed`).
6. **Builds the coverage matrix** (`build_coverage_matrix`):
   - For each (req, check_id), computes the per-env status
     (`compliant` / `non_compliant` / `not_scanned`) and collapses
     across envs.
   - Validates `out_of_scope_requirements` (refuses to emit if any
     field is missing or any date is malformed).
   - Builds `expected_by_req` (the full set of check_ids mapped to
     each in-scope req) and `fired_check_ids` (the set of check_ids
     that actually produced SARIF findings) so the gap calculation is
     honest.
7. **Computes coverage gaps** (`compute_coverage_gaps`,
   `write_coverage_gaps_csv`): the diff `expected_by_req -
   fired_check_ids`. Each row gets a `triage_hint` based on the
   pattern (single missing → likely stale, many missing → possibly
   env doesn't deploy the resource).
8. **Writes the per-run artifacts**:
   - `coverage_matrix.csv` — one row per (req, check) cell.
   - `coverage_gaps.csv` — one row per in-scope req, with the missing
     IDs and triage hint.
   - `combined.sarif` — all per-env SARIFs merged (with
     `pci_project`, `pci_env` properties attached).
   - `junit.xml` — one `<testcase>` per finding (FAIL = HIGH/CRITICAL).
   - `report.html` — the single-page SPA report.
   - `fix_list.md` (opt-in via `--emit-fix-list`) — developer-friendly
     markdown sorted by severity.

### Layer 4 — `scan_audit.sh` and `scan_baseline_init.sh` (post-scan tools)

`scan_audit.sh` re-emits a prior report from the `pacioli-reports`
archive (no re-scan). `scan_baseline_init.sh` reads a combined SARIF and
emits stub baseline entries with TBD for `owner`, `ticket_id`,
`expires_on` so the team can triage top-N by `hit_count`.

### Layer 5 — `checkov_url_overrides.py` and `rewrite_sarif_help.py` (the URL problem)

Checkov OSS populates `helpUri` with `docs.prismacloud.io` URLs. That
domain was acquired by Palo Alto in 2026; the per-rule deep-links
redirect to a generic landing page. We solve this in three places:

- `checkov_url_overrides.py` is the **single source of truth**: a
  `{rule_id: canonical_github_url}` table covering 83 rules.
- `aggregate.py` uses it to rewrite the `helpUri` when building the
  HTML report.
- `rewrite_sarif_help.py` uses it to rewrite the `helpUri` in every
  per-env SARIF on disk so the SARIF artifacts are correct on their
  own.
- `scan.sh`'s `checkov_stderr_filter` rewrites Checkov's CLI output
  in the operator's terminal so they don't see broken
  `prismacloud.io` links as Checkov runs.

Adding a new rule? One entry in `checkov_url_overrides.py` is
enough — the aggregator, the SARIF rewriter, and the shell filter
all pick it up.

## The mapping pack

`mappings/pci_dss_4.0.1.yaml` is a YAML file that maps a PCI
requirement to a list of Checkov rule IDs. The schema is small:

```yaml
version: 2
framework_name: PCI DSS
framework_version: '4.0.1'
doc_anchor: https://listings.pcisecuritystandards.org/documents/...
requirements:
  - id: 1.2.1
    title: Configuration standards for NSCs are defined and implemented
    checks:
      - CKV_AZURE_9
      - CKV_AZURE_10
    note: CKV_AZURE_89 anchored here as 1.2.1 network-access evidence.
out_of_scope_requirements:
  - id: 11.x
    title: Test security of systems and networks regularly
    rationale: ...
    control_owner: ...
    approved_on: '2026-08-01'
    expires_on: '2027-08-01'
    evidence_link: ...
```

The full schema (every field, the OOS validation rules, the
`note` semantics) is in [Mapping Schema](MAPPING_SCHEMA.md).

## The custom checks

`scanner/checks/CKV_AZURE_PCI_*.py` is the directory Pacioli
auto-loads via Checkov's `--external-checks-dir` mechanism. Each
file is a self-contained Checkov check that:

- Inherits from `BaseResourceCheck`.
- Declares `name`, `id`, `categories`, `supported_resources`, and
  `guideline`.
- Implements `scan_resource_conf(conf)` returning `CheckResult.PASSED`
  or `CheckResult.FAILED`.

The five shipped checks are:

| ID | Purpose | PCI req |
|---|---|---|
| `CKV_AZURE_PCI_001` | `lifecycle.ignore_changes` on security-sensitive attribute | 6.5.5 |
| `CKV_AZURE_PCI_002` | Storage account without explicit `network_rules` (default Deny) | 1.2.1 / 1.3 |
| `CKV_AZURE_PCI_003` | `min_tls_version` below 1.2 | 4.2.1 |
| `CKV_AZURE_PCI_004` | Customer-managed key (CMK) missing on encryption-bearing resource | 3.5.1 |
| `CKV_AZURE_PCI_005` | Key Vault purge protection disabled | 3.6.5 / 8.6.3 |

[Check Authoring](CHECK_AUTHORING.md) walks through adding a new one.

## The HTML report

The HTML report is a single static file with a sidebar SPA. There
is no build step, no bundler, no framework. The full
`<style>...{CSS}...</style>` block and the full `<script>...{JS}...</script>`
block are emitted in-line by `aggregate.py`'s
`write_html_report` function. The CSS is held as a plain
triple-quoted string (NOT inside an f-string) because Python 3.12+
parses `{...}` greedily inside f-strings — and CSS has braces.

Routes:

| Route | Content |
|---|---|
| `#dashboard` | KPI cards, severity donut, env health bars, top-N lists |
| `#findings` | Filterable findings table (the bulk of the data) |
| `#environments` | Per-env summary table with drilldown |
| `#coverage` | PCI coverage heatmap + per-req status table |
| `#remediation` | Aggregated remediation library pulled from `terraform_remediation.yaml` |
| `#oos` | Out-of-scope rows (with stale badge) |
| `#drift` | Drift findings (tier 3 only) |

Cross-filtering is implemented in the client JS: clicking a
heatmap cell sets `FILTER.pci` and navigates to `#findings`; clicking
an env bar sets `FILTER.env` and navigates to `#findings`. The
filter UI syncs across all routes via `applyAll()` + `syncAllFilterUIs()`.

## File-by-file index

| File | Purpose | Read this when… |
|---|---|---|
| `scanner/scan.sh` | Driver; orchestrates Checkov per env | Changing the per-env flow |
| `scanner/scan_audit.sh` | Re-emit prior report from the `pacioli-reports` archive | Adding a new audit tier |
| `scanner/scan_baseline_init.sh` | Bulk-generate baseline stubs | Changing the baseline schema |
| `scanner/aggregate.py` | SARIF → HTML/CSV/JUnit | Changing the report layout, adding a new aggregate output, fixing coverage math |
| `scanner/rewrite_sarif_help.py` | Rewrite helpUri in SARIF on disk | Adding a new consumer of the URL override table |
| `scanner/checkov_url_overrides.py` | The URL override table | Adding a new rule, fixing a wrong URL |
| `scanner/tfstate_to_plan.py` | `.tfstate` → plan-JSON shape | Adding a new state-shape converter |
| `scanner/drift_report.py` | Plan vs state attribute diff | Changing the drift signal |
| `scanner/terraform_remediation.yaml` | Canonical azurerm 4.x HCL fixes | Adding a new remediation, fixing a wrong HCL block |
| `scanner/checks/*.py` | The custom PaaC checks | Adding a new `CKV_AZURE_PCI_*` check |
| `scanner/lib/common.sh` | Paths, run-id, IP helpers, scope loader | Adding a new path or env var |
| `scanner/lib/safety.sh` | Read-only invariant | Adding a new refusal pattern, changing the safety guarantee |
| `scanner/tests/*.py` | pytest suite | Running the tests, fixing a test |
| `mappings/pci_dss_4.0.1.yaml` | Framework requirement → check_id | Adding a new mapping row, validating an OOS exclusion |
| `examples/*` | Runnable templates | Onboarding a new consumer |

## Why bash + Python instead of pure Python?

The driver is bash for one reason: `set -uo pipefail` + an EXIT trap
gives you a clean, *guaranteed* cleanup story for the storage firewall
IP whitelist. Pure-Python equivalents require explicit `try/finally`
*and* `atexit` registration *and* signal-handler coverage to match
the same guarantee. The bash trap is shorter, more obvious, and has
been in production for 90+ days without a single missed cleanup.

The aggregator and post-processors are Python because the work is
data-join (rule + mapping + baseline + suppression + coverage),
which is awkward in bash and natural in Python.

The custom checks are Python because they have to be — Checkov
loads them as Python modules.

## See also

- [Operator Guide](OPERATOR_GUIDE.md) — for running the scanner
- [Developer Guide](DEVELOPER_GUIDE.md) — for extending it
- [Safety Model](SAFETY_MODEL.md) — for the read-only invariant
- [CLI Reference](CLI_REFERENCE.md) — for every argument
- [Mapping Schema](MAPPING_SCHEMA.md) — for the YAML file format
- [Check Authoring](CHECK_AUTHORING.md) — for adding a custom check
- [Report Format](REPORT_FORMAT.md) — for the output files
- [Troubleshooting](TROUBLESHOOTING.md) — for common failures
