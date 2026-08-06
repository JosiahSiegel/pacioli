# Pacioli — CLI Reference

This is the complete reference for every command-line argument and
environment variable in the Pacioli scanner. Use it as a lookup
table; for the workflow-level narrative, see
[Operator Guide](OPERATOR_GUIDE.md).

## `scan.sh`

The driver script. Orchestrates Checkov per in-scope env.

### Synopsis

```bash
bash scanner/scan.sh [--mode MODE] [--project P] [--env E]
                     [--scan-plan | --scan-state]
                     [--dry-run] [--verbose]
                     [--no-aggregate] [--label TEXT]
```

### Arguments

| Argument | Values | Default | Description |
|---|---|---|---|
| `--mode` | `gate` \| `report` \| `audit` | `report` (or `gate` if `CI=1`) | `gate` exits non-zero on HIGH/CRITICAL. `report` never blocks; auto-aggregates. `audit` re-emits a prior report. |
| `--project` | `<project name>` | (no filter) | Restrict to a single project from `pci_scope.yaml`. |
| `--env` | `<env name>` | (no filter) | Restrict to a single env. |
| `--scan-plan` | flag | off | Add the `terraform_plan` layer (tier 2). Implies `terraform init` + `terraform plan`. |
| `--scan-state` | flag | off | Add the state-as-plan + drift layer (tier 3). Implies `--scan-plan`. |
| `--dry-run` | flag | off | Print every command without executing. Does not actually run Checkov or `terraform`. |
| `--verbose` | flag | off | Enable INFO-level logging. Same as `PCI_VERBOSE=1`. |
| `--no-aggregate` | flag | off | Skip the end-of-run `aggregate.py` call. (Only meaningful for `--mode report`; gate and audit never aggregate.) |
| `--label` | `<text>` | (derived from scope) | Custom slug for the run-dir name. Sanitized to `[A-Za-z0-9_.-]`. Suffixes the UTC date. |
| `--help` / `-h` | flag | — | Show usage and exit. |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (no HIGH/CRITICAL in gate mode, or report mode completed) |
| 1 | Audit mode not implemented (or scan failed) |
| 2 | Required input file missing (e.g. `pci_scope.yaml`, `pci_mapping.yaml`, `pci_baseline.yaml`) |
| 7 | Aggregator found HIGH/CRITICAL findings (only used in gate mode where it matters; suppressed in report mode) |
| 64 | Invalid command-line argument |
| 99 | Safety guard refused a command (read-only invariant violation) |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PACIOLI_TARGET_REPO` | `${PCI_REPO_ROOT}` or `$(pwd)` | The consumer's Terraform repo (where `pci_scope.yaml`, `pci_baseline.yaml`, and `env/` live). |
| `PACIOLI_MAPPING` | `${PACIOLI_INSTALL_DIR}/mappings/pci_dss_4.0.1.yaml` | The framework mapping pack. Override with `--mapping <file>` (see `aggregate.py`). |
| `PACIOLI_STATE_STORAGE_ACCOUNT` | `iacsa` | Azure storage account for tier 2/3 state-blob access. |
| `PACIOLI_REPORTS_CONTAINER` | `iac-reports` | Azure storage container for the iac-reports archive. |
| `PCI_CACHE_ROOT` | `${PACIOLI_TARGET_REPO}/.checkov` | Where the run dir is created. |
| `PCI_VERBOSE` | unset | Same as `--verbose`. |
| `PCI_DEBUG` | unset | Even more verbose (DEBUG level). |
| `CI` | unset | If set, `--mode report` is auto-promoted to `--mode gate`. |
| `PYTHONIOENCODING` | `utf-8` | Forced by `lib/common.sh` to avoid Windows cp1252 crashes. |
| `PYTHONUTF8` | `1` | Same. |
| `LC_ALL` / `LANG` | `C.UTF-8` | Same. |

### Examples

```bash
# Default — source-only scan, auto-aggregate, print report path
bash scanner/scan.sh

# CI gate — source-only, exit non-zero on HIGH/CRITICAL
bash scanner/scan.sh --mode gate

# Source + plan — for the canonical env before merge to main
bash scanner/scan.sh --mode report --scan-plan --project myapp --env prod

# Source + plan + state-drift — for monthly deep reviews
bash scanner/scan.sh --mode report --scan-state

# Dry-run — see what would happen without doing it
bash scanner/scan.sh --dry-run --project myapp --env prod

# Ad-hoc label
bash scanner/scan.sh --mode report --label pre-deploy --project myapp --env prod
```

## `scan_audit.sh`

Re-emits a prior report from the iac-reports archive. No re-scan.

### Synopsis

```bash
bash scanner/scan_audit.sh [--run-id ID | --latest] [--out PATH] [--dry-run]
```

### Arguments

| Argument | Description |
|---|---|
| `--run-id <id>` | Specific run id to fetch (e.g. `20260804T153407Z-2455`). |
| `--latest` | Fetch the most recent run from the `iac-reports` container. |
| `--out <path>` | Optional destination for `report.html`. |
| `--dry-run` | Print the blob-download commands without executing. |
| `--help` / `-h` | Show usage. |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PACIOLI_STATE_STORAGE_ACCOUNT` | `iacsa` | Storage account. |
| `PACIOLI_REPORTS_CONTAINER` | `iac-reports` | Container holding the archived reports. |

## `scan_baseline_init.sh`

Bulk-generates stub baseline entries from a prior run.

### Synopsis

```bash
bash scanner/scan_baseline_init.sh [--run-dir DIR] [--top N] [--append]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `--run-dir <dir>` | `.checkov/<most-recent>/` | The run dir to read `combined.sarif` from. |
| `--top <N>` | 50 | The number of top-by-priority entries to highlight for triage. (All findings get a stub entry regardless.) |
| `--append` | off | Merge with the existing `pci_baseline.yaml` instead of replacing. |
| `--help` / `-h` | Show usage. |

The output `pci_baseline.yaml` entries have `TBD` for
`justification`, `owner`, `ticket_id`, `expires_on`. Triage
top-N by `hit_count`: populate the schema fields, and the
suppression takes effect. See
[Operator Guide → Baseline entry schema](OPERATOR_GUIDE.md#baseline-entry-schema).

## `aggregate.py`

The per-run aggregator. Converts per-env SARIFs into a single
HTML/CSV/JUnit report. Normally invoked by `scan.sh` at the end
of `--mode report`, but can be re-run independently on a prior
run dir.

### Synopsis

```bash
python scanner/aggregate.py --run-dir DIR
                           [--out OUT]
                           [--scope SCOPE]
                           [--mapping MAPPING]
                           [--baseline BASELINE]
                           [--emit-fix-list]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `--run-dir <path>` | (required) | The run dir produced by `scan.sh`. |
| `--out <path>` | `<run-dir>/aggregate/` | Output directory. |
| `--scope <path>` | `${PACIOLI_TARGET_REPO}/pci_scope.yaml` | Override the scope file. |
| `--mapping <path>` | `${PACIOLI_MAPPING}` | Override the framework mapping. |
| `--baseline <path>` | `${PACIOLI_TARGET_REPO}/pci_baseline.yaml` | Override the baseline. |
| `--emit-fix-list` | off | Emit `fix_list.md` in the output dir. |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid arguments |
| 2 | PyYAML missing or required input file missing |
| 7 | HIGH/CRITICAL findings present (gating signal) |

## `rewrite_sarif_help.py`

Rewrites the `helpUri` field in Checkov SARIF files. Used by
`scan.sh` after every Checkov run, but exposed as a standalone
tool for batch-processing historical SARIFs.

### Synopsis

```bash
python scanner/rewrite_sarif_help.py <sarif_path> [<sarif_path> ...]
```

### Behavior

- Replaces the `helpUri` of every rule with the canonical GitHub
  source URL from `checkov_url_overrides.RULE_SOURCE_URLS`.
- Writes back atomically (`.tmp` + rename).
- Idempotent — re-running on an already-rewritten SARIF is a no-op.
- Non-SARIF JSON: error, no changes.
- Missing `runs` array: error, no changes.
- Unmapped rule IDs: keep the upstream `helpUri`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Always (errors are printed to stderr, but the script does not raise) |
| 64 | No arguments supplied |

## `tfstate_to_plan.py`

Converts a Terraform state JSON file into the plan-JSON shape
Checkov expects. Used by `scan.sh` in tier 3.

### Synopsis

```bash
python scanner/tfstate_to_plan.py <state.tfstate> <out.plan.json>
```

### Behavior

- Reads `state.tfstate`, extracts the resource attributes, and
  emits a JSON document shaped like `terraform show -json plan`.
- Skips data sources (`mode == "data"`).
- Flattens single-key wrapping (`{"foo": {"value": "bar"}}` →
  `{"foo": "bar"}`).
- Groups resources by module path so Checkov's graph rules see
  nested deps.

## `drift_report.py`

Compares two plan-shaped JSONs (source plan and state plan) and
emits a drift report at the destination.

### Synopsis

```bash
python scanner/drift_report.py <plan.json> <state_as_plan.json> <out.json>
```

### Output

A JSON document with:

- `summary` — counts and an `interpretation` string.
- `address_in_state_only` — resources in state but not source
  (will be destroyed on next apply).
- `address_in_source_only` — resources in source but not state
  (will be created on next apply).
- `attribute_drift` — per-resource, per-attribute list of differences
  on security-interesting attrs.
- `sensitive_findings` — source `<sensitive>` markers with concrete
  state values (token-rotation review).

## `lib/safety.sh` (sourced)

Defines the read-only invariant. See [Safety Model](SAFETY_MODEL.md)
for the full list of refused patterns. The script can be invoked
directly to run the self-test:

```bash
bash scanner/lib/safety.sh
# safety_selftest: PASS
```

This is the `make selftest` target.

## `lib/common.sh` (sourced)

Defines the path-resolution, run-id, scope-loading, and IP
whitelist helpers used by every driver script. Not a standalone
script — always sourced via `source "$(dirname
"${BASH_SOURCE[0]}")/lib/common.sh"` in a driver.

## Makefile targets

The wrapper Makefile (`examples/Makefile.consumer`, typically
copied to your repo as `Makefile.pacioli`) provides:

| Target | Underlying command |
|---|---|
| `make scan` | `bash scanner/scan.sh --mode report [filters]` |
| `make scan-plan` | `bash scanner/scan.sh --mode report --scan-plan [filters]` |
| `make scan-state` | `bash scanner/scan.sh --mode report --scan-state [filters]` |
| `make scan-gate` | `bash scanner/scan.sh --mode gate [filters]` |
| `make scan-baseline-init` | `bash scanner/scan_baseline_init.sh --run-dir <RUN_DIR>` |
| `make scan-fix-list` | `python scanner/aggregate.py --run-dir <RUN_DIR> --emit-fix-list` |
| `make scan-cleanup` | Echoes the manual cleanup steps (no auto-remove) |
| `make test` | Delegates to the scanner repo's `make test` (pytest) |

Common args: `PROJECT=<p>`, `ENV=<e>`, `LABEL=<text>`,
`RUN_DIR=.checkov/<run_id>`.

The scanner's own `Makefile` (at the repo root) provides:

| Target | Underlying command |
|---|---|
| `make help` | Print the target list |
| `make test` | `cd scanner && PYTHONPATH=. pytest tests/ -v` |
| `make lint` | `shellcheck` on all `.sh` files + `py_compile` on all `.py` files |
| `make selftest` | `bash scanner/lib/safety.sh` |
| `make install` | `pip install -r scanner/requirements-pinned.txt` + pytest + pyyaml |
| `make clean` | Remove `__pycache__`, `.pytest_cache`, build artifacts |

## See also

- [Operator Guide](OPERATOR_GUIDE.md) — narrative
- [Architecture](ARCHITECTURE.md) — how the pieces fit
- [Consuming Pacioli](CONSUMING_GUIDE.md) — first-time setup
- [Safety Model](SAFETY_MODEL.md) — the read-only invariant
- [Report Format](REPORT_FORMAT.md) — every output file
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
