# Pacioli — CLI Reference

This is the complete reference for every command-line argument and
environment variable in the Pacioli scanner. Use it as a lookup
table; for the workflow-level narrative, see
[Operator Guide](OPERATOR_GUIDE.md).

## `pacioli` (top-level flags)

These flags are accepted before any subcommand and apply to every
command. They are also re-declared on the subcommand parsers so they
can be passed positionally after the subcommand.

### Synopsis

```bash
pacioli [--non-interactive] [--version] [--help] <subcommand> ...
```

### Arguments

| Argument | Values | Default | Description |
|---|---|---|---|
| `--non-interactive` | flag | off | Disable the interactive mapping picker. Same as `PACIOLI_NON_INTERACTIVE=1` or `CI=1`. |
| `--version` | flag | — | Print the installed package version (read from `importlib.metadata`) and exit 0. Use this to confirm which wheel is actually installed before reporting an issue. |
| `--help` / `-h` | flag | — | Show the top-level usage banner and exit. |

## `pacioli scan`

The driver subcommand. Orchestrates Checkov per in-scope env.

### Synopsis

```bash
pacioli scan [--mode MODE] [--project P] [--env E]
              [--tier {source,plan,state}]
              [--dry-run] [--verbose]
              [--label TEXT]
              [target_dir]
```

### Arguments

| Argument | Values | Default | Description |
|---|---|---|---|
| `--mode` | `gate` \| `report` \| `audit` | `report` (or `gate` if `CI=1`) | `gate` exits non-zero on HIGH/CRITICAL. `report` never blocks; auto-aggregates. `audit` re-emits a prior report. |
| `--tier` | `source` \| `plan` \| `state` | `source` | Scan depth tier. `plan` adds `terraform init` + `terraform plan`. `state` adds the `.tfstate` blob download + drift diff (implies `plan`). |
| `--project` | `<project name>` | (no filter) | Filter the post-scope set of `in_scope` pairs to one project; it cannot add a pending or excluded project. |
| `--env` | `<env name>` | (no filter) | Filter the post-scope set of `in_scope` pairs to one environment; it cannot add a pending or excluded environment. |
| `--dry-run` | flag | off | Print every command without executing. Does not actually run Checkov or `terraform`. |
| `--verbose` | flag | off | Enable INFO-level logging. Same as `PACIOLI_VERBOSE=1`. |
| `--label` | `<text>` | (derived from scope) | Custom slug for the run-dir name. Sanitized to `[A-Za-z0-9_.-]`. Suffixes the UTC date. |
| `--no-open` | flag | off | Do not auto-open `report.html` after a successful aggregate. |
| `--init` | flag | off | Auto-create missing `.pacioli/scope.yaml` and `.pacioli/baseline.yaml` without prompting. Works in non-interactive environments (CI). |
| `--non-interactive` | flag | off | Disable the interactive mapping picker. Same as `PACIOLI_NON_INTERACTIVE=1` or `CI=1`. |
| `--help` / `-h` | flag | — | Show usage and exit. |

`--project` and `--env` run after `.pacioli/scope.yaml` has resolved the
in-scope project/environment set (including `scan_paths:`). They narrow an
already permitted scan scope; they do not change audit scope or override a
`pending`/`excluded` declaration.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (no HIGH/CRITICAL in gate mode, or report mode completed) |
| 1 | Audit mode not implemented; scope-manifest validation error (e.g. unknown field, wrong type in `.pacioli/scope.yaml`); or scan failed |
| 2 | Required input file missing (e.g. `.pacioli/scope.yaml`, `.pacioli/baseline.yaml`) |
| 7 | Aggregator found HIGH/CRITICAL findings (only used in gate mode where it matters; suppressed in report mode) |
| 64 | Invalid command-line argument |
| 99 | Safety guard refused a command (read-only invariant violation) |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PACIOLI_TARGET_REPO` | (cwd) | The consumer's Terraform repo (where `.pacioli/scope.yaml`, `.pacioli/baseline.yaml`, and `env/` live). |
| `PACIOLI_MAPPING` | `${PACIOLI_INSTALL_DIR}/mappings/pci_dss_4.0.1.yaml` | The framework mapping pack. Override with `--mapping <file>`. |
| `PACIOLI_STATE_STORAGE_ACCOUNT` | (empty) | Azure storage account for tier 2/3 state-blob access. **Required** for tier 2/3 and `pacioli audit`; the scanner refuses to run without it. |
| `PACIOLI_REPORTS_CONTAINER` | (empty) | Azure storage container for the `pacioli-reports` archive. **Required** for `pacioli audit`; refused if unset. |
| `PACIOLI_VERBOSE` | unset | Same as `--verbose`. |
| `CI` | unset | If set, `--mode report` is auto-promoted to `--mode gate`. |
| `PACIOLI_NON_INTERACTIVE` | unset | When truthy, suppress the interactive mapping picker. Same as `--non-interactive`. |
| `PYTHONIOENCODING` | `utf-8` | Forced by `scanner/_utf8.py` to avoid Windows cp1252 crashes. |
| `PYTHONUTF8` | `1` | Same. |
| `LC_ALL` / `LANG` | `C.UTF-8` | Same. |

### Auto-open behavior

By default, `pacioli scan`, `pacioli gate`, and `pacioli audit --out <path>`
open `report.html` in the OS default browser after the run completes.
Auto-open is suppressed when:

* `--no-open` is passed.
* `CI=1` is set (for `scan` and `gate`; audit ignores `CI` because it is
  always operator-initiated).
* No browser is registered (e.g. headless Linux without `xdg-open`) —
  in this case a WARN is logged and the scan exits 0; the report path
  is still printed on stdout.

To save the report into the scanned repo, use `--output-dir .`. The
report lands at `./aggregate/report.html` and is auto-opened.

### Interactive mapping picker

When `pacioli scan` is invoked in an interactive shell with no `--mapping`
and no `PACIOLI_MAPPING` set, and the run is interactive (no `CI=1`,
no `--non-interactive`, no `PACIOLI_NON_INTERACTIVE=1`, stdin is a TTY),
the scanner prints a numbered list of installed mapping packs and waits
for a selection. Each row shows the filename, framework name, and
framework version parsed from the YAML header (e.g. `1. pci_dss_4.0.1.yaml - PCI DSS 4.0.1`).

Pressing Esc, sending blank input, or selecting a number out of range
all raise the same `PathResolutionError` resolve_mapping raises — the
CLI exits with code 2, mirroring the existing "Mapping pack does not
exist" recovery path. To force a specific mapping without being
prompted, pass `--mapping <path>` or set `PACIOLI_MAPPING=<path>`.
See `scanner/mapping_picker.py` for the full contract.

### First-run scope+baseline bootstrap

When `pacioli scan` or `pacioli gate` is run and either `.pacioli/scope.yaml`
or `.pacioli/baseline.yaml` is missing, the CLI prompts you to create both
files (interactive shells only). The generated files use auto-discovered
IaC projects and environments across all Checkov-supported frameworks
(Terraform, CloudFormation, Kubernetes, Dockerfile, Bicep, Helm, OpenAPI,
etc.).

Pass `--init` to auto-create the files without prompting (works in CI):

```bash
pacioli scan --init .
```

Existing files are never overwritten. The bootstrap is skipped entirely
when stdin is not a TTY, `--non-interactive` is set,
`PACIOLI_NON_INTERACTIVE=1` is set, or `CI` is set (unless `--init` is
also passed).

### Examples

```bash
# Default — source-only scan, auto-aggregate, print report path
pacioli scan

# CI gate — source-only, exit non-zero on HIGH/CRITICAL
pacioli gate

# Source + plan — for the canonical env before merge to main
pacioli scan --tier plan --project myapp --env prod

# Source + plan + state-drift — for monthly deep reviews
pacioli scan --tier state

# Dry-run — see what would happen without doing it
pacioli scan --dry-run --project myapp --env prod

# Ad-hoc label
pacioli scan --label pre-deploy --project myapp --env prod
```

## `pacioli audit`

Re-emits a prior report from the `pacioli-reports` archive. No re-scan.

### Synopsis

```bash
pacioli audit [--run-id ID | --latest] [--out PATH] [--dry-run]
              [--source {local,remote}]
```

### Arguments

| Argument | Description |
|---|---|
| `--run-id <id>` | Specific run id to fetch (e.g. `20260804T153407Z-2455`). |
| `--latest` | Fetch the most recent run from the local archive or `pacioli-reports` container. |
| `--out <path>` | Optional destination for `report.html`. |
| `--source <src>` | `local` (default; reads `~/.pacioli/runs/`) or `remote` (`pacioli-reports` Azure container). |
| `--dry-run` | Print the blob-download commands without executing. |
| `--no-open` | Do not auto-open the `--out` destination after a successful audit. |
| `--help` / `-h` | Show usage. |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PACIOLI_STATE_STORAGE_ACCOUNT` | (empty) | Storage account. **Required** for `--source remote` — the scanner refuses to run if unset. |
| `PACIOLI_REPORTS_CONTAINER` | (empty) | Container holding the archived reports (typically `pacioli-reports`). **Required** for `--source remote`; refused if unset. |

## `pacioli baseline init`

Bulk-generates stub baseline entries from a prior run.

### Synopsis

```bash
pacioli baseline init <run_dir>
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `<run_dir>` | (required) | The run dir to read `combined.sarif` from. |

The output `.pacioli/baseline.yaml` entries have `TBD` for
`justification`, `owner`, `ticket_id`, `expires_on`. Triage
top-N by `hit_count`: populate the schema fields, and the
suppression takes effect. See
[Operator Guide → Baseline entry schema](OPERATOR_GUIDE.md#baseline-entry-schema).

## `pacioli aggregate`

The per-run aggregator. Converts per-env SARIFs into a single
HTML/CSV/JUnit report. Normally invoked by `pacioli scan` at the end
of `--mode report`, but can be re-run independently on a prior
run dir.

### Synopsis

```bash
pacioli aggregate <run_dir>
                  [--out OUT]
                  [--mapping MAPPING]
                  [--baseline BASELINE]
                  [--emit-fix-list]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `<run_dir>` | (required) | The run dir produced by `pacioli scan`. |
| `--out <path>` | `<run_dir>/aggregate/` | Output directory. |
| `--mapping <path>` | `${PACIOLI_MAPPING}` | Override the framework mapping. |
| `--baseline <path>` | `${PACIOLI_TARGET_REPO}/.pacioli/baseline.yaml` | Override the baseline. |
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
`pacioli scan` after every Checkov run, but exposed as a standalone
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
Checkov expects. Used by `pacioli scan --tier state`.

### Synopsis

```text
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

```text
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

## `scanner/safety.py` (`make selftest`)

Defines the read-only invariant. See [Safety Model](SAFETY_MODEL.md)
for the full list of refused patterns. The module can be invoked
directly to run the self-test:

```bash
python -m scanner.safety
# safety_selftest: PASS
```

This is the `make selftest` target.

## `scanner/orchestrator.py`

The driver module. Implements the per-(project, env) loop, run-dir
layout, scope parsing, storage firewall IP whitelist (and cleanup),
and the EXIT-trap-equivalent signal handling. Imported by
`scanner/cli.py` when `pacioli scan` or `pacioli gate` is invoked.

## Makefile targets

The wrapper Makefile (`examples/Makefile.consumer`, typically
copied to your repo as `Makefile.pacioli`) provides:

| Target | Underlying command |
|---|---|
| `make scan` | `pacioli scan [filters]` |
| `make scan-plan` | `pacioli scan --tier plan [filters]` |
| `make scan-state` | `pacioli scan --tier state [filters]` |
| `make scan-gate` | `pacioli gate [filters]` |
| `make scan-baseline-init` | `pacioli baseline init <RUN_DIR>` |
| `make scan-fix-list` | `pacioli aggregate <RUN_DIR> --emit-fix-list` |
| `make scan-cleanup` | Echoes the manual cleanup steps (no auto-remove) |
| `make test` | Delegates to the scanner repo's `make test` (pytest) |

Common args: `PROJECT=<p>`, `ENV=<e>`, `LABEL=<text>`,
`RUN_DIR=~/.pacioli/runs/current/<run_id>`.

The scanner's own `Makefile` (at the repo root) provides:

| Target | Underlying command |
|---|---|
| `make help` | Print the target list |
| `make test` | `cd scanner && PYTHONPATH=. pytest tests/ -v` |
| `make lint` | `ruff check scanner/` |
| `make selftest` | `python -m scanner.safety` |
| `make install` | `pip install -e .` |
| `make clean` | Remove `__pycache__`, `.pytest_cache`, build artifacts |

## See also

- [Operator Guide](OPERATOR_GUIDE.md) — narrative
- [Architecture](ARCHITECTURE.md) — how the pieces fit
- [Consuming Pacioli](CONSUMING_GUIDE.md) — first-time setup
- [Safety Model](SAFETY_MODEL.md) — the read-only invariant
- [Report Format](REPORT_FORMAT.md) — every output file
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
