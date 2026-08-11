# Pacioli — Troubleshooting

> **Common failure modes and how to fix them.** Use this when
> something doesn't work; use [Operator Guide](OPERATOR_GUIDE.md)
> when you're not sure what to do at all.

For a quick orientation on what the scanner does, see
[Consuming Pacioli](CONSUMING_GUIDE.md).

## Setup failures

### `checkov: command not found`

Checkov is not installed. Run:

```bash
make install
# or
pip install -r scanner/requirements-pinned.txt
```

Confirm with:

```bash
checkov --version
# 3.3.9
```

### `jq: command not found`

Pacioli's Python CLI does not require `jq`. If you have an older
shell-based integration that still references `jq`, install it:

```bash
# macOS
brew install jq

# Debian / Ubuntu
sudo apt-get install -y jq

# Windows
choco install jq
```

### `python: command not found` or wrong version

The driver and aggregator require Python 3.13+.

```bash
python --version
# Python 3.13.x
```

If `python` is older or absent:

```bash
# macOS
brew install python@3.12

# Debian / Ubuntu
sudo apt-get install -y python3.12

# Windows
winget install Python.Python.3.12
```

### `ModuleNotFoundError: No module named 'yaml'`

PyYAML is missing:

```bash
pip install pyyaml
```

### `ModuleNotFoundError: No module named 'checkov'`

Checkov is missing. See the `checkov: command not found` section
above.

## Scan-time failures

### `REFUSED: ...`

The safety guard caught a command. The message names the refused
pattern and the reason:

```
REFUSED: Terraform apply mutates Azure. Forbidden by the scanner's read-only safety guard. Use the scanner for read-only scans only.
         Command: terraform apply
```

This is the scanner doing its job. If the command is genuinely
necessary, open a discussion in an issue — never bypass the
guard.

### `required file not found: .../pci_scope.yaml`

`pci_scope.yaml` (or `pci_baseline.yaml`) is missing from the
consumer's Terraform repo. Copy from the templates:

```bash
cp examples/scope.yaml.example ./pci_scope.yaml
cp examples/baseline.yaml.example ./pci_baseline.yaml
```

Edit them for your projects. See
[Consuming Pacioli → Step 3](CONSUMING_GUIDE.md#step-3-create-the-scope-file).

### `ACCESS REQUIRED: ...`

A tier that needs remote state or another protected input could not reach
its resource. This is an alert-only condition. Pacioli does not change Azure
firewall rules or grant access.

The alert uses this format:

```text
ACCESS REQUIRED: <operation> cannot reach <resource>.
  Required access: <access requirement>.
  Action: grant access outside Pacioli, then rerun the scan.
  No Azure firewall changes were made by Pacioli.
```

Grant the required access through your normal network and identity controls,
then rerun the affected tier. A skipped layer is not evidence that the layer
passed.

### `terraform init failed for <project>/<env>; skipping plan layer`

`terraform init -backend=false` errored. Plan-tier initialization still
resolves providers and modules, so it is not offline. Common causes include:

- Network restriction: resolution from `registry.terraform.io` is blocked.
  Use the scanner's `--registry-mirror` option with an isolated
  `TF_CLI_CONFIG_FILE` that points at an approved mirror.
- Backend configuration or module resolution errors in the environment.
- Provider authentication or local dependency problems.

Re-run with `--verbose` for the Checkov and Terraform output:

```bash
pacioli scan --tier plan --project <p> --env <e> --verbose
```

### `terraform plan failed for <project>/<env>; skipping plan layer`

The plan failed. Common causes:

- State lock held by another process. Find and release it:
  ```bash
  az storage account show --name <account> --query primaryEndpoints.blob
  # then look for the .tflock file in the iac container
  ```
- Pre-condition failure: the env references an Azure resource
  that does not exist. Run `terraform plan` manually against the
  env to see the error.

### `az storage blob download ... 403`

The state-dependent layer cannot access the configured storage account.
Pacioli does not add an IP to an allow list. Look for the `ACCESS REQUIRED`
alert, grant the required access outside Pacioli, and rerun the scan. If the
access policy is intentionally restrictive, accept that the state layer is
unavailable and treat its results as incomplete.

### `ERROR  Mapping pack does not exist` on `pacioli scan`

You're hitting a v0.1.0 (and earlier) bug where `scanner/paths.py:resolve_mapping` only looked at `<install-root>/mappings/pci_dss_4.0.1.yaml` — i.e. the `site-packages/mappings/` directory, which never receives the mapping YAML under wheel installs. The mapping is actually shipped at `site-packages/scanner/mappings/pci_dss_4.0.1.yaml` (inside the `scanner` package).
**Upgrade to v0.1.1+** (`pip install --upgrade pacioli`) — the importlib.resources fallback in `resolve_mapping` locates the bundled mapping correctly. If you must stay on ≤ v0.1.0, pass `--mapping /path/to/scanner/mappings/pci_dss_4.0.1.yaml` explicitly.

### `combined.sarif not found in <run-dir>/aggregate/ — run aggregate first`

You ran `pacioli baseline init` before `pacioli aggregate`. Order
matters:

1. `pacioli scan` → produces per-env SARIFs.
2. `pacioli aggregate <run_dir>` (or `pacioli scan` which calls
   it automatically) → produces `combined.sarif`.
3. `pacioli baseline init <run_dir>` → reads `combined.sarif`
   to generate stub baseline entries.

## Aggregate-time failures

### `PyYAML is required. Install with: pip install pyyaml`

```bash
pip install pyyaml
```

### `out_of_scope <id>: missing required field '<field>'`

The `out_of_scope_requirements` entry in `mappings/<framework>.yaml`
is missing a required field. The full list:

- `id`
- `title`
- `rationale`
- `control_owner`
- `approved_on`
- `expires_on`
- `evidence_link`

Fix the YAML and re-run.

### `out_of_scope <id>: field '<field>' is still 'TBD'`

A field is set to the literal string `TBD`. The aggregator
refuses this — it must be filled in with a concrete value before
producing a report. (The whole point of the refusal is to catch
half-filled waivers that slip through review.)

### `out_of_scope <id>: approved_on <date> is AFTER expires_on <date>`

The approval date is later than the expiration date. The
aggregator refuses because the entry is illogical. Fix the dates
or remove the entry.

### `drift_report.py: KeyError: 'summary'`

The drift report file is malformed. The most likely cause is a
tier 1/2 scan producing an empty `drift_report.json` that the
aggregator then tries to parse. Tier 1/2 should not produce a
drift report at all — confirm the scan tier.

## Report-rendering failures

### Report HTML opens but findings show 0

The scan tier was 2 or 3 but the state layer failed. The
dashboard KPIs reflect only the layers that succeeded. Open
`report.html` → `#dashboard` to see which envs are marked
`failed_to_plan` or `no_sarif`.

### Cross-filtering not working (clicking a heatmap cell does nothing)

The report was opened from the file system and the browser
blocked the script. The SPA JS is inline (no external
dependencies), so this should not happen with a static file open.
If it does, open the browser's dev tools console and look for
the actual error.

### `report.html` reports "framework_name not found"

The `mappings/<framework>.yaml` file is missing the
`framework_name` top-level key. The aggregator falls back to
`PCI DSS` for the title but logs a warning. Add the key:

```yaml
framework_name: SOC 2
framework_version: '2017'
```

## Test failures

### `make test` fails

Run pytest directly for a clearer traceback:

```bash
cd scanner && PYTHONPATH=. pytest tests/ -v
```

The most common failures:

- `INTENTIONALLY_ABSENT` mismatch — you added a remediation to a
  check that was marked intentionally absent. Remove it from
  `INTENTIONALLY_ABSENT` in `test_terraform_remediation_yaml.py`.
- Missing required field in `terraform_remediation.yaml` — add
  the field.
- URL override removed or wrong — the test
  `test_checkov_url_overrides.py` enforces that every URL ends
  in `.py` or `.yaml` and points to `github.com`.

### `make selftest` fails

`scanner/safety.py` rejected one of the `should_refuse` test
cases (or accepted one of the `should_allow` cases). The
selftest is the most reliable safety net — if it fails, a
recent change likely weakened the safety guard.

1. Run `python -m scanner.safety` for the full error.
2. Identify which command was misclassified.
3. Either add the new pattern to `REFUSE_PATTERN` (and a test
   case to `should_refuse`), or remove the misclassified pattern.
4. Re-run `make selftest`.

## Performance issues

### Scan takes > 5 minutes per env (tier 1)

Tier 1 should be seconds. The most common cause is the
`--external-checks-dir` arg being applied to a non-existent
directory, which makes Checkov traverse the parent looking for
checks. Confirm:

```bash
ls -la scanner/checks/
# should list 5 .py files plus __init__.py
```

If the directory is empty, the five custom PCI checks are
missing — re-clone the repo or restore them from the
`CKV_AZURE_PCI_001..005` sources.

### Scan takes > 30 minutes per env (tier 2/3)

Tier 2/3 cost is dominated by:

1. `terraform init` — provider download. First run is slow;
   subsequent runs are cached.
2. `terraform plan` — depends on the number of resources in the
   env. Hundreds of resources → minutes.
3. `terraform refresh` — pulls live state from Azure. Slow if
   the storage account is in a different region.
4. State blob download + parse + Checkov pass — seconds.

To profile, add `--verbose` and look for the per-step timing
in the log. If `terraform plan` is the bottleneck, the
underlying issue is the env's resource count and not something
the scanner can fix.

## Specific to state scan (tier 3)

### `no module.tfstate` — backend key not found

The orchestrator derives the state blob name from the env's
`terraform.aztfexport.tf` `key = "..."` line. If the line is
missing, it falls back to a synthesized name
(`CR_<Env-prefix>_<project>.tfstate`). If neither works, the
state blob cannot be downloaded.

The default key format expected by the orchestrator:

```hcl
# in env/<project>/<env>/terraform.aztfexport.tf
terraform {
  backend "azurerm" {
    container_name = "iac"
    key            = "CR_Prod_<project>.tfstate"
    ...
  }
}
```

If your keys have a different naming convention, edit the
fallback in `scanner/orchestrator.py` (search for
`CR_<Env-prefix>`).

### Drift report is empty but the operator knows there is drift

The most common cause is a state blob that was downloaded but
not refreshed recently. `tfstate_to_plan.py` reads the
attributes as they were at the last `terraform apply`; if a
manual Azure change was made AFTER the last apply, the state
blob does not reflect it until the next `terraform refresh`.

Solution: re-run `pacioli scan --tier state` after a fresh
`terraform refresh` in the env.

## Still stuck?

- Search the [GitHub issues](https://github.com/JosiahSiegel/pacioli/issues)
  for the symptom.
- Open a [new issue](https://github.com/JosiahSiegel/pacioli/issues/new/choose)
  with:
  - The exact command you ran.
  - The full output (including `pci_log` lines).
  - `checkov --version`, `python --version`, `uname -a`.
  - A minimal `.tf` snippet if the failure is in a specific check.

## See also

- [Operator Guide](OPERATOR_GUIDE.md) — workflow-level narrative
- [Architecture](ARCHITECTURE.md) — how the pieces fit
- [CLI Reference](CLI_REFERENCE.md) — every argument
- [Safety Model](SAFETY_MODEL.md) — the read-only invariant
