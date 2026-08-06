# Pacioli — Developer Guide

This document is for people extending the Pacioli scanner itself —
adding a custom check, adding a new framework mapping pack, fixing a
bug, or contributing a PR. It assumes you have read
[Architecture](ARCHITECTURE.md) so you know how the pieces fit
together.

For running the scanner, see [Operator Guide](OPERATOR_GUIDE.md).
For the read-only invariant, see [Safety Model](SAFETY_MODEL.md).

## Repository layout

```
.
├── Makefile                          # test / lint / selftest / install / clean
├── pyproject.toml                    # Python packaging metadata
├── pytest.ini                        # pytest config
├── CITATION.cff                      # CFF for academic citation
├── LICENSE                           # Apache 2.0
├── CONTRIBUTING.md                   # PR / issue workflow
├── SECURITY.md                       # Vulnerability reporting
├── SUPPORT.md                        # Where to get help
├── CODE_OF_CONDUCT.md                # Contributor Covenant 2.1
├── docs/                             # All long-form documentation
│   ├── INDEX.md                      # Master table of contents
│   ├── CONSUMING_GUIDE.md            # First-time consumer setup
│   ├── OPERATOR_GUIDE.md             # Full operator runbook
│   ├── ARCHITECTURE.md               # How the scanner is put together
│   ├── DEVELOPER_GUIDE.md            # (this file)
│   ├── SAFETY_MODEL.md               # Read-only invariant
│   ├── CLI_REFERENCE.md              # Every argument + env var
│   ├── MAPPING_SCHEMA.md             # mappings/*.yaml format
│   ├── CHECK_AUTHORING.md            # Adding a CKV_AZURE_PCI_* check
│   ├── REPORT_FORMAT.md              # Every output file
│   └── TROUBLESHOOTING.md            # Common failures
├── examples/
│   ├── scope.yaml.example            # Template pci_scope.yaml
│   ├── baseline.yaml.example         # Template pci_baseline.yaml
│   └── Makefile.consumer             # Wrapper Makefile template
├── mappings/
│   └── pci_dss_4.0.1.yaml            # The shipped PCI mapping pack
├── scanner/
│   ├── scan.sh                       # Driver
│   ├── scan_audit.sh                 # Audit (re-emit from archive)
│   ├── scan_baseline_init.sh         # Bulk-generate baseline stubs
│   ├── aggregate.py                  # Aggregator
│   ├── rewrite_sarif_help.py         # SARIF helpUri rewriter
│   ├── checkov_url_overrides.py      # Canonical rule-URL table
│   ├── tfstate_to_plan.py            # .tfstate → plan-JSON shape
│   ├── drift_report.py               # Plan vs state diff
│   ├── terraform_remediation.yaml    # Canonical azurerm 4.x fixes
│   ├── requirements-pinned.txt       # Pinned dependencies
│   ├── checks/                       # Custom PaaC checks
│   │   ├── CKV_AZURE_PCI_001__lifecycle_ignore_changes.py
│   │   ├── CKV_AZURE_PCI_002__storage_default_deny.py
│   │   ├── CKV_AZURE_PCI_003__tls_min_version.py
│   │   ├── CKV_AZURE_PCI_004__cmk_required.py
│   │   └── CKV_AZURE_PCI_005__kv_purge_protection.py
│   ├── lib/                          # Bash helpers
│   │   ├── common.sh
│   │   └── safety.sh
│   └── tests/                        # pytest suite
│       ├── conftest.py
│       ├── test_aggregate_pci.py
│       ├── test_checkov_url_overrides.py
│       ├── test_rewrite_sarif_help.py
│       └── test_terraform_remediation_yaml.py
└── .github/
    ├── workflows/ci.yml              # CI: test + lint + selftest
    ├── ISSUE_TEMPLATE/               # Issue templates
    ├── PULL_REQUEST_TEMPLATE.md
    ├── CODEOWNERS
    └── FUNDING.yml
```

## Development environment

```bash
# Clone
git clone https://github.com/ORG/pacioli.git
cd pacioli

# Python deps
python -m pip install -r scanner/requirements-pinned.txt
python -m pip install pytest pyyaml

# jq (used by scan.sh for JSON queries)
# macOS:
brew install jq
# Debian / Ubuntu:
sudo apt-get install -y jq

# shellcheck (optional, for `make lint`)
# macOS:
brew install shellcheck
# Debian / Ubuntu:
sudo apt-get install -y shellcheck
```

## The test suite

```bash
# Run pytest
make test

# Run shell lint + Python compile
make lint

# Run the safety self-test (refuse_if_mutating invariants)
make selftest
```

`make test` runs all 35 tests across 4 files:

| Test file | What it covers |
|---|---|
| `test_aggregate_pci.py` | Mapping loader, OOS validation, baseline loader |
| `test_checkov_url_overrides.py` | URL table integrity, get_help_uri fallback, sed filter shape |
| `test_rewrite_sarif_help.py` | SARIF rewrite, idempotency, missing-file handling, mixed rules |
| `test_terraform_remediation_yaml.py` | YAML schema, minimum entry count, required fields |

`make selftest` runs `lib/safety.sh` directly. It tests that the
read-only invariant refuses every command on the
`should_refuse` list and accepts every command on the
`should_allow` list. The script is run via:

```bash
bash scanner/lib/safety.sh
```

When sourced from `lib/common.sh` (which is what `scan.sh` does),
the `__SAFETY_SH_LOADED` guard prevents the test from running
automatically; only an explicit invocation of `make selftest`
runs it.

## Code style

### Python

- 3.12+ syntax. `from __future__ import annotations` at the top of
  every module.
- Type hints on every public function signature (private helpers can
  omit them).
- 4-space indent, double-quoted strings, trailing commas in
  multi-line container literals.
- `argparse` for CLI parsers (no `click`, no `typer`).
- `pathlib.Path` for filesystem paths.
- `dataclasses` for value types.
- Logging to stderr; only `print` for end-user output (the report
  HTML is fine to print but no logging should go to stdout).
- Imports ordered: stdlib, then third-party, then local (no blank
  line between groups is fine; the codebase uses no blank line).
- The UTF-8 env-var bootstrap (`PYTHONIOENCODING=utf-8`,
  `PYTHONUTF8=1`, `sys.stdout.reconfigure`) is mandatory in every
  module that opens files or prints. The reason: Windows cp1252
  crashes on byte 0x8F (the second byte of `⏳` and `⚠` UTF-8
  sequences), and Checkov's `.tf` parser does not override the
  encoding.

### Bash

- `set -uo pipefail` at the top of every executable script
  (not `-e` — we want to handle failures explicitly and continue past
  a non-critical step).
- Always run external commands through `run_cmd` (driver) or
  `safe_run_exec` (`common.sh`) so the safety guard is enforced.
- Quote everything. `[[ -n "$x" ]]`, not `[[ -n $x ]]`.
- Use `pci_log INFO|WARN|ERROR` instead of bare `echo`.
- Source `lib/common.sh` first (which sources `lib/safety.sh`).
- The `__SOMETHING_SH_LOADED` source guard pattern prevents
  double-sourcing and is required on `lib/safety.sh` and
  `lib/common.sh`.
- `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"` at the
  top so helpers can find each other regardless of CWD.
- No `realpath` — it does not resolve `S:/` paths on Windows MSYS
  Git Bash. Use the `cd && pwd` idiom instead.

### Commit messages

- Present tense imperative ("add", not "added").
- First line ≤ 72 characters, capitalized.
- Body should reference the issue or describe the *why*, not the
  *what* (the diff shows the *what*).
- Use one of these prefixes so the change shows up correctly in
  tooling:
  - `feat:` — new feature
  - `fix:` — bug fix
  - `docs:` — documentation only
  - `chore:` — housekeeping (deps, CI, formatting)
  - `refactor:` — no behavior change
  - `severity:` — new entry in `SEVERITY_OVERRIDE`
  - `mapping:` — change to `mappings/*.yaml`
  - `safety:` — change to `lib/safety.sh`

### Branches

- `feature/<short-slug>` — new feature
- `fix/<short-slug>` — bug fix
- `docs/<short-slug>` — documentation
- `chore/<short-slug>` — housekeeping

## Adding a custom Checkov check

See [Check Authoring](CHECK_AUTHORING.md) for a full walkthrough.
TL;DR:

1. Create `scanner/checks/CKV_AZURE_PCI_<NNN>__<name>.py`.
2. Use the next available PCI check ID.
3. Inherit from `BaseResourceCheck`; implement `scan_resource_conf`.
4. Anchor the check to a PCI req by adding a row to
   `mappings/pci_dss_4.0.1.yaml`.
5. Add an entry to `SEVERITY_OVERRIDE` in `aggregate.py` if the
   default `MEDIUM` is wrong.
6. Add a remediation block to `terraform_remediation.yaml` if one
   applies.
7. Add a test under `scanner/tests/`.

## Adding a mapping row

See [Mapping Schema](MAPPING_SCHEMA.md) for the full schema. The
short version:

```yaml
# in mappings/pci_dss_4.0.1.yaml
- id: 1.2.1
  title: Configuration standards for NSCs are defined and implemented
  checks:
    - CKV_AZURE_<N>
  note: "Why this rule satisfies 1.2.1; verbatim PCI SSC citation if non-obvious"
```

`pci_mapping.yaml` (in the consumer's repo) is a local override
copy; the upstream mapping pack is the one in `mappings/`.

## Adding a remediation block

In `scanner/terraform_remediation.yaml`:

```yaml
- check_id: CKV_AZURE_<N>
  resource_type: azurerm_<service>
  current_problem: <one-line verbatim from checkov --list>
  remediation_hcl: |
    resource "azurerm_<service>" "example" {
      ...
    }
  verification_step: <one-line command + expected outcome>
  provenance: <registry.terraform.io URL for the canonical attribute docs>
```

The pytest test `test_terraform_remediation_yaml.py` enforces:

- ≥ 68 entries.
- Every block has all 5 required fields.
- HCL is multi-line (not a one-liner).
- `verification_step` is non-empty.
- `INTENTIONALLY_ABSENT` check IDs are not in the file.

## Adding a refusal pattern to the safety guard

See [Safety Model](SAFETY_MODEL.md#extending). The short version:

```bash
# in scanner/lib/safety.sh
declare -a REFUSE_PATTERN+=(  # note the += to append, not =
  'terraform[[:space:]]+console\b'
)
declare -A REFUSE_REASON+=(
  ['terraform[[:space:]]+console\b']='Terraform console is interactive. Forbidden.'
)
```

Add a test case in `safety_selftest`:

```bash
local -a should_refuse=(
  "terraform apply -auto-approve"
  ...
  "terraform console"   # <-- new
)
```

Then verify with `make selftest`.

## Working with the URL override table

When a Checkov rule's URL is broken (or wrong), add it to
`scanner/checkov_url_overrides.py`:

```python
RULE_SOURCE_URLS["CKV_AZURE_<N>"] = "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/<File>.py"
```

The URL MUST end in a real file (`.py` or `.yaml`) and MUST point
at the canonical `bridgecrewio/checkov` GitHub repository. The
pytest test `test_checkov_url_overrides.py` enforces both.

The aggregator, the SARIF rewriter, and the shell CLI filter all
pick the new entry up automatically — there is no second place to
edit.

## What to do when Checkov upstream changes

Checkov is pinned in `scanner/requirements-pinned.txt` to an exact
version (`checkov==3.3.9`). When a new Checkov release is published:

1. Bump the pin in a dedicated PR titled
   `chore: bump checkov <old> -> <new>`.
2. Run `make test` — many pytest tests will fail if rules have
   been renumbered.
3. Run `bash scanner/scan.sh --mode report --project <test-env> --env prod`
   against the golden env.
4. Diff the SARIF against the prior run:
   - New rule IDs that fired → add to `mappings/pci_dss_4.0.1.yaml`.
   - Rule IDs that disappeared → remove from mappings or remap.
   - Severities that changed → update `SEVERITY_OVERRIDE`.
5. Bump `verified_against` in `mappings/pci_dss_4.0.1.yaml`.
6. Commit the mapping changes as a separate PR titled
   `mapping: refresh for checkov <new>`.

The "Defect anchor: P2-02" comment at the top of
`requirements-pinned.txt` documents the original reason for the
exact pin; keep that comment in sync with the new pin.

## CI

The CI pipeline (`.github/workflows/ci.yml`) runs on every push to
`main` and every PR. It has three jobs:

1. **test** — `pytest` on Python 3.12.
2. **shellcheck** — `shellcheck` over the four shell scripts +
   `lib/common.sh` + `lib/safety.sh`, plus `make selftest` for the
   safety invariants.
3. **mapping-lint** — validates the `mappings/pci_dss_4.0.1.yaml`
   schema and OOS entries.

A PR cannot merge unless all three pass.

## Releasing

Pacioli does not have a tagged-release cadence yet. When the first
release is cut:

1. Pick a version (semver; 0.x.y is OK until 1.0).
2. Update `version` in `pyproject.toml` and `CITATION.cff`.
3. Add a `CHANGELOG.md` entry under the new version.
4. Tag the commit (`git tag v0.1.0`).
5. Push the tag (`git push origin v0.1.0`).
6. Optionally, build a sdist/wheel with `python -m build` and
   upload to PyPI with `python -m twine upload dist/*`.

## See also

- [Architecture](ARCHITECTURE.md) — how the scanner is put together
- [Check Authoring](CHECK_AUTHORING.md) — adding a custom check
- [Mapping Schema](MAPPING_SCHEMA.md) — mapping YAML format
- [Safety Model](SAFETY_MODEL.md) — read-only invariant + extension
- [CLI Reference](CLI_REFERENCE.md) — every argument
- [Report Format](REPORT_FORMAT.md) — every output file
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
