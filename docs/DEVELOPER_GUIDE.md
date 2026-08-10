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
│   ├── cli.py                        # CLI entry point (`pacioli` / `python -m scanner.cli`)
│   ├── orchestrator.py               # Driver; orchestrates Checkov per env
│   ├── aggregate.py                  # Aggregator (SARIF → HTML/CSV/JUnit)
│   ├── baseline_init.py              # Bulk-generate baseline stubs
│   ├── safety.py                     # Read-only invariant (`SafetyGuard`)
│   ├── trap.py                       # Signal/atexit cleanup (IP + plan shred)
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
│   └── tests/                        # pytest suite
│       ├── conftest.py
│       ├── test_aggregate_html.py            (new)
│       ├── test_aggregate_pci.py
│       ├── test_baseline_parity.py
│       ├── test_checkov_runner.py
│       ├── test_checkov_url_overrides.py
│       ├── test_checks.py                    (new)
│       ├── test_cli.py
│       ├── test_config.py
│       ├── test_discovery.py
│       ├── test_drift_report.py              (new)
│       ├── test_mapping_pack_rules.py        (new)
│       ├── test_orchestrator.py
│       ├── test_paths.py
│       ├── test_rewrite_sarif_help.py
│       ├── test_safety.py
│       ├── test_terraform_remediation_yaml.py
│       ├── test_tfstate_to_plan.py           (new)
│       ├── test_trap.py
│       ├── test_url_rewrite.py               (new)
│       └── test_utf8.py                      (new)
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
git clone https://github.com/JosiahSiegel/pacioli.git
cd pacioli

# Python deps
python -m pip install -r scanner/requirements-pinned.txt
python -m pip install pytest pyyaml

# ruff (optional, for `make lint`)
# macOS:
brew install ruff
# Debian / Ubuntu:
pip install ruff
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

`make test` runs all 348 tests across 20 files:

| Test file | What it covers |
|---|---|
| `test_aggregate_pci.py` | Mapping loader, OOS validation, baseline loader |
| `test_checkov_url_overrides.py` | URL table integrity, get_help_uri fallback, sed filter shape |
| `test_rewrite_sarif_help.py` | SARIF rewrite, idempotency, missing-file handling, mixed rules |
| `test_terraform_remediation_yaml.py` | YAML schema, minimum entry count, required fields |

`make selftest` runs `scanner/safety.py` directly via
`python -m scanner.safety`. It tests that the
read-only invariant refuses every command on the
`should_refuse` list and accepts every command on the
`should_allow` list. The selftest is run via:

```bash
python -m scanner.safety
```

The selftest runs only when the module is invoked directly
(`python -m scanner.safety`); importing `scanner/safety.py` from
`scanner/orchestrator.py` does not trigger it. CI runs the
selftest explicitly via `make selftest`.

## Code style

### Python

- 3.13+ syntax. `from __future__ import annotations` at the top of
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

### Python (process-spawn conventions)

- Every external command MUST go through the process-spawn helpers
  in `scanner/orchestrator.py`. Both call
  `SafetyGuard.refuse_if_mutating(cmd)` first; a refusal raises
  `scanner.safety.MutatingOperationRefused` and the scanner exits
  with code 99.
- Do not invoke `subprocess.run` (or `os.system`, or
  `subprocess.Popen`) directly from driver code — you will bypass
  the safety guard.
- For dry-run support, route the call through the guarded-runner
  helper and pass `dry_run=True` (or set `DRY_RUN=1` in the
  environment); the helper prints the command instead of executing
  it.

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
  - `safety:` — change to `scanner/safety.py`

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

```python
# in scanner/safety.py
REFUSE_PATTERN = REFUSE_PATTERN + (   # tuple, so use + (not += for tuple)
    r"terraform\s+console\b",
)
REFUSE_REASON[r"terraform\s+console\b"] = "Terraform console is interactive. Forbidden."
```

Add a test case in `safety_selftest`:

```python
should_refuse = [
    "terraform apply -auto-approve",
    # ...
    "terraform console",   # <-- new
]
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
3. Run `pacioli scan --project <test-env> --env prod <test-env>`
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
2. **lint + selftest** — `ruff check scanner/` over the Python
   package, plus `make selftest` for the safety invariants.
3. **mapping-lint** — validates the `mappings/pci_dss_4.0.1.yaml`
   schema and OOS entries.

A PR cannot merge unless all three pass.

## Releasing

Releases are automated end-to-end. Contributors write
[Conventional Commits](../../CONTRIBUTING.md#commit-messages); two
GitHub Actions workflows do the rest.

**.github/workflows/release-please.yml** runs on every push to
`main` and opens (or updates) a release PR titled
`chore(main): release <next-version>`. The PR body is the draft
changelog grouped by commit type.

Merging the release PR:

- bumps `version` in `pyproject.toml` and `CITATION.cff`,
- moves `[Unreleased]` entries in `CHANGELOG.md` into a dated
  `## [X.Y.Z] - <today>` block, and
- creates the `vX.Y.Z` git tag on the merge commit.

**.github/workflows/release.yml** triggers on any pushed `v*` tag.
It builds the wheel + sdist with `python -m build`, attaches both
artifacts to the matching GitHub Release, and signs them with a
GitHub OIDC provenance attestation via
`actions/attest-build-provenance@v1`. Consumers verify the wheel
with `gh attestation verify`.

There's no manual version bump, no manual changelog edit, and no
manual tag. To cut a release, merge the release PR release-please
opens.

## See also

- [Architecture](ARCHITECTURE.md) — how the scanner is put together
- [Check Authoring](CHECK_AUTHORING.md) — adding a custom check
- [Mapping Schema](MAPPING_SCHEMA.md) — mapping YAML format
- [Safety Model](SAFETY_MODEL.md) — read-only invariant + extension
- [CLI Reference](CLI_REFERENCE.md) — every argument
- [Report Format](REPORT_FORMAT.md) — every output file
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
