# Contributing to Pacioli

Thanks for your interest in improving Pacioli. This document covers
how to file issues, submit pull requests, add new mappings or
remediations, and contribute a new framework pack.

For deep development workflow, see
[docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md). For the
read-only invariant and how to extend the safety guard, see
[docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md). For how the pieces
fit together, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Code of conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating, you agree to abide by its terms.

## Project structure

```
.
├── Makefile                         # test / lint / selftest / install / clean
├── pyproject.toml                   # Python packaging metadata
├── pytest.ini                       # pytest config
├── LICENSE                          # Apache 2.0
├── CONTRIBUTING.md                  # (this file)
├── SECURITY.md                      # Vulnerability reporting
├── SUPPORT.md                       # Where to get help
├── CODE_OF_CONDUCT.md               # Contributor Covenant 2.1
├── CITATION.cff                     # CFF for academic citation
├── docs/                            # Long-form documentation (see docs/INDEX.md)
│   ├── INDEX.md
│   ├── CONSUMING_GUIDE.md           # First-time consumer setup
│   ├── OPERATOR_GUIDE.md            # Full operator runbook
│   ├── ARCHITECTURE.md              # How the scanner is put together
│   ├── DEVELOPER_GUIDE.md           # Extending the scanner
│   ├── SAFETY_MODEL.md              # Read-only invariant
│   ├── CLI_REFERENCE.md             # Every argument + env var
│   ├── MAPPING_SCHEMA.md            # Mapping YAML format
│   ├── CHECK_AUTHORING.md           # Adding a CKV_AZURE_PCI_* check
│   ├── REPORT_FORMAT.md             # Every output file
│   └── TROUBLESHOOTING.md           # Common failures
├── examples/
│   ├── scope.yaml.example           # Template pci_scope.yaml
│   ├── baseline.yaml.example        # Template pci_baseline.yaml
│   └── Makefile.consumer            # Wrapper Makefile template
├── mappings/
│   └── pci_dss_4.0.1.yaml           # The shipped PCI mapping pack
├── scanner/
│   ├── scan.sh                      # Driver; orchestrates Checkov
│   ├── scan_audit.sh                # Audit (re-emit from archive)
│   ├── scan_baseline_init.sh        # Bulk-generate baseline stubs
│   ├── aggregate.py                 # SARIF → HTML/CSV/JUnit
│   ├── rewrite_sarif_help.py        # Post-processor: fixes helpUri
│   ├── checkov_url_overrides.py     # Canonical rule-URL table
│   ├── tfstate_to_plan.py           # .tfstate → plan-JSON shape
│   ├── drift_report.py              # Plan vs state diff
│   ├── terraform_remediation.yaml   # Canonical azurerm 4.x fixes
│   ├── requirements-pinned.txt      # Pinned dependencies
│   ├── checks/                      # Custom PaaC checks
│   │   ├── CKV_AZURE_PCI_001__lifecycle_ignore_changes.py
│   │   ├── CKV_AZURE_PCI_002__storage_default_deny.py
│   │   ├── CKV_AZURE_PCI_003__tls_min_version.py
│   │   ├── CKV_AZURE_PCI_004__cmk_required.py
│   │   └── CKV_AZURE_PCI_005__kv_purge_protection.py
│   ├── lib/                         # Bash helpers
│   │   ├── safety.sh                # READ-ONLY invariant
│   │   └── common.sh                # Paths, run-id, IP whitelist helpers
│   └── tests/                       # pytest suite
└── .github/
    ├── workflows/ci.yml             # CI: test + lint + selftest
    ├── ISSUE_TEMPLATE/              # Issue templates
    ├── PULL_REQUEST_TEMPLATE.md
    ├── CODEOWNERS
    └── FUNDING.yml
```

## Filing issues

Use the GitHub issue tracker. Pick the right template:

- **Bug report** — something doesn't work.
- **Feature request** — new functionality.
- **Mapping suggestion** — add a Checkov rule to a framework
  mapping.
- **Question** — usage question (also see [SUPPORT.md](SUPPORT.md)
  first).

For security issues, **do not file a public GitHub issue**. See
[SECURITY.md](SECURITY.md).

## Pull requests

1. Fork the repo and create a branch (`feature/<short-slug>`,
   `fix/<short-slug>`, `docs/<short-slug>`, `chore/<short-slug>`).
2. Make your changes. Follow the style guide below.
3. Run `make test`, `make lint`, and `make selftest`. All three
   must pass.
4. If you changed a mapping or a remediation, run a real scan
   against a fixture env and confirm the change is what you
   intended.
5. Use the PR template. Reference any related issue.
6. Maintainers will review within a few business days.

### Project-specific commit scopes

Use a Conventional Commits **scope** when a change is local to a
specific area of the codebase. (See the "Commit messages" section
above for the full grammar.)

- `feat(severity):` or `fix(severity):` — change to `SEVERITY_OVERRIDE`
- `feat(mapping):` or `fix(mapping):` — change to `mappings/*.yaml`
- `feat(safety):` or `fix(safety):` — change to `lib/safety.sh`
- `feat(scanner):` or `fix(scanner):` — change to the `scanner/`
  Python package
- `feat(release):` or `fix(release):` — change to the release
  pipeline (`.github/release-please-config.json`,
  `.github/workflows/release*.yml`)

Example:

```
fix(severity): add PCI_REQ_8.3.4 to HIGH-severity override
```

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/)
so release-please can derive the next version and the
Keep-a-Changelog-style release notes automatically. Every commit
message MUST start with one of these types:

- `feat:` — new user-facing capability (triggers a minor bump)
- `fix:` — bug fix (triggers a patch bump)
- `perf:` — performance improvement (triggers a patch bump)
- `refactor:` — code change that neither fixes a bug nor adds a
  feature (patch bump)
- `docs:` — documentation only (no version bump)
- `test:` — test additions or corrections (no version bump)
- `build:` — build system or dependency changes (no version bump)
- `ci:` — CI configuration changes (no version bump)
- `chore:` — tooling or maintenance (no version bump)
- `revert:` — reverts a previous commit

Example `feat:` commit with a body:

```
feat(scanner): add --tier state flag for .tfstate drift scans

Allows operators to point Pacioli at a Terraform state file blob
and emit a drift diff alongside the static + plan findings.
```

A `BREAKING CHANGE:` footer triggers a MAJOR bump:

```
feat(scanner): rename --gate-threshold to --fail-on

The old flag name is removed. Update CI configs accordingly.

BREAKING CHANGE: --gate-threshold has been replaced with --fail-on.
```

See <https://www.conventionalcommits.org/en/v1.0.0/#specification>
for the full grammar.

## Adding a new Checkov rule → framework mapping

Most contributions happen in `mappings/pci_dss_4.0.1.yaml` (or
whatever your framework file is named). The schema is in
[docs/MAPPING_SCHEMA.md](docs/MAPPING_SCHEMA.md). The short version:

```yaml
- id: 1.2.1
  title: Configuration standards for NSCs are defined and implemented
  checks:
    - CKV_AZURE_59
    - CKV_AZURE_212
  note: CKV_AZURE_89 anchored here as 1.2.1 evidence.
```

Workflow:

1. Identify the Checkov rule ID (e.g. `CKV_AZURE_212`) from a
   failed scan.
2. Find the framework requirement the rule satisfies. Cross-reference
   the linked standards document (PCI SSC, NIST 800-53, CIS, etc.).
3. Add the entry to `mappings/<framework>.yaml` under the right
   requirement.
4. Verify the `doc_anchor` URL is live (HEAD 200).
5. If the rule's severity should not be `MEDIUM` (the default),
   add it to `SEVERITY_OVERRIDE` in `scanner/aggregate.py`.
6. Add a remediation block to `scanner/terraform_remediation.yaml`
   if one applies.
7. Bump `verified_against` at the top of the mapping YAML.
8. Run `make test`, `make lint`, `make selftest`, and a real scan
   to confirm.

## Adding a canonical remediation

Every finding should have an actionable fix block in the HTML
report. The remediation library lives in
`scanner/terraform_remediation.yaml`. The pytest test
`test_terraform_remediation_yaml.py` enforces the schema:

- At least 68 entries.
- Every block has all 5 required fields:
  `resource_type`, `current_problem`, `remediation_hcl`,
  `verification_step`, `provenance`.
- `remediation_hcl` is multi-line.
- `verification_step` is non-empty.
- `INTENTIONALLY_ABSENT` check IDs are not in the file.

To add one:

```yaml
- check_id: CKV_AZURE_<n>
  resource_type: azurerm_<service>
  current_problem: <one-line verbatim from checkov --list>
  remediation_hcl: |
    resource "azurerm_<service>" "example" {
      ...
    }
  verification_step: <one-line command + expected outcome>
  provenance: <registry.terraform.io URL>
```

Style:

- One snippet per check_id. Multiple snippets per check_id are
  allowed when there are multiple resource types.
- HCL must be the canonical azurerm 4.x form (no deprecated
  `enable_*`).
- Always include the `verification_step` so the operator can
  confirm the fix landed.

## Adding a new framework pack (SOC 2, CIS Azure, NIST 800-53, …)

1. Copy `mappings/pci_dss_4.0.1.yaml` to
   `mappings/<framework>_<version>.yaml`.
2. Change `framework_name` and `framework_version` at the top.
3. Replace the `requirements:` list with the new framework's
   controls. The `checks:` IDs MUST be valid Checkov rule IDs
   (run `checkov -l | grep CKV_` for the list).
4. Replace `out_of_scope_requirements` with the req families that
   the scanner cannot evaluate for this framework.
5. Re-run the scanner with
   `--mapping mappings/<framework>_<version>.yaml`.
6. The HTML title and sidebar will reflect the new framework name.

For the custom checks in `scanner/checks/`, you can either:

- Keep them (they're general Azure hygiene checks that apply to any
  compliance framework), or
- Move them to a framework-specific subdirectory and update the
  `--external-checks-dir` flag in `scanner/scan.sh`.

## Adding a new custom check

See [docs/CHECK_AUTHORING.md](docs/CHECK_AUTHORING.md) for a full
walkthrough. The short version:

1. Create `scanner/checks/CKV_AZURE_PCI_<NNN>__<name>.py`.
2. Use the next available PCI check ID.
3. Inherit from `BaseResourceCheck`; implement
   `scan_resource_conf`.
4. Anchor the check to a PCI req by adding a row to
   `mappings/pci_dss_4.0.1.yaml`.
5. Add an entry to `SEVERITY_OVERRIDE` in
   `scanner/aggregate.py` if the default `MEDIUM` is wrong.
6. Add a remediation block to
   `scanner/terraform_remediation.yaml` if one applies.
7. Run `make test` and confirm the new schema is satisfied.

## Running tests

```bash
# Python unit tests
make test

# Shell lint + Python compile
make lint

# Safety invariant self-test
make selftest
```

All three must pass before a PR is mergeable.

## Style guide

- **Python**: 3.12+ syntax. Type hints on every public function.
  Use `pathlib.Path`, `dataclasses`, and `argparse`. 4-space indent,
  double-quoted strings, trailing commas in multi-line container
  literals. The UTF-8 env-var bootstrap (`PYTHONIOENCODING=utf-8`,
  `PYTHONUTF8=1`, `sys.stdout.reconfigure`) is mandatory in every
  module that opens files or prints.
- **Bash**: `set -uo pipefail` at the top. Always go through
  `run_cmd` (driver) or `safe_run_exec` (`lib/common.sh`) so the
  safety invariant is enforced. Source `lib/common.sh` first (which
  sources `lib/safety.sh`). No `realpath` — use the
  `cd "$(dirname ...)" && pwd` idiom (realpath breaks on Windows
  `S:/` paths in MSYS Git Bash).
- **Commits**: present tense imperative ("add", not "added"). Body
  should reference the issue or describe the *why*, not the *what*.
  Use the prefixes above.
- **Branches**: `feature/<slug>`, `fix/<slug>`, `docs/<slug>`,
  `chore/<slug>`.

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

## Security reports

See [SECURITY.md](SECURITY.md). Do not file security issues as
public GitHub issues.
