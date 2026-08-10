# Changelog

All notable changes to Pacioli are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.

## [Unreleased]

### Added
- `docs/INDEX.md` — master table of contents for the documentation.
- `docs/CONSUMING_GUIDE.md` — first-time consumer setup walkthrough.
- `docs/ARCHITECTURE.md` — how the scanner is put together.
- `docs/DEVELOPER_GUIDE.md` — extending the scanner.
- `docs/CLI_REFERENCE.md` — every argument and env var.
- `docs/SAFETY_MODEL.md` — read-only invariant and extension guide.
- `docs/REPORT_FORMAT.md` — every output file.
- `docs/MAPPING_SCHEMA.md` — mapping YAML format.
- `docs/CHECK_AUTHORING.md` — adding a custom Checkov check.
- `docs/TROUBLESHOOTING.md` — common failures.
- `CHANGELOG.md` (this file).
- `examples/Makefile.consumer` — wrapper Makefile template.
- `examples/scope.yaml.example` — scope file template.
- `examples/baseline.yaml.example` — baseline file template.

### Changed
- Rewrote `README.md` to reflect the post-extraction layout (no
  more `.scripts/checkov/`, no more `make scan-pci-*`).
- Rewrote `CONTRIBUTING.md` to reflect the new `scanner/` paths and
  link to the new developer docs.
- Rewrote `docs/OPERATOR_GUIDE.md` to reflect the new layout.
- Updated `SECURITY.md` to point at the new paths and `make selftest`.
- Updated `SUPPORT.md` to point at the new docs tree.
- Updated `CITATION.cff` to remove placeholder `YOUR_ORG` URLs.
- Updated `Makefile` to lint all five Python entry points.
- Updated `.github/workflows/ci.yml` paths to `scanner/` and
  `mappings/`.
- Updated all four `.github/ISSUE_TEMPLATE/*.md` files.
- Updated `.github/PULL_REQUEST_TEMPLATE.md`.
- Updated `.github/CODEOWNERS` and `.github/FUNDING.yml`.

### Fixed
- `lib/safety.sh` `safety_selftest` was defined but never invoked
  when the file was sourced via `lib/common.sh`. The bottom-of-file
  `if [[ "${BASH_SOURCE[0]}" == "${0}" ]]` block now runs the
  selftest when the file is invoked directly (e.g. via
  `make selftest`).
- `scan.sh` previously referenced
  `${PCI_REPO_ROOT}/scanner/rewrite_sarif_help.py` and
  `${PCI_REPO_ROOT}/scanner/checks` in some code paths. Now
  consistently uses `${SCRIPT_DIR}/...` (correct: `SCRIPT_DIR` IS
  the `scanner/` directory).

### Removed
- Dead code from `lib/common.sh`: `redact_cmd` (never called),
  `common_selftest` (never called), `init_run_dir` (only caller
  was `common_selftest`).

## [0.1.0] - 2026-08-06

Initial open-source release. The scanner was extracted from an
internal Azure Terraform monorepo and scrubbed of all internal
naming. First commit on the public main branch.

### Notes

This is the first public release, so there is no "what changed
since the last version" section. The first version reflects the
state of the scanner after the extraction commit.

[Unreleased]: https://github.com/JosiahSiegel/pacioli/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/JosiahSiegel/pacioli/releases/tag/v0.1.0
