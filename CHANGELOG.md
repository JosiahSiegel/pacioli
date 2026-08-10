# Changelog

All notable changes to Pacioli are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.

## 0.1.0 (2026-08-10)


### Features

* empty defaults + pacioli-reports rename for full tenant neutrality ([3da6d99](https://github.com/JosiahSiegel/pacioli/commit/3da6d999e0e2491cca6a6474fc3642dcbc425a71))
* extract Pacioli scanner from global-terraform to standalone repo ([b9d5865](https://github.com/JosiahSiegel/pacioli/commit/b9d5865cd8d4f555a3f27a402fee5c801cdceeb1))
* standalone pure-Python CLI (pacioli scan) ([7e0dbf9](https://github.com/JosiahSiegel/pacioli/commit/7e0dbf969af12b3003a8e98d195b912a2ef87ea5))
* standalone pure-Python CLI (pacioli scan) ([fa9eb3a](https://github.com/JosiahSiegel/pacioli/commit/fa9eb3a727fb214a815dbb2118e6578af057f57c))


### Bug Fixes

* aggregate default mapping fallback + packaging pin (followup to [#1](https://github.com/JosiahSiegel/pacioli/issues/1)) ([6164c0e](https://github.com/JosiahSiegel/pacioli/commit/6164c0e9f801c2f0773a8e0825fb0d88254e1490))
* aggregate default mapping fallback + packaging pin (followup to [#1](https://github.com/JosiahSiegel/pacioli/issues/1)) ([bcf5944](https://github.com/JosiahSiegel/pacioli/commit/bcf5944c792b7a3d4cc254a1553b36a50e3cb4c7))
* bash quote escape in mapping-lint CI job (mapping-lint job failing on PR [#3](https://github.com/JosiahSiegel/pacioli/issues/3)) ([c4e0d9b](https://github.com/JosiahSiegel/pacioli/commit/c4e0d9bface60ec62bde0289c98d923656a1fe18))
* broaden path allow-list + fix test_trap.py child import ([238e385](https://github.com/JosiahSiegel/pacioli/commit/238e385c689dd915c1f60f4b01548c9717b09b5c))
* CI workflow + SonarCloud cleanups ([5bfcc27](https://github.com/JosiahSiegel/pacioli/commit/5bfcc27fea76deda64cb2e7a7ee222bd9ffd572b))
* **common.sh:** correct PACIOLI_INSTALL_DIR path + drop realpath for Windows compat ([02095a9](https://github.com/JosiahSiegel/pacioli/commit/02095a9a7fe372706e5b79d415b7556452240d78))
* e2e audit found 3 real bugs - all fixed ([83df480](https://github.com/JosiahSiegel/pacioli/commit/83df480df426869c47c1f21d44ae673b047207a9))
* harden test_register_traps_registers_sigterm_on_posix against pytest interception ([65f3bc5](https://github.com/JosiahSiegel/pacioli/commit/65f3bc55d7e6ad3b7912efe9f8fb86f68cd63ff5))
* pin pip version and inline requirements-pinned.txt contents ([71fed3b](https://github.com/JosiahSiegel/pacioli/commit/71fed3b57a4fc6b675375edfbba54c34e2da370d))
* **scan:** align wrapper output with consumption guide expectations ([861788f](https://github.com/JosiahSiegel/pacioli/commit/861788f5b61bc7d6a5d457070138309e2f692fc7))
* **scan:** gate mode now actually gates on HIGH/CRITICAL findings ([e843ba3](https://github.com/JosiahSiegel/pacioli/commit/e843ba339c98a7ae7e3f9489d5660986edbebd57))
* SonarCloud cleanups round 2 + CI pytest install ([eff3a3e](https://github.com/JosiahSiegel/pacioli/commit/eff3a3e6e884bc3cfb81e720fd2287c0b2e1825a))
* SonarCloud round 3 - final BLOCKER + workflow pinning ([aaa0ba4](https://github.com/JosiahSiegel/pacioli/commit/aaa0ba4950f711673c0a6bdb3f1f724bd41c992c))
* SonarCloud round 4 - finalized path sanitization + wheel build ([f465d5f](https://github.com/JosiahSiegel/pacioli/commit/f465d5f2dfb7e67b5503c1e2ffbb5417f493b3e7))
* SonarCloud round 5 - Path.open() pattern + re.fullmatch guard ([5235b8f](https://github.com/JosiahSiegel/pacioli/commit/5235b8f82de43548b178dfd21059d5d902d6cee4))


### Documentation

* comprehensive documentation suite for public consumption ([ccf2779](https://github.com/JosiahSiegel/pacioli/commit/ccf277931271b183cb717b26f7e40bff8759130e))
* fix DEVELOPER_GUIDE.md test count and directory tree ([4c922a8](https://github.com/JosiahSiegel/pacioli/commit/4c922a8a21c71a432139549788114708b6922f36))
* fix invalid bash/yaml/json code blocks + TUI consistency ([d360bea](https://github.com/JosiahSiegel/pacioli/commit/d360bead144febbe87e2c4e4b1dfc2e792398449))

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
