# Changelog

All notable changes to Pacioli are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.

## [1.2.1](https://github.com/JosiahSiegel/pacioli/compare/v1.2.0...v1.2.1) (2026-08-13)


### Bug Fixes

* **checkov_runner:** invoke Checkov as subprocess to avoid process-level cache (1.2.1) ([63bb482](https://github.com/JosiahSiegel/pacioli/commit/63bb48236b41064c65275f369464e22577028885))
* hotfix 1.2.1 — Checkov subprocess isolation (cross-env SARIF contamination) ([0a9a049](https://github.com/JosiahSiegel/pacioli/commit/0a9a049e5704fd3fe4ef3b85472cf1db18e8cac3))


### Documentation

* CHANGELOG entry for 1.2.1 hotfix ([793de2e](https://github.com/JosiahSiegel/pacioli/commit/793de2e114b831decfaa845de9dce0ec5011a5b7))

## [1.2.0](https://github.com/JosiahSiegel/pacioli/compare/v1.1.1...v1.2.0) (2026-08-13)


## [1.2.1](https://github.com/JosiahSiegel/pacioli/compare/v1.2.0...v1.2.1) (2026-08-13)


### Bug Fixes

* **checkov_runner:** invoke Checkov as subprocess to avoid process-level cache

  Checkov 3.3.9 has a process-level cache that returns SARIF results from
  the FIRST scan regardless of the second scan's `env_dir` or CWD.
  Reproduced locally with a 4-scan sequence on alternating env_dirs; all 4
  SARIFs were byte-identical.

  Fix: invoke Checkov as `python -m checkov.main <args>` via
  `subprocess.run` with `cwd=env_dir`. Each scan gets its own Python
  process and its own cache namespace.

  Side benefits:
  * The Windows relpath workaround (`os.chdir` to `env_dir`) is no longer
    needed — the subprocess starts with `cwd=env_dir` natively.
  * The runner becomes thread-safe again (no process-global CWD mutation).
  * Each scan is now bounded by a 900s timeout so a stuck subprocess
    cannot wedge the orchestrator.

  Reported symptom: a `cognitive_services.tf` finding scanned in
  `CR_Formstax_ADF/prod` would appear in the SARIF for `CR_Personelle/stage`
  (which has no `cognitive_services.tf`).

### Tests

* **checkov_runner:** rewrite to mock `subprocess.run` instead of `Checkov`

  The previous tests mocked `Checkov(argv=...).run()` because the runner
  called Checkov in-process. The mocking surface moved to `subprocess.run`
  to match the fix. Added a regression test
  (`test_two_sequential_subprocess_scans_produce_independent_sarifs`) that
  runs two real Checkov subprocesses against distinct envs and asserts
  the SARIFs reference their respective env paths.


## Features

* **cli:** --version flag, version read from importlib.metadata (1.1.2) ([369d1a1](https://github.com/JosiahSiegel/pacioli/commit/369d1a16483767fe66bc518b5d0bf252809b6b10))


### Bug Fixes

* hotfix 1.1.2 — --version flag + wheel-build sync fix ([a908bd7](https://github.com/JosiahSiegel/pacioli/commit/a908bd770d4903d2a90346cd7da83aedd2ba3402))
* **release:** sync mapping packs into wheel bundle before build (1.1.2) ([3d70ccd](https://github.com/JosiahSiegel/pacioli/commit/3d70ccd394f31a38266f1da917412d7624e80508))


### Documentation

* CHANGELOG entry for 1.1.2 hotfix ([9d6e92f](https://github.com/JosiahSiegel/pacioli/commit/9d6e92fe8c59652e0989ae650784b0a6dded4e82))
* CLI_REFERENCE entry for --version flag (1.1.2 hotfix) ([4aa4977](https://github.com/JosiahSiegel/pacioli/commit/4aa497797e9eab6853900ba73204b52a8810b782))

## [1.1.1](https://github.com/JosiahSiegel/pacioli/compare/v1.1.0...v1.1.1) (2026-08-13)


### Bug Fixes

* **cli:** wrap picker in helper with PathResolutionError catch (1.1.1) ([54de6a3](https://github.com/JosiahSiegel/pacioli/commit/54de6a34f2f4d973ef11c4e465b2c5e3d955f390))
* hotfix 1.1.1 — mapping picker zero-packs crash ([6629d71](https://github.com/JosiahSiegel/pacioli/commit/6629d714af8f07744ffa2e4f6a0a67591e847a11))
* **mapping_picker:** distinct zero-packs error + skip picker when no packs (1.1.1) ([093ee33](https://github.com/JosiahSiegel/pacioli/commit/093ee332497dc04f297bd74cc67f10d0e6defce3))


### Documentation

* CHANGELOG entry for 1.1.1 hotfix ([0168bae](https://github.com/JosiahSiegel/pacioli/commit/0168bae9cbb1027eb99c1c64b422394093bea512))

## [1.1.0](https://github.com/JosiahSiegel/pacioli/compare/v1.0.0...v1.1.0) (2026-08-13)


### Features

* **cli:** wire interactive mapping picker into scan/gate handlers ([ee9f0f1](https://github.com/JosiahSiegel/pacioli/commit/ee9f0f1d31b19ca5aa608ba9045737f730578bb1))
* interactive mapping-pack picker + README quickstart fix ([5d93124](https://github.com/JosiahSiegel/pacioli/commit/5d93124b9a6eddcfecf4950403eee2591cccddd8))
* **mapping_picker:** interactive picker module ([38b1fb8](https://github.com/JosiahSiegel/pacioli/commit/38b1fb8436bae36783903edd37743f45c3f0221a))


### Documentation

* CHANGELOG entry for mapping picker ([f692ea4](https://github.com/JosiahSiegel/pacioli/commit/f692ea4bd7e631de37f60487833b35bae64775df))
* CLI_REFERENCE entries for --non-interactive and picker ([193c92c](https://github.com/JosiahSiegel/pacioli/commit/193c92c7e14e81e4ae0b1852c61eb4e14ba4c888))
* README quickstart reword for mapping picker ([c4ad9bc](https://github.com/JosiahSiegel/pacioli/commit/c4ad9bc25769e0c30c944c38e8c0734440b74f40))

## [1.1.1](https://github.com/JosiahSiegel/pacioli/compare/v1.1.0...v1.1.1) (2026-08-13)


### Bug Fixes

* **mapping_picker:** distinguish "no packs installed" from "user cancelled"

  1.1.0 raised `PathResolutionError("<picker cancelled>")` with a leaked
  traceback when no mapping packs were installed (e.g. fresh wheel install
  with no editable mappings). The user was told to pass `--mapping`, but
  the actual problem was that nothing was installed to point at.

  Fix:
  * `is_interactive()` now returns `False` when `_discover_packs()` is
    empty, so the picker is never invoked in the zero-pack case.
  * `pick_mapping_pack()` raises a distinct `_NO_PACKS_MESSAGE` ("No
    mapping packs installed. Run 'pacioli init' to install one, or
    pass --mapping <path>.") when zero packs are found.
  * `cli.py` now routes both `scan` and `gate` through a shared
    `_maybe_prompt_for_mapping_pack()` helper that catches every
    `PathResolutionError` from the picker and converts it to a clean
    exit-2 with the friendly message on stderr. No more stack traces.

  Coverage: 2 new tests in `scanner/tests/test_mapping_picker.py` pin
  both the message and the `is_interactive` gate.


## [1.1.2](https://github.com/JosiahSiegel/pacioli/compare/v1.1.1...v1.1.2) (2026-08-13)


### Bug Fixes

* **release:** sync mapping packs into the wheel bundle before build

  1.1.1 shipped a wheel that did not contain `scanner/mappings/*.yaml`
  because the release workflow skipped the `sync_mappings.py` step that
  `ci.yml` runs. Symptom: a fresh `pip install` of 1.1.1 followed by
  `pacioli scan .` produced a misleading `Mapping pack does not exist:
  C:\Python314\Lib\site-packages\mappings` error pointing at the
  editable-install dir (which never exists on wheel installs).

  Fix: add the sync step to `release.yml` mirroring `ci.yml`, AND
  improve the `resolve_mapping` error message so the user sees
  "No installed mapping packs found. Run 'pacioli init' to install
  one, or pass --mapping <path> or set PACIOLI_MAPPING=<path>." when
  both layouts are empty.


### Features

* **cli:** add `--version` top-level flag

  `pacioli --version` prints the installed package version and exits
  0. The version is read from `importlib.metadata.version('pacioli')`
  so the printed value is ALWAYS the actually-installed wheel, never
  a hardcoded literal that could drift from `pyproject.toml`.

  Resolves the UX gap exposed by the 1.1.0 -> 1.1.1 hotfix episode:
  the user had no way to ask the binary which version it was, so
  wheel-upgrade failures were silent until the next scan.


## [Unreleased]


### Features

* **cli:** interactive mapping-pack picker when no `--mapping` / `PACIOLI_MAPPING` is set in an interactive shell (#[26](https://github.com/JosiahSiegel/pacioli/pull/26))


### Documentation

* clarify Quick start — default mapping is shipped; first-time users no longer need to know the mapping name (#[26](https://github.com/JosiahSiegel/pacioli/pull/26))


## [1.0.0](https://github.com/JosiahSiegel/pacioli/compare/v0.2.2...v1.0.0) (2026-08-12)


### ⚠ BREAKING CHANGES

* CSV/SARIF column/property rename.
    - coverage_matrix.csv: pci_requirement -> requirement
    - coverage_gaps.csv: pci_requirement -> requirement, pci_anchor_url -> doc_anchor_url
    - SARIF properties: pci_project -> project, pci_env -> env, pci_source_sarif -> source_sarif
    - Mapping pack's doc_anchor top-level key now controls the HTML section header link.

### Features

* generalize scanner to support all Checkov clouds and frameworks ([0d32001](https://github.com/JosiahSiegel/pacioli/commit/0d3200138466b58cb3c573144953cf38ff2996f9))
* generalize scanner to support all Checkov clouds and frameworks ([3717092](https://github.com/JosiahSiegel/pacioli/commit/37170926ef4265c07ba6d4dd1c276c5efe900eb3))


### Bug Fixes

* address CI failures and Sonar findings for [#21](https://github.com/JosiahSiegel/pacioli/issues/21) ([af621de](https://github.com/JosiahSiegel/pacioli/commit/af621de7d250dbd699f78984c0fdea4fceeb87cc))
* address remaining SonarCloud findings for [#21](https://github.com/JosiahSiegel/pacioli/issues/21) ([4c0282f](https://github.com/JosiahSiegel/pacioli/commit/4c0282f12884543bded619429912993909ddd955))
* **ci:** sync mapping packs into scanner/mappings/ before wheel build ([c517661](https://github.com/JosiahSiegel/pacioli/commit/c51766136d0826daefb5dfc2d2cedeb73da028ca))

## [0.2.2](https://github.com/JosiahSiegel/pacioli/compare/v0.2.1...v0.2.2) (2026-08-12)


### Documentation

* **release:** document artifact workflow fallback ([1156940](https://github.com/JosiahSiegel/pacioli/commit/115694039790a685393fe83a8dc422616e12ae94))
* **release:** drop stale publish-target reference ([84b661e](https://github.com/JosiahSiegel/pacioli/commit/84b661eed2121432603d731933eee131015601d1))

## [0.2.1](https://github.com/JosiahSiegel/pacioli/compare/v0.2.0...v0.2.1) (2026-08-12)


### Documentation

* add RELEASING.md and correct CONTRIBUTING release-please description ([#16](https://github.com/JosiahSiegel/pacioli/issues/16)) ([3ab5d2d](https://github.com/JosiahSiegel/pacioli/commit/3ab5d2dabd4f6057e9e41548ea67674afeb77b2a))

## [0.2.0](https://github.com/JosiahSiegel/pacioli/compare/v0.1.1...v0.2.0) (2026-08-11)


### Features

* **safety:** typed operation registry, isolated TF env, no firewall mutation ([#11](https://github.com/JosiahSiegel/pacioli/issues/11)) ([43bf9ee](https://github.com/JosiahSiegel/pacioli/commit/43bf9ee6cf78ddfbf6ee952cefed353a760281f6))
* slim README and auto-open HTML report ([#9](https://github.com/JosiahSiegel/pacioli/issues/9)) ([a5a305a](https://github.com/JosiahSiegel/pacioli/commit/a5a305a84edb038f5ee0e0fd6048e7473cbf674d))

## [0.1.1](https://github.com/JosiahSiegel/pacioli/compare/v0.1.0...v0.1.1) (2026-08-10)


### Bug Fixes

* resolve mapping pack from install-bundled location in scan path ([ba2d338](https://github.com/JosiahSiegel/pacioli/commit/ba2d3389ba2a4fc1ebf36db5c0bb6f7b21e49b35))


### Documentation

* add TROUBLESHOOTING entry for v0.1.0 'Mapping pack does not exist' bug ([dc5b8cf](https://github.com/JosiahSiegel/pacioli/commit/dc5b8cf18cf89fa5d5f004186a5aa0a18430d43d))
* fix critical user-facing references (--gate, --scope, baseline init, CODEOWNERS path, etc.) ([f305c85](https://github.com/JosiahSiegel/pacioli/commit/f305c856bf2eaef747f8b02c0081c43d6f258845))
* fix default run-dir path, Python 3.13, CHANGELOG cleanup, SUPPORT.md ([69463d2](https://github.com/JosiahSiegel/pacioli/commit/69463d2da83951a8be322fbbd8a2ccd3d195dcd6))
* replace bash scanner references with Python CLI equivalents ([fbc2215](https://github.com/JosiahSiegel/pacioli/commit/fbc2215436a2ba9a660b8ece78240adf054aeee3))

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

[Unreleased]: https://github.com/JosiahSiegel/pacioli/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/JosiahSiegel/pacioli/releases/tag/v0.1.0
