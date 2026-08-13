# Learnings

- `pci_scope.yaml` is now a strict structured boundary: environments are `{name, status, reason?}` records; scalar environment entries are rejected.
- Explicit `scan_paths` are exclusion-gated only when their logical `(project, env)` has a declared pending/excluded record. Unmatched explicit paths stay valid.
- The orchestrator must resolve and validate scope before creating either `output_dir` or a labeled run root.
- Each valid scan pair has `pacioli_environment.json` written atomically before its first Checkov pass.
- The standalone report now establishes its theme before body paint through a guarded, namespaced `localStorage` read; storage denial, invalid state, and absent preference all resolve to dark without a flash or page error.
- Theme palette values must remain CSS token declarations only; generated markup, SVG attributes, inline-style fragments, and JavaScript-created controls use classes or `var(--color-...)` references.
- The shipped scope example must remain parser-valid: its fixture-backed regression asserts exact permitted record keys, required status/reason combinations, and the resulting in-scope pairs.
- Browser smoke coverage generates the existing synthetic aggregate fixture, then serves it from an ephemeral `127.0.0.1` origin so browser storage remains origin-scoped and repeatable without an application server.
- The report model is an inert schema-version-1 JSON script payload parsed from `textContent`; logical environments use `pacioli_environment.json` identity and a labeled stack renders as `project/env [stack_label]`, while metadata-free directories retain the legacy `stack_label=None` fallback.
- Environment exclusions are report-local view state: canonical `identity_label` is serialized per finding, and a guarded `pacioli.report.filters` localStorage record owns `q`, `sev`, `req`, and sorted `excluded` labels. The legacy `pacioli_req` cookie is read once, maps `env` into the exclusion set, then is cleared.
- Documentation uses `scan scope` only for structured-only, version-controlled `pci_scope.yaml` exclusions applied at scan time; `report view` is browser-local filtering that recomputes visible views while leaving SARIF/CSV/JUnit full-scan evidence unchanged.
- Task 8 browser evidence uses the existing loopback fixture and Playwright, records 375/768/1280 dark/light/system/reduced-motion views, navigates to `#environments` before recording labeled-stack output, and proves both persisted preferences and `SecurityError`-denied localStorage fall back without page or console errors.
- The retired template was the sole hash router and was inert; routing must live in the active renderer, invoke once from the current hash on load, and subscribe to `hashchange` so both deep links and post-load navigation activate exactly one route and sidebar link.
