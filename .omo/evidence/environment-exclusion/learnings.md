# Learnings

- `pci_scope.yaml` is now a strict structured boundary: environments are `{name, status, reason?}` records; scalar environment entries are rejected.
- Explicit `scan_paths` are exclusion-gated only when their logical `(project, env)` has a declared pending/excluded record. Unmatched explicit paths stay valid.
- The orchestrator must resolve and validate scope before creating either `output_dir` or a labeled run root.
- Each valid scan pair has `pacioli_environment.json` written atomically before its first Checkov pass.
- The standalone report now establishes its theme before body paint through a guarded, namespaced `localStorage` read; storage denial, invalid state, and absent preference all resolve to dark without a flash or page error.
- Theme palette values must remain CSS token declarations only; generated markup, SVG attributes, inline-style fragments, and JavaScript-created controls use classes or `var(--color-...)` references.
- The shipped scope example must remain parser-valid: its fixture-backed regression asserts exact permitted record keys, required status/reason combinations, and the resulting in-scope pairs.
- Browser smoke coverage generates the existing synthetic aggregate fixture, then serves it from an ephemeral `127.0.0.1` origin so browser storage remains origin-scoped and repeatable without an application server.
