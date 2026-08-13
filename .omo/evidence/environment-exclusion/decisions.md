# Decisions

- The manifest accepts only `projects` and `scan_paths` at root, requiring at least one non-empty list.
- A project-level pending/excluded status overrides an otherwise in-scope environment and supplies the logged reason.
- Exclusion matching is constrained to declared logical pairs: it never suppresses an unmatched `scan_paths` record.
- Per-pair identity is persisted as `{schema_version: 1, project, env, stack_label}` before Checkov execution.
- Scope documentation treats `--project` and `--env` as post-scope filters only; neither flag changes the declared audit boundary or reintroduces pending/excluded pairs.
