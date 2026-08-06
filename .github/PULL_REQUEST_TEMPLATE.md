---
name: Pull request
about: Submit a code change
title: "[PR] "
labels: ''
assignees: ''
---

## What this PR does

One-paragraph summary. Link any related issues.

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (would require existing users to migrate)
- [ ] Documentation only
- [ ] Refactor (no behavior change)

## How I tested

- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] `make selftest` passes
- [ ] I ran a real scan against at least one environment
- [ ] Output verified (paste run dir name or attach a screenshot)

## Checklist

- [ ] My code follows the style guide (see
      [CONTRIBUTING.md](CONTRIBUTING.md) →
      [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md))
- [ ] I added tests for new behavior
- [ ] I updated relevant docs (runbook, README, docstrings)
- [ ] I bumped `verified_against` in the mapping YAML (if mapping
      change)
- [ ] I added a `verification_step` to the remediation (if
      remediation change)
- [ ] I added a `doc_anchor` and verified it returns 200 (if
      mapping change)
- [ ] I added an entry to `SEVERITY_OVERRIDE` (if severity change)

## Screenshots

If this changes the HTML report, attach a before/after screenshot.
