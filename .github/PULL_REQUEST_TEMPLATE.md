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

## How I tested

- [ ] `make scan-pci-selftest` passes
- [ ] `pytest .scripts/checkov/tests/` passes
- [ ] I ran a real scan against at least one environment
- [ ] Output verified (paste screenshot or run dir name)

## Checklist

- [ ] My code follows the style guide (see `CONTRIBUTING.md`)
- [ ] I added tests for new behavior
- [ ] I updated relevant docs (runbook, README, docstrings)
- [ ] I added a doc_anchor and verified it returns 200 (if mapping change)
- [ ] I added a verification_step to the remediation (if remediation change)

## Screenshots

If this changes the HTML report, attach a before/after screenshot.
