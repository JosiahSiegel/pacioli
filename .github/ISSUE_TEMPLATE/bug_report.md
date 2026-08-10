---
name: Bug report
about: Report something that doesn't work
title: "[Bug] "
labels: bug
assignees: ''
---

## What happened

A clear description of the bug.

## Steps to reproduce

The exact command(s) you ran:

```bash
pacioli scan --project ... --env ...
```

## Expected behavior

What you expected to see.

## Actual behavior

What you actually saw. Paste the full output (including the
`pci_log` lines).

## Environment

- Pacioli version / commit: `git rev-parse HEAD`
- Checkov version: `checkov --version`
- Python version: `python --version`
- OS: `uname -a` or equivalent

## Minimal reproduction

If you can, include a minimal `.tf` snippet that produces the
issue.

```hcl
resource "azurerm_storage_account" "example" {
  # ...
}
```

## Have you checked

- [ ] [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- [ ] [Existing issues](https://github.com/JosiahSiegel/pacioli/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc)
- [ ] [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md)
