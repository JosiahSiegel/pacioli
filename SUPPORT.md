# Support

## Documentation

Start with these:
- `README.md` — Quick start, what the scanner does, three scan tiers
- `docs/runbooks/pci-checkov.md` — Full operator guide (PCI DSS v4.0.1)
- `CONTRIBUTING.md` — How to add mappings, remediations, or new frameworks

## Asking Questions

For usage questions or troubleshooting:
1. Check the existing GitHub issues and discussions
2. Search the runbook for your error message
3. If still stuck, open a GitHub issue with:
   - The exact command you ran
   - The full output (including the `pci_log` lines)
   - Your `checkov --version` and `python --version`
   - A minimal `.tf` snippet that reproduces the issue (if applicable)

## Filing Bugs

Use the GitHub issue tracker. Please include:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Run command + output
- Environment (Python version, Checkov version, OS)

## Commercial Support

This is an open-source project. Commercial support is not provided.
For enterprise deployments, you may want to engage with the upstream
project (https://www.checkov.io/) or a Cloud Security Posture Management
(CSPM) vendor.

## Release Cadence

There is no fixed release cadence. Bug fixes are released as soon as
they're tested. New features are batched into tagged releases roughly
quarterly.
