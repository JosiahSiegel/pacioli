# Support

## Documentation

Start with the [docs/INDEX.md](docs/INDEX.md) master table of
contents. The most useful entry points are:

- [docs/CONSUMING_GUIDE.md](docs/CONSUMING_GUIDE.md) — if you
  are setting up the scanner in a Terraform repo for the first
  time.
- [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) — if you are
  running scans and interpreting the output.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — if you need to
  understand how the pieces fit together.
- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) — if you need a
  lookup table for an argument or env var.
- [docs/CHECK_AUTHORING.md](docs/CHECK_AUTHORING.md) — if you
  want to add a custom Checkov check.
- [docs/MAPPING_SCHEMA.md](docs/MAPPING_SCHEMA.md) — if you want
  to add a new framework mapping.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — if
  something doesn't work.

## Asking Questions

For usage questions or troubleshooting:

1. Check the existing [GitHub issues](https://github.com/JosiahSiegel/pacioli/issues)
   and [discussions](https://github.com/JosiahSiegel/pacioli/discussions).
2. Search [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for
   your error message.
3. If still stuck, open a [GitHub issue](https://github.com/JosiahSiegel/pacioli/issues/new/choose)
   with:
   - The exact command you ran.
   - The full output (including the `pci_log` lines).
   - Your `checkov --version` and `python --version`.
   - A minimal `.tf` snippet that reproduces the issue (if
     applicable).

## Filing Bugs

Use the [GitHub issue tracker](https://github.com/JosiahSiegel/pacioli/issues).
Please use the **Bug report** template and include:

- Steps to reproduce.
- Expected behavior.
- Actual behavior.
- Run command + output.
- Environment (Python version, Checkov version, OS).

## Commercial Support

This is an open-source project. Commercial support is not
provided. For enterprise deployments, you may want to engage with
the upstream project ([Checkov](https://www.checkov.io/)) or a
Cloud Security Posture Management (CSPM) vendor.

## Release Cadence

There is no fixed release cadence. Bug fixes are released as soon
as they're tested. New features are batched into tagged releases
roughly quarterly.

## Maintainer Contact

The maintainers can be reached via:

- The GitHub private vulnerability reporting feature (for
  security issues — see [SECURITY.md](SECURITY.md)).
- A public GitHub issue (for general questions; security issues go through the GitHub Security tab → "Report a vulnerability" — see [SECURITY.md](SECURITY.md)).
