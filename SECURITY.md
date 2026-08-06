# Security Policy

## Supported Versions

The `main` branch receives security updates. Older branches may receive
backports on a best-effort basis.

| Version | Supported          |
|---------|--------------------|
| main    | :white_check_mark: |
| < main  | :x:                |

## Reporting a Vulnerability

**Please do not file a public GitHub issue for security vulnerabilities.**

Send a private report to the maintainers via GitHub's private vulnerability
reporting feature (Security tab → "Report a vulnerability"). You can also
email the maintainer directly — see the GitHub profile for contact info.

What to include in your report:
- A clear description of the vulnerability
- Steps to reproduce
- Affected version(s) (commit hash, tag, or branch)
- Potential impact (what an attacker could do)
- Any suggested fix (optional)

## Response Timeline

- **Acknowledgement**: within 3 business days
- **Triage and assessment**: within 10 business days
- **Fix and disclosure**: coordinated with the reporter

We aim to follow responsible disclosure. Critical issues may warrant
faster disclosure timelines.

## Scope

In-scope:
- The scanner itself (`.scripts/checkov/`)
- The HTML report's faithfulness (no XSS, no broken links, no fabricated PCI citations)
- The mapping YAML files (correctness of citations, not their coverage)
- The custom checks in `pci_checks/` (no false negatives that could mask vulnerabilities)

Out-of-scope:
- Issues in upstream Checkov (file at https://github.com/bridgecrewio/checkov)
- Issues in Terraform itself (file at https://github.com/hashicorp/terraform)
- Issues in Azure (file with Microsoft)

## Security Considerations

The scanner is **read-only** against your cloud. The only Azure mutation is
the storage firewall IP whitelist (added/removed via the trap), and even
that is opt-in (only runs when `--scan-plan` or `--scan-state` is set).

You can verify the read-only invariant at any time:
```bash
make scan-pci-selftest
```

If you discover a way to bypass the safety guard and apply a mutation
through the scanner, that's a critical vulnerability — please report
immediately.
