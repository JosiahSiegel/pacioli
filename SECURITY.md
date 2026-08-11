# Security Policy

## Supported Versions

The `main` branch receives security updates. Older branches may
receive backports on a best-effort basis.

| Version | Supported          |
|---------|--------------------|
| main    | :white_check_mark: |
| < main  | :x:                |

## Reporting a Vulnerability

**Please do not file a public GitHub issue for security
vulnerabilities.**

Send a private report to the maintainers via GitHub's private
vulnerability reporting feature (Security tab → "Report a
vulnerability"). You can also email the maintainer directly — see
the GitHub profile for contact info.

What to include in your report:

- A clear description of the vulnerability.
- Steps to reproduce.
- Affected version(s) (commit hash, tag, or branch).
- Potential impact (what an attacker could do).
- Any suggested fix (optional).

## Response Timeline

- **Acknowledgement**: within 3 business days.
- **Triage and assessment**: within 10 business days.
- **Fix and disclosure**: coordinated with the reporter.

We aim to follow responsible disclosure. Critical issues may warrant
faster disclosure timelines.

## Scope

In-scope:

- The scanner itself under `scanner/`.
- The HTML report's faithfulness (no XSS, no broken links, no
  fabricated PCI citations).
- The mapping YAML files under `mappings/` (correctness of
  citations, not their coverage).
- The custom checks in `scanner/checks/` (no false negatives that
  could mask vulnerabilities).
- The URL override table in `scanner/checkov_url_overrides.py`
  (no URL that points to attacker-controlled content).

Out-of-scope:

- Issues in upstream Checkov (file at
  <https://github.com/bridgecrewio/checkov/issues>).
- Issues in Terraform itself (file at
  <https://github.com/hashicorp/terraform/issues>).
- Issues in Azure (file with Microsoft).

## Security Considerations

The scanner's primary safety control is the typed operation registry in
`scanner/ops.py`. It is the canonical subprocess boundary, and
`scanner/safety.py` rejects known mutating operations before execution.
Pacioli does not change Azure storage firewall rules. When required access is
unavailable, it emits an `ACCESS REQUIRED` alert and skips the dependent
layer. Access must be granted outside Pacioli.

Plan-tier execution uses `terraform init -backend=false` and
`terraform plan -lock=false -refresh=false`. This plan is not offline:
`init` can contact `registry.terraform.io` for provider and module resolution.
The `--registry-mirror` flag and an isolated `TF_CLI_CONFIG_FILE` constrain
that resolution. Operators must validate the mirror and network boundary.

Temporary material is removed with verified cleanup through `safe_unlink()`.
This is best-effort data minimization, not a cryptographic erase guarantee.
There is no universal safety guarantee. SSD behavior, copy-on-write,
journaling, VM snapshots, Windows filesystem semantics, and external
processes are outside the scanner's verification boundary.

You can verify the refusal rules with:

```bash
make selftest
# safety_selftest: PASS
```

A way to make the scanner execute a cloud mutation through an unregistered or
improperly classified operation is a critical vulnerability. Report it
privately.

## Reporting a Path-Traversal or RCE

Specific things to look for and report:

- A `pacioli scan` codepath that allows `--project <name>` or
  `--label <text>` to traverse outside the intended run dir.
- A `rewrite_sarif_help.py` or `aggregate.py` codepath that allows
  the SARIF `helpUri` rewrite to inject HTML or JavaScript into
  the report.
- A `tfstate_to_plan.py` or `drift_report.py` codepath that
  allows the state blob to inject paths outside the run dir.
- A way to make an unregistered or improperly classified operation bypass
  `scanner/ops.py` or `scanner/safety.py` and perform an Azure mutation.

## Cryptography

The scanner does NOT handle secrets in any way that requires
cryptographic review. It scans `.tf` source for hardcoded secrets
(via Checkov's `secrets` framework) and reports findings; it does
not decrypt or re-encrypt anything.

## What We Won't Fix

- "I disagree with the severity rating" — file a feature request,
  not a security report.
- "The custom check `CKV_AZURE_PCI_005` should fire on
  `enable_purge_protection = true`" — that's a logic issue, not
  a security issue.
- "The report HTML doesn't render in IE 11" — not a security
  issue.

For all of the above, open a normal GitHub issue.
