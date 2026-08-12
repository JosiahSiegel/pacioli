# Pacioli — Mapping Schema

> **The format of `mappings/<framework>_<version>.yaml` files.**
> Use this when you add a new framework pack (SOC 2, CIS, NIST 800-53,
> ISO 27001, …), edit an existing row, or add an out-of-scope exclusion.

## Supported frameworks

Pacioli runs against every Checkov 3.3.9 framework. The
authoritative list lives in `scanner/frameworks.py` as the
`SUPPORTED_FRAMEWORKS` tuple (auto-discovered from Checkov's
`checkov_runners` at import time, with a 22-framework hardcoded
fallback when Checkov is not installed). At Checkov 3.3.9 that set
is (alphabetical):

`ansible`, `argo_workflows`, `arm`, `azure_pipelines`, `bicep`,
`bitbucket_configuration`, `bitbucket_pipelines`, `circleci_pipelines`,
`cloudformation`, `dockerfile`, `github_actions`, `github_configuration`,
`gitlab_ci`, `gitlab_configuration`, `helm`, `kubernetes`, `kustomize`,
`openapi`, `secrets`, `serverless`, `terraform`, `terraform_plan`.

The same tuple is the canonical source for the keyword list in
`pyproject.toml`, the framework examples in `README.md` and the
operator / consumer guides — do NOT duplicate the literal list
elsewhere in the docs; link to this section instead. The full
list of mapping packs shipped in `mappings/` is whatever YAML
files are present at install time; today the only shipped pack is
`mappings/pci_dss_4.0.1.yaml` (the primary worked example), with
SOC 2 / CIS / NIST / ISO 27001 packs delivered as custom mapping
packs authored by the consumer.

The aggregator (`scanner/aggregate.py`) reads the mapping file at
startup. Every field in the schema is required unless explicitly
noted. Validation is strict — the aggregator refuses to emit a
report if any required field is missing or malformed.

## Top-level schema

```yaml
version: 2                                     # Schema version (integer)
verified_against: 'YYYY-MM-DD'                 # Date the URLs were last HEAD-200 verified
framework_name: PCI DSS                        # Display name in the HTML report title
framework_version: '4.0.1'                     # Display version in the HTML report subtitle
doc_anchor: 'https://...'                      # The framework's canonical public document URL
doc_anchor_wayback: 'https://web.archive.org/...'   # Optional; verifier checks both
doc_anchor_wayback_full_pdf: 'https://...'     # Optional; frozen full-text mirror
pci_dss_version: 4.0.1                         # Optional legacy alias (PCI mapping only)
requirements:                                  # List of in-scope requirements
  - id: 1.2.1
    title: ...
    checks: [...]
    note: ...
    out_of_scope: false                        # Optional (default false)
    approach: defined                          # Optional
out_of_scope_requirements:                     # List of out-of-scope requirement families
  - id: ...
    title: ...
    rationale: ...
    control_owner: ...
    approved_by: ...                           # Optional
    approved_on: 'YYYY-MM-DD'
    expires_on: 'YYYY-MM-DD'
    evidence_link: 'https://...'
```

## Top-level keys

| Key | Required | Description |
|---|---|---|
| `version` | yes | Schema version. Currently `2`. Increment when changing the schema. |
| `verified_against` | yes | ISO date the operator last verified every `doc_anchor` URL with HEAD 200. |
| `framework_name` | yes | Display name shown in the HTML report title and sidebar. |
| `framework_version` | yes | Display version shown in the HTML report subtitle. |
| `doc_anchor` | yes | The framework's single canonical public document URL. Must return HEAD 200. |
| `doc_anchor_wayback` | no | Optional Wayback Machine mirror. The aggregator does not require it but operators use it for resilience. |
| `doc_anchor_wayback_full_pdf` | no | Optional frozen full-text mirror. |
| `pci_dss_version` | no | PCI-specific legacy alias for `framework_version`. Kept for backward compat with pre-extraction tooling. |
| `requirements` | yes | List of in-scope requirements. May be empty. |
| `out_of_scope_requirements` | yes (as a key) | List of out-of-scope requirement families. May be empty. The aggregator still validates the list — see below. |
| `severity_overrides` | no | Optional `check_id → severity` map. See [Severity overrides](#severity-overrides) below. When absent, every check falls through to `DEFAULT_SEVERITY` (`MEDIUM`). |

The key `out_of_scope_requirements` must be present even if the
list is empty. The aggregator iterates over it unconditionally.

## In-scope requirement schema

```yaml
- id: 1.2.1                                              # Framework req id (string)
  title: Configuration standards for NSCs are defined    # Human-readable title
  checks:                                                # List of Checkov rule IDs
    - CKV_AZURE_9
    - CKV_AZURE_10
    - CKV_AZURE_59
  note: CKV_AZURE_89 anchored here as 1.2.1 evidence.   # Optional; rationale
  out_of_scope: false                                    # Optional; default false
  approach: defined                                      # Optional; free text
```

| Field | Required | Description |
|---|---|---|
| `id` | yes | Stable framework requirement ID. Format depends on the framework: PCI uses `1.2.1`, SOC 2 uses `CC6.1`, CIS uses `2.1.1`, etc. |
| `title` | yes | The full requirement title, copied from the framework's authoritative document. |
| `checks` | yes | List of Checkov rule IDs that satisfy this requirement. May be empty if the requirement has no IaC-attestable surface. |
| `note` | no | Free-text rationale. Used for non-obvious anchorings (e.g. "CKV_AZURE_89 anchored here as 1.2.1 evidence"). When the `checks` list contains a `CKV_AZURE_PCI_NOTE_*` token, the note is rendered as the `triage_hint` in `coverage_gaps.csv`. |
| `out_of_scope` | no | Boolean. Default `false`. Reserved for marking rows as out-of-scope without moving them to the `out_of_scope_requirements` list. Not currently rendered in the report; documented for forward compat. |
| `approach` | no | Free text. Used by the operator to record the verification approach (e.g. "defined"). Not currently rendered. |

### `checks` — list of Checkov rule IDs

The aggregator inverts this list to a `{check_id → [req_id, ...]}`
map at load time. A check_id can appear in multiple requirements
(it is unusual but valid; the report handles it correctly).

Valid check_id formats:

- `CKV_AWS_<N>` — Checkov OSS AWS checks (e.g. `CKV_AWS_18`,
  `CKV_AWS_53`)
- `CKV_AZURE_<N>` — Checkov OSS Azure checks (e.g. `CKV_AZURE_212`)
- `CKV_GCP_<N>` — Checkov OSS GCP checks (e.g. `CKV_GCP_6`,
  `CKV_GCP_21`)
- `CKV_K8S_<N>` — Checkov OSS Kubernetes checks (e.g. `CKV_K8S_8`,
  `CKV_K8S_22`)
- `CKV2_AZURE_<N>` — Checkov graph checks (e.g. `CKV2_AZURE_1`)
- `CKV2_AWS_<N>` — Checkov graph checks (e.g. `CKV2_AWS_6`)
- `CKV_SECRET_<N>` — Checkov secrets framework
- `CKV_TF_<N>` — Checkov generic Terraform checks
- `CKV_AZURE_PCI_<NNN>` — Pacioli's custom PaaC checks
  (`CKV_AZURE_PCI_001` through `CKV_AZURE_PCI_005` ship today;
  custom checks follow the same `<cloud>_<pack>_<NNN>` shape so
  the prefix matches the rule ID family they target)
- `CKV_AZURE_PCI_NOTE_<X>` — symbolic placeholder for reqs with
  no working Checkov coverage. See below.

### `CKV_AZURE_PCI_NOTE_*` tokens

Some PCI requirements have no working Checkov 3.3.9 coverage (e.g.
PCI 10.7, audit log retention — Checkov evaluates the *existence*
of diagnostic settings, not the *retention period*). For these
reqs, the mapping author can declare a symbolic token in
`checks:` and pair it with a `note:` field:

```yaml
- id: 10.7
  checks:
    - CKV_AZURE_PCI_NOTE_10_7
  note: |
    PCI 10.7 (audit log retention 12 months) has no working
    Checkov 3.3.9 coverage. Validation lives in the
    application/SIEM log-retention config, not in Terraform.
```

The aggregator filters `CKV_AZURE_PCI_NOTE_*` tokens out of
`expected_by_req` (so `expected_count` and `missing_count` stay
zero for note-only reqs) and carries the `note` text via
`triage_hint` in `coverage_gaps.csv` so the auditor sees the
rationale instead of a generic "1 check expected, 0 fired" string.

Adding a new note token requires updating the
`PCI_NOTE_TOKENS` set in `scanner/aggregate.py`. The CI
pytest test `test_aggregate_pci.py` validates the mapping
loader; the manual list lives at the top of
`scanner/aggregate.py`.

### Severity overrides

Each mapping pack MAY declare a top-level `severity_overrides`
table that pins a Checkov rule ID to a canonical severity tag.
This is the per-pack replacement for the legacy in-code
`SEVERITY_OVERRIDE` constant — the table now travels with the
mapping YAML so a SOC 2 / CIS / NIST pack can ship its own
severity policy without touching `scanner/aggregate.py`.

```yaml
severity_overrides:
  CKV_AZURE_44: HIGH     # Storage Account TLS latest version (PCI 4.2.1)
  CKV_AZURE_18: MEDIUM   # Web App http2_enabled (PCI 10.2.1)
  CKV_AZURE_70: MEDIUM   # Function app HTTPS only (PCI 4.2.1)
  CKV2_AZURE_1: HIGH     # Storage critical data encrypted with CMK
```

| Field | Required | Format | Description |
|---|---|---|---|
| key | yes | Checkov rule ID (`CKV_AZURE_<N>`, `CKV2_AZURE_<N>`, `CKV_SECRET_<N>`, `CKV_TF_<N>`) | The rule whose severity you want to pin. |
| value | yes | Upper-case `HIGH` \| `MEDIUM` \| `LOW` \| `CRITICAL` | Severity tag emitted in the HTML report and consulted by `pacioli gate`. |

**Resolution precedence** (highest first), implemented in
`resolve_severity(check_id, mapping_pack, rule_severity=...)`:

1. `rule.properties.severity` from the SARIF rule entry (when
   the SARIF producer actually emits it — Checkov 3.3.9 does
   not, so this slot is normally `None`).
2. `mapping_pack["severity_overrides"][check_id]` — the
   per-pack table. Lookup is **pack-scoped**: once a pack is
   in play, the function does NOT silently substitute the
   install-bundled PCI overrides. A SOC 2 / CIS pack that
   omits `severity_overrides` (or declares an empty table)
   sees a MISS for every check and falls through to
   `DEFAULT_SEVERITY`. This avoids a framework-mismatch bug
   where a non-PCI pack would silently inherit PCI's
   `CKV_AZURE_44=HIGH` (or similar) for shared rule IDs.
3. `DEFAULT_SEVERITY` (`MEDIUM`) — last-resort for any rule
   not pinned by either of the above.

When `severity_overrides` is **omitted** from a pack entirely,
the pack still loads and runs end-to-end — every finding just
defaults to `MEDIUM`. This is the contract `test_resolve_severity_falls_back_when_pack_has_no_overrides`
asserts in `scanner/tests/test_aggregate_pci.py`.

The legacy `SEVERITY_OVERRIDE` Python constant in
`scanner/aggregate.py` is preserved as a thin alias for any
external caller that imports it directly. New code should call
`resolve_severity()` instead.

### Out-of-scope requirement schema

```yaml
- id: 11.x (excluding 11.6.1)                          # Stable req-family ID
  title: Test security of systems and networks regularly
  rationale: |
    PCI 11.x covers runtime vulnerability scanning
    (internal/external scans, ASV, pentest). IaC scanners
    cannot evaluate running-system posture, so we exclude
    this family and rely on the runtime controls listed
    under evidence_link.
  control_owner: Security team -- Vulnerability Management
  approved_by: <approver-name>                       # Optional
  approved_on: '<YYYY-MM-DD>'
  expires_on: '<YYYY-MM-DD>'
  evidence_link: '<resolvable URL or ticket ID>'
```

| Field | Required | Format | Description |
|---|---|---|---|
| `id` | yes | Free string | Stable req-family ID. The ID MUST be unique across both `requirements` and `out_of_scope_requirements` (the aggregator's validation refuses duplicates). |
| `title` | yes | Free text | The full requirement title from the framework doc. |
| `rationale` | yes | Free text | WHY IaC scanning cannot evaluate this. Must be concrete ("process", "runtime", "vendor-managed"), not a tautology like "out of scope". |
| `control_owner` | yes | Free text | Who owns the control OUTSIDE the scanner. Answerable question: "If not us, then who?" |
| `approved_by` | no | Free text | Optional historical record of who approved the exclusion. Not required. |
| `approved_on` | yes | ISO `YYYY-MM-DD` | Date of approval. |
| `expires_on` | yes | ISO `YYYY-MM-DD` | Auto-expiry. Aggregator renders a red `STALE (expired Nd ago)` badge once `expires_on < today`. |
| `evidence_link` | yes | Resolvable URL or ticket ID | Where an auditor verifies external proof. NOT a placeholder like `tbd` or `to be defined`. |

### Validation rules for out-of-scope entries

`validate_out_of_scope_entries` in `scanner/aggregate.py` enforces:

1. **Every required field is present and non-empty.**
2. **No field is the literal `"TBD"`** (loud warning that someone
   meant to fill it in later).
3. **`approved_on` and `expires_on` parse as ISO `YYYY-MM-DD`.**
4. **`approved_on <= expires_on`** (illogical if reversed).
5. **`expires_on >= today`** is NOT a refusal — it surfaces as the
   `STALE` badge but does NOT block the run. A stale exclusion is
   informational, not invalid.

A missing-required field, TBD placeholder, or invalid date
**refuses the run with return code 2** BEFORE any artifact is
written. The operator cannot produce a partial compliance report.

### What the report shows for out-of-scope rows

In `coverage_matrix.csv`, the OOS row has all fields as columns
(`title`, `rationale`, `control_owner`, `approved_by`,
`approved_on`, `expires_on`, `evidence_link`) plus `stale`
(`true`/`false`) and `days_to_expiry` (int).

In `report.html`, each OOS row expands into a definition list
with clickable `evidence_link`. Stale entries show a red
`STALE (expired Nd ago)` badge.

### Renewing stale exclusions

When the `STALE` badge appears:

1. Review with the control owner whether the exclusion is still
   valid.
2. If yes: bump `expires_on` (audit has been re-confirmed). Commit
   with a justification line in the commit message linking to the
   approval ticket.
3. If no: REMOVE the entry from `out_of_scope_requirements`. If
   the requirement now has IaC-attestable coverage, add it back to
   `requirements` with the appropriate `checks:` list. If it
   remains unactionable, leave it out and the per-req cell will
   show `not_applicable` in the matrix.

## Adding a new mapping pack

1. Copy `mappings/pci_dss_4.0.1.yaml` to
   `mappings/<framework>_<version>.yaml`.
2. Change `framework_name` and `framework_version` at the top.
3. (Optional) Declare a top-level `severity_overrides` table that
   pins Checkov rule IDs to canonical severity tags — see
   [Severity overrides](#severity-overrides) below. A pack without
   `severity_overrides` falls through to `DEFAULT_SEVERITY`
   (`MEDIUM`) for every check.
4. Replace the `requirements:` list with the new framework's
   controls. The `checks:` IDs MUST be valid Checkov rule IDs
   (run `checkov -l | grep CKV_` for the full list, scoped to
   the framework your pack targets — e.g. `CKV_AWS_*` for an AWS
   SOC 2 pack, `CKV_K8S_*` for a Kubernetes CIS pack).
5. Replace `out_of_scope_requirements` with the req families that
   the scanner cannot evaluate for this framework.
6. Re-run the scanner with
   `--mapping mappings/<framework>_<version>.yaml
   --framework <matching-framework>`. Auto-detection also works
   when the pack's `framework_name` matches a Checkov framework;
   otherwise pass `--framework` explicitly.
7. The HTML title and sidebar will reflect the new framework name.
8. Optionally, set `PACIOLI_MAPPING` (or `--mapping`) in CI so
   every run ships with the new pack.

For the custom checks in `scanner/checks/`:

- Keep them (the existing `CKV_AZURE_PCI_*` checks are
  Terraform-family hygiene checks that apply to any compliance
  framework that targets Azure Terraform), or
- Move them to a framework-specific subdirectory and update the
  `--external-checks-dir` flag in `scanner/checkov_runner.py`
  (the orchestrator consumes the runner; the
  `--external-checks-dir` gate lives in `_run` /
  `_run_paac`). The current pack filters to the Terraform
  framework only because the shipped custom checks are
  Terraform-shaped — a non-Terraform pack will not get them
  wired in automatically.

## Verifying the mapping file

`make selftest` does not validate mapping files. The
`mapping-lint` job in `.github/workflows/ci.yml` does — it runs
on every PR and refuses to merge if:

- A required top-level key is missing.
- `load_pci_mapping` returns 0 check_ids.
- `validate_out_of_scope_entries` returns any errors.

To validate locally:

```python
import yaml
from pathlib import Path
import sys
sys.path.insert(0, "scanner")
from aggregate import load_pci_mapping, validate_out_of_scope_entries

data = yaml.safe_load(Path("mappings/pci_dss_4.0.1.yaml").read_text())
for key in ("framework_name", "framework_version", "requirements"):
    assert key in data, f"missing required key: {key}"

mapping = load_pci_mapping(Path("mappings/pci_dss_4.0.1.yaml"))
assert len(mapping) > 0, "no checks mapped"

if "out_of_scope_requirements" in data:
    errors, _ = validate_out_of_scope_entries(
        data["out_of_scope_requirements"],
        today_iso="2026-08-06",
    )
    if errors:
        for e in errors:
            print("  -", e)
        sys.exit(1)

print(f"OK: {len(mapping)} checks mapped to {len(data['requirements'])} requirements")
```

## See also

- [Operator Guide → What the scanner checks](OPERATOR_GUIDE.md#what-the-scanner-checks)
- [Architecture](ARCHITECTURE.md) — how the mapping is loaded
- [Developer Guide](DEVELOPER_GUIDE.md) — extending the scanner
- [CLI Reference](CLI_REFERENCE.md) — every argument
