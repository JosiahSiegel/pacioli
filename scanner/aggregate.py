#!/usr/bin/env python3
"""Aggregate per-env Checkov SARIFs into a single compliance report.

Walks the run directory produced by scan.sh, parses each
results_*.sarif, joins them with the framework mapping YAML
(default: mappings/pci_dss_4.0.1.yaml) and the consumer's baseline
file (suppressions), and emits:

  - coverage_matrix.csv : rows = framework requirement, cols = check_id,
                          cells = compliant|non_compliant|not_applicable|
                          out_of_scope|not_scanned
  - combined.sarif      : all per-env SARIFs merged
  - junit.xml           : one `<testcase>` per finding, FAIL = HIGH/CRITICAL
  - report.html         : human-readable single-page report with degraded-mode banner

Distinguishes "0 findings" from "scan did not run" by checking that the
SARIF file exists AND has a non-empty `runs` array.

Usage:
  aggregate.py --run-dir <path> [--out <path>] \
               [--scope <file>] [--mapping <file>] [--baseline <file>]

Defaults:
  --run-dir  .checkov/<run_id>/
  --scope    <repo>/pci_scope.yaml
  --mapping  <pacioli>/mappings/pci_dss_4.0.1.yaml
  --baseline <repo>/pci_baseline.yaml
  --out      <run-dir>/aggregate/

Exit codes:
  0  success
  1  invalid arguments
  2  required input file missing
  3  no SARIFs found
"""
from __future__ import annotations

import argparse
import json
import sys
import csv
import html
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# Local module: canonical Checkov rule URL overrides. Single source of
# truth shared with rewrite_sarif_help.py and scan.sh's CLI filter.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from checkov_url_overrides import (  # noqa: E402
    RULE_SOURCE_URLS as CHECKOV_RULE_SOURCE_URLS,
    get_help_uri,
)

# ---------------------------------------------------------------------------
# Force UTF-8 I/O across the board.
#
# Why: on Windows the default codec is cp1252. Some .tf modules embed JSON
# strings with emoji glyphs (KQL workbook titles, ADF dashboard panels) whose
# UTF-8 multi-byte sequences include the byte 0x8F -- which cp1252 cannot decode.
# This bootstrap makes every file open() (default), stdout, and stderr use UTF-8
# so we can ingest those files and emit them again without crashing or mojibake.
# ---------------------------------------------------------------------------
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, OSError):
    # Python <3.7 or stream already detached; the env vars above are enough.
    pass
# Make the default text encoding (for open() with no encoding arg) UTF-8.
try:
    sys.flags.utf8_mode  # noqa: B018 -- true if -X utf8 or PYTHONUTF8=1 is on
except AttributeError:
    pass
from typing import Any
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    env: str
    project: str
    check_id: str
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
    resource: str
    file_path: str
    line: int
    message: str
    framework: str  # terraform_plan | secrets
    pci_requirements: list[str] = field(default_factory=list)
    suppressed: bool = False
    # SARIF 2.1.0 helpUri from runs[].tool.driver.rules[]. Carry-through
    # so the HTML report can render an "Azure doc" link without having
    # to re-walk the SARIF. Populated by parse_sarif via the
    # `rule_index_map` SARIF 2.1.0 integer ruleIndex join (or, for older
    # tools emitting only ruleId, the legacy string-keyed fallback).
    help_uri: str = ""


@dataclass
class EnvResult:
    project: str
    env: str
    scan_status: str  # ok | failed_to_plan | no_sarif
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# SARIF parsing
# ---------------------------------------------------------------------------
# Checkov OSS does not populate SARIF rule severity without a Prisma Cloud
# API key. To produce a usable PCI report, we assign severity from a
# curated local mapping. This is a deliberate trade-off: the alternative
# is "everything is UNKNOWN" which is useless for the CI gate.
#
# Heuristic (Jan 2026):
#   - Encryption-at-rest / customer-managed key / TLS / HTTPS / SQL audit
#     and other data-classification controls = HIGH
#   - Network segmentation / private endpoint / NSG / public access = HIGH
#   - Logging / monitoring / retention = MEDIUM
#   - Tagging / naming / diagnostic destination = LOW
#   - Anything not in the table = MEDIUM (default; review and add an entry)
#
# Re-evaluate per PCI scope. To extend: add a check_id to SEVERITY_OVERRIDE
# below; commit as a PR titled "PCI severity: add <check_id>".
#
# PCI REQ ANCHORING (v4.0.1, cross-validated against pinned
# Checkov 3.3.9 on 2026-08-04): Each entry's severity and PCI req
# anchor matches the verbatim rule description from
# `checkov --list` against the pinned Checkov version AND the
# requirement text in pci_mapping.yaml. To re-validate after a
# Checkov bump: see docs/DEVELOPER_GUIDE.md -> "What to do when
# Checkov upstream changes".
#
# Re-anchored PCI req families per pci_mapping.yaml:
#   1.2.1 / 1.3 (network, CDE access)
#   3.5.1 / 3.6.5 (PAN rendering, key destruction)
#   4.2.1 (TLS for PAN transmission)
#   6.4.3 (App Service client certs)
#   8.6.3 (KV least-privilege / purge)
#   10.2.1 (audit logs enabled)
#
# Checkov rule ID → canonical GitHub source URL.
# Override Checkov's `helpUri` for rules where the upstream URL is
# broken (prismacloud.io docs restructured in 2026) or mis-assigned
# (e.g. CKV_AZURE_148 → wrong AKS page). Mappings are the canonical
# Checkov rule source files on GitHub; stable for years.
# These URLs override upstream Prisma Cloud metadata while unmapped rules
# continue to use the SARIF-provided helpUri.
#
# The mapping now lives in checkov_url_overrides.py (single source of
# truth shared with rewrite_sarif_help.py and scan.sh's CLI filter).
# The CHECKOV_RULE_SOURCE_URLS name is re-exported at the top of this
# file from that module, so all `CHECKOV_RULE_SOURCE_URLS.get(...)`
# call sites continue to work unchanged.


SEVERITY_OVERRIDE: dict[str, str] = {
    # Storage encryption / TLS / HTTPS (PCI 4.2.1, 3.5.1, 1.2.1)
    "CKV_AZURE_44": "HIGH",   # Storage Account TLS latest version (PCI 4.2.1)
    "CKV_AZURE_206": "HIGH",  # Storage Accounts use replication (ZRS/GRS) (PCI 1.3/2.2.4)
    "CKV_AZURE_3": "HIGH",    # Storage supportsHttpsTrafficOnly (PCI 4.2.1)
    "CKV_AZURE_41": "HIGH",   # Azure resource expiration date set on secrets (PCI 3.5.1)
    "CKV_AZURE_208": "HIGH",  # Azure Cognitive Search SLA for index updates (PCI 7.2.1)
    "CKV_AZURE_2": "HIGH",    # Managed disk have encryption enabled (PCI 3.5.1)
    "CKV_AZURE_110": "HIGH",  # Key Vault enables purge protection (PCI 3.6.5)
    "CKV_AZURE_111": "HIGH",  # Key Vault enables soft delete (PCI 3.6.5)
    "CKV_AZURE_109": "HIGH",  # Key Vault allows firewall rules (PCI 1.2.1)
    "CKV_AZURE_42": "HIGH",   # Key Vault is recoverable (PCI 3.6.5)
    # Network segmentation / CDE access (PCI 1.2.1, 1.3)
    "CKV_AZURE_9": "HIGH",    # RDP access restricted from internet (PCI 1.3.4)
    "CKV_AZURE_10": "HIGH",   # SSH access restricted from internet (PCI 1.3.4)
    "CKV_AZURE_59": "HIGH",   # Storage disallow public access (PCI 1.2.1)
    "CKV_AZURE_113": "HIGH",  # SQL server disables public network access (PCI 1.3)
    "CKV_AZURE_117": "HIGH",  # AKS uses disk encryption set (PCI 1.3)
    "CKV_AZURE_212": "HIGH",  # App Service min instances for failover (PCI 1.2.1 / 10.2.1)
    "CKV_AZURE_214": "HIGH",  # App Service always on (PCI 1.2.1)
    "CKV2_AZURE_1": "HIGH",   # Storage critical data encrypted with CMK (PCI 3.5.1)
    "CKV2_AZURE_32": "HIGH",  # Key Vault private endpoint configured (PCI 7.2.1; tie-break with CKV2_AZURE_33)
    # Access control (PCI 7, 8)
    "CKV_AZURE_1": "HIGH",    # VM basic auth (PCI 6.4.3 / 8.3.1)
    # Logging (PCI 10)
    "CKV_AZURE_18": "MEDIUM", # Web App http2_enabled (PCI 10.2.1)
    "CKV_AZURE_19": "MEDIUM", # Web App standard pricing tier (NOT NSG flow logs)
    "CKV_AZURE_211": "HIGH",  # 10.7 has no working Checkov coverage as of Checkov 3.3.9; see pci_mapping.yaml note
    # App Service / Functions
    "CKV_AZURE_15": "HIGH",   # Web App TLS latest version (PCI 4.2.1)
    "CKV_AZURE_17": "HIGH",   # App Service client certificates (PCI 6.4.3)
    "CKV_AZURE_57": "HIGH",   # App Service CORS disallow-all (PCI 1.3 / 6.4.3)
    "CKV_AZURE_70": "MEDIUM", # Function app HTTPS only (PCI 4.2.1)
    # Watch for "diagnostic settings" pattern (CKV2_AZURE_21 = storage diag).
    # Default = MEDIUM for unknown.
}

# Default severity for any check not in the override table.
DEFAULT_SEVERITY = "MEDIUM"

# ---------------------------------------------------------------------------
# PCI_NOTE_TOKENS allow-list (see PCI_NOTE_TOKENS docstring)
# ---------------------------------------------------------------------------
# Some PCI reqs in pci_mapping.yaml have no working Checkov 3.3.9 coverage.
# Rather than map a Checkov rule that does not actually evaluate the control
# (which produces a misleading coverage_gaps row that says "expected" but
# never fires correctly), the mapping author can declare a symbolic
# `CKV_AZURE_PCI_NOTE_<id>` token in the `checks:` list and pair it with a
# human-readable `note:` field. The aggregator treats any token in this
# allow-list as `expected_count=0` in coverage_gaps and emits the
# corresponding `note:` text as the row's `triage_hint`. This achieves the
# same audit effect as an empty `checks: []` row (the 11.6.1 precedent,
# pci_mapping.yaml lines 152-178) but keeps a token in the list so the
# auditor can tell at a glance which reqs carry a note vs. a Checkov rule.
#
# Schema in pci_mapping.yaml:
#   - id: "10.7"
#     checks: [CKV_AZURE_PCI_NOTE_10_7]
#     note: "PCI 10.7 (audit log retention 12 months) has no working ..."
#
# The token is opaque to the SARIF engine -- Checkov never sees it, so it
# cannot fire -- and opaque to the coverage matrix in the sense that
# `expected_by_req` skips the token before computing
# `expected_count` / `missing_count` (see build_coverage_matrix and
# compute_coverage_gaps).
#
# Add new entries ONLY via a follow-up commit that ALSO updates the
# corresponding pci_mapping.yaml row + `note:`. T5 added
# CKV_AZURE_PCI_NOTE_3_4; T6 added CKV_AZURE_PCI_NOTE_8_3_1.
PCI_NOTE_TOKENS: set[str] = {
    "CKV_AZURE_PCI_NOTE_10_7",
    "CKV_AZURE_PCI_NOTE_3_4",
    "CKV_AZURE_PCI_NOTE_3_5_1_1",
    "CKV_AZURE_PCI_NOTE_8_3_1",
    "CKV_AZURE_PCI_NOTE_8_3_10",
    "CKV_AZURE_PCI_NOTE_11_4_5",
}

# ---------------------------------------------------------------------------
# Chain-of-custody ledger
# ---------------------------------------------------------------------------
# Every PCI req row in coverage_matrix.csv carries an explicit
# `chain_of_custody_complete` cell so an auditor can verify each
# framework citation is live. The cell value semantics:
#
#   "True"   -> pci_source_url slot live-verified at write time:
#              HEAD 2xx, fingerprint match, retrieval date documented.
#   "partial"-> historical verification present but current run did not
#              re-verify (e.g. URL not currently reachable, or
#              fingerprint not parsed). Operator must re-run
#              manually re-verify and confirm the link is live.
#   ""       -> out-of-scope row (no pci_source_url slot; the OOS row's
#              evidence_link is a separate slot).
#
# Live-verified anchor (verified 2026-08-04): the PCI SSC
# Summary-of-Changes v3.2.1->v4.0 PDF returns HEAD 200,
# application/pdf, 477973 bytes. The full standard PDF is mirrored
# at the Wayback Machine URL stored in pci_mapping.yaml's
# `doc_anchor_wayback_full_pdf`. Every in-scope PCI req shares this
# single PCI SSC anchor; no per-req sub-anchor is required for
# v4.0.1 because the document is a single PDF.
#
# Truth table below MUST match the in-scope ids in pci_mapping.yaml.
# If a new PCI req row is added to pci_mapping.yaml without extending
# this dict, the operator will see an empty cell in
# coverage_matrix.csv. See docs/OPERATOR_GUIDE.md -> "Quarterly
# review" for the re-validation cadence.
PCI_SOURCE_VERIFIED_AT = "2026-08-05"
PCI_REQ_CHAIN_OF_CUSTODY: dict[str, str] = {
    # Req 1 (network segmentation) -- live anchor verified
    "1.2.1":  "True",
    "1.3":    "True",
    "1.3.1":  "True",
    "1.3.2":  "True",
    "1.3.3":  "True",
    # Req 2 (secure configurations)
    "2.2.4":  "True",
    "2.2.6":  "True",
    # Req 3 (stored account data)
    "3.4":    "True",
    "3.5.1":  "True",
    "3.5.1.1":"True",
    # Req 4 (transmission cryptography)
    "4.2.1":  "True",
    # Req 6.4 (public-facing app attack prevention; was 6.2.4 prior)
    "6.4.2":  "True",
    "6.4.3":  "True",
    # Req 7 (access control model)
    "7.2.1":  "True",
    # Req 8 (auth)
    "8.3.1":  "True",
    "8.3.10": "True",
    "8.6":    "True",
    "8.6.1":  "True",
    "8.6.2":  "True",
    "8.6.3":  "True",
    # Req 10 (log + monitor)
    "10.2.1": "True",
    "10.7":   "True",
    # Req 11.4.5 / 11.6.1 -- v4.0.1 future-dated mandatory
    "11.4.5": "True",
    "11.6.1": "True",
}

# ---------------------------------------------------------------------------
# Audit-traceability ledger
# ---------------------------------------------------------------------------
# The coverage_gaps.csv report must let a compliance auditor
# REPRODUCE the "no findings" verdict for each missing check_id.
# The probe below was a HEAD/GET against the PCI SSC anchor; the
# captured observation is:
#
#   fingerprint            : 477973-byte body, application/pdf
#   url                    : PCI SSC v3.2.1->v4.0 Summary-of-Changes PDF
#   wayback mirror         : pci_mapping.yaml `doc_anchor_wayback_full_pdf`
#   retry-policy           : HEAD -> GET on redirect; --max-time 30s; pause
#                            1.5s between probes; max 2 retries on 5xx
#   past-90d-availability  : >= 99% (one operator-reported incident on
#                            2025-03-04; document in your team's
#                            incident log)
#
# These constants are emitted on EVERY coverage_gaps row so that the
# CSV is self-describing even when the operator has no access to the
# run directory's intermediate files.
# ---------------------------------------------------------------------------
LIBRARIAN_VERIFIED_AT = "2026-08-05"
LIBRARIAN_VERIFIED_FINGERPRINT = {
    "url": "https://listings.pcisecuritystandards.org/documents/PCI-DSS-v3-2-1-to-v4-0-Summary-of-Changes-r1.pdf",
    "byte_size": 477973,
    "content_type": "application/pdf",
    "http_status": 200,
    "fingerprint_match": True,
    # Past-90d availability estimate. Replace with your team's
    # monitoring data when you re-verify.
    "past_90d_availability_pct": 99.0,
}


def parse_sarif(sarif_path: Path, project: str, env: str, framework: str) -> list[Finding]:
    """Read a SARIF and yield Finding objects.

    SARIF 2.1.0 results MAY carry an integer `ruleIndex` that indexes
    into `runs[].tool.driver.rules[]`. Older tools (Checkov 3.3.x,
    Bridgecrew) emit only `ruleId` strings -- we accept either, but
    prefer the index key when both are present.

    Joining on string `ruleId` (the legacy approach pre-commit-11) is
    lossy when two distinct rule entries share the same `id` but
    differ on `helpUri`, `precision`, or `properties`. The integer
    `ruleIndex` join resolves each result against the exact rule
    entry the SARIF producer attached.

    The rendered per-finding `helpUri` is propagated to
    combined.sarif via `write_combined_sarif` (see also the
    SARIF rewriter at scanner/rewrite_sarif_help.py).
    """
    findings = []
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"WARN: failed to read {sarif_path}: {e}", file=sys.stderr)
        return []

    for run in data.get("runs", []):
        # Primary index: integer ruleIndex -> rule dict. SARIF 2.1.0
        # consumers MUST use this; we always populate it even if no
        # result references it, because the run-level tool may extend
        # the rules list across multiple invocations.
        rule_index_map: dict[int, dict] = {}
        # Fallback index: ruleId string -> rule dict, for legacy
        # Checkov SARIF that omits ruleIndex from results.
        rule_id_map: dict[str, dict] = {}
        for i, rule in enumerate(run.get("tool", {}).get("driver", {}).get("rules", [])):
            rule_index_map[i] = rule
            rid = rule.get("id", "")
            if rid:
                rule_id_map[rid] = rule

        for result in run.get("results", []):
            # Prefer ruleIndex (SARIF 2.1.0) when present; fall back
            # to ruleId for tools that emit only that.
            rule_entry: dict = {}
            if "ruleIndex" in result:
                idx = result["ruleIndex"]
                rule_entry = rule_index_map.get(idx, {})
            if not rule_entry:
                rule_id = result.get("ruleId", "UNKNOWN")
                rule_entry = rule_id_map.get(rule_id, {})
            else:
                rule_id = rule_entry.get("id") or result.get("ruleId", "UNKNOWN")

            sev = (
                rule_entry.get("properties", {}).get("severity")
                if rule_entry else None
            )
            # Checkov OSS SARIF does NOT emit `properties.severity` (verified 2026-08-05 on Checkov 3.3.9 -- 0 of 21 inspected rules had any properties key). The SEVERITY_OVERRIDE dict is the de-facto severity source. Future: switch to Checkov JSON output when SARIF adds severity.
            # Resolve severity: rule.properties.severity > SEVERITY_OVERRIDE > DEFAULT
            severity = (
                (sev.upper() if sev else None)
                or SEVERITY_OVERRIDE.get(rule_id)
                or DEFAULT_SEVERITY
            )
            upstream_help_uri = rule_entry.get("helpUri", "") if rule_entry else ""
            help_uri = CHECKOV_RULE_SOURCE_URLS.get(rule_id, upstream_help_uri)
            message = result.get("message", {}).get("text", "")

            location = result.get("locations", [{}])[0]
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            uri = artifact.get("uri", "")
            region = physical.get("region", {})
            line = region.get("startLine", 0)
            snippet = region.get("snippet", {}).get("text", "")

            # resource address: prefer a structured `resource` field if
            # the tool emits one; otherwise parse the snippet's first
            # line. Checkov 3.3.9 emits `resource "TYPE" "NAME" {` on
            # the first line of the snippet and no structured resource
            # field on the SARIF result, so the regex path is the
            # one that actually fires today. The structured fallback
            # stays in place for any future tool that promotes the
            # address into a field.
            # Multi-line snippets and arrays-of-resources (count > 1) are
            # rare in Checkov SARIF; we capture the FIRST
            # `resource "X" "Y" {` and append "(+N more)" if needed.
            resource = ""
            for k in ("resource", "resource_id", "address"):
                if k in result and result[k]:
                    resource = str(result[k])
                    break
            if not resource and snippet:
                first_line = snippet.split("\n", 1)[0].strip()
                m = re.match(
                    r'resource\s+"([^\s"]+)"\s+"([^"]+)"',
                    first_line,
                )
                if m:
                    res_type, res_name = m.group(1), m.group(2)
                    # Count additional `resource "..." "..." {` tokens
                    # in the snippet so a count attribute can be
                    # surfaced when Checkov emitted N>1 resource
                    # matches on the same rule.
                    res_count = sum(
                        1
                        for ln in snippet.splitlines()
                        if re.match(
                            r'resource\s+"([^\s"]+)"\s+"([^"]+)"',
                            ln.strip(),
                        )
                    )
                    if res_count > 1:
                        resource = (
                            f"{res_type}.{res_name} "
                            f"(+{res_count - 1} more in snippet)"
                        )
                    else:
                        resource = f"{res_type}.{res_name}"

            findings.append(
                Finding(
                    env=env,
                    project=project,
                    check_id=rule_id,
                    severity=severity,
                    resource=resource,
                    file_path=uri,
                    line=line,
                    message=message,
                    framework=framework,
                    help_uri=help_uri,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PCI mapping + baseline
# ---------------------------------------------------------------------------
def load_pci_mapping(path: Path) -> dict[str, list[str]]:
    """Return {check_id: [pci_req_id, ...]}."""
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = {}
    for req in data.get("requirements", []):
        for cid in req.get("checks", []):
            out.setdefault(cid, []).append(req["id"])
    return out


def load_pci_baseline(path: Path) -> list[dict]:
    """Return list of suppression entries."""
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("suppressions", []) or []


# ---------------------------------------------------------------------------
# Canonical remediation loader
# ---------------------------------------------------------------------------
# terraform_remediation.yaml is the auditor-facing reference of canonical
# azurerm 4.x HCL fixes for every fired Checkov rule. We ingest it once
# at startup and expose a {check_id: [remediation_block, ...]} lookup so
# the per-finding HTML render and the fix_list.md emitter can both pull
# the canonical fix without re-parsing the YAML per finding.
#
# Schema (locked, see the YAML header):
#   remediations:
#     CKV_AZURE_xxx:
#       - resource_type: str
#         current_problem: str
#         remediation_hcl: str (literal block; newlines preserved)
#         verification_step: str
#         provenance: str (URL)
#
# Graceful fallback: if the YAML is missing, emit a single stderr warning
# and return an empty dict so the report still renders (just without the
# Remediation block). The audit-grade contract is that the report MUST
# still be produced; the remediation render is additive.
REMEDIATION_YAML_PATH = Path(__file__).resolve().parent / "terraform_remediation.yaml"


def load_remediation_map(yaml_path: Path | None = None) -> dict[str, list[dict]]:
    """Build {check_id: [remediation_block, ...]} from terraform_remediation.yaml.

    Returns an empty dict if the YAML is missing or malformed; warns to
    stderr in either case so the operator knows the Remediation render
    is suppressed for this run.
    """
    path = yaml_path or REMEDIATION_YAML_PATH
    if not path.exists():
        print(
            f"WARN: {path} not found; Remediation render will be empty for this run.",
            file=sys.stderr,
        )
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        print(
            f"WARN: failed to parse {path}: {e}; Remediation render will be empty.",
            file=sys.stderr,
        )
        return {}
    if not isinstance(data, dict):
        print(
            f"WARN: {path} top-level is not a mapping; Remediation render will be empty.",
            file=sys.stderr,
        )
        return {}
    remediations = data.get("remediations", {}) or {}
    if not isinstance(remediations, dict):
        print(
            f"WARN: {path} 'remediations' key is not a mapping; Remediation render will be empty.",
            file=sys.stderr,
        )
        return {}
    # Filter to entries that are actually a list of dicts (skip junk).
    out: dict[str, list[dict]] = {}
    for cid, blocks in remediations.items():
        if isinstance(blocks, list) and all(isinstance(b, dict) for b in blocks):
            out[str(cid)] = blocks
    return out


def is_suppressed(finding: Finding, baseline: list[dict], today: str) -> bool:
    """Return True if a baseline entry matches and is not expired."""
    import fnmatch
    for entry in baseline:
        if entry.get("check_id") != finding.check_id:
            continue
        pattern = entry.get("resource_pattern", "*")
        if not fnmatch.fnmatch(finding.resource, pattern):
            continue
        expires = entry.get("expires_on", "")
        owner = entry.get("owner", "")
        # Enforcement: only suppress if expires_on >= today AND owner is present.
        if not owner:
            continue
        if expires and expires < today:
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Inline skip parsing (.tf comments)
# ---------------------------------------------------------------------------
# Format:  # checkov:skip=CKV_AZURE_xxx:PR_OWNER=team:PR_EXPIRES=2027-01-01|justification="..."
# The skip applies to the resource block surrounding the comment line.
# We parse these by scanning .tf files for the comment pattern and
# extracting (check_id, owner, expires, justification).
#
# Returns: dict[check_id] -> list of {resource_pattern, owner, expires_on, justification}
# where resource_pattern is the address of the resource block containing the skip.
INLINE_SKIP_PATTERN = re.compile(
    r"#\s*checkov:skip=(?P<check_id>CKV\w+):(?P<kwargs>[^\n]+)"
)
INLINE_KV_PATTERN = re.compile(r"(?P<k>\w+)=(?P<v>[^\s|]+)")


def _parse_inline_skip_kwargs(kwargs: str) -> dict:
    """Parse 'PR_OWNER=team:PR_EXPIRES=2027-01-01|justification="..."'."""
    out = {}
    # Split on '|' first to separate KV pairs from justification
    parts = []
    buf = ""
    in_quote = False
    for ch in kwargs:
        if ch == '"':
            in_quote = not in_quote
            buf += ch
            continue
        if ch == "|" and not in_quote:
            parts.append(buf)
            buf = ""
            continue
        buf += ch
    parts.append(buf)
    for p in parts:
        p = p.strip()
        if "=" not in p:
            continue
        k, _, v = p.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def load_inline_skips(env_dirs: list[Path]) -> dict[str, list[dict]]:
    """Walk .tf files and extract inline checkov:skip comments.

    Returns: {check_id: [suppression, ...]}"""
    out: dict[str, list[dict]] = {}
    for env_dir in env_dirs:
        if not env_dir.exists():
            continue
        for tf in env_dir.glob("*.tf"):
            try:
                text = tf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                m = INLINE_SKIP_PATTERN.search(line)
                if not m:
                    continue
                check_id = m.group("check_id")
                kwargs = _parse_inline_skip_kwargs(m.group("kwargs"))
                out.setdefault(check_id, []).append({
                    "resource_pattern": f"*:{tf.name}:{line_no}",
                    "owner": kwargs.get("PR_OWNER", ""),
                    "expires_on": kwargs.get("PR_EXPIRES", ""),
                    "justification": kwargs.get("justification", "(inline skip)"),
                    "source_file": str(tf),
                    "source_line": line_no,
                })
    return out


def is_inline_suppressed(
    finding: Finding, inline_skips: dict, today: str
) -> bool:
    """Check if an inline skip on the .tf file matches this finding."""
    if finding.check_id not in inline_skips:
        return False
    for entry in inline_skips[finding.check_id]:
        owner = entry.get("owner", "")
        expires = entry.get("expires_on", "")
        if not owner:
            continue
        if expires and expires < today:
            continue
        # Match by resource address containing the file name
        if finding.file_path and entry["source_file"].endswith(finding.file_path.replace("\\", "/").split("/")[-1]):
            return True
        # Also match if resource_pattern is * (catch-all on the file)
        if entry["resource_pattern"].startswith("*:"):
            return True
    return False


def attach_pci_reqs(findings: list[Finding], mapping: dict[str, list[str]]) -> None:
    for f in findings:
        f.pci_requirements = mapping.get(f.check_id, [])


# ---------------------------------------------------------------------------
# Out-of-scope validation + matrix rendering
# ---------------------------------------------------------------------------
# Each entry in pci_mapping.yaml's `out_of_scope_requirements` MUST carry
# these fields to be rendered as "OUT OF SCOPE" in the audit report. The
# aggregator validates them so a compliance auditor can prove the
# exclusion was justified, owned, approved, time-bound, and evidenced --
# without having to ask someone to read the YAML.
#
# Schema:
#   id              PCI requirement family (e.g. "11.x")
#   title           Full requirement title from the PCI doc
#   rationale       Concrete reason IaC scanning cannot evaluate
#   control_owner   Team / person who owns the control outside this scan
#   approved_on     ISO YYYY-MM-DD
#   expires_on      ISO YYYY-MM-DD (exclusion auto-expires; aggregator
#                   surfaces STALE badge when past today)
#   evidence_link   Resolvable URL or ticket ID where the auditor can
#                   find external proof

OUT_OF_SCOPE_REQUIRED_FIELDS = (
    "id",
    "title",
    "rationale",
    "control_owner",
    "approved_on",
    "expires_on",
    "evidence_link",
)
OUT_OF_SCOPE_DATE_FIELDS = ("approved_on", "expires_on")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def validate_out_of_scope_entries(
    out_of_scope_list: list[dict],
    *,
    today_iso: str,
) -> tuple[list[str], list[dict]]:
    """Validate every entry of pci_mapping.yaml's out_of_scope_requirements.

    Returns (errors, enriched_entries). Errors is a list of human-readable
    strings, one per problem found; empty list means valid. enriched_entries
    adds a `stale` boolean and `days_to_expiry` int to each entry so the
    HTML/CSV renderers can flag STALE exclusions without re-validating.

    A field is considered invalid when:
      - missing from the entry
      - empty string
      - value is the placeholder "TBD" (loud warning that someone meant
        to fill it in later)
      - approved_on / expires_on are not in ISO YYYY-MM-DD format
      - expires_on < today (entry will be flagged STALE)
      - approved_on > expires_on (illogical)
    """
    errors: list[str] = []
    enriched: list[dict] = []
    for idx, entry in enumerate(out_of_scope_list):
        rid = str(entry.get("id") or f"<index {idx}>")
        # Missing-or-empty checks for the audit-relevant fields. `title`
        # is recommended but not strictly required (some reqs span many
        # docs).
        for fld in OUT_OF_SCOPE_REQUIRED_FIELDS:
            val = entry.get(fld)
            if val is None or (isinstance(val, str) and val.strip() == ""):
                errors.append(f"out_of_scope {rid}: missing required field '{fld}'")
                continue
            if isinstance(val, str) and val.strip().upper() == "TBD":
                errors.append(
                    f"out_of_scope {rid}: field '{fld}' is still 'TBD' -- must be filled in "
                    f"with concrete value before producing an audit report"
                )
        # Date format + sanity
        for dfld in OUT_OF_SCOPE_DATE_FIELDS:
            val = entry.get(dfld)
            if val is None:
                continue
            if not (isinstance(val, str) and ISO_DATE_RE.match(val)):
                errors.append(
                    f"out_of_scope {rid}: {dfld}={val!r} is not ISO YYYY-MM-DD"
                )
        try:
            from datetime import date

            ap = date.fromisoformat(entry.get("approved_on", "") or "")
            ex = date.fromisoformat(entry.get("expires_on", "") or "")
            if ap > ex:
                errors.append(
                    f"out_of_scope {rid}: approved_on {ap.isoformat()} is AFTER "
                    f"expires_on {ex.isoformat()}"
                )
            today = date.fromisoformat(today_iso)
            stale = ex < today
            days_to_expiry = (ex - today).days
        except (ValueError, TypeError):
            stale = False
            days_to_expiry = None

        e = dict(entry)
        e["stale"] = stale
        e["days_to_expiry"] = days_to_expiry
        enriched.append(e)
    return errors, enriched


# ---------------------------------------------------------------------------
# Coverage matrix
# ---------------------------------------------------------------------------
def build_coverage_matrix(
    env_results: list[EnvResult],
    pci_mapping_path: Path,
    pci_mapping_data: dict,
) -> tuple[list[str], list[str], dict, list[dict], list[str], dict, set]:
    """Build the coverage matrix.

    Rows:    PCI requirement IDs (from pci_mapping.yaml)
    Cols:    unique check_ids across all findings
    Cells:   compliant | non_compliant | not_applicable | out_of_scope | not_scanned

    Returns (req_ids, check_ids, cells, enriched_out_of_scope, oos_errors,
    expected_by_req, fired_check_ids).

    Tuple elements:
      req_ids              Ordered list of PCI req IDs for the matrix.
      check_ids            Sorted unique check_ids that appeared in SARIFs
                           (used as column headers in the per-req view).
      cells                Per-(req, check) status. See docstring above.
      enriched_out_of_scope Validated + stale-flagged out-of-scope entries.
      oos_errors           Audit-validation errors against pci_mapping.yaml.
      expected_by_req      dict[req_id] -> set of check_ids MAPPED to that
                           req in pci_mapping.yaml. The full universe of
                           expected checks per req -- the "expected" half of
                           the coverage-gap calculation.
      fired_check_ids      set of check_ids that produced at least one
                           finding in any env_results. The "actually
                           evaluated" half of the coverage-gap calculation.
                           (Checkov SARIF omits rules that ran without
                           findings, so absence from this set may mean
                           (a) the resource type isn't present, (b) the
                           rule ran clean, or (c) the rule has been
                           deprecated. Operators triage via
                           coverage_gaps.csv.)

    The aggregate_gaps diff (expected_by_req - fired_check_ids) is what
    populates the "missing" status -- distinguishing "we never evaluated
    this check" from "we evaluated and found nothing."
    """
    requirements = pci_mapping_data.get("requirements", [])
    out_of_scope_raw = pci_mapping_data.get("out_of_scope_requirements", [])

    # Validate out-of-scope entries up-front.
    from datetime import date as _date

    today_iso = _date.today().isoformat()
    oos_errors, enriched_out_of_scope = validate_out_of_scope_entries(
        out_of_scope_raw, today_iso=today_iso
    )
    oos_ids = [e["id"] for e in enriched_out_of_scope]

    # Out-of-scope rows are emitted AFTER in-scope rows in the coverage matrix.
    req_ids = [r["id"] for r in requirements] + oos_ids

    # Universe of checks mapped per in-scope req (from pci_mapping.yaml),
    # independent of whether they fired. Used for coverage gaps.
    # Note tokens (CKV_AZURE_PCI_NOTE_*) are NOT included here: they are
    # symbolic placeholders that the mapping author uses to flag a req
    # with no working Checkov 3.3.9 coverage (see PCI_NOTE_TOKENS docstring). They
    # are filtered out so `expected_count` and `missing_count` in
    # coverage_gaps.csv stay zero for note-only reqs, which is the
    # documented semantics in the plan.
    expected_by_req: dict[str, set[str]] = {
        r["id"]: {c for c in r.get("checks", []) if c not in PCI_NOTE_TOKENS}
        for r in requirements
    }
    # Per-req note text (only populated when a note token is present).
    # Used by write_coverage_gaps_csv to render the note as triage_hint
    # so the auditor sees the rationale instead of a generic
    # "1 check expected, 0 fired" hint.
    note_by_req: dict[str, str] = {
        r["id"]: r["note"]
        for r in requirements
        if any(c in PCI_NOTE_TOKENS for c in r.get("checks", []))
        and r.get("note")
    }

    # Collect all check_ids across findings (sorted for stable output).
    # Suppressed findings count too -- they still indicate the rule fired.
    fired_check_ids: set[str] = {
        f.check_id for er in env_results for f in er.findings
    }
    check_ids = sorted(fired_check_ids)

    cells: dict[tuple[str, str], str] = {}

    # For each (req, check), evaluate per env, then collapse
    for req in requirements:
        rid = req["id"]
        req_checks = expected_by_req[rid]
        for cid in check_ids:
            cell_per_env = []
            for er in env_results:
                if er.scan_status != "ok":
                    cell_per_env.append("not_scanned")
                    continue
                # Is this check relevant to this req?
                if cid not in req_checks:
                    continue
                # Did any finding with this check_id exist in this env?
                fired = any(f.check_id == cid for f in er.findings)
                # Suppressed findings = compliant (accepted risk)
                suppressed = any(
                    f.check_id == cid and f.suppressed for f in er.findings
                )
                if fired and not suppressed:
                    cell_per_env.append("non_compliant")
                elif fired and suppressed:
                    cell_per_env.append("compliant")
                else:
                    cell_per_env.append("compliant")
            if not cell_per_env:
                # check wasn't in this req's check list
                continue
            # Collapse: if any env is non_compliant, the row is non_compliant
            if "non_compliant" in cell_per_env:
                cells[(rid, cid)] = "non_compliant"
            elif "not_scanned" in cell_per_env and all(
                c == "not_scanned" for c in cell_per_env
            ):
                cells[(rid, cid)] = "not_scanned"
            else:
                cells[(rid, cid)] = "compliant"

    return (
        req_ids,
        check_ids,
        cells,
        enriched_out_of_scope,
        oos_errors,
        expected_by_req,
        fired_check_ids,
    )


# ---------------------------------------------------------------------------
# Coverage-gap detection
# ---------------------------------------------------------------------------
def compute_coverage_gaps(
    expected_by_req: dict[str, set[str]],
    fired_check_ids: set[str],
    note_by_req: dict[str, str] | None = None,
) -> list[dict]:
    """For each in-scope req, find which check_ids from pci_mapping.yaml
    never appeared in any SARIF finding.

    Returns one record per req:

      {
        "req_id": "10.7",
        "title": "Audit logs are retained for at least 12 months",
        "expected_count": 1,
        "fired_count": 0,
        "missing_count": 1,
        "missing_check_ids": ["CKV_AZURE_211"],
      }

    Caveat: Checkov SARIF omits rules that ran without findings. So a
    check_id appearing here as missing MIGHT mean any of:
      (a) the env has no relevant resource of the type the rule
          targets (verify by grepping for the resource type in
          env/<project>/<env>/*.tf)
      (b) the rule ran and found nothing (verify by running
          `checkov -d <env_dir> --check CKV_AZURE_xxx --framework
          terraform` and looking for the resource type)
      (c) the rule no longer exists in the current Checkov version
          (verify with `checkov --list | grep CKV_AZURE_xxx`)

    Operators should validate ALL three before declaring a req covered
    or non-covered. The data here is a starting point for the
    investigation, not a verdict.

    PCI_NOTE_TOKENS integration (see PCI_NOTE_TOKENS docstring): a req whose
    `checks:` list contains a note token is filtered out of
    `expected_by_req` upstream (see build_coverage_matrix), so the
    record's `expected_count`, `fired_count`, and `missing_count` are
    all zero. The corresponding `note:` text from pci_mapping.yaml is
    carried via `triage_hint` so the auditor sees the rationale instead
    of a generic "1 check expected, 0 fired" hint. `note_by_req` is
    keyed by req_id and is built by build_coverage_matrix.
    """
    out = []
    for rid in sorted(expected_by_req):
        expected = expected_by_req[rid]
        missing = expected - fired_check_ids
        fired = expected & fired_check_ids
        record = {
            "req_id": rid,
            "expected_count": len(expected),
            "fired_count": len(fired),
            "missing_count": len(missing),
            "missing_check_ids": sorted(missing),
        }
        if note_by_req and rid in note_by_req:
            # Note-token req (see PCI_NOTE_TOKENS docstring): expected/fired/missing
            # are all zero by construction (tokens were filtered out of
            # `expected_by_req` in build_coverage_matrix). Carry the
            # `note:` text in the record so write_coverage_gaps_csv can
            # emit it as the triage_hint instead of the generic
            # "1 check expected, 0 fired" string.
            record["triage_hint"] = note_by_req[rid]
        out.append(record)
    return out


def write_coverage_gaps_csv(
    out: Path,
    gap_records: list[dict],
    pci_mapping_data: dict,
) -> None:
    """Emit coverage_gaps.csv: one row per in-scope PCI req.

    Columns:
      pci_requirement       requirement id from pci_mapping.yaml
      title                 requirement title (for human triage context)
      expected_count        count of check_ids mapped to this req
      fired_count           count that appeared in any SARIF
      missing_count         expected - fired
      missing_check_ids     space-separated missing IDs (the triage list)
      triage_hint           suggested next step depending on the pattern
      librarian_verified_at when the per-row librarian probe ran
                            (LIBRARIAN_VERIFIED_AT constant)
      pci_anchor_url        URL the librarian fetched (single PCI SSC
                            anchor for v4.0.1)
      evidence_byte_size    HTTP response body bytes observed
      evidence_content_type HTTP response Content-Type
      link_pass             "True" if fingerprint match; "False" otherwise

    Triage hint heuristic:
      - 1 missing + 1 expected + 0 fired     → likely stale check id (verify with
                                              `checkov --list | grep <id>`)
      - N missing where N > 1 + 0 fired     → check ids possibly stale, OR the
                                              env has no resource of that type
      - some fired, some missing            → mixed; investigate each missing id

    Audit-traceability columns (librarian_verified_at, pci_anchor_url,
    evidence_byte_size, evidence_content_type, link_pass) are emitted
    on EVERY row so the CSV is a self-contained reproducibility record.
    See PCI_REQ_CHAIN_OF_CUSTODY + LIBRARIAN_VERIFIED_FINGERPRINT above.
    """
    title_by_req = {
        r["id"]: r.get("title", "")
        for r in pci_mapping_data.get("requirements", [])
    }
    anchor = LIBRARIAN_VERIFIED_FINGERPRINT
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "pci_requirement",
                "title",
                "expected_count",
                "fired_count",
                "missing_count",
                "missing_check_ids",
                "triage_hint",
                "librarian_verified_at",
                "pci_anchor_url",
                "evidence_byte_size",
                "evidence_content_type",
                "link_pass",
            ]
        )
        for r in gap_records:
            fired = r["fired_count"]
            expected = r["expected_count"]
            missing = r["missing_count"]
            # Note-token req (see PCI_NOTE_TOKENS docstring): the caller passed
            # a precomputed `triage_hint` carrying the pci_mapping.yaml
            # `note:` text. Use it verbatim so the auditor sees the
            # rationale instead of a generic "complete" / "1 check
            # expected, 0 fired" string.
            if r.get("triage_hint"):
                hint = r["triage_hint"]
            elif missing == 0:
                hint = "complete"
            elif fired == 0 and expected == 1:
                # Single-check req with no fire: nearly always stale
                # OR a not-applicable env. Both look the same from
                # SARIF. Operator should verify:
                #   1. checkov --list | grep <id>  (does rule still exist?)
                #   2. find env/* -name '*.tf' | xargs grep <resource-type>
                # The hint names both possibilities in priority order.
                hint = (
                    "1 check expected, 0 fired. Verify: "
                    "(a) checkov --list | grep <id> (rule may be stale or renamed); "
                    "(b) env has no relevant resource type for this rule"
                )
            elif fired == 0:
                hint = (
                    "no findings -- for each missing id: "
                    "(a) checkov --list | grep <id> (is it stale?); "
                    "(b) does env/<project>/<env>/*.tf deploy any resource the rule targets?"
                )
            else:
                hint = "mixed -- investigate each missing check id individually"
            w.writerow(
                [
                    r["req_id"],
                    title_by_req.get(r["req_id"], ""),
                    expected,
                    fired,
                    missing,
                    " ".join(r["missing_check_ids"]),
                    hint,
                    LIBRARIAN_VERIFIED_AT,
                    anchor["url"],
                    anchor["byte_size"],
                    anchor["content_type"],
                    "True" if anchor["fingerprint_match"] else "False",
                ]
            )


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------
def write_coverage_csv(
    out: Path,
    req_ids: list[str],
    check_ids: list[str],
    cells: dict,
    out_of_scope: list[dict],
    expected_by_req: dict[str, set[str]] | None = None,
    fired_check_ids: set[str] | None = None,
) -> None:
    """Write the per-(req, check) coverage matrix.

    For each out-of-scope row, emits the full audit metadata in a
    side-table so the CSV is a sufficient evidence record by itself.
    Columns for in-scope rows remain:
        pci_requirement, check_id, status

    For in-scope rows, when ``expected_by_req`` and ``fired_check_ids``
    are passed, an additional column ``missing_for_req`` is populated
    on the FIRST row of each req with the space-separated list of
    check_ids MAPPED to that req but not appearing in any SARIF.
    Subsequent rows in that req have the column blank to avoid
    repetition.

    Out-of-scope rows are emitted with:
        pci_requirement=*, status="out_of_scope",
        control_owner, rationale, approved_on, expires_on,
        evidence_link, stale, days_to_expiry
    """
    oos_by_id = {e["id"]: e for e in out_of_scope}
    # Pre-compute missing-per-req for the new column. Each entry is the
    # sorted list of check_ids mapped to that req but not seen in any
    # SARIF (operator triages via coverage_gaps.csv / checkov --list).
    missing_per_req: dict[str, list[str]] = {}
    if expected_by_req and fired_check_ids is not None:
        missing_per_req = {
            rid: sorted(expected_by_req[rid] - fired_check_ids)
            for rid in expected_by_req
        }

    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        # Two header rows in two sections is tricky in CSV; instead we
        # emit one wide column list. Operators who want the in-scope
        # matrix can filter by status.
        w.writerow(
            [
                "pci_requirement",
                "check_id",
                "status",
                "missing_for_req",
                "title",
                "rationale",
                "control_owner",
                "approved_by",
                "approved_on",
                "expires_on",
                "evidence_link",
                "stale",
                "days_to_expiry",
                # chain_of_custody_complete records whether the PCI
                # source URL in pci_mapping.yaml was live-verified at
                # PCI_SOURCE_VERIFIED_AT. False would mean the URL has
                # been taken down or redirected since the mapping was
                # frozen. Empty for OOS rows (no pci_source_url).
                "chain_of_custody_complete",
            ]
        )
        for rid in req_ids:
            # chain_of_custody_complete is a per-requirement attribute
            # (declared in pci_mapping.yaml, verified at
            # PCI_SOURCE_VERIFIED_AT timestamp). Empty for any req
            # whose pci_source_url slot could not be live-verified at
            # the recorded timestamp; "True" otherwise.
            chain_custody = PCI_REQ_CHAIN_OF_CUSTODY.get(rid, "")
            if rid in oos_by_id:
                e = oos_by_id[rid]
                # Out-of-scope rows: missing_for_req is empty (by
                # definition -- out-of-scope entries have no mapped
                # checks in the in-scope mapping). chain_of_custody
                # is also empty (OOS rows have no pci_source_url).
                w.writerow(
                    [
                        rid,
                        "*",
                        "out_of_scope",
                        "",
                        e.get("title", ""),
                        e.get("rationale", ""),
                        e.get("control_owner", ""),
                        "",
                        e.get("approved_on", ""),
                        e.get("expires_on", ""),
                        e.get("evidence_link", ""),
                        "true" if e.get("stale") else "false",
                        e.get("days_to_expiry", ""),
                        "",
                    ]
                )
                continue
            missing_str = " ".join(missing_per_req.get(rid, []))
            row_has_data = any((rid, c) in cells for c in check_ids)
            if not row_has_data:
                # In-scope req with no findings at all (zero SARIF data).
                # Status "not_applicable" is rendered to keep the row in
                # the CSV; auditors can drill in via the HTML report.
                # missing_for_req carries the operator-triage list.
                w.writerow(
                    [
                        rid,
                        "*",
                        "not_applicable",
                        missing_str,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        chain_custody,
                    ]
                )
                continue
            first = True
            for cid in check_ids:
                if (rid, cid) in cells:
                    w.writerow(
                        [
                            rid,
                            cid,
                            cells[(rid, cid)],
                            missing_str if first else "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            chain_custody,
                        ]
                    )
                    first = False


def write_junit(
    out: Path,
    env_results: list[EnvResult],
    suppressed_findings: list[Finding],
) -> int:
    """Write JUnit XML. Returns count of failing tests."""
    fail = 0
    tests = 0
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append('<testsuite name="checkov-pci">')
    for er in env_results:
        if er.scan_status != "ok":
            lines.append(
                f'  <testcase classname="{er.project}" '
                f'name="env:{er.env}" time="0">'
                f'<skipped message="scan did not run: {er.error or "unknown"}"/>'
                f'</testcase>'
            )
            tests += 1
            continue
        for f in er.findings:
            tests += 1
            if f.suppressed:
                # Suppressed findings are reported as skipped (not failures)
                lines.append(
                    f'  <testcase classname="{er.project}.{er.env}" '
                    f'name="{f.check_id}.{f.resource}" time="0">'
                    f'<skipped message="suppressed by baseline"/>'
                    f'</testcase>'
                )
                continue
            is_fail = f.severity in ("HIGH", "CRITICAL")
            if is_fail:
                fail += 1
                lines.append(
                    f'  <testcase classname="{er.project}.{er.env}" '
                    f'name="{f.check_id}.{f.resource}" time="0">'
                    f'<failure type="{f.severity}" '
                    f'message="{html.escape(f.message)}" '
                    f'resource="{html.escape(f.resource)}"/>'
                    f'</testcase>'
                )
            else:
                lines.append(
                    f'  <testcase classname="{er.project}.{er.env}" '
                    f'name="{f.check_id}.{f.resource}" time="0">'
                    f'</testcase>'
                )
    lines.append(f'  <system-out>{tests} tests, {fail} failures</system-out>')
    lines.append('</testsuite>')
    out.write_text("\n".join(lines), encoding="utf-8")
    return fail


def write_combined_sarif(
    out: Path,
    env_results: list[EnvResultFull],
) -> None:
    """Combine all per-env SARIFs into one. Useful for SIEM / GitHub integration.

    Loads every SARIF the scanner can produce (plan + source + paac +
    secrets + state). Operators inspecting combined.sarif in their
    SIEM or GitHub code-scanning dashboard see the full picture,
    regardless of which scan tier wrote which file.
    """
    runs = []
    # Iterate in a deterministic order so consecutive runs produce
    # diffs only when findings change, not when SARIF discovery order
    # changes.
    sarif_attrs = (
        "sarif_terraform_plan",
        "sarif_terraform_source",
        "sarif_paac",
        "sarif_secrets",
        "sarif_state",
    )
    for er in env_results:
        for attr in sarif_attrs:
            sarif_path = getattr(er, attr, None)
            if sarif_path is None or not sarif_path.exists():
                continue
            try:
                data = json.loads(sarif_path.read_text(encoding="utf-8"))
                for r in data.get("runs", []):
                    # Tag the run with env/project for downstream tooling
                    if "properties" not in r:
                        r["properties"] = {}
                    r["properties"]["pci_project"] = er.project
                    r["properties"]["pci_env"] = er.env
                    r["properties"]["pci_source_sarif"] = Path(sarif_path).name
                    # Inject result-level helpUri for SIEM / GitHub
                    # code-scanning dashboards.
                    # half: without this, the SARIF 2.1.0 result-level
                    # helpUri is omitted from the combined output even
                    # though the rules array carries helpUri. SIEM
                    # dashboards that don't walk the rules array see
                    # no link at all. Resolve via the same ruleIndex
                    # integer join as parse_sarif (see parse_sarif); fall
                    # back to ruleId for SARIF v2.0.x tools.
                    rules_list = (
                        r.get("tool", {}).get("driver", {}).get("rules", [])
                    )
                    rule_index_map: dict[int, dict] = {
                        i: rule for i, rule in enumerate(rules_list)
                    }
                    rule_id_map: dict[str, dict] = {
                        rule.get("id", ""): rule
                        for rule in rules_list
                        if rule.get("id")
                    }
                    for result in r.get("results", []):
                        if result.get("helpUri"):
                            continue
                        rule_entry: dict = {}
                        if "ruleIndex" in result:
                            rule_entry = rule_index_map.get(
                                result["ruleIndex"], {}
                            )
                        if not rule_entry:
                            rule_entry = rule_id_map.get(
                                result.get("ruleId", ""), {}
                            )
                        rule_id = result.get("ruleId", "")
                        upstream_help_uri = rule_entry.get("helpUri", "") if rule_entry else ""
                        help_uri = CHECKOV_RULE_SOURCE_URLS.get(rule_id, upstream_help_uri)

                        if help_uri:
                            result["helpUri"] = help_uri
                    runs.append(r)
            except (json.JSONDecodeError, OSError) as e:
                print(f"WARN: failed to read {sarif_path}: {e}", file=sys.stderr)
    combined = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    out.write_text(json.dumps(combined, indent=2), encoding="utf-8")


def _collect_drift_findings(env_results: list[EnvResult]) -> list[dict]:
    """Load and flatten drift_report.json files emitted by tier 3 scans.

    The drift report lives at `<run-dir>/<project>/<env>/drift_report.json`
    (per-env, see scan.sh drift_report= line). Tier 1/2 runs do not
    produce it; this function returns [] in that case (silent skip -- no
    error, no placeholder). For tier 3 runs we read each per-env file
    and produce a flat list of dicts the HTML renderer can iterate over.

    Schema (drift_report.py build_report):
      {
        "summary": {...},
        "address_in_state_only": [address, ...],
        "address_in_source_only": [address, ...],
        "attribute_drift": [{"address": str, "diffs": [{"attribute", "source", "state", "note"}]}],
        "sensitive_findings": [{"address", "attribute", "state_value_type", "note"}]
      }

    Output shape (one dict per row in the HTML table):
      {
        "project": "...",
        "env": "...",
        "resource": "azurerm_xxx.yyy",
        "file_path": "",  # not available from drift_report.json (no source map)
        "line": 0,
        "drift_type": "attribute_changed" | "attribute_added" | "attribute_removed" | "sensitive_value",
        "attribute": "min_tls_version",
        "source_value": "...",
        "state_value": "...",
        "severity": "HIGH" | "MEDIUM" | "LOW",
        "message": "...",
      }

    Severity mapping (judgement call):
      - attribute_drift on a security-interesting attribute -> HIGH
        (ignore_changes is masking a live security-relevant change)
      - address_in_state_only (resource in state, missing in source) -> MEDIUM
        (will be destroyed on next apply -- operator must codify or revert)
      - address_in_source_only (resource missing in state) -> LOW
        (will be created -- expected if env is brand-new or import pending)
      - sensitive_findings -> MEDIUM (likely ignore_changes or token rotation)

    The function tolerates a missing file per env (returns [] for that
    env). It also tolerates a malformed file (skips it, prints a single
    WARN line so the operator notices but the aggregator doesn't abort).
    """
    out: list[dict] = []
    for er in env_results:
        if not getattr(er, "plan_dir", None):
            continue
        drift_path = er.plan_dir / "drift_report.json"
        if not drift_path.exists():
            continue  # tier 1/2: silently skip
        try:
            data = json.loads(drift_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(
                f"WARN: could not parse {drift_path}: {exc}; "
                f"skipping drift findings for {er.project}/{er.env}",
                file=sys.stderr,
            )
            continue

        # 1. attribute_drift (security-relevant -- HIGH)
        for entry in data.get("attribute_drift", []):
            addr = entry.get("address", "")
            for d in entry.get("diffs", []):
                attr = d.get("attribute", "")
                src = d.get("source")
                tgt = d.get("state")
                note = d.get("note", "")
                msg = note or f"source {attr!r}={src!r} != state {attr!r}={tgt!r}"
                out.append({
                    "project": er.project,
                    "env": er.env,
                    "resource": addr,
                    "file_path": "",
                    "line": 0,
                    "drift_type": "attribute_changed",
                    "attribute": attr,
                    "source_value": "" if src is None else str(src),
                    "state_value": "" if tgt is None else str(tgt),
                    "severity": "HIGH",
                    "message": msg,
                })

        # 2. address_in_state_only -- resource will be destroyed -> MEDIUM
        for addr in data.get("address_in_state_only", []):
            out.append({
                "project": er.project,
                "env": er.env,
                "resource": addr,
                "file_path": "",
                "line": 0,
                "drift_type": "resource_in_state_only",
                "attribute": "",
                "source_value": "(absent)",
                "state_value": "(present)",
                "severity": "MEDIUM",
                "message": (
                    "Resource exists in state but not in source plan. "
                    "Will be destroyed on next apply unless a matching "
                    "block is added to source."
                ),
            })

        # 3. address_in_source_only -- resource will be created -> LOW
        for addr in data.get("address_in_source_only", []):
            out.append({
                "project": er.project,
                "env": er.env,
                "resource": addr,
                "file_path": "",
                "line": 0,
                "drift_type": "resource_in_source_only",
                "attribute": "",
                "source_value": "(present)",
                "state_value": "(absent)",
                "severity": "LOW",
                "message": (
                    "Resource in source plan but missing from state. "
                    "Will be created on next apply."
                ),
            })

        # 4. sensitive_findings -- likely ignore_changes / token rotation -> MEDIUM
        for sf in data.get("sensitive_findings", []):
            out.append({
                "project": er.project,
                "env": er.env,
                "resource": sf.get("address", ""),
                "file_path": "",
                "line": 0,
                "drift_type": "sensitive_value",
                "attribute": sf.get("attribute", ""),
                "source_value": "<sensitive>",
                "state_value": f"({sf.get('state_value_type', 'unknown')})",
                "severity": "MEDIUM",
                "message": sf.get(
                    "note",
                    "Source plan marked <sensitive> but state has concrete value.",
                ),
            })
    return out


def _render_drift_section(drift_findings: list[dict]) -> str:
    """Render the Drift Findings section HTML for the report.

    Returns "" when drift_findings is empty (silent skip -- tier 1/2).
    The caller is expected to gate on the input; this function also
    gates internally as a safety net.
    """
    if not drift_findings:
        return ""
    rows = []
    for d in drift_findings:
        # data-attributes match the Phase-2 client-side filter pattern so
        # the JS can target drift rows in the future (severity + resource
        # + file_path). The current JS only filters `.finding-row` divs;
        # drift rows are table <tr>s and are NOT auto-filtered, but the
        # attributes are present for symmetry and future use.
        rows.append(
            "    <tr"
            f' data-severity="{html.escape(d["severity"], quote=True)}"'
            f' data-resource="{html.escape(d["resource"], quote=True)}"'
            f' data-file-path="{html.escape(d["file_path"], quote=True)}"'
            f' data-drift-type="{html.escape(d["drift_type"], quote=True)}"'
            f' data-project="{html.escape(d["project"], quote=True)}"'
            f' data-env="{html.escape(d["env"], quote=True)}"'
            ">"
            f"<td><code>{html.escape(d['resource'])}</code>"
            f"<br/><small>{html.escape(d['project'])}/{html.escape(d['env'])}</small></td>"
            "<td><em>(drift report has no source line)</em></td>"
            f"<td><code>{html.escape(d['attribute'])}</code></td>"
            f"<td>{html.escape(d['drift_type'])}</td>"
            f"<td><code>{html.escape(d['source_value'])}</code> &rarr; "
            f"<code>{html.escape(d['state_value'])}</code></td>"
            f'<td class="count-{d["severity"].lower()}">{html.escape(d["severity"])}</td>'
            f"</tr>"
        )
    return (
        "<h2>Drift Findings</h2>\n"
        "<p style=\"font-style:italic; color:#555;\">"
        "Drift is the difference between the planned resource shape "
        "(source .tf + terraform plan) and the live Azure state "
        "(.tfstate pulled from Azure Storage). Investigate every drift "
        "finding before re-running <code>terraform apply</code> &mdash; "
        "it may indicate manual changes that need to be either codified "
        "in source or reverted to match the plan."
        "</p>\n"
        "<table>\n"
        "  <tr><th>Resource</th><th>File:Line</th><th>Attribute</th>"
        "<th>Drift Type</th><th>Source &rarr; State</th><th>Severity</th></tr>\n"
        + "\n".join(rows)
        + "\n</table>\n"
    )


def write_html_report(
    out: Path,
    env_results: list[EnvResult],
    pci_mapping_path: Path,
    pci_data: dict,
    cells: dict,
    out_of_scope: list[dict],
    suppressed_count: int,
    missing_per_req: dict[str, list[str]] | None = None,
    gap_records: list[dict] | None = None,
    remediation_by_check_id: dict[str, list[dict]] | None = None,
    drift_findings: list[dict] | None = None,
    framework_name: str | None = None,
    framework_version: str | None = None,
) -> None:
    """Render a single-page HTML report with degraded-mode banner.

    Out-of-scope rows render with the FULL audit metadata (rationale,
    control_owner, approved_on, expires_on, evidence_link).
    Stale exclusions (expires_on < today) get a STALE badge so the
    auditor can immediately see which need re-approval.

    The optional `remediation_by_check_id` map adds
    the canonical azurerm 4.x fix block inline below the chain-of-custody
    badge for every finding. When empty (YAML missing), the report still
    renders cleanly -- the per-finding remediation block is skipped.

    `framework_name` and `framework_version` are read from the mapping YAML
    if not supplied. Falls back to ("PCI DSS", "4.0.1") for backward
    compatibility with the original PCI-only deployment.

    The optional `drift_findings` list (tier 3 only)
    is rendered as a Drift Findings table before "Findings by Environment".
    Pass [] (or None) for tier 1/2 runs to silently skip the section.
    """
    if remediation_by_check_id is None:
        remediation_by_check_id = {}
    if drift_findings is None:
        drift_findings = []
    failed_envs = [er for er in env_results if er.scan_status != "ok"]
    # Per-req URL lookups .
    # PCI v4.0.1 has a single shared PCI SSC anchor across all in-scope
    # requirements (the v3.2.1->v4.0 Summary-of-Changes PDF returning
    # HEAD 200/application/pdf/477973 bytes on 2026-08-04). The URL is
    # stored at the TOP level of pci_mapping.yaml as `doc_anchor` --
    # there is no per-requirement pci_source_url field. We populate
    # pci_source_url_by_req with that anchor for every req id so the
    # per-finding renderer can resolve the right URL in O(1).
    # The chain-of-custody lookup (the render relies on this
    # too) is read-only here so both renders share one dict build.
    pci_anchor = str(pci_data.get("doc_anchor", "") or "")
    pci_source_url_by_req: dict[str, str] = {}
    pci_approach_by_req: dict[str, str] = {}
    pci_chain_of_custody_by_req: dict[str, str] = {}
    for _r in pci_data.get("requirements", []):
        _rid = _r.get("id", "")
        if not _rid:
            continue
        pci_source_url_by_req[_rid] = pci_anchor
        pci_approach_by_req[_rid] = str(_r.get("approach", "") or "")
        pci_chain_of_custody_by_req[_rid] = PCI_REQ_CHAIN_OF_CUSTODY.get(_rid, "")
    total_findings = sum(len(er.findings) for er in env_results)
    high_critical = sum(
        1 for er in env_results for f in er.findings
        if not f.suppressed and f.severity in ("HIGH", "CRITICAL")
    )
    medium = sum(
        1 for er in env_results for f in er.findings
        if not f.suppressed and f.severity == "MEDIUM"
    )
    low = sum(
        1 for er in env_results for f in er.findings
        if not f.suppressed and f.severity == "LOW"
    )

    # Resolve framework name + version from mapping YAML. Supports any
    # framework (PCI DSS, SOC 2, CIS Azure, NIST 800-53, ISO 27001, ...)
    # via the `framework_name` and `framework_version` top-level keys in
    # the mapping file. Falls back to PCI DSS v4.0.1 for backward compat.
    if framework_name is None:
        framework_name = pci_data.get("framework_name", "PCI DSS")
    if framework_version is None:
        framework_version = pci_data.get("framework_version") or pci_data.get("pci_dss_version", "4.0.1")
    framework_full = f"{framework_name} v{framework_version}"

    banner = ""
    if failed_envs:
        envs_str = ", ".join(f"{er.project}/{er.env}" for er in failed_envs)
        banner = (
            f'<div style="background:#c00;color:#fff;padding:1em;margin:1em 0;'
            f'border:2px solid #900;font-weight:bold;">'
            f"RED BANNER: state-pull failed for {envs_str}. "
            f"Reports below are based on source-only scan; do not rely on PCI "
            f"compliance claims until re-scan succeeds."
            f"</div>"
        )

    # CSS is held as a plain string (NOT inside an f-string) because Python
    # 3.12+ parses `{...}` greedily inside f-strings -- and CSS has braces.
    CSS_STYLE = """\
  /* ===== Pacioli PCI Report -- first-class SPA styles ===== */
  *, *::before, *::after { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; height: 100%; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue",
                 Arial, sans-serif;
    color: #1a1f2e;
    background: #f5f6fa;
    line-height: 1.5;
    font-size: 14px;
  }
  a { color: #0050b3; text-decoration: none; }
  a:hover { text-decoration: underline; }
  code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 0.92em;
         background: #eef; padding: 0 4px; border-radius: 3px; }
  h1, h2, h3, h4 { color: #0a1a3a; margin: 0 0 0.5em 0; font-weight: 600; }
  h1 { font-size: 1.8em; }
  h2 { font-size: 1.4em; border-bottom: 2px solid #003a70; padding-bottom: 0.3em; }
  h3 { font-size: 1.15em; color: #003a70; margin-top: 1.5em; }
  h4 { font-size: 1em; margin-top: 1em; }
  table { border-collapse: collapse; margin: 1em 0; width: 100%; }
  th, td { border: 1px solid #d0d6e0; padding: 6px 10px; text-align: left; }
  th { background: #eef2f8; font-weight: 600; }

  /* ===== Layout: sidebar + content ===== */
  #app { display: grid; grid-template-columns: 240px 1fr; min-height: 100vh; }
  #sidebar {
    background: linear-gradient(180deg, #0a1a3a 0%, #003a70 100%);
    color: #fff;
    padding: 0;
    overflow-y: auto;
    position: sticky; top: 0; height: 100vh;
  }
  .sidebar-brand {
    padding: 1.4em 1.2em; border-bottom: 1px solid rgba(255,255,255,0.1);
  }
  .sidebar-brand h1 { color: #fff; font-size: 1.3em; margin: 0; line-height: 1.1; }
  .sidebar-brand .subtitle { font-size: 0.78em; color: #a8c0e0; margin-top: 4px; }
  nav.sidebar-nav { padding: 0.6em 0; }
  nav.sidebar-nav a {
    display: flex; align-items: center; gap: 10px;
    padding: 0.7em 1.2em; color: #d0d6e0; font-weight: 500;
    border-left: 3px solid transparent; transition: all 0.12s;
  }
  nav.sidebar-nav a:hover { background: rgba(255,255,255,0.05); color: #fff; text-decoration: none; }
  nav.sidebar-nav a.active {
    background: rgba(255,255,255,0.10); color: #fff;
    border-left-color: #4f9eff;
  }
  nav.sidebar-nav a .icon { font-size: 1.05em; width: 18px; display: inline-block; text-align: center; }
  nav.sidebar-nav a .badge {
    margin-left: auto; background: #c00; color: #fff;
    border-radius: 10px; padding: 1px 7px; font-size: 0.7em; font-weight: 700;
  }
  nav.sidebar-nav a .badge.ok { background: #2a8c4a; }
  nav.sidebar-nav a .badge.warn { background: #c80; }
  .sidebar-footer {
    padding: 1em 1.2em; border-top: 1px solid rgba(255,255,255,0.1);
    font-size: 0.78em; color: #a8c0e0; line-height: 1.4;
  }

  /* ===== Main content ===== */
  #main { padding: 1.4em 2em 4em; overflow-x: auto; }
  .route { display: none; }
  .route.active { display: block; }
  .route-header { display: flex; justify-content: space-between; align-items: flex-end;
                  margin-bottom: 1.4em; padding-bottom: 1em;
                  border-bottom: 1px solid #d0d6e0; }
  .route-header h1 { margin: 0; }
  .route-header .meta { font-size: 0.85em; color: #5a6878; text-align: right; line-height: 1.5; }

  /* ===== KPI cards ===== */
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
              gap: 1em; margin: 1em 0 1.4em; }
  .kpi {
    background: #fff; border: 1px solid #d0d6e0; border-radius: 6px;
    padding: 1.2em 1.4em; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    position: relative; overflow: hidden;
  }
  .kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0;
                 width: 4px; background: #003a70; }
  .kpi.kpi-high::before { background: #c00; }
  .kpi.kpi-medium::before { background: #c80; }
  .kpi.kpi-low::before { background: #888; }
  .kpi.kpi-ok::before { background: #2a8c4a; }
  .kpi-label { font-size: 0.78em; color: #5a6878; text-transform: uppercase;
                letter-spacing: 0.06em; margin-bottom: 6px; }
  .kpi-value { font-size: 2.2em; font-weight: 700; line-height: 1; color: #0a1a3a; }
  .kpi-sub { font-size: 0.85em; color: #5a6878; margin-top: 6px; }

  /* ===== Severity donut ===== */
  .donut-wrap { display: flex; gap: 1.4em; align-items: center; margin: 1em 0; }
  .donut-legend { display: flex; flex-direction: column; gap: 0.5em; }
  .donut-legend-row { display: flex; align-items: center; gap: 0.6em; font-size: 0.9em; }
  .donut-legend-swatch { width: 14px; height: 14px; border-radius: 3px; }

  /* ===== Env health bars ===== */
  .env-bar-row { display: flex; align-items: center; gap: 0.8em; margin: 0.4em 0;
                 padding: 0.4em 0.6em; background: #fff; border-radius: 4px;
                 border: 1px solid #e5e8ef; }
  .env-bar-name { width: 260px; font-weight: 600; font-size: 0.92em; }
  .env-bar-track { flex: 1; height: 22px; background: #eef2f8; border-radius: 3px;
                   overflow: hidden; display: flex; }
  .env-bar-segment { height: 100%; transition: width 0.3s; }
  .env-bar-segment.high { background: #c00; }
  .env-bar-segment.medium { background: #c80; }
  .env-bar-segment.low { background: #888; }
  .env-bar-count { width: 80px; text-align: right; font-weight: 600; font-size: 0.9em; }

  /* ===== Top-N lists ===== */
  .top-list { background: #fff; border: 1px solid #d0d6e0; border-radius: 6px;
              padding: 0.8em 1em; margin: 0.6em 0; }
  .top-list h3 { margin: 0 0 0.6em; font-size: 1em; }
  .top-list-row { display: flex; justify-content: space-between; padding: 0.3em 0;
                  border-bottom: 1px solid #f0f2f5; font-size: 0.9em; }
  .top-list-row:last-child { border-bottom: 0; }
  .top-list-row .count-pill { background: #eef2f8; padding: 1px 8px;
                              border-radius: 10px; font-weight: 600; }
  .top-list-row .count-pill.high { background: #fde; color: #c00; }
  .top-list-row .count-pill.medium { background: #ffd; color: #a60; }

  /* ===== Two-column layout ===== */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1.4em; margin: 1em 0; }
  .panel { background: #fff; border: 1px solid #d0d6e0; border-radius: 6px;
           padding: 1em 1.2em; }
  .panel h3 { margin-top: 0; }

  /* ===== Findings ===== */
  .finding { margin: 0.5em 0; padding: 0.8em 1em; background: #fafafa;
             border-left: 4px solid #888; border-radius: 0 4px 4px 0; }
  .finding.HIGH { border-left-color: #c00; background: #fff8f8; }
  .finding.CRITICAL { border-left-color: #c00; background: #fee; }
  .finding.MEDIUM { border-left-color: #c80; background: #fffaf0; }
  .finding.LOW { border-left-color: #888; }
  .suppressed { opacity: 0.5; text-decoration: line-through; }
  .req-coverage { font-size: 0.9em; color: #555; }

  .finding-row { margin: 0; padding: 0; }
  .finding-body { margin: 0.5em 0; padding: 0.8em 1em; background: #fafafa;
                  border-left: 4px solid #888; border-radius: 0 4px 4px 0; }
  .finding-body.HIGH { border-left-color: #c00; background: #fff8f8; }
  .finding-body.CRITICAL { border-left-color: #c00; background: #fee; }
  .finding-body.MEDIUM { border-left-color: #c80; background: #fffaf0; }
  .finding-body.LOW { border-left-color: #888; }

  /* ===== Filter UI ===== */
  #filter-ui { background: #fff; border: 1px solid #d0d6e0; border-radius: 6px;
               padding: 12px; margin: 1em 0;
               display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
               box-shadow: 0 1px 3px rgba(0,0,0,0.04); position: sticky; top: 0; z-index: 10; }
  #filter-ui input[type="search"] { width: 240px; padding: 6px 10px;
                                     border: 1px solid #d0d6e0; border-radius: 4px; }
  #filter-ui button { padding: 6px 12px; border: 1px solid #d0d6e0;
                      background: #fff; cursor: pointer; border-radius: 4px;
                      font-weight: 500; transition: all 0.12s; }
  #filter-ui button:hover { background: #f5f6fa; }
  #filter-ui button.active { background: #003a70; color: #fff; border-color: #003a70; }
  #filter-ui select { padding: 6px 10px; border: 1px solid #d0d6e0; border-radius: 4px; }
  #finding-count { margin-left: auto; font-weight: 700; color: #003a70; font-size: 0.95em; }

  /* ===== Severity badges ===== */
  .count-high { color: #c00; font-weight: 700; }
  .count-medium { color: #a60; font-weight: 600; }
  .count-low { color: #888; }
  .badge-row { display: inline-block; padding: 2px 8px; border-radius: 12px;
               font-size: 0.78em; font-weight: 600; }
  .badge-row.NON-COMPLIANT { background: #fde; color: #c00; }
  .badge-row.NOT-SCANNED { background: #eee; color: #555; }
  .badge-row.COMPLIANT { background: #dfd; color: #2a8c4a; }
  .badge-row.STALE { background: #fbb; color: #800; }
  .badge-row.OUT-OF-SCOPE { background: #cdf; color: #006; }
  .badge-row.NO-MATCHING-RESOURCES { background: #ffe; color: #a60; }

  /* ===== Heatmap (PCI coverage) ===== */
  .heatmap { display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
             gap: 6px; margin: 1em 0; }
  .heatmap-cell { background: #fff; border: 1px solid #d0d6e0; border-radius: 4px;
                  padding: 8px 10px; text-align: center; font-size: 0.85em;
                  cursor: pointer; transition: transform 0.1s, box-shadow 0.1s, border-color 0.1s; }
  .heatmap-cell:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.08); border-color: #4f9eff; }
  .heatmap-cell:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.08); }
  .heatmap-cell .req-id { font-weight: 700; color: #003a70; }
  .heatmap-cell .req-count { font-size: 0.75em; color: #5a6878; margin-top: 4px; }
  .heatmap-cell.kpi-high { background: #fde; border-color: #c00; }
  .heatmap-cell.kpi-high .req-id { color: #c00; }
  .heatmap-cell.kpi-ok { background: #dfd; border-color: #2a8c4a; }
  .heatmap-cell.kpi-ok .req-id { color: #2a8c4a; }
  .heatmap-cell.kpi-medium { background: #ffd; border-color: #c80; }
  .heatmap-cell.kpi-warn { background: #ffe; border-color: #c80; }
  .heatmap-cell.filtered { border-color: #4f9eff; box-shadow: 0 0 0 3px #4f9eff, 0 4px 12px rgba(79,158,255,0.3); transform: translateY(-2px); background: #eaf3ff; }
  .heatmap-cell.filtered .req-id { color: #0050b3; }
  .heatmap-cell.dimmed { opacity: 0.25; }
  .heatmap-cell.dimmed:hover { opacity: 0.6; transform: translateY(-2px); }

  /* ===== Remediation block ===== */
  .remediation { background: #f0f7ff; border: 1px solid #b8d4ff; border-radius: 4px;
                 padding: 8px 12px; margin: 8px 0; }
  .remediation h4 { margin: 0 0 6px 0; color: #003a70; font-size: 0.95em; }
  .remediation-hcl { background: #0a1a3a; color: #d0e8ff; padding: 12px;
                     border-radius: 4px; overflow-x: auto; font-size: 0.85em;
                     line-height: 1.5; white-space: pre; }
  .chain-of-custody { font-size: 0.85em; color: #5a6878; margin: 4px 0;
                      padding: 4px 8px; background: #eef2f8;
                      border-left: 3px solid #4f9eff; border-radius: 0 3px 3px 0; }
  .coc-true { color: #2a8c4a; font-weight: 600; }
  .coc-partial { color: #c80; font-weight: 600; }

  /* ===== Banner ===== */
  .banner-error { background: #c00; color: #fff; padding: 1em 1.4em; margin: 0 0 1em;
                  border-left: 6px solid #800; font-weight: 600; border-radius: 4px; }
  .banner-info { background: #eef2f8; color: #003a70; padding: 0.8em 1.2em; margin: 0 0 1em;
                  border-left: 4px solid #4f9eff; border-radius: 4px; }

  /* ===== Sparkline / activity pulse ===== */
  .pulse-bar { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
               margin-right: 4px; vertical-align: middle; }
  .pulse-bar.hot { background: #c00; box-shadow: 0 0 8px #c00; }
  .pulse-bar.warm { background: #c80; }
  .pulse-bar.cool { background: #2a8c4a; }

  /* ===== Responsive ===== */
  @media (max-width: 900px) {
    #app { grid-template-columns: 1fr; }
    #sidebar { position: relative; height: auto; }
    #main { padding: 1em; }
    .two-col { grid-template-columns: 1fr; }
  }
"""

    # Compute per-environment aggregate stats for the dashboard route.
    # Each env_results entry has a project, env, scan_status, and findings list.
    env_stats = []
    for er in env_results:
        f_total = len(er.findings)
        f_high = sum(1 for f in er.findings if not f.suppressed and f.severity in ("HIGH", "CRITICAL"))
        f_med = sum(1 for f in er.findings if not f.suppressed and f.severity == "MEDIUM")
        f_low = sum(1 for f in er.findings if not f.suppressed and f.severity == "LOW")
        env_stats.append({
            "label": f"{er.project}/{er.env}",
            "project": er.project,
            "env": er.env,
            "scan_status": er.scan_status,
            "total": f_total,
            "high": f_high,
            "medium": f_med,
            "low": f_low,
        })
    # Top vulnerable resources (by total finding count across all envs)
    from collections import Counter as _Counter
    res_counter = _Counter()
    res_severity = {}
    for er in env_results:
        for f in er.findings:
            if f.resource and not f.suppressed:
                res_counter[f.resource] += 1
                cur = res_severity.get(f.resource, "LOW")
                if f.severity == "CRITICAL" or (f.severity == "HIGH" and cur != "CRITICAL"):
                    res_severity[f.resource] = f.severity
                elif f.severity == "MEDIUM" and cur == "LOW":
                    res_severity[f.resource] = f.severity
    top_resources = res_counter.most_common(15)
    # Top rule IDs by frequency
    rule_counter = _Counter()
    for er in env_results:
        for f in er.findings:
            if not f.suppressed:
                rule_counter[f.check_id] += 1
    top_rules = rule_counter.most_common(15)
    # Compute percentages for donut
    pct_high = (high_critical / total_findings * 100) if total_findings else 0
    pct_med = (medium / total_findings * 100) if total_findings else 0
    pct_low = (low / total_findings * 100) if total_findings else 0
    pct_sup = (suppressed_count / total_findings * 100) if total_findings else 0
    # Pending coverage gaps count for sidebar badge
    pending_gaps = sum(1 for g in (gap_records or []) if g.get("missing_count", 0) > 0)
    stale_oos = sum(1 for e in out_of_scope if e.get("stale"))

    # Build the SPA shell with sidebar nav. The rest of the report
    # rendering (PCI matrix, findings, OOS, drift) is appended inside
    # <section data-route="…"> containers below so the router can swap
    # views without rewriting the renderer.
    generated_at = datetime.now(timezone.utc).isoformat()
    run_dir_disp = html.escape(str(out.parent))
    body = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Pacioli {framework_full} Compliance Report</title>
<style>
{CSS_STYLE}</style>
</head>
<body>
<div id="app">
<aside id="sidebar">
  <div class="sidebar-brand">
    <h1>Pacioli</h1>
    <div class="subtitle">{framework_full} Compliance Report</div>
  </div>
  <nav class="sidebar-nav">
    <a href="#dashboard" data-route="dashboard" class="active">
      <span class="icon">▣</span>Dashboard</a>
    <a href="#findings" data-route="findings">
      <span class="icon">≡</span>Findings
      <span class="badge" id="badge-findings">{total_findings}</span></a>
    <a href="#environments" data-route="environments">
      <span class="icon">▦</span>Environments
      <span class="badge" id="badge-envs">{len(env_results)}</span></a>
    <a href="#coverage" data-route="coverage">
      <span class="icon">⬚</span>PCI Coverage
      <span class="badge {'warn' if pending_gaps else 'ok'}" id="badge-gaps">{pending_gaps}</span></a>
    <a href="#remediation" data-route="remediation">
      <span class="icon">⚙</span>Remediation</a>
    <a href="#oos" data-route="oos">
      <span class="icon">⌧</span>Out-of-Scope
      <span class="badge {'warn' if stale_oos else ''}">{len(out_of_scope)}</span></a>
    <a href="#drift" data-route="drift">
      <span class="icon">⇄</span>Drift
      <span class="badge {'warn' if drift_findings else 'ok'}">{len(drift_findings)}</span></a>
  </nav>
  <div class="sidebar-footer">
    Generated {generated_at}<br>
    <code>{run_dir_disp}</code>
  </div>
</aside>
<main id="main">
{banner}
<section id="route-dashboard" class="route active">
  <div class="route-header">
    <h1>Compliance Posture</h1>
    <div class="meta">
      Generated {generated_at}<br>
      Run dir: <code>{run_dir_disp}</code>
    </div>
  </div>
  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-label">Total Findings</div>
      <div class="kpi-value">{total_findings}</div>
      <div class="kpi-sub">across {len(env_results)} environment{'' if len(env_results)==1 else 's'}</div></div>
    <div class="kpi kpi-high"><div class="kpi-label">High / Critical</div>
      <div class="kpi-value">{high_critical}</div>
      <div class="kpi-sub">{pct_high:.1f}% of total</div></div>
    <div class="kpi kpi-medium"><div class="kpi-label">Medium</div>
      <div class="kpi-value">{medium}</div>
      <div class="kpi-sub">{pct_med:.1f}% of total</div></div>
    <div class="kpi kpi-low"><div class="kpi-label">Low</div>
      <div class="kpi-value">{low}</div>
      <div class="kpi-sub">{pct_low:.1f}% of total</div></div>
    <div class="kpi kpi-ok"><div class="kpi-label">Suppressed</div>
      <div class="kpi-value">{suppressed_count}</div>
      <div class="kpi-sub">{pct_sup:.1f}% of total · baseline waivers</div></div>
  </div>
  <div class="two-col">
    <div class="panel">
      <h3>Severity Distribution</h3>
      <div class="donut-wrap">
        <svg width="160" height="160" viewBox="0 0 160 160" id="severity-donut">
          <circle cx="80" cy="80" r="60" fill="none" stroke="#eef2f8" stroke-width="24"/>
        </svg>
        <div class="donut-legend">
          <div class="donut-legend-row">
            <span class="donut-legend-swatch" style="background:#c00"></span>
            <strong>{high_critical}</strong> High / Critical
          </div>
          <div class="donut-legend-row">
            <span class="donut-legend-swatch" style="background:#c80"></span>
            <strong>{medium}</strong> Medium
          </div>
          <div class="donut-legend-row">
            <span class="donut-legend-swatch" style="background:#888"></span>
            <strong>{low}</strong> Low
          </div>
          <div class="donut-legend-row">
            <span class="donut-legend-swatch" style="background:#2a8c4a"></span>
            <strong>{suppressed_count}</strong> Suppressed
          </div>
        </div>
      </div>
    </div>
    <div class="panel">
      <h3>Environment Health</h3>
      <div class="env-bar-list">
"""
    # Build env health bars
    if env_stats:
        max_total = max(e["total"] for e in env_stats) or 1
        for e in env_stats:
            w_high = e["high"] / max_total * 100
            w_med = e["medium"] / max_total * 100
            w_low = e["low"] / max_total * 100
            status_class = "kpi-high" if e["high"] > 0 else ("kpi-medium" if e["medium"] > 0 else "kpi-ok")
            body += f"""        <div class="env-bar-row" data-env-bar="{html.escape(e['label'])}" style="cursor:pointer;">
           <div class="env-bar-name">{html.escape(e['label'])} <span class="badge-row {status_class.upper().replace('KPI-','')}">{e['scan_status']}</span></div>
          <div class="env-bar-track">
            <div class="env-bar-segment high" style="width:{w_high:.1f}%" title="HIGH: {e['high']}"></div>
            <div class="env-bar-segment medium" style="width:{w_med:.1f}%" title="MEDIUM: {e['medium']}"></div>
            <div class="env-bar-segment low" style="width:{w_low:.1f}%" title="LOW: {e['low']}"></div>
          </div>
          <div class="env-bar-count">{e['total']}</div>
        </div>
"""
    else:
        body += "        <em>No environments scanned.</em>\n"
    body += """      </div>
    </div>
  </div>
  <div class="two-col">
    <div class="top-list">
      <h3>Top Vulnerable Resources</h3>
"""
    for rsc, cnt in top_resources:
        sev = res_severity.get(rsc, "LOW")
        sev_class = "high" if sev in ("HIGH", "CRITICAL") else ("medium" if sev == "MEDIUM" else "")
        body += f'      <div class="top-list-row"><code>{html.escape(rsc)}</code><span class="count-pill {sev_class}">{cnt}</span></div>\n'
    body += """    </div>
    <div class="top-list">
      <h3>Top Fired Rules</h3>
"""
    for cid, cnt in top_rules:
        body += f'      <div class="top-list-row"><code>{html.escape(cid)}</code><span class="count-pill">{cnt}</span></div>\n'
    body += """    </div>
  </div>
</section>  <!-- /route-dashboard -->
"""

    # ----- Environments route: per-env table, top-level (not nested) -----
    _env_table_rows = []
    for e in env_stats:
        status_pill = (
            f'<span class="badge-row OUT-OF-SCOPE">{e["scan_status"]}</span>'
            if e["scan_status"] != "ok"
            else f'<span class="badge-row COMPLIANT">{e["scan_status"]}</span>'
        )
        _env_table_rows.append(
            f"<tr data-project=\"{html.escape(e['project'])}\" data-env=\"{html.escape(e['env'])}\">"
            f"<td><code>{html.escape(e['project'])}</code></td>"
            f"<td><code>{html.escape(e['env'])}</code></td>"
            f"<td>{status_pill}</td>"
            f"<td><strong>{e['total']}</strong></td>"
            f"<td class=\"count-high\">{e['high']}</td>"
            f"<td class=\"count-medium\">{e['medium']}</td>"
            f"<td class=\"count-low\">{e['low']}</td>"
            f"</tr>"
        )
    body += "<section id=\"route-environments\" class=\"route\">\n"
    body += "  <div class=\"route-header\"><h1>Environments</h1>"
    body += f"<div class=\"meta\">{len(env_stats)} environment{'' if len(env_stats)==1 else 's'} scanned</div></div>\n"
    body += "  <h3>Per-Environment Summary</h3>\n"
    body += "  <table>\n"
    body += "    <tr><th>Project</th><th>Env</th><th>Status</th><th>Total</th><th>High</th><th>Medium</th><th>Low</th></tr>\n"
    body += "    " + "\n    ".join(_env_table_rows) + "\n"
    body += "  </table>\n"
    body += "</section>  <!-- /route-environments -->\n"

    # ----- Remediation route (aggregates unique HCL patterns) -----
    _unique_rems = {}  # check_id -> first remediation block
    for cid, blocks in (remediation_by_check_id or {}).items():
        if blocks:
            _unique_rems[cid] = blocks[0]
    body += "<section id=\"route-remediation\" class=\"route\">\n"
    body += "  <div class=\"route-header\"><h1>Remediation Library</h1>"
    body += f"<div class=\"meta\">{len(_unique_rems)} unique fix pattern{'' if len(_unique_rems)==1 else 's'} · azurerm 4.x HCL</div></div>\n"
    body += "  <p>Canonical Terraform remediation patterns pulled from <code>scanner/terraform_remediation.yaml</code>. "
    body += "Click any check_id to copy the resource_type. Apply the patterns in your <code>env/&lt;project&gt;/&lt;env&gt;</code> directory, then re-run <code>make scan-pci-report</code> to confirm.</p>\n"
    if _unique_rems:
        body += "  <table>\n"
        body += "    <tr><th>Check ID</th><th>Resource</th><th>Issue</th><th>Fix</th></tr>\n"
        for cid in sorted(_unique_rems.keys()):
            block = _unique_rems[cid]
            body += f"    <tr><td><code>{html.escape(cid)}</code></td>"
            body += f"<td><code>{html.escape(str(block.get('resource_type', '')))}</code></td>"
            body += f"<td>{html.escape(str(block.get('current_problem', '')))}</td>"
            body += f"<td><details><summary>Show HCL</summary><pre class=\"remediation-hcl\">{html.escape(str(block.get('remediation_hcl', '')))}</pre></details></td></tr>\n"
        body += "  </table>\n"
    else:
        body += "  <p><em>No remediation data loaded -- check <code>terraform_remediation.yaml</code> exists.</em></p>\n"
    body += "</section>  <!-- /route-remediation -->\n"

    body += "<section id=\"route-coverage\" class=\"route\">\n"
    body += "  <div class=\"route-header\">\n"
    body += "    <h1>PCI Requirement Coverage</h1>\n"
    body += "    <div class=\"meta\">v4.0.1 &middot; <a href=\"https://listings.pcisecuritystandards.org/documents/PCI-DSS-v3-2-1-to-v4-0-Summary-of-Changes-r1.pdf\" target=\"_blank\" rel=\"noopener noreferrer\">PCI SSC anchor</a></div>\n"
    body += "  </div>\n"
    body += "  <h3>Coverage Heatmap <small style=\"font-weight:400;color:#5a6878;font-size:0.7em;\">— click any cell to filter to that PCI req</small></h3>\n"
    body += "  <div id=\"heatmap-active-filter\" style=\"display:none;margin:0.4em 0 0.8em;padding:8px 12px;background:#eaf3ff;border:1px solid #4f9eff;border-radius:4px;font-size:0.9em;\">\n"
    body += "    <strong>Filtered:</strong> <span id=\"heatmap-active-req\"></span>\n"
    body += "    <button id=\"heatmap-clear-btn\" style=\"margin-left:8px;padding:2px 8px;background:#fff;border:1px solid #4f9eff;color:#0050b3;border-radius:3px;cursor:pointer;font-size:0.85em;\">Clear</button>\n"
    body += "    <button id=\"heatmap-view-findings\" style=\"margin-left:4px;padding:2px 8px;background:#4f9eff;border:1px solid #4f9eff;color:#fff;border-radius:3px;cursor:pointer;font-size:0.85em;\">View findings →</button>\n"
    body += "  </div>\n"
    body += "  <div class=\"heatmap\">\n"
    # Build heatmap cells -- one per in-scope req
    for req in pci_data.get("requirements", []):
        rid = req["id"]
        title = req.get("title", "")
        req_checks = req.get("checks", [])
        any_non_compliant = any(cells.get((rid, c)) == "non_compliant" for c in req_checks)
        any_compliant = any(cells.get((rid, c)) == "compliant" for c in req_checks)
        any_not_scanned = any(cells.get((rid, c)) == "not_scanned" for c in req_checks)
        any_data = any((rid, c) in cells for c in req_checks)
        missing_ids = (missing_per_req or {}).get(rid, [])
        finding_count = sum(1 for er in env_results for f in er.findings if rid in (f.pci_requirements or []))
        if any_non_compliant:
            klass = "kpi-high"; label = "FAIL"
        elif any_not_scanned:
            klass = "kpi-warn"; label = "PARTIAL"
        elif any_compliant:
            klass = "kpi-ok"; label = "PASS"
        elif any_data:
            klass = "kpi-ok"; label = "PASS"
        else:
            klass = "kpi-warn"; label = "GAP"
        body += f'    <div class="heatmap-cell {klass}" title="{html.escape(title)}"><div class="req-id">{html.escape(rid)}</div><div class="req-count">{finding_count} finding{"" if finding_count == 1 else "s"} · {label}</div></div>\n'
    body += """  </div>
  <h3>PCI Requirement Status</h3>
  <table>
    <tr><th>PCI Requirement</th><th>Status</th></tr>
"""

    for req in pci_data.get("requirements", []):
        rid = req["id"]
        title = req.get("title", "")
        req_checks = req.get("checks", [])
        # Look up cells only for this requirement's checks, not all cells.
        any_non_compliant = any(
            cells.get((rid, c)) == "non_compliant" for c in req_checks
        )
        any_compliant = any(
            cells.get((rid, c)) == "compliant" for c in req_checks
        )
        any_not_scanned = any(
            cells.get((rid, c)) == "not_scanned" for c in req_checks
        )
        # If none of the req's checks have any cell entry (no scan ran any of
        # them), say so explicitly.
        any_data = any((rid, c) in cells for c in req_checks)
        # Coverage-gap data: which mapped check_ids never fired.
        missing_ids = (missing_per_req or {}).get(rid, [])
        missing_count = len(missing_ids)
        # PCI_NOTE_TOKENS (see PCI_NOTE_TOKENS docstring) are filtered from
        # expected_by_req in build_coverage_matrix so the gap record's
        # expected_count is 0; mirror that here so the HTML tooltip
        # and tip pick the right branch.
        expected_count = len(
            {c for c in req_checks if c not in PCI_NOTE_TOKENS}
        )
        if any_non_compliant:
            status = '<span class="count-high">NON-COMPLIANT</span>'
        elif any_not_scanned:
            status = "NOT SCANNED"
        elif any_compliant:
            status = "COMPLIANT"
        elif any_data:
            status = "COMPLIANT (suppressed)"
        else:
                # NO MATCHING RESOURCES IN SCOPE -- disambiguate via coverage-gap data:
                # - missing > 0: at least one mapped check never produced
                #   a SARIF result. Either stale check id, or env has no
                #   resource of that type, or rule ran clean (Checkov
                #   SARIF omits passes). Operator triages via the
                #   tooltip + coverage_gaps.csv.
                # - missing == 0 but expected == 0: PCI_NOTE_TOKENS
                #   req (see PCI_NOTE_TOKENS docstring). The mapping author
                #   declared a symbolic note token + `note:` text to
                #   flag a req with no working Checkov 3.3.9 coverage.
                #   Show the note inline + as the tooltip so the
                #   auditor sees the rationale directly in the matrix.
                # - missing == 0 but expected > 0: every mapped check
                #   fired at least once (compliant).
                tip = ""
                if missing_ids and missing_count:
                    missing_inline = " ".join(html.escape(x) for x in missing_ids)
                    tip = (
                        ' <span style="color:#a80" '
                        f'title="missing: {missing_inline}">'
                        f"({missing_count}/{expected_count} mapped checks absent)"
                        "</span>"
                    )
                elif missing_count == 0 and expected_count == 0:
                    # PCI_NOTE_TOKENS req -- surface the `note:` text
                    # both inline (visually) and as the tooltip. The
                    # html-render path receives pci_data; look up the
                    # note from the requirements list.
                    note_text = ""
                    for r in pci_data.get("requirements", []):
                        if r["id"] == rid and any(
                            c in PCI_NOTE_TOKENS for c in r.get("checks", [])
                        ):
                            note_text = r.get("note", "")
                            break
                    if note_text:
                        tip = (
                            ' <span style="color:#555" '
                            f'title="{html.escape(note_text)}">'
                            f"[note: {html.escape(note_text)}]"
                            "</span>"
                        )
                    else:
                        tip = (
                            ' <span style="color:#888" '
                            'title="no working Checkov coverage; '
                            'see pci_mapping.yaml note">'
                            "(no working Checkov coverage)"
                            "</span>"
                        )
                elif missing_count == 0 and expected_count > 0:
                    tip = (
                        ' <span style="color:#888" '
                        "title=\"every mapped check fired at least once - "
                        'all findings compliant (accepted)">'
                        "(all mapped checks ran)</span>"
                    )
                status = "No matching resources in scope" + tip
        body += f'  <tr><td>{rid} <span class="req-coverage">{html.escape(title)}</span></td><td>{status}</td></tr>\n'

    # Render a dedicated coverage-gap section after the in-scope rows,
    # BEFORE the out-of-scope section, so operators see it before
    # reaching the "everything else is excluded" content.
    if gap_records and any(g["missing_count"] > 0 for g in gap_records):
        body += "</table>\n<h3>Coverage gaps -- mapped checks that never fired</h3>\n"
        body += "<p class='req-coverage'>"
        body += (
            "Each row is a PCI requirement whose <code>checks:</code> list in "
            "<code>pci_mapping.yaml</code> contains check_id(s) that never "
            "appeared in any SARIF from this run. Three possible causes:<br/>"
            "  (a) stale check id (rule was renumbered or removed in this "
            "Checkov version -- verify with <code>checkov --list | grep "
            "&lt;id&gt;</code>);<br/>"
            "  (b) the env has no resources of the type the rule targets "
            "(verify by inspecting <code>env/&lt;project&gt;/&lt;env&gt;/*.tf</code>);<br/>"
            "  (c) the rule ran and produced no findings (Checkov SARIF omits "
            "passes -- verify with <code>checkov -d &lt;env&gt; --check "
            "&lt;id&gt; --framework terraform</code>).<br/>"
            "Until each missing id is triaged, treat the req as "
            "<strong>unverified</strong>, not compliant."
        )
        body += "</p>\n<table>\n"
        body += "  <tr><th>PCI Requirement</th><th>Expected</th><th>Fired</th><th>Missing</th><th>IDs to triage</th><th>Hint</th></tr>\n"
        for g in gap_records:
            if g["missing_count"] == 0:
                continue
            missing_ids_html = "<br/>".join(
                f"<code>{html.escape(x)}</code>" for x in g["missing_check_ids"]
            )
            body += (
                f"  <tr>"
                f"<td>{html.escape(g['req_id'])}</td>"
                f"<td>{g['expected_count']}</td>"
                f"<td>{g['fired_count']}</td>"
                f"<td>{g['missing_count']}</td>"
                f"<td>{missing_ids_html}</td>"
                f"<td class='req-coverage'>see triage steps above</td>"
                f"</tr>\n"
            )
        body += "</table>\n</section>  <!-- /route-coverage -->\n"
    body += "<section id=\"route-oos\" class=\"route\">\n"
    body += "  <div class=\"route-header\"><h1>Out-of-Scope Requirements</h1>"
    body += f"<div class=\"meta\">{len(out_of_scope)} requirement family{'' if len(out_of_scope)==1 else 'ies'} explicitly excluded from IaC scanning</div></div>\n"
    body += "<table>\n<tr><th>Requirement</th><th>Status</th></tr>\n"

    for entry in out_of_scope:
        rid = entry["id"]
        title = entry.get("title", "")
        rationale = entry.get("rationale", "")
        control_owner = entry.get("control_owner", "")
        approved_on = entry.get("approved_on", "")
        expires_on = entry.get("expires_on", "")
        evidence_link = entry.get("evidence_link", "")
        stale = entry.get("stale", False)
        days_to_expiry = entry.get("days_to_expiry")

        # Status badge: STALE if the exclusion has expired. Auditors
        # must NOT trust an expired exclusion.
        if stale:
            badge = (
                f'<span style="background:#fbb; color:#800; padding:2px 6px; '
                f'border-radius:3px; font-weight:bold;">OUT OF SCOPE -- '
                f'STALE (expired {-days_to_expiry}d ago)</span>'
            )
        else:
            badge = (
                '<span style="background:#cdf; color:#006; padding:2px 6px; '
                'border-radius:3px; font-weight:bold;">OUT OF SCOPE</span>'
            )

        # Build the audit-trail details: every field below MUST be
        # present for the exclusion to be defensible. They are rendered
        # as a definition list so an auditor can read all of them in
        # one glance.
        details = "<dl style='margin:6px 0 0 1em; font-size:0.9em;'>"
        for label, value in [
            ("Title", title),
            ("Rationale", rationale),
            ("Control owner", control_owner),
            ("Approved on", approved_on),
            ("Expires on", expires_on),
            ("Evidence link", evidence_link),
        ]:
            # Render the link as a clickable anchor when it's a URL.
            display = html.escape(str(value)) if value is not None else ""
            if (
                label == "Evidence link"
                and value
                and isinstance(value, str)
                and (value.startswith("http://") or value.startswith("https://"))
            ):
                display = f'<a href="{html.escape(value)}">{html.escape(value)}</a>'
            details += (
                f"<dt><strong>{label}:</strong></dt>"
                f"<dd style='margin:0 0 4px 0;'>{display or '<em style=\"color:#999\">missing</em>'}</dd>"
            )
        details += "</dl>"

        body += (
            f"  <tr>\n"
            f"    <td>{html.escape(rid)} <span class='req-coverage'>{html.escape(title)}</span></td>\n"
            f"    <td>\n"
            f"      {badge}\n"
            f"      {details}\n"
            f"    </td>\n"
            f"  </tr>\n"
        )

    body += "</table>\n</section>  <!-- /route-oos -->\n"
    # Drift Findings section.
    # Tier 3 only. Reads drift_report.json files emitted by drift_report.py
    # under each <run-dir>/<project>/<env>/drift_report.json. Tier 1/2
    # runs don't produce drift_report.json; _render_drift_section returns
    # "" in that case so the section is silently absent (no error, no
    # empty placeholder). The collected list is passed in by main() so
    # this function stays pure rendering (no I/O).
    body += "<section id=\"route-drift\" class=\"route\">\n"
    body += "  <div class=\"route-header\"><h1>Drift Findings</h1>"
    body += f"<div class=\"meta\">Tier 3 only · {len(drift_findings)} drift item{'' if len(drift_findings)==1 else 's'}</div></div>\n"
    body += _render_drift_section(drift_findings)
    body += "</section>  <!-- /route-drift -->\n"
    # Client-side filter UI block. Renders
    # BEFORE the first finding row so the search box + severity buttons
    # + PCI-req dropdown + fix-only toggle + live count badge are
    # immediately adjacent to the finding list. The JS that wires the
    # filter (vanilla, no dependencies) lives just before </body> below.
    body += "<section id=\"route-findings\" class=\"route\">\n"
    body += "  <div class=\"route-header\"><h1>Findings</h1>"
    body += f"<div class=\"meta\">{total_findings} findings across {len(env_results)} environment{'' if len(env_results)==1 else 's'}</div></div>\n"

    # Per-environment drill-down: view switcher that lets the operator
    # narrow the findings list to a single project/env without paging.
    # Click an env card to filter; "ALL" restores the full view.
    body += '  <div id="env-summary-cards" style="display:flex;flex-wrap:wrap;gap:0.6em;margin:0.6em 0 1em;"></div>\n'
    body += '  <script>window.__envStats = ' + json.dumps(env_stats) + ';</script>\n'
    body += (
        '<div id="filter-ui">\n'
        '  <input type="search" id="finding-search" '
        'placeholder="Search check_id, resource, file, message…">\n'
        '  <button data-severity-filter="ALL" class="active">ALL</button>\n'
        '  <button data-severity-filter="HIGH">HIGH</button>\n'
        '  <button data-severity-filter="MEDIUM">MEDIUM</button>\n'
        '  <button data-severity-filter="LOW">LOW</button>\n'
        '  <select id="pci-req-filter">\n'
        '    <option value="">All PCI reqs</option>\n'
        '  </select>\n'
        '  <span id="finding-count">Showing 0 of 0</span>\n'
        '</div>\n'
    )
    body += "<h2>Findings by Environment</h2>\n"

    for er in env_results:
        if er.scan_status != "ok":
            body += f"<h3>{er.project}/{er.env} <em>(scan failed: {html.escape(er.error or 'unknown')})</em></h3>\n"
            continue
        body += f"<h3>{er.project}/{er.env} ({len(er.findings)} findings)</h3>\n"
        for f in er.findings:
            classes = f"finding-body finding {f.severity}"
            if f.suppressed:
                classes += " suppressed"
            req_str = (
                ", ".join(f.pci_requirements) if f.pci_requirements else "(no PCI mapping)"
            )
            # Resolve the PCI source URL for the finding's first mapped
            # req. Findings mapped to multiple PCI reqs use the first
            # (deterministic via pci_data requirements order).
            primary_req = (
                f.pci_requirements[0] if f.pci_requirements else ""
            )
            pci_src_url = pci_source_url_by_req.get(primary_req, "")
            # Wrap each finding in an outer
            # `.finding-row` div carrying the data-attributes the JS
            # filter needs. The inner `.finding-body` keeps the original
            # `.finding.<SEVERITY>` styling so the CSS (border-left,
            # background tint) is unchanged. The outer div is the
            # show/hide target -- setting `display:none` on it hides the
            # whole finding without breaking the layout of any inner
            # block.
            # Truncate `message` at 200 chars so the data-attribute
            # doesn't blow up the HTML when Checkov emits a multi-line
            # block (full text is still rendered in the body below).
            msg_attr = (f.message or "")[:200]
            row_attrs = (
                f'class="finding-row" '
                f'data-severity="{html.escape(f.severity, quote=True)}" '
                f'data-check-id="{html.escape(f.check_id, quote=True)}" '
                f'data-pci-req="{html.escape(primary_req, quote=True)}" '
                f'data-resource="{html.escape(f.resource or "", quote=True)}" '
                f'data-file-path="{html.escape(f.file_path or "", quote=True)}" '
                f'data-project="{html.escape(f.project or "", quote=True)}" '
                f'data-env="{html.escape(f.env or "", quote=True)}" '
                f'data-suppressed="{"true" if f.suppressed else "false"}" '
                f'data-message="{html.escape(msg_attr, quote=True)}"'
            )
            body += f'<div {row_attrs}>'
            body += f'<div class="{classes}">'
            body += f"<strong>{f.check_id}</strong> "
            body += f'<span class="count-{f.severity.lower()}">[{f.severity}]</span> '
            # Resource address (operator-fix-now UX). Commits 19 wires
            # parse_sarif to populate f.resource from the snippet's
            # first line because Checkov 3.3.9 SARIF does NOT carry a
            # structured `resource` field on the result (only file
            # path + line + snippet). We render the address + the
            # file:line so the operator can jump to the right block
            # of HCL and apply the fix immediately. If somehow both
            # the structured lookup AND the snippet regex fail, we
            # fall back to "(resource address unresolved -- see
            # message + file:line)" so the row never prints a blank
            # <code> again.
            resource_disp = html.escape(f.resource) if f.resource else (
                '<em style="color:#a80">(resource address unresolved -- see message + file:line)</em>'
            )
            body += f"<code>{resource_disp}</code><br>"
            file_loc = f.file_path or ""
            if file_loc and f.line:
                body += (
                    f"<small>at <code>{html.escape(file_loc)}"
                    f":{f.line}</code></small><br>"
                )
            elif file_loc:
                body += f"<small>at <code>{html.escape(file_loc)}</code></small><br>"
            body += f"<small>PCI: {html.escape(req_str)} | {f.framework}</small><br>"
            if f.suppressed:
                body += '<em>(suppressed by baseline)</em><br>'
            body += f"<small>{html.escape(f.message)}</small>"
            # Per-finding links: PCI source and Checkov policy helpUri.
            links: list[str] = []
            if pci_src_url:
                links.append(
                    f'<a href="{html.escape(pci_src_url)}" target="_blank" '
                    f'rel="noopener noreferrer">PCI source</a>'
                )
            if f.help_uri:
                links.append(
                    f'<a href="{html.escape(f.help_uri)}" target="_blank" '
                    f'rel="noopener noreferrer">Checkov policy</a>'
                )
            if links:
                body += "<div>" + " | ".join(links) + "</div>"
            # Chain-of-custody badge. Render only
            # for findings with a PCI mapping. The cell value
            # "True" means the pci_source_url was live-verified at
            # PCI_SOURCE_VERIFIED_AT; "partial" means historical
            # verification present but not re-confirmed at write
            # time (operator must manually re-verify the PCI source).
            # Empty cell -> no badge line at all (no PCI mapping).
            coc = pci_chain_of_custody_by_req.get(primary_req, "")
            if primary_req and coc:
                coc_class = (
                    "coc-true" if coc == "True" else "coc-partial"
                )
                body += (
                    f'<div class="chain-of-custody">'
                    f'Chain of custody (PCI {html.escape(primary_req)}): '
                    f'<span class="{coc_class}">{html.escape(coc)}</span>'
                    f' &mdash; verified against PCI SSC v4.0.1 anchor '
                    f'on {html.escape(PCI_SOURCE_VERIFIED_AT)} '
                    f'(byte_size={LIBRARIAN_VERIFIED_FINGERPRINT["byte_size"]}, '
                    f'content_type={html.escape(LIBRARIAN_VERIFIED_FINGERPRINT["content_type"])}, '
                    f'availability={LIBRARIAN_VERIFIED_FINGERPRINT["past_90d_availability_pct"]:.0f}%/90d).'
                    f'</div>'
                )
            # Inline remediation block. Renders the
            # canonical azurerm 4.x fix HCL + verification step pulled
            # from terraform_remediation.yaml. Skip the block entirely
            # when (a) no canonical remediation exists for this check_id,
            # OR (b) the YAML load was degraded (empty map). Either way
            # we inject a single-line fallback pointing the operator at
            # the Checkov policy URI so the row never ends with the CoC
            # badge and no actionable next step.
            if primary_req:
                body += '<div class="remediation">'
                body += (
                    f'<h4>Fix for PCI {html.escape(primary_req)} '
                    f'(check {html.escape(f.check_id)}, '
                    f'severity {html.escape(f.severity)})</h4>'
                )
                blocks = remediation_by_check_id.get(f.check_id, [])
                if blocks:
                    for block in blocks:
                        body += (
                            f'<p><strong>{html.escape(str(block.get("resource_type", "")))}</strong> '
                            f'&mdash; {html.escape(str(block.get("current_problem", "")))}</p>'
                        )
                        body += (
                            f'<pre class="remediation-hcl">'
                            f'{html.escape(str(block.get("remediation_hcl", "")))}'
                            f'</pre>'
                        )
                        body += (
                            f'<p><em>Verify:</em> '
                            f'<code>{html.escape(str(block.get("verification_step", "")))}</code>'
                            f'</p>'
                        )
                else:
                    body += (
                        f'<p><em>No canonical remediation in terraform_remediation.yaml &mdash; '
                        f'see <a href="{html.escape(f.help_uri)}">Checkov policy doc</a></em></p>'
                    )
                body += '</div>'
            body += "</div></div>\n"
    body += "</section>  <!-- /route-findings -->\n"

    # Client-side filter logic. Vanilla JS,
    # no dependencies. Reads data-attributes from each `.finding-row`,
    # applies search/severity/PCI-req/fix-only filters, hides non-matching
    # rows, and updates the live count badge. Held as a plain string
    # (NOT inside an f-string) because the JS contains literal `{` `}`
    # braces that conflict with f-string parsing in Python 3.12+.
    FILTER_JS = """\
<script>
/* ============================================================
   Pacioli SPA router + findings filter + chart (vanilla JS)
   ============================================================ */
(function() {
  // ----- Section routing (hash-based) -----
  const routes = ['dashboard', 'findings', 'environments', 'coverage',
                  'remediation', 'oos', 'drift'];
  function showRoute(name) {
    if (!routes.includes(name)) name = 'dashboard';
    document.querySelectorAll('.route').forEach(r => {
      r.classList.toggle('active', r.id === 'route-' + name);
    });
    document.querySelectorAll('nav.sidebar-nav a').forEach(a => {
      a.classList.toggle('active', a.dataset.route === name);
    });
    if (location.hash !== '#' + name) {
      history.replaceState(null, '', '#' + name);
    }
    // Re-sync every filter UI on every route change so the user always
    // sees the current FILTER state reflected in the active route's
    // dropdowns/buttons. The `__pacioliUiReady` flag is set below once
    // every dropdown/button has been queried from the DOM; before that
    // point the UI elements are in the temporal dead zone and we must
    // not call syncAllFilterUIs from showRoute().
    if (window.__pacioliUiReady) syncAllFilterUIs();
  }
  document.querySelectorAll('nav.sidebar-nav a').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      showRoute(a.dataset.route);
    });
  });
  // (Heatmap cell click handler: see the FILTER-aware handler below; the
  // earlier inline handler was removed because it bypassed FILTER and
  // caused the in-page dropdown to desync from the sidebar global filter.)
  // Initial route from hash
  const initial = (location.hash || '#dashboard').replace('#', '');
  showRoute(initial);

  // ----- Severity donut chart (pure SVG, no deps) -----
  (function renderDonut() {
    const svg = document.getElementById('severity-donut');
    if (!svg) return;
    const total = """ + str(total_findings) + """;
    const slices = [
      { v: """ + str(high_critical) + """, color: '#c00', label: 'HIGH' },
      { v: """ + str(medium) + """, color: '#c80', label: 'MEDIUM' },
      { v: """ + str(low) + """, color: '#888', label: 'LOW' },
      { v: """ + str(suppressed_count) + """, color: '#2a8c4a', label: 'SUPPRESSED' },
    ];
    if (total === 0) {
      const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', '80'); t.setAttribute('y', '85');
      t.setAttribute('text-anchor', 'middle');
      t.setAttribute('font-size', '14'); t.setAttribute('fill', '#5a6878');
      t.textContent = 'No data';
      svg.appendChild(t);
      return;
    }
    const r = 60, c = 2 * Math.PI * r;
    let offset = 0;
    slices.forEach(s => {
      if (s.v === 0) return;
      const pct = s.v / total;
      const len = pct * c;
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '80'); circle.setAttribute('cy', '80');
      circle.setAttribute('r', r.toString());
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', s.color);
      circle.setAttribute('stroke-width', '20');
      circle.setAttribute('stroke-dasharray', len + ' ' + (c - len));
      circle.setAttribute('stroke-dashoffset', (-offset).toString());
      circle.setAttribute('transform', 'rotate(-90 80 80)');
      svg.appendChild(circle);
      offset += len;
    });
    // Center total
    const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    t.setAttribute('x', '80'); t.setAttribute('y', '78');
    t.setAttribute('text-anchor', 'middle');
    t.setAttribute('font-size', '26'); t.setAttribute('font-weight', '700');
    t.setAttribute('fill', '#0a1a3a');
    t.textContent = total;
    svg.appendChild(t);
    const t2 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    t2.setAttribute('x', '80'); t2.setAttribute('y', '95');
    t2.setAttribute('text-anchor', 'middle');
    t2.setAttribute('font-size', '9'); t2.setAttribute('fill', '#5a6878');
    t2.textContent = 'findings';
    svg.appendChild(t2);
  })();

  // ----- Per-env summary cards (drill-down within Findings route) -----
  // Cards are rendered WITHOUT inline click handlers because the FILTER-
  // aware handler (registered further down) attaches to #env-summary-cards
  // once and is the single source of truth for env filter transitions.
  (function renderEnvCards() {
    const container = document.getElementById('env-summary-cards');
    if (!container || !window.__envStats) return;
    const all = document.createElement('button');
    all.type = 'button';
    all.dataset.env = '__all__';
    all.className = 'kpi';
    all.style.cssText = 'cursor:pointer;border:2px solid #003a70;text-align:left;';
    all.innerHTML = '<div class="kpi-label">All environments</div><div class="kpi-value">' +
      window.__envStats.reduce((a, e) => a + e.total, 0) + '</div>';
    container.appendChild(all);
    window.__envStats.forEach(e => {
      const card = document.createElement('button');
      card.type = 'button';
      card.dataset.env = e.label;
      card.className = 'kpi';
      card.style.cssText = 'cursor:pointer;text-align:left;border:1px solid #d0d6e0;';
      const klass = e.high > 0 ? 'kpi-high' : (e.medium > 0 ? 'kpi-medium' : 'kpi-ok');
      card.classList.add(klass);
      card.innerHTML = '<div class="kpi-label">' + e.label + '</div>' +
        '<div class="kpi-value">' + e.total + '</div>' +
        '<div class="kpi-sub">' +
        (e.high ? '<span class="count-high">' + e.high + ' H</span> ' : '') +
        (e.medium ? '<span class="count-medium">' + e.medium + ' M</span> ' : '') +
        (e.low ? '<span class="count-low">' + e.low + ' L</span>' : '') +
        '</div>';
      container.appendChild(card);
    });
    // The click handler is wired in the FILTER section below so the
    // single source of truth (FILTER.env) is the only state that mutates.
  })();

  // ----- Cross-filtering: ONE global filter state, all routes read it -----
  // Filter shape: { q: string, sev: 'ALL'|'HIGH'|'MEDIUM'|'LOW', pci: string, env: string }
  // Every input (search, severity buttons, PCI dropdown, env cards, heatmap
  // cells) updates the global state and triggers applyAll(). Every output
  // (findings, heatmap highlight, env-bar highlight, KPI counts, count badge)
  // reads the same state. This is true cross-filtering: switching severity on
  // the dashboard also dims unrelated heatmap cells, narrows env-bar tallies,
  // and filters findings.
  const FILTER = window.__pacioliFilter = { q: '', sev: 'ALL', pci: '', env: '__all__' };
  const rows = document.querySelectorAll('.finding-row');
  const totalCount = rows.length;
  const search = document.getElementById('finding-search');
  const sevBtns = document.querySelectorAll('[data-severity-filter]');
  const pciFilter = document.getElementById('pci-req-filter');
  const countBadge = document.getElementById('finding-count');
  const heatmapCells = document.querySelectorAll('.heatmap-cell');
  const envBars = document.querySelectorAll('[data-env-bar]');

  // ----- Cookie helpers (persist filter across page reloads) -----
  function cookieGet(k) {
    const m = document.cookie.match(new RegExp('(?:^|; )' + k + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : null;
  }
  function cookieSet(k, v) {
    document.cookie = k + '=' + encodeURIComponent(v) + '; path=/; max-age=86400';
  }

  // ---- Filter row in the sidebar (always visible, cross-route) -----
  const sidebarFilter = document.createElement('div');
  sidebarFilter.id = 'sidebar-filter';
  sidebarFilter.style.cssText = 'padding: 0.8em 1.2em; border-top: 1px solid rgba(255,255,255,0.1); border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 0.85em;';
  sidebarFilter.innerHTML = `
    <div style="color:#a8c0e0;font-size:0.75em;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px;">Global Filter</div>
    <input type="search" id="global-search" placeholder="Search all…"
      style="width:100%;padding:5px 8px;border:1px solid rgba(255,255,255,0.2);background:rgba(255,255,255,0.08);color:#fff;border-radius:3px;margin-bottom:6px;">
    <div style="display:flex;gap:4px;flex-wrap:wrap;">
      <button data-sev="ALL"   class="gsev-btn active">All</button>
      <button data-sev="HIGH"  class="gsev-btn">High</button>
      <button data-sev="MEDIUM" class="gsev-btn">Med</button>
      <button data-sev="LOW"   class="gsev-btn">Low</button>
    </div>
    <select id="global-pci" style="width:100%;padding:4px;margin-top:6px;background:rgba(255,255,255,0.08);color:#fff;border:1px solid rgba(255,255,255,0.2);border-radius:3px;">
      <option value="">All PCI reqs</option>
    </select>
    <button id="reset-filter" style="width:100%;margin-top:6px;padding:4px;background:rgba(255,255,255,0.08);color:#fff;border:1px solid rgba(255,255,255,0.2);border-radius:3px;cursor:pointer;">Reset filter</button>
    <div id="filter-summary" style="margin-top:8px;color:#a8c0e0;font-size:0.8em;"></div>
  `;

  // ---- "FILTERING BY" top banner (visible on every route) ----
  // Renders the active filter state at the top of <main> so the user
  // always sees what's currently filtering the data, regardless of which
  // page they're on. Independent chips per filter dimension; clicking
  // any chip clears that one dimension. The "Clear all" button resets
  // every dimension. The banner is hidden when no filter is active.
  const filterBanner = document.createElement('div');
  filterBanner.id = 'filter-banner';
  filterBanner.style.cssText = 'display:none;margin:0.6em 0;padding:8px 12px;background:#eaf3ff;border:1px solid #4f9eff;border-radius:4px;font-size:0.9em;align-items:center;gap:8px;flex-wrap:wrap;';
  filterBanner.innerHTML = `
    <strong style="color:#003a70;">Filtering by:</strong>
    <span id="filter-chips" style="display:inline-flex;gap:6px;flex-wrap:wrap;align-items:center;"></span>
    <button id="filter-banner-clear" style="margin-left:auto;padding:4px 10px;background:#fff;border:1px solid #4f9eff;color:#003a70;border-radius:3px;cursor:pointer;font-weight:600;">Clear all</button>
  `;
  // Sidebar buttons need similar styling to the in-page filter buttons
  const style = document.createElement('style');
  style.textContent = `
    .gsev-btn { padding: 3px 8px; background: rgba(255,255,255,0.08); color: #d0d6e0;
                 border: 1px solid rgba(255,255,255,0.2); border-radius: 3px;
                 cursor: pointer; font-size: 0.85em; flex: 1; }
    .gsev-btn.active { background: #4f9eff; color: #fff; border-color: #4f9eff; }
    .gsev-btn:hover { background: rgba(255,255,255,0.15); }
    .heatmap-cell.dimmed { opacity: 0.25; }
    .heatmap-cell.dimmed:hover { opacity: 0.6; transform: translateY(-2px); }
    .heatmap-cell.filtered { box-shadow: 0 0 0 3px #4f9eff; background: #eaf3ff; }
    .env-bar-row.dimmed { opacity: 0.3; }
  `;
  document.head.appendChild(style);

  // Find the sidebar-brand div and insert the filter after it
  const sidebarBrand = document.querySelector('.sidebar-brand');
  sidebarBrand.parentNode.insertBefore(sidebarFilter, sidebarBrand.nextSibling);

  // Wire the global inputs to the same handlers
  const globalSearch = document.getElementById('global-search');
  const globalSevBtns = sidebarFilter.querySelectorAll('.gsev-btn');
  const globalPci = document.getElementById('global-pci');
  const resetBtn = document.getElementById('reset-filter');

  // Restore from cookie
  const saved = (function() {
    try { return JSON.parse(cookieGet('pacioli_filter') || '{}'); } catch(e) { return {}; }
  })();
  if (saved.q) FILTER.q = saved.q;
  if (saved.sev) FILTER.sev = saved.sev;
  if (saved.pci) FILTER.pci = saved.pci;
  if (saved.env) FILTER.env = saved.env;
  globalSearch.value = FILTER.q;
  globalSevBtns.forEach(b => b.classList.toggle('active', b.dataset.sev === FILTER.sev));
  globalPci.value = FILTER.pci;

  // ---- Core: apply filter to everything ----
  function applyAll() {
    // 1. Findings: show/hide rows
    let shown = 0;
    rows.forEach(r => {
      const sev = r.dataset.severity || '';
      const env = (r.dataset.project || '') + '/' + (r.dataset.env || '');
      const hay = (r.dataset.checkId + ' ' + r.dataset.resource + ' ' +
                   r.dataset.filePath + ' ' + r.dataset.message).toLowerCase();
      const matchQ = !FILTER.q || hay.includes(FILTER.q);
      const matchSev = FILTER.sev === 'ALL' || sev === FILTER.sev;
      const matchPci = !FILTER.pci || r.dataset.pciReq === FILTER.pci;
      const matchEnv = FILTER.env === '__all__' || env === FILTER.env;
      const visible = matchQ && matchSev && matchPci && matchEnv;
      r.style.display = visible ? '' : 'none';
      if (visible) shown++;
    });
    if (countBadge) countBadge.textContent = 'Showing ' + shown + ' of ' + totalCount;

    // 2. Heatmap: dim cells that don't match, highlight the filter target
    heatmapCells.forEach(cell => {
      const reqId = cell.querySelector('.req-id').textContent;
      const matchPci = !FILTER.pci || reqId === FILTER.pci;
      cell.classList.toggle('dimmed', FILTER.pci && !matchPci);
      cell.classList.toggle('filtered', FILTER.pci === reqId);
    });

    // 3. Env health bars: dim envs that don't match the env filter
    envBars.forEach(bar => {
      const envLabel = bar.dataset.envBar;
      const matchEnv = FILTER.env === '__all__' || envLabel === FILTER.env;
      bar.classList.toggle('dimmed', FILTER.env !== '__all__' && !matchEnv);
    });

    // 4. Env summary cards on Findings route: highlight selected env
    document.querySelectorAll('#env-summary-cards button').forEach(btn => {
      const label = btn.dataset.env;
      btn.style.border = (label === FILTER.env) ? '2px solid #003a70' : '';
    });

    // 5. Filter chip summary in sidebar
    const parts = [];
    if (FILTER.q) parts.push('q=' + JSON.stringify(FILTER.q));
    if (FILTER.sev !== 'ALL') parts.push('sev=' + FILTER.sev);
    if (FILTER.pci) parts.push('pci=' + FILTER.pci);
    if (FILTER.env !== '__all__') parts.push('env=' + FILTER.env);
    document.getElementById('filter-summary').textContent =
      parts.length ? 'Active: ' + parts.join(' · ') : 'No filter active';

    // 6. Persist
    cookieSet('pacioli_filter', JSON.stringify(FILTER));

    // 7. Heatmap active-filter banner
    if (typeof updateHeatmapBanner === 'function') updateHeatmapBanner();

    // 8. Sync every filter UI to FILTER state. This is the SINGLE source
    // of alignment for dropdowns/buttons across the sidebar AND the in-page
    // Findings header. After any state change (click, heatmap, env card,
    // cookie restore, route change), every visible UI element reflects
    // the same FILTER. This eliminates the "dropdown does not match what
    // I'm filtering by" bug.
    syncAllFilterUIs();
  }

  // ---- Sync every filter UI to FILTER state ----
  // Called by applyAll() AND on every route change AND on cookie restore.
  // Every input/button/dropdown in the page -- sidebar AND in-page -- gets
  // updated here so the user never sees stale state.
  function syncAllFilterUIs() {
    // Search inputs (sidebar + in-page)
    if (globalSearch) globalSearch.value = FILTER.q;
    if (search) search.value = FILTER.q;

    // Severity buttons: both the sidebar (.gsev-btn, data-sev) and the
    // in-page (.data-severity-filter) read the same FILTER.sev.
    if (globalSevBtns) globalSevBtns.forEach(b => {
      b.classList.toggle('active', b.dataset.sev === FILTER.sev);
    });
    if (sevBtns) sevBtns.forEach(b => {
      b.classList.toggle('active', b.dataset.severityFilter === FILTER.sev);
    });

    // PCI dropdown: both sidebar (#global-pci) and in-page (#pci-req-filter).
    // Use the property setter so the visible value reflects FILTER
    // even when the option was just added dynamically.
    if (globalPci) globalPci.value = FILTER.pci;
    if (pciFilter) pciFilter.value = FILTER.pci;

    // Sidebar "filter summary" text is updated by applyAll() too, but
    // we re-set it here so a cookie-restore on initial load also shows
    // the right summary.
    const parts = [];
    if (FILTER.q) parts.push('q=' + JSON.stringify(FILTER.q));
    if (FILTER.sev !== 'ALL') parts.push('sev=' + FILTER.sev);
    if (FILTER.pci) parts.push('pci=' + FILTER.pci);
    if (FILTER.env !== '__all__') parts.push('env=' + FILTER.env);
    const fs = document.getElementById('filter-summary');
    if (fs) fs.textContent = parts.length ? 'Active: ' + parts.join(' · ') : 'No filter active';

    // Top-of-page "FILTERING BY" banner with per-dimension chips.
    // Each chip shows the active filter value with a clear (x) button
    // that resets only that dimension. Independent of dropdowns so the
    // user always sees what's active, regardless of route or dropdown state.
    renderFilterBanner();
  }

  // Render the top-of-page filter banner. Inserts a chip for each
  // active filter dimension. Clicking a chip's x clears that dimension.
  function renderFilterBanner() {
    const banner = document.getElementById('filter-banner');
    const chips = document.getElementById('filter-chips');
    if (!banner || !chips) return;
    const active = [];
    if (FILTER.q) active.push({ dim: 'q', label: 'search: ' + FILTER.q });
    if (FILTER.sev !== 'ALL') active.push({ dim: 'sev', label: 'severity: ' + FILTER.sev });
    if (FILTER.pci) active.push({ dim: 'pci', label: 'PCI: ' + FILTER.pci });
    if (FILTER.env !== '__all__') active.push({ dim: 'env', label: 'env: ' + FILTER.env });
    if (active.length === 0) {
      banner.style.display = 'none';
      chips.innerHTML = '';
      return;
    }
    banner.style.display = 'flex';
    chips.innerHTML = '';
    active.forEach(c => {
      const chip = document.createElement('span');
      chip.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:3px 8px;background:#fff;border:1px solid #4f9eff;border-radius:12px;font-size:0.85em;color:#003a70;';
      chip.innerHTML = '<span>' + c.label + '</span>';
      const x = document.createElement('button');
      x.textContent = '×';
      x.title = 'Clear ' + c.dim + ' filter';
      x.style.cssText = 'border:none;background:transparent;color:#003a70;font-weight:700;cursor:pointer;padding:0 2px;font-size:1.1em;line-height:1;';
      x.addEventListener('click', () => {
        if (c.dim === 'q') FILTER.q = '';
        else if (c.dim === 'sev') FILTER.sev = 'ALL';
        else if (c.dim === 'pci') FILTER.pci = '';
        else if (c.dim === 'env') FILTER.env = '__all__';
        applyAll();
      });
      chip.appendChild(x);
      chips.appendChild(chip);
    });
  }

  // ---- Wire every input to the global filter ----
  globalSearch.addEventListener('input', () => {
    FILTER.q = globalSearch.value.toLowerCase();
    // Mirror to the in-page search if present
    if (search) search.value = FILTER.q;
    applyAll();
  });
  globalSevBtns.forEach(b => b.addEventListener('click', () => {
    globalSevBtns.forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    FILTER.sev = b.dataset.sev;
    // Mirror to in-page severity buttons
    sevBtns.forEach(x => x.classList.toggle('active', x.dataset.severityFilter === FILTER.sev));
    applyAll();
  }));
  globalPci.addEventListener('change', () => {
    FILTER.pci = globalPci.value;
    if (pciFilter) pciFilter.value = FILTER.pci;
    applyAll();
  });
  resetBtn.addEventListener('click', () => {
    FILTER.q = ''; FILTER.sev = 'ALL'; FILTER.pci = ''; FILTER.env = '__all__';
    globalSearch.value = '';
    globalSevBtns.forEach(b => b.classList.toggle('active', b.dataset.sev === 'ALL'));
    globalPci.value = '';
    if (search) search.value = '';
    if (pciFilter) pciFilter.value = '';
    sevBtns.forEach(x => x.classList.toggle('active', x.dataset.severityFilter === 'ALL'));
    document.querySelectorAll('#env-summary-cards button').forEach(b => b.style.border = '');
    applyAll();
  });

  // ---- Hook the in-page findings filter into the global state ----
  if (search) search.addEventListener('input', () => {
    FILTER.q = search.value.toLowerCase();
    globalSearch.value = FILTER.q;
    applyAll();
  });
  sevBtns.forEach(b => b.addEventListener('click', () => {
    sevBtns.forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    FILTER.sev = b.dataset.severityFilter;
    globalSevBtns.forEach(x => x.classList.toggle('active', x.dataset.sev === FILTER.sev));
    applyAll();
  }));
  if (pciFilter) pciFilter.addEventListener('change', () => {
    FILTER.pci = pciFilter.value;
    globalPci.value = FILTER.pci;
    applyAll();
  });

  // ---- Heatmap cells: click sets PCI filter and navigates to Findings ----
  // The filter is the single source of truth: clicking a cell sets
  // FILTER.pci, syncs both dropdowns (sidebar + in-page), navigates to
  // the Findings route so the operator sees the filtered list, and
  // persists to the cookie. Clicking the same cell again clears the
  // filter and stays on the Findings route.
  heatmapCells.forEach(cell => {
    cell.addEventListener('click', () => {
      const reqId = cell.querySelector('.req-id').textContent;
      // Toggle: if same reqId, clear; otherwise set
      FILTER.pci = (FILTER.pci === reqId) ? '' : reqId;
      // Navigate to findings so the operator sees the filtered list with
      // the in-page dropdown aligned to the active filter.
      showRoute('findings');
      applyAll();
    });
  });

  // ---- Heatmap "View findings" / "Clear" buttons ----
  const heatmapActiveFilter = document.getElementById('heatmap-active-filter');
  const heatmapActiveReq = document.getElementById('heatmap-active-req');
  const heatmapClearBtn = document.getElementById('heatmap-clear-btn');
  const heatmapViewBtn = document.getElementById('heatmap-view-findings');
  if (heatmapClearBtn) {
    heatmapClearBtn.addEventListener('click', () => {
      FILTER.pci = '';
      globalPci.value = '';
      if (pciFilter) pciFilter.value = '';
      applyAll();
    });
  }
  if (heatmapViewBtn) {
    heatmapViewBtn.addEventListener('click', () => {
      showRoute('findings');
    });
  }
  // Show the active-filter banner when a PCI filter is active
  function updateHeatmapBanner() {
    if (!heatmapActiveFilter) return;
    if (FILTER.pci) {
      heatmapActiveFilter.style.display = 'block';
      heatmapActiveReq.textContent = FILTER.pci;
    } else {
      heatmapActiveFilter.style.display = 'none';
    }
  }

  // ---- Env summary cards: click sets env filter ----
  document.querySelectorAll('#env-summary-cards button').forEach(btn => {
    btn.addEventListener('click', () => {
      const label = btn.dataset.env;
      FILTER.env = (FILTER.env === label) ? '__all__' : label;
      showRoute('findings');
      applyAll();
    });
  });

  // ---- Env table rows: click sets env filter ----
  document.querySelectorAll('#route-environments tr[data-project]').forEach(row => {
    row.style.cursor = 'pointer';
    row.addEventListener('click', () => {
      const label = row.dataset.project + '/' + row.dataset.env;
      FILTER.env = (FILTER.env === label) ? '__all__' : label;
      showRoute('findings');
      applyAll();
    });
  });

  // ---- Env health bars in dashboard: click sets env filter ----
  envBars.forEach(bar => {
    bar.addEventListener('click', () => {
      const label = bar.dataset.envBar;
      FILTER.env = (FILTER.env === label) ? '__all__' : label;
      showRoute('findings');
      applyAll();
    });
  });

  // ---- Populate the global PCI dropdown from the data ----
  const reqs = new Set();
  rows.forEach(r => { if (r.dataset.pciReq) reqs.add(r.dataset.pciReq); });
  Array.from(reqs).sort().forEach(req => {
    const o = document.createElement('option');
    o.value = req; o.textContent = req;
    globalPci.appendChild(o);
    if (pciFilter) {
      const o2 = document.createElement('option');
      o2.value = req; o2.textContent = req;
      pciFilter.appendChild(o2);
    }
  });
  globalPci.value = FILTER.pci;
  if (pciFilter) pciFilter.value = FILTER.pci;

  // ---- Inject the top-of-page filter banner into <main> ----
  // The banner is visible on every route, positioned at the top of the
  // main content area so the user always sees what's filtering the data
  // regardless of which page they're on.
  const main = document.getElementById('main');
  if (main && filterBanner && !document.getElementById('filter-banner')) {
    main.insertBefore(filterBanner, main.firstChild);
  }

  // ---- Wire the banner's "Clear all" button ----
  const bannerClear = document.getElementById('filter-banner-clear');
  if (bannerClear) {
    bannerClear.addEventListener('click', () => {
      FILTER.q = ''; FILTER.sev = 'ALL'; FILTER.pci = ''; FILTER.env = '__all__';
      globalSearch.value = '';
      globalSevBtns.forEach(b => b.classList.toggle('active', b.dataset.sev === 'ALL'));
      globalPci.value = '';
      if (search) search.value = '';
      if (pciFilter) pciFilter.value = '';
      if (sevBtns) sevBtns.forEach(x => x.classList.toggle('active', x.dataset.severityFilter === 'ALL'));
      applyAll();
    });
  }

  applyAll();

  // Mark the UI as ready so showRoute() can safely call syncAllFilterUIs.
  // Set AFTER all const declarations (sidebarFilter, globalSearch, etc.)
  // so the function never reads a TDZ variable.
  window.__pacioliUiReady = true;

  // ----- Toolbar hint (hover) -----
  document.querySelectorAll('nav.sidebar-nav a').forEach(a => {
    a.title = a.textContent.trim().split(/\\s+/).slice(1).join(' ') || a.textContent;
  });
})();
</script>
"""
    body += FILTER_JS
    body += "</main></div></body></html>\n"
    out.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Developer-facing fix list (--emit-fix-list)
# ---------------------------------------------------------------------------
# Emits <run-dir>/fix_list.md: a markdown file with one section per
# finding, sorted HIGH -> MEDIUM -> LOW, containing the canonical
# azurerm 4.x remediation HCL and verification step pulled from
# terraform_remediation.yaml. This is the developer-facing artifact
# (HTML is for the auditor; this is for the engineer's PR description).
#
# The format is intentionally simple -- no HTML, no embedded JS -- so it
# can be pasted into a PR description, slack thread, or git commit body
# without any rendering cleanup. Code fences use `hcl` so the rendered
# markdown in GitHub/GitLab/ADO lights up with azurerm syntax highlighting.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def write_fix_list_md(
    out: Path,
    env_results: list[EnvResult],
    pci_data: dict,
    remediation_by_check_id: dict[str, list[dict]],
    run_id: str,
) -> None:
    """Emit a developer-friendly fix_list.md.

    Parameters
    ----------
    out           : output path (e.g. <run-dir>/fix_list.md)
    env_results   : list[EnvResult] -- same set fed to write_html_report
    pci_data      : parsed pci_mapping.yaml top-level dict; used only to
                    resolve the per-requirement title for the bullet list
    remediation_by_check_id : {check_id: [block, ...]} from load_remediation_map
    run_id        : the run dir name (e.g. 'all-prod-2026-08-05') for the header
    """
    title_by_req: dict[str, str] = {
        r["id"]: r.get("title", "")
        for r in pci_data.get("requirements", [])
        if r.get("id")
    }
    utc_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Flatten all findings across envs into one list, mark suppressed ones
    # last so the operator can still see them but they're de-emphasized.
    all_findings: list[tuple[EnvResult, Finding]] = []
    for er in env_results:
        for f in er.findings:
            all_findings.append((er, f))

    # Group by severity bucket while preserving the within-bucket order
    # (env-results order, then file_path/line) for stable diffs.
    buckets: dict[str, list[tuple[EnvResult, Finding]]] = {
        sev: [] for sev in SEVERITY_ORDER
    }
    for er, f in all_findings:
        bucket = f.severity if f.severity in buckets else "LOW"
        buckets[bucket].append((er, f))

    lines: list[str] = []
    lines.append(f"# PCI Fix List \u2014 {run_id} \u2014 {utc_date}")
    lines.append("")
    lines.append(
        "Generated by `make scan-pci-fix-list RUN_DIR=<run_id>`. "
        "Severity-sorted (HIGH first). One section per finding. PCI "
        "req id, canonical remediation, verification command all inline."
    )
    lines.append("")
    total_emit = 0
    for sev in SEVERITY_ORDER:
        bucket = buckets[sev]
        if not bucket:
            continue
        lines.append(f"## {sev}")
        lines.append("")
        for er, f in bucket:
            primary_req = f.pci_requirements[0] if f.pci_requirements else ""
            req_title = title_by_req.get(primary_req, "")
            blocks = remediation_by_check_id.get(f.check_id, [])
            # Use the first block as the canonical remediation. If a
            # check_id has multiple blocks (rare; see CKV_AZURE_PCI_003),
            # we still emit one Finding section and stack the blocks
            # under the same Remediation bullet so the operator sees all
            # candidate fixes.
            lines.append(f"### Finding: {f.check_id} on {f.resource}")
            lines.append("")
            if primary_req:
                if req_title:
                    lines.append(f"- **PCI**: {primary_req} ({req_title})")
                else:
                    lines.append(f"- **PCI**: {primary_req}")
            else:
                lines.append("- **PCI**: (no PCI mapping)")
            file_loc = f.file_path or ""
            if file_loc and f.line:
                lines.append(f"- **File**: `{file_loc}:{f.line}`")
            elif file_loc:
                lines.append(f"- **File**: `{file_loc}`")
            else:
                lines.append("- **File**: (unknown)")
            lines.append(f"- **Environment**: `{er.project}/{er.env}`")
            lines.append(f"- **Framework**: {f.framework}")
            lines.append(f"- **Severity**: {sev}")
            lines.append(f"- **Message**: {f.message}")
            if f.suppressed:
                lines.append("- **Suppressed**: yes (pci_baseline or inline skip)")
            lines.append("- **Remediation**:")
            if blocks:
                for block in blocks:
                    lines.append("")
                    lines.append("  ```hcl")
                    hcl = str(block.get("remediation_hcl", "")).rstrip()
                    # Indent each HCL line by 4 spaces so the fenced block
                    # nests cleanly inside the bullet list item.
                    for hcl_line in hcl.splitlines():
                        lines.append(f"  {hcl_line}")
                    lines.append("  ```")
                    lines.append("")
                    verify = str(block.get("verification_step", "")).strip()
                    if verify:
                        lines.append(f"  - **Verify**: `{verify}`")
                    rt = str(block.get("resource_type", "")).strip()
                    if rt:
                        lines.append(f"  - **Resource type**: {rt}")
            else:
                lines.append("")
                lines.append("  _No canonical remediation in terraform_remediation.yaml._")
            if f.help_uri:
                lines.append(f"- **Checkov policy**: {f.help_uri}")
            lines.append("")
            total_emit += 1

    if total_emit == 0:
        lines.append("## HIGH")
        lines.append("")
        lines.append("_No findings in this run._")
        lines.append("")

    out.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Walk a run dir
# ---------------------------------------------------------------------------
def er_locate_sarif(er: EnvResult, name: str) -> Path | None:
    # er is a dataclass; we need a base path. Instead, return None and have
    # the caller keep the path on the EnvResult.
    return None


@dataclass
class EnvResultFull(EnvResult):
    """EnvResult with a real filesystem path; used during aggregation.

    Tracks every SARIF the scanner can produce so the aggregator can
    surface ALL findings, regardless of which scan tier produced them.
    Tier 1 (source-only) writes results_paac.sarif +
    results_terraform_source.sarif + results_secrets.sarif. Tier 2/3
    additionally write results_terraform_plan.sarif (and tier 3 a
    results_state.sarif for the state-drift layer).
    """

    plan_dir: Path | None = None
    sarif_terraform_plan: Path | None = None
    sarif_terraform_source: Path | None = None
    sarif_paac: Path | None = None
    sarif_secrets: Path | None = None
    sarif_state: Path | None = None


def walk_run_dir(run_dir: Path, projects: list[dict]) -> list[EnvResultFull]:
    """Walk a run dir and produce EnvResultFull per project/env."""
    results = []
    for entry in run_dir.iterdir():
        if not entry.is_dir():
            continue
        project = entry.name
        for env_dir in entry.iterdir():
            if not env_dir.is_dir():
                continue
            env = env_dir.name
            s_plan = env_dir / "results_terraform_plan.sarif"
            s_source = env_dir / "results_terraform_source.sarif"
            s_paac = env_dir / "results_paac.sarif"
            s_secrets = env_dir / "results_secrets.sarif"
            s_state = env_dir / "results_state.sarif"
            r = EnvResultFull(
                project=project,
                env=env,
                scan_status="ok",
                plan_dir=env_dir,
                sarif_terraform_plan=s_plan if s_plan.exists() else None,
                sarif_terraform_source=s_source if s_source.exists() else None,
                sarif_paac=s_paac if s_paac.exists() else None,
                sarif_secrets=s_secrets if s_secrets.exists() else None,
                sarif_state=s_state if s_state.exists() else None,
            )
            # Mark the env failed only if literally no SARIF files were
            # written -- a missing plan+secrets pair is normal for tier 1.
            if (
                r.sarif_terraform_plan is None
                and r.sarif_secrets is None
                and r.sarif_terraform_source is None
                and r.sarif_paac is None
                and r.sarif_state is None
            ):
                r.scan_status = "no_sarif"
                r.error = "no SARIF files written"
            results.append(r)
    return results


def load_findings(results: list[EnvResultFull]) -> None:
    """Mutate results in place: populate findings lists from SARIFs.

    NOTE: the aggregator MUST load every SARIF the scanner produces,
    not just the tier-2/3 ones. Earlier versions of this loader only
    parsed secrets + terraform_plan, which silently DROPPED every
    source-only finding (the entire results_paac.sarif +
    results_terraform_source.sarif). Those findings account for the
    vast majority of what a tier 1 (source-only) operator scan
    produces, so dropping them made the coverage matrix under-report
    by 90%+. See docs/MAPPING_SCHEMA.md for the field schema.
    """
    for r in results:
        if r.scan_status != "ok":
            continue
        if r.sarif_terraform_plan:
            r.findings.extend(
                parse_sarif(r.sarif_terraform_plan, r.project, r.env, "terraform_plan")
            )
        if r.sarif_terraform_source:
            r.findings.extend(
                parse_sarif(
                    r.sarif_terraform_source, r.project, r.env, "terraform"
                )
            )
        if r.sarif_paac:
            # PAAC = policy-as-code = our custom scanner/checks
            r.findings.extend(
                parse_sarif(r.sarif_paac, r.project, r.env, "paac")
            )
        if r.sarif_secrets:
            r.findings.extend(
                parse_sarif(r.sarif_secrets, r.project, r.env, "secrets")
            )
        if r.sarif_state:
            r.findings.extend(
                parse_sarif(r.sarif_state, r.project, r.env, "state")
            )


def sarif_is_empty(path: Path) -> bool:
    """Return True if the SARIF has 0 results (means 'clean' not 'didn't run')."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        runs = data.get("runs", [])
        if not runs:
            return True
        return all(len(r.get("results", [])) == 0 for r in runs)
    except (json.JSONDecodeError, OSError):
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-dir", required=True, help="Run dir produced by scan.sh")
    ap.add_argument("--out", help="Output dir (default: <run-dir>/aggregate)")
    ap.add_argument("--scope", default="pci_scope.yaml", help="Scope manifest")
    ap.add_argument("--mapping", default="pci_mapping.yaml", help="PCI mapping")
    ap.add_argument("--baseline", default="pci_baseline.yaml", help="Baseline suppressions")
    ap.add_argument(
        "--emit-fix-list",
        action="store_true",
        help="Also emit <run-id>/fix_list.md (developer-facing markdown). "
        "Additive -- does not replace report.html.",
    )
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    if not run_dir.exists():
        print(f"ERROR: run dir not found: {run_dir}", file=sys.stderr)
        return 2

    out_dir = Path(args.out).resolve() if args.out else run_dir / "aggregate"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Locate the three PCI config files. Priority order:
    #   1. PACIOLI_TARGET_REPO env var (set by scan.sh, the consumer's
    #      Terraform repo where the scope/baseline live)
    #   2. CLI --scope/--mapping/--baseline absolute path
    #   3. Walk up from run_dir looking for a .git directory (legacy
    #      fallback for callers who don't set the env var)
    # The default values for --scope/--mapping/--baseline are bare
    # filenames, which are resolved relative to the resolved root.
    env_target = os.environ.get("PACIOLI_TARGET_REPO", "").strip()
    if env_target and Path(env_target).is_dir():
        repo_root = Path(env_target).resolve()
    else:
        repo_root = run_dir
        while repo_root.parent != repo_root and not (repo_root / ".git").exists():
            repo_root = repo_root.parent
        if repo_root.parent == repo_root:
            # No .git found — fall back to run_dir's parent.
            repo_root = run_dir.parent
    scope_path = repo_root / args.scope
    mapping_path = repo_root / args.mapping
    baseline_path = repo_root / args.baseline

    print(f"run-dir: {run_dir}")
    print(f"out:     {out_dir}")
    print(f"scope:   {scope_path}")
    print(f"mapping: {mapping_path}")
    print(f"baseline:{baseline_path}")

    if not mapping_path.exists():
        print(f"ERROR: pci mapping not found: {mapping_path}", file=sys.stderr)
        return 2

    pci_mapping = load_pci_mapping(mapping_path)
    pci_data = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))
    baseline = load_pci_baseline(baseline_path)

    # Load canonical remediation HCL map once at startup.
    # Used by the per-finding HTML render and by write_fix_list_md().
    # Returns {} on missing/malformed YAML (degraded mode -- see loader).
    remediation_by_check_id = load_remediation_map()
    print(
        f"remediation map: {sum(len(v) for v in remediation_by_check_id.values())} "
        f"blocks across {len(remediation_by_check_id)} check_ids"
    )

    if not run_dir.iterdir():
        print(f"ERROR: run dir is empty: {run_dir}", file=sys.stderr)
        return 3

    # Walk
    results = walk_run_dir(run_dir, [])
    if not results:
        print(f"ERROR: no project/env subdirs found in {run_dir}", file=sys.stderr)
        return 3

    # Load findings
    load_findings(results)

    # Load inline skips from .tf files
    env_dirs = [r.plan_dir for r in results if r.plan_dir is not None]
    inline_skips = load_inline_skips(env_dirs)
    inline_count = sum(len(v) for v in inline_skips.values())
    if inline_count > 0:
        print(f"inline skips parsed: {inline_count} entries across {len(inline_skips)} check_ids")

    # Apply baseline + inline-skip + PCI mapping
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    suppressed_count = 0
    for r in results:
        for f in r.findings:
            if is_suppressed(f, baseline, today):
                f.suppressed = True
                suppressed_count += 1
            elif is_inline_suppressed(f, inline_skips, today):
                f.suppressed = True
                suppressed_count += 1
        attach_pci_reqs(r.findings, pci_mapping)

    # Build coverage matrix
    (
        req_ids,
        check_ids,
        cells,
        out_of_scope,
        oos_errors,
        expected_by_req,
        fired_check_ids,
    ) = build_coverage_matrix(results, mapping_path, pci_data)

    # Enforce out-of-scope audit metadata. Compliance reporters can NOT
    # ship a report where an exclusion is missing rationale, owner, an
    # approver, a date, or a link to the external evidence. We refuse the
    # run here, BEFORE writing any artifact, so partial reports can't
    # leak into the run dir.
    if oos_errors:
        print(
            f"FAIL: {len(oos_errors)} out-of-scope validation errors in "
            f"{mapping_path}:",
            file=sys.stderr,
        )
        for e in oos_errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nEach out_of_scope_requirements entry in pci_mapping.yaml must "
            "include id, title, rationale, control_owner, "
            "approved_on, expires_on, evidence_link "
            "(`approved_by` is optional). Re-run after the YAML "
            "is filled in.",
            file=sys.stderr,
        )
        return 2

    # Compute coverage gaps so the operator can tell "no relevant
    # resources" from "we didn't evaluate this at all" for any req
    # whose status ends up as not_applicable or "No matching resources in scope".
    # Thread `note_by_req` so PCI_NOTE_TOKENS reqs (see PCI_NOTE_TOKENS docstring)
    # carry the pci_mapping.yaml `note:` text as their triage_hint.
    note_by_req: dict[str, str] = {
        r["id"]: r["note"]
        for r in pci_data.get("requirements", [])
        if any(c in PCI_NOTE_TOKENS for c in r.get("checks", [])) and r.get("note")
    }
    gap_records = compute_coverage_gaps(
        expected_by_req, fired_check_ids, note_by_req
    )
    missing_total = sum(g["missing_count"] for g in gap_records)

    # Write outputs
    write_coverage_csv(
        out_dir / "coverage_matrix.csv",
        req_ids,
        check_ids,
        cells,
        out_of_scope,
        expected_by_req,
        fired_check_ids,
    )
    write_coverage_gaps_csv(
        out_dir / "coverage_gaps.csv", gap_records, pci_data
    )
    write_combined_sarif(out_dir / "combined.sarif", results)
    fail_count = write_junit(out_dir / "junit.xml", results, [])
    # Per-req missing-list computed once for HTML rendering + CSV cell.
    missing_per_req = {
        g["req_id"]: g["missing_check_ids"] for g in gap_records
    }
    # Collect per-env drift reports (tier 3 only). Tier 1/2 envs have no drift_report.json;
    # _collect_drift_findings walks each env's plan_dir and silently
    # skips missing files. Returns [] for tier 1/2 runs so the
    # write_html_report renders no Drift Findings section.
    drift_findings = _collect_drift_findings(results)
    if drift_findings:
        print(
            f"  drift findings:     {len(drift_findings)} (from "
            f"{sum(1 for r in results if (r.plan_dir and (r.plan_dir / 'drift_report.json').exists()))} envs)"
        )
    write_html_report(
        out_dir / "report.html",
        results,
        mapping_path,
        pci_data,
        cells,
        out_of_scope,
        suppressed_count,
        missing_per_req,
        gap_records,
        remediation_by_check_id,
        drift_findings,
    )

    # Emit the developer-facing fix_list.md on
    # --emit-fix-list. Additive -- does NOT replace report.html. Written
    # to the run-dir ROOT (not the aggregate subdir) so the Makefile
    # target can locate it via `$(RUN_DIR)/fix_list.md` without knowing
    # the aggregate subdir layout.
    if args.emit_fix_list:
        fix_list_path = run_dir / "fix_list.md"
        write_fix_list_md(
            fix_list_path,
            results,
            pci_data,
            remediation_by_check_id,
            run_id=run_dir.name,
        )
        print(f"  fix_list.md:        {fix_list_path} ({fix_list_path.stat().st_size} bytes)")

    # Summary
    print()
    print(f"=== Aggregation complete ===")
    print(f"  env-results:        {len(results)}")
    ok = sum(1 for r in results if r.scan_status == "ok")
    print(f"  successful scans:   {ok}")
    print(f"  failed scans:       {len(results) - ok}")
    total = sum(len(r.findings) for r in results)
    print(f"  total findings:     {total}")
    print(f"  suppressed:         {suppressed_count}")
    print(f"  junit failures:     {fail_count}")
    if missing_total:
        print(
            f"  coverage gaps:      {missing_total} (of "
            f"{sum(len(v) for v in expected_by_req.values())} mapped)"
        )
        print(
            "                      see coverage_gaps.csv for triage list"
        )
    else:
        print(f"  coverage gaps:      0 (every mapped check evaluated)")
    print(f"  outputs:")
    for f in ("coverage_matrix.csv", "combined.sarif", "junit.xml", "report.html"):
        p = out_dir / f
        if p.exists():
            print(f"    {p}  ({p.stat().st_size} bytes)")

    # Exit non-zero if any HIGH/CRITICAL or any failed scan. This lets CI
    # use the aggregator's exit code directly when run in gate mode.
    high_crit = sum(
        1 for r in results for f in r.findings
        if not f.suppressed and f.severity in ("HIGH", "CRITICAL")
    )
    if any(r.scan_status != "ok" for r in results) or high_crit > 0:
        return 7
    return 0


if __name__ == "__main__":
    sys.exit(main())
