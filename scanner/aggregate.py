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
  --scope    <repo>/.pacioli/scope.yaml
  --mapping  <pacioli>/mappings/pci_dss_4.0.1.yaml
  --baseline <repo>/.pacioli/baseline.yaml
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
import importlib.resources
from dataclasses import dataclass, field
from pathlib import Path

# Local module: canonical Checkov rule URL overrides. Single source of
# truth shared with rewrite_sarif_help.py and scan.sh's CLI filter.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from checkov_url_overrides import (  # noqa: E402
    RULE_SOURCE_URLS as CHECKOV_RULE_SOURCE_URLS,
)

# Single source of truth for SARIF run-level property names. The
# aggregator writes these tags on each run in combined.sarif;
# baseline_init reads them back. Generic names (no PCI prefix) so any
# framework pack can reuse the same contract.
# NOTE on the requirement-filter constants: ``REQUIREMENT_DATA_ATTR`` and
# ``REQUIREMENT_FILTER_ID`` are consumed in the Python code (one
# interpolates into an HTML attribute, the other is referenced as the
# single source of truth for the in-page filter id). The JS-side
# counterparts (``REQUIREMENT_GLOBAL_FILTER_ID``,
# ``REQUIREMENT_FILTER_STATE_KEY``, ``REQUIREMENT_FILTER_COOKIE_KEY``)
# are defined in ``scanner.frameworks`` for the same single-source-of-
# truth reason but the JS string is currently literal-named to match
# the existing CSS. aggregate.py re-exports them so importers find the
# contract in one place.
from scanner.frameworks import (  # noqa: E402
    REQUIREMENT_DATA_ATTR,
    REQUIREMENT_FILTER_ID,
    SARIF_PROPERTY_ENV,
    SARIF_PROPERTY_PROJECT,
    SARIF_PROPERTY_SOURCE_SARIF,
    is_terraform_family,
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
    requirements: list[str] = field(default_factory=list)
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
    # Identity belongs to the scan metadata, not a physical run-directory name.
    # ``None`` marks a legacy run directory with no metadata sidecar.
    stack_label: str | None = None


@dataclass
class CoverageGaps:
    """Coverage-gap data for the HTML report.

    Aggregates the two structures that ``write_html_report`` used to
    take as separate parameters (``missing_per_req`` and
    ``gap_records``). The two carry the same information in two
    shapes:

    * ``records`` -- the full per-req gap list (req_id, expected_count,
      fired_count, missing_count, missing_check_ids, hint). Used by
      the "Coverage gaps" section + the sidebar pending-count badge.
    * ``missing_by_req`` -- a derived dict mapping ``req_id`` to the
      list of missing check_ids. Used by the PCI status matrix to
      render the per-row "(N/M mapped checks absent)" tooltip.

    A single ``CoverageGaps`` instance is cheaper to pass through
    ``write_html_report`` than two loose parameters (and the
    parameter count was tripping the SonarCloud quality gate).
    """

    records: list[dict] = field(default_factory=list)
    missing_by_req: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_records(cls, records: list[dict]) -> "CoverageGaps":
        """Build from a fresh ``compute_coverage_gaps`` result.

        Derives ``missing_by_req`` from the ``records`` list so the
        dataclass is internally consistent regardless of which fields
        the caller already computed.
        """
        missing_by_req = {
            g["req_id"]: g["missing_check_ids"] for g in records
        }
        return cls(records=records, missing_by_req=missing_by_req)


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
    # Thin alias kept for back-compat with any external callers that
    # import ``SEVERITY_OVERRIDE`` directly. The authoritative table
    # now lives at ``mappings/pci_dss_4.0.1.yaml`` under the
    # top-level ``severity_overrides`` key, and is consumed via
    # ``resolve_severity(check_id, mapping_pack)`` so each framework
    # pack can carry its own severity policy.
    #
    # The dict is populated lazily on first access by
    # ``_load_pci_severity_overrides()`` so unit tests and CLI tools
    # that import the module without a mapping pack still get a
    # usable (empty-by-default) override table.
}

# Default severity for any check not in the override table.
DEFAULT_SEVERITY = "MEDIUM"

# _load_pci_severity_overrides resolves the install-bundled PCI pack
# via importlib.resources (see the function body). The previous
# ``_DEFAULT_SEVERITY_OVERRIDES_PATH`` filesystem-path constant was
# removed during the CI test fix -- multiple CI jobs ran the
# aggregator from a working directory that did not have a ``mappings/``
# sibling, which broke the filesystem-path lookup. The importlib.resources
# version is the canonical path for an installed wheel.


def _load_pci_severity_overrides(
    mapping_pack: dict | None = None,
) -> dict[str, str]:
    """Return the ``severity_overrides`` table from a mapping pack.

    Lookup contract (multi-cloud generalization):

    1. If ``mapping_pack`` is supplied and declares a non-empty
       ``severity_overrides`` dict, return THAT table and nothing
       else. We never silently mix per-pack overrides with the
       install-bundled PCI overrides -- a SOC 2 / CIS / NIST pack
       that omits a check_id wants the lookup to MISS so the call
       falls through to ``DEFAULT_SEVERITY``.
    2. If ``mapping_pack`` is ``None`` (legacy callers, CLI tools
       that import the module without a pack), fall back to:

       a. The legacy module-level ``SEVERITY_OVERRIDE`` dict
          (kept for any external caller that populates it
          directly).
       b. The install-bundled ``mappings/pci_dss_4.0.1.yaml`` if
          the legacy dict is empty.

    Returns an empty dict in degraded mode (no mapping pack
    reachable, malformed YAML, missing file). Never raises -- the
    SARIF loader must keep going even if the severity table is
    missing.
    """
    # Fast path: pack supplied + declares overrides. This is the
    # ONLY path that consults the pack's own table -- once a pack
    # is in play, we trust its overrides (or its absence) and
    # refuse to backfill from the PCI pack.
    if isinstance(mapping_pack, dict):
        so = mapping_pack.get("severity_overrides")
        if isinstance(so, dict) and so:
            return {str(k): str(v) for k, v in so.items()}
        # Pack supplied but no overrides key (or empty value).
        # Return empty so the caller falls through to
        # DEFAULT_SEVERITY for every check -- we do NOT silently
        # substitute the PCI pack (that would be a framework
        # mismatch bug for a SOC 2 / CIS pack).
        return {}

    # Back-compat path: legacy SEVERITY_OVERRIDE dict (kept for any
    # external callers that populate it directly).
    if SEVERITY_OVERRIDE:
        return SEVERITY_OVERRIDE

    # Final fallback: load install-bundled pack via importlib.resources
    # (only when no mapping_pack was supplied at all). The wheel install
    # ships the mapping inside the ``scanner`` package; using
    # ``importlib.resources`` here avoids a CI/runtime edge case where
    # the process working directory does not have a ``mappings/``
    # sibling (which the old ``Path(__file__).parent / "mappings" / ...``
    # call depended on).
    try:
        traversable = importlib.resources.files("scanner").joinpath(
            "mappings/pci_dss_4.0.1.yaml"
        )
    except (ModuleNotFoundError, AttributeError, OSError):
        return {}
    try:
        is_file = traversable.is_file()
    except (AttributeError, OSError):
        return {}
    if not is_file:
        return {}
    try:
        with traversable.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(data, dict):
        return {}
    so = data.get("severity_overrides")
    if not isinstance(so, dict) or not so:
        return {}
    return {str(k): str(v) for k, v in so.items()}


def resolve_severity(
    check_id: str,
    mapping_pack: dict | None = None,
    *,
    rule_severity: str | None = None,
) -> str:
    """Resolve the canonical severity for a finding.

    Precedence (highest first):

    1. ``rule_severity`` -- the SARIF rule's ``properties.severity``
       (when the producer emits it). Upper-cased before comparison.
    2. ``mapping_pack["severity_overrides"][check_id]`` -- the
       per-pack override table. Lookup is pack-scoped: a brand-new
       SOC 2 / CIS pack that omits ``severity_overrides`` (or
       declares an empty table) sees MISS for every check and
       falls through to ``DEFAULT_SEVERITY``. The function does
       NOT silently substitute the install-bundled PCI pack -- that
       would be a framework-mismatch bug.
    3. ``DEFAULT_SEVERITY`` (``"MEDIUM"``).

    Parameters
    ----------
    check_id:
        The Checkov / SARIF rule ID (e.g. ``"CKV_AZURE_44"``).
    mapping_pack:
        The parsed mapping YAML (the ``mapping_data`` dict ``main()``
        loads). Optional -- if omitted, the install-bundled PCI pack
        is consulted (legacy behavior).
    rule_severity:
        Optional SARIF ``properties.severity`` string. May be
        ``None`` or empty (Checkov 3.3.9 does not emit it).

    Returns
    -------
    str
        Upper-case severity tag: ``HIGH`` | ``MEDIUM`` | ``LOW`` |
        ``CRITICAL``. Always non-empty.
    """
    if rule_severity:
        upper = str(rule_severity).strip().upper()
        if upper:
            return upper
    overrides = _load_pci_severity_overrides(mapping_pack)
    if check_id in overrides:
        v = str(overrides[check_id]).strip().upper()
        if v:
            return v
    return DEFAULT_SEVERITY


# ---------------------------------------------------------------------------
# NOTE_TOKENS allow-list (generic, framework-agnostic)
# ---------------------------------------------------------------------------
# Some reqs in the mapping pack have no working Checkov coverage.
# Rather than map a Checkov rule that does not actually evaluate the
# control (which produces a misleading coverage_gaps row that says
# "expected" but never fires correctly), the mapping author can declare
# a symbolic `PACIOLI_NOTE_<id>` token in the `checks:` list and pair
# it with a human-readable `note:` field. The aggregator treats any
# token in this allow-list as `expected_count=0` in coverage_gaps and
# emits the corresponding `note:` text as the row's `triage_hint`.
#
# Schema in the mapping pack YAML:
#   note_tokens:
#     - PACIOLI_NOTE_10_7
#   requirements:
#     - id: "10.7"
#       checks: [PACIOLI_NOTE_10_7]
#       note: "..."
#
# The token is opaque to the SARIF engine -- Checkov never sees it, so
# it cannot fire -- and opaque to the coverage matrix in the sense
# that `expected_by_req` skips the token before computing
# `expected_count` / `missing_count` (see build_coverage_matrix and
# compute_coverage_gaps).
#
# The Python default is an empty set. The mapping pack provides its
# own list via ``note_tokens`` at the top level. ``resolve_note_tokens``
# returns the pack's list (or the empty default).
NOTE_TOKENS_DEFAULT: set[str] = set()


def _resolve_note_tokens(mapping_pack: dict | None) -> set[str]:
    """Return the active ``note_tokens`` allow-list for a mapping pack.

    Graceful degradation: a pack without ``note_tokens`` (or with a
    non-list value) returns the empty set. The renderers treat the
    empty set as "no notes; behave like a normal SARIF row".
    """
    if not isinstance(mapping_pack, dict):
        return NOTE_TOKENS_DEFAULT
    tokens = mapping_pack.get("note_tokens")
    if not isinstance(tokens, list):
        return NOTE_TOKENS_DEFAULT
    return {str(t) for t in tokens if isinstance(t, str)}


# ---------------------------------------------------------------------------
# Chain-of-custody ledger
# ---------------------------------------------------------------------------
# Every req row in coverage_matrix.csv carries an explicit
# `chain_of_custody_complete` cell so an auditor can verify each
# framework citation is live. The cell value semantics:
#
#   "True"   -> source URL slot live-verified at write time:
#              HEAD 2xx, fingerprint match, retrieval date documented.
#   "partial"-> historical verification present but current run did not
#              re-verify (e.g. URL not currently reachable, or
#              fingerprint not parsed). Operator must re-run
#              manually re-verify and confirm the link is live.
#   ""       -> out-of-scope row (no doc_anchor slot; the OOS row's
#              evidence_link is a separate slot).
#
# The previous PCI-specific Python constant (``PCI_REQ_CHAIN_OF_CUSTODY``)
# moved into the mapping pack YAML under the top-level ``chain_of_custody``
# key. The Python default is an empty dict; the value comes from the
# pack. ``resolve_chain_of_custody`` returns the per-pack dict.
CHAIN_OF_CUSTODY_DEFAULT: dict[str, str] = {}


def _resolve_chain_of_custody(mapping_pack: dict | None) -> dict[str, str]:
    """Return the per-requirement chain-of-custody ledger for a pack.

    A pack without ``chain_of_custody`` (or with a non-dict value)
    returns the empty dict. The mapping pack YAML in
    ``mappings/pci_dss_4.0.1.yaml`` carries the PCI-specific ledger.
    """
    if not isinstance(mapping_pack, dict):
        return CHAIN_OF_CUSTODY_DEFAULT
    coc = mapping_pack.get("chain_of_custody")
    if not isinstance(coc, dict):
        return CHAIN_OF_CUSTODY_DEFAULT
    return {str(k): str(v) for k, v in coc.items()}


# ---------------------------------------------------------------------------
# Audit-traceability ledger (librarian probe metadata)
# ---------------------------------------------------------------------------
# The coverage_gaps.csv report must let a compliance auditor
# REPRODUCE the "no findings" verdict for each missing check_id. The
# mapping pack (PCI-SSC URL specific) carries the librarian probe
# metadata under the top-level ``librarian_verified_at`` and
# ``librarian_verified_fingerprint`` keys. For other frameworks
# (SOC 2, CIS, NIST), the mapping pack author overrides these keys.
#
# Defaults are empty so a pack without librarian metadata emits
# empty cells in coverage_gaps.csv (acceptable for non-PCI packs).
# ---------------------------------------------------------------------------
LIBRARIAN_VERIFIED_AT_DEFAULT: str = ""
LIBRARIAN_VERIFIED_FINGERPRINT_DEFAULT: dict = {
    "url": "",
    "byte_size": 0,
    "content_type": "",
    "http_status": 0,
    "fingerprint_match": False,
    "past_90d_availability_pct": 0.0,
}


def _resolve_librarian_metadata(
    mapping_pack: dict | None,
) -> tuple[str, dict]:
    """Return ``(librarian_verified_at, librarian_verified_fingerprint)``.

    Empty defaults when the pack omits the keys. The fingerprint is
    copied (not aliased) so a caller mutating the result cannot
    corrupt the pack.
    """
    if not isinstance(mapping_pack, dict):
        return LIBRARIAN_VERIFIED_AT_DEFAULT, dict(
            LIBRARIAN_VERIFIED_FINGERPRINT_DEFAULT
        )
    at = mapping_pack.get("librarian_verified_at", "")
    at = str(at) if isinstance(at, str) else ""
    fp = mapping_pack.get("librarian_verified_fingerprint")
    if not isinstance(fp, dict):
        return at, dict(LIBRARIAN_VERIFIED_FINGERPRINT_DEFAULT)
    return at, {str(k): v for k, v in fp.items()}


# Regex matching the HCL `resource "TYPE" "NAME" {` token at the
# start of a Checkov snippet line. Captures the resource type and
# name. Compiled once at module import so the per-result loop does
# not re-parse the pattern on every finding.
_RESOURCE_HCL_PATTERN = re.compile(r'resource\s+"([^\s"]+)"\s+"([^"]+)"')


def _read_sarif(sarif_path: Path) -> dict | None:
    """Read and parse a SARIF JSON file. Returns ``None`` on I/O or
    JSON decode error (a warning is printed to stderr)."""
    try:
        return json.loads(sarif_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"WARN: failed to read {sarif_path}: {e}", file=sys.stderr)
        return None


def _build_rule_indices(run: dict) -> tuple[dict[int, dict], dict[str, dict]]:
    """Build the two rule lookup dictionaries for a single run.

    Returns (index_map, id_map) where:

    * ``index_map`` maps the integer ``ruleIndex`` (SARIF 2.1.0) to the
      rule dict -- the PRIMARY lookup table.
    * ``id_map`` maps the string ``ruleId`` (legacy Checkov SARIF)
      to the rule dict -- the FALLBACK table used when a result
      omits ``ruleIndex``.
    """
    index_map: dict[int, dict] = {}
    id_map: dict[str, dict] = {}
    for i, rule in enumerate(run.get("tool", {}).get("driver", {}).get("rules", [])):
        index_map[i] = rule
        rid = rule.get("id", "")
        if rid:
            id_map[rid] = rule
    return index_map, id_map


def _resolve_rule_for_result(
    result: dict,
    rule_index_map: dict[int, dict],
    rule_id_map: dict[str, dict],
) -> tuple[str, dict]:
    """Join a SARIF result against its rule entry.

    Prefers the integer ``ruleIndex`` join (SARIF 2.1.0 -- exact
    match against the rule entry the producer attached). Falls back
    to ``ruleId`` string join for legacy emitters that omit the
    index. Returns ``(rule_id, rule_entry)``; both may be empty
    when the join misses.
    """
    if "ruleIndex" in result:
        rule_entry = rule_index_map.get(result["ruleIndex"], {})
        if rule_entry:
            return rule_entry.get("id") or result.get("ruleId", "UNKNOWN"), rule_entry
    rule_id = result.get("ruleId", "UNKNOWN")
    return rule_id, rule_id_map.get(rule_id, {})


def _resource_from_snippet(snippet: str) -> str:
    """Extract the HCL resource address from a Checkov snippet.

    Returns ``"TYPE.NAME"`` for a single match, or
    ``"TYPE.NAME (+N more in snippet)"`` when the snippet contains
    multiple ``resource "X" "Y" {`` tokens. Returns ``""`` when no
    match is found.
    """
    first_line = snippet.split("\n", 1)[0].strip()
    m = _RESOURCE_HCL_PATTERN.match(first_line)
    if not m:
        return ""
    res_type, res_name = m.group(1), m.group(2)
    res_count = sum(
        1 for ln in snippet.splitlines() if _RESOURCE_HCL_PATTERN.match(ln.strip())
    )
    if res_count > 1:
        return f"{res_type}.{res_name} (+{res_count - 1} more in snippet)"
    return f"{res_type}.{res_name}"


def _extract_resource(result: dict, snippet: str) -> str:
    """Pick the best resource address for a SARIF result.

    Prefers a structured ``resource`` (or ``resource_id`` /
    ``address``) field emitted by the tool. Falls back to HCL
    snippet parsing for Checkov 3.3.9 which emits the resource
    address on the first line of the snippet only.
    """
    for k in ("resource", "resource_id", "address"):
        if result.get(k):
            return str(result[k])
    if snippet:
        return _resource_from_snippet(snippet)
    return ""


def _result_to_finding(
    result: dict,
    project: str,
    env: str,
    framework: str,
    mapping_pack: dict | None,
    rule_index_map: dict[int, dict],
    rule_id_map: dict[str, dict],
) -> Finding:
    """Convert a single SARIF result entry into a :class:`Finding`.

    Resolves severity (rule.properties.severity > mapping_pack
    overrides > DEFAULT), helpUri (override map > upstream > empty),
    message, location, and resource address. Decorated helper so
    :func:`parse_sarif` stays focused on the iteration loop.
    """
    rule_id, rule_entry = _resolve_rule_for_result(result, rule_index_map, rule_id_map)
    # Checkov OSS SARIF does NOT emit ``properties.severity`` (0 of 21
    # inspected rules on Checkov 3.3.9). The mapping pack's
    # ``severity_overrides`` table is the de-facto severity source.
    sev = rule_entry.get("properties", {}).get("severity") if rule_entry else None
    severity = resolve_severity(rule_id, mapping_pack, rule_severity=sev)
    upstream_help_uri = rule_entry.get("helpUri", "") if rule_entry else ""
    help_uri = CHECKOV_RULE_SOURCE_URLS.get(rule_id, upstream_help_uri)
    message = result.get("message", {}).get("text", "")
    location = result.get("locations", [{}])[0]
    physical = location.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    snippet = physical.get("region", {}).get("snippet", {}).get("text", "")
    return Finding(
        env=env,
        project=project,
        check_id=rule_id,
        severity=severity,
        resource=_extract_resource(result, snippet),
        file_path=artifact.get("uri", ""),
        line=physical.get("region", {}).get("startLine", 0),
        message=message,
        framework=framework,
        help_uri=help_uri,
    )


def parse_sarif(
    sarif_path: Path,
    project: str,
    env: str,
    framework: str,
    mapping_pack: dict | None = None,
) -> list[Finding]:
    """Read a SARIF and yield Finding objects.

    SARIF 2.1.0 results MAY carry an integer ``ruleIndex`` that
    indexes into ``runs[].tool.driver.rules[]``. Older tools (Checkov
    3.3.x, Bridgecrew) emit only ``ruleId`` strings -- we accept
    either, but prefer the index key when both are present.

    Joining on string ``ruleId`` (the legacy approach pre-commit-11)
    is lossy when two distinct rule entries share the same ``id``
    but differ on ``helpUri``, ``precision``, or ``properties``. The
    integer ``ruleIndex`` join resolves each result against the
    exact rule entry the SARIF producer attached.

    The rendered per-finding ``helpUri`` is propagated to
    combined.sarif via ``write_combined_sarif`` (see also the
    SARIF rewriter at scanner/rewrite_sarif_help.py).

    ``mapping_pack`` is the parsed mapping YAML (the ``mapping_data``
    dict ``main()`` loads). When supplied, per-check severity
    overrides are read from ``mapping_pack["severity_overrides"]``.
    When ``None`` (the default for back-compat with existing call
    sites), ``resolve_severity`` falls back to the install-bundled
    PCI pack so the behavior matches the pre-extraction code path.
    """
    data = _read_sarif(sarif_path)
    if data is None:
        return []
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rule_index_map, rule_id_map = _build_rule_indices(run)
        for result in run.get("results", []):
            findings.append(
                _result_to_finding(
                    result,
                    project,
                    env,
                    framework,
                    mapping_pack,
                    rule_index_map,
                    rule_id_map,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Mapping + baseline loading (generic, framework-agnostic)
# ---------------------------------------------------------------------------
# Pre-T7 the loaders were named ``load_pci_mapping`` and
# ``load_pci_baseline``. The names are kept as thin deprecated aliases
# at the bottom of this block so external callers (CLI tools, tests,
# CI scripts) continue to work. The new generic names are the source
# of truth.
def load_mapping(path: Path) -> dict[str, list[str]]:
    """Return {check_id: [req_id, ...]} from a mapping pack's ``requirements``."""
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for req in data.get("requirements", []):
        for cid in req.get("checks", []):
            out.setdefault(cid, []).append(req["id"])
    return out


def load_baseline(path: Path) -> list[dict]:
    """Return list of suppression entries from a baseline YAML."""
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("suppressions", []) or []


# Deprecated thin aliases kept for backward compatibility with external
# callers that import the PCI-prefixed names. These MUST NOT be re-
# implemented; they only delegate to the generic implementations above.
load_pci_mapping = load_mapping
load_pci_baseline = load_baseline


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
#
# Framework gating (T8): the YAML is azurerm 4.x Terraform-specific. For
# non-Terraform-family frameworks (cloudformation, kubernetes, bicep,
# arm, secrets, ...), is_terraform_family() returns False and we return
# {} early so no azurerm-specific guidance leaks into a CFN/K8s/etc.
# report. The constant REMEDIATION_YAML_PATH stays declared so the
# diagnostic path remains intact; only its loading is gated.
REMEDIATION_YAML_PATH = Path(__file__).resolve().parent / "terraform_remediation.yaml"


def load_remediation_map(
    yaml_path: Path | None = None,
    *,
    framework: str = "terraform",
) -> dict[str, list[dict]]:
    """Build {check_id: [remediation_block, ...]} from terraform_remediation.yaml.

    Gated by framework family: when ``framework`` is not in the
    terraform family (``is_terraform_family(framework) is False``),
    returns ``{}`` immediately and does NOT touch the YAML. The
    terraform_remediation.yaml artifact is azurerm 4.x-specific and has
    no analog for cloudformation/kubernetes/bicep/etc., so loading it
    for those frameworks would emit incorrect remediation guidance.

    Returns an empty dict if the YAML is missing or malformed; warns to
    stderr in either case so the operator knows the Remediation render
    is suppressed for this run.

    ``yaml_path`` is keyword-positional (kept for backward compatibility
    with existing positional callers); ``framework`` is keyword-only and
    defaults to ``"terraform"`` so legacy call sites that omit it
    continue to receive the azurerm remediation map unchanged.
    """
    # Single function, gated at the top. No parallel implementation.
    if not is_terraform_family(framework):
        return {}
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


def attach_reqs(findings: list[Finding], mapping: dict[str, list[str]]) -> None:
    """Mutate findings in place: populate ``requirements`` from the mapping."""
    for f in findings:
        f.requirements = mapping.get(f.check_id, [])


# Deprecated thin alias for backward compatibility with external callers.
attach_pci_reqs = attach_reqs


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
    # NOTE_TOKENS: prefix allow-list (formerly hardcoded
    # ``CKV_AZURE_PCI_NOTE_*``) is now driven by the mapping pack so
    # SOC 2 / CIS / NIST packs can reuse the same convention. The
    # empty default is fine — a pack without ``note_tokens`` simply
    # has no symbolic placeholders to filter.
    note_tokens = _resolve_note_tokens(pci_mapping_data)

    # Validate out-of-scope entries up-front.
    from datetime import date as _date

    today_iso = _date.today().isoformat()
    oos_errors, enriched_out_of_scope = validate_out_of_scope_entries(
        out_of_scope_raw, today_iso=today_iso
    )
    oos_ids = [e["id"] for e in enriched_out_of_scope]

    # Out-of-scope rows are emitted AFTER in-scope rows in the coverage matrix.
    req_ids = [r["id"] for r in requirements] + oos_ids

    # Universe of checks mapped per in-scope req (from the mapping pack),
    # independent of whether they fired. Used for coverage gaps.
    # Note tokens (PACIOLI_NOTE_*) are NOT included here: they are
    # symbolic placeholders that the mapping author uses to flag a req
    # with no working Checkov coverage (see NOTE_TOKENS docstring). They
    # are filtered out so `expected_count` and `missing_count` in
    # coverage_gaps.csv stay zero for note-only reqs, which is the
    # documented semantics in the plan.
    expected_by_req: dict[str, set[str]] = {
        r["id"]: {c for c in r.get("checks", []) if c not in note_tokens}
        for r in requirements
    }
    # Per-req note text (only populated when a note token is present).
    # Used by write_coverage_gaps_csv to render the note as triage_hint
    # so the auditor sees the rationale instead of a generic
    # "1 check expected, 0 fired" hint.
    note_by_req: dict[str, str] = {  # noqa: F841  (dead-code, kept for parity with downstream consumers)
        r["id"]: r["note"]
        for r in requirements
        if any(c in note_tokens for c in r.get("checks", []))
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

    NOTE_TOKENS integration (see NOTE_TOKENS docstring): a req whose
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
            # Note-token req (see NOTE_TOKENS docstring): expected/fired/missing
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
    """Emit coverage_gaps.csv: one row per in-scope req.

    Columns (generic, framework-agnostic):
      requirement          requirement id from the mapping pack
      title                requirement title (for human triage context)
      expected_count       count of check_ids mapped to this req
      fired_count          count that appeared in any SARIF
      missing_count        expected - fired
      missing_check_ids    space-separated missing IDs (the triage list)
      triage_hint          suggested next step depending on the pattern
      librarian_verified_at when the per-row librarian probe ran
                           (pack's librarian_verified_at key)
      doc_anchor_url       URL the librarian fetched (pack's
                           doc_anchor top-level key)
      evidence_byte_size   HTTP response body bytes observed
      evidence_content_type HTTP response Content-Type
      link_pass            "True" if fingerprint match; "False" otherwise

    Triage hint heuristic:
      - 1 missing + 1 expected + 0 fired     → likely stale check id (verify with
                                              `checkov --list | grep <id>`)
      - N missing where N > 1 + 0 fired     → check ids possibly stale, OR the
                                              env has no resource of that type
      - some fired, some missing            → mixed; investigate each missing id

    Audit-traceability columns (librarian_verified_at, doc_anchor_url,
    evidence_byte_size, evidence_content_type, link_pass) are emitted
    on EVERY row so the CSV is a self-contained reproducibility record.
    The metadata is read from the mapping pack via
    ``_resolve_librarian_metadata`` so SOC 2 / CIS / NIST packs each
    carry their own anchor evidence.
    """
    title_by_req = {
        r["id"]: r.get("title", "")
        for r in pci_mapping_data.get("requirements", [])
    }
    librarian_at, anchor = _resolve_librarian_metadata(pci_mapping_data)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "requirement",
                "title",
                "expected_count",
                "fired_count",
                "missing_count",
                "missing_check_ids",
                "triage_hint",
                "librarian_verified_at",
                "doc_anchor_url",
                "evidence_byte_size",
                "evidence_content_type",
                "link_pass",
            ]
        )
        for r in gap_records:
            fired = r["fired_count"]
            expected = r["expected_count"]
            missing = r["missing_count"]
            # Note-token req (see NOTE_TOKENS docstring): the caller passed
            # a precomputed `triage_hint` carrying the mapping pack's
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
                    librarian_at,
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
    pci_mapping_data: dict | None = None,
) -> None:
    """Write the per-(req, check) coverage matrix.

    For each out-of-scope row, emits the full audit metadata in a
    side-table so the CSV is a sufficient evidence record by itself.
    Columns for in-scope rows remain:
        requirement, check_id, status

    For in-scope rows, when ``expected_by_req`` and ``fired_check_ids``
    are passed, an additional column ``missing_for_req`` is populated
    on the FIRST row of each req with the space-separated list of
    check_ids MAPPED to that req but not appearing in any SARIF.
    Subsequent rows in that req have the column blank to avoid
    repetition.

    Out-of-scope rows are emitted with:
        requirement=*, status="out_of_scope",
        control_owner, rationale, approved_on, expires_on,
        evidence_link, stale, days_to_expiry

    ``pci_mapping_data`` is the parsed mapping pack -- the chain-of-
    custody ledger is read from ``mapping_pack["chain_of_custody"]``
    so SOC 2 / CIS / NIST packs can carry their own per-requirement
    verification metadata. Backward compat: when omitted, the chain
    of custody column is empty for every row.
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
    chain_of_custody = _resolve_chain_of_custody(pci_mapping_data)

    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        # Two header rows in two sections is tricky in CSV; instead we
        # emit one wide column list. Operators who want the in-scope
        # matrix can filter by status.
        w.writerow(
            [
                "requirement",
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
                # chain_of_custody_complete records whether the
                # source URL in the mapping pack was live-verified at
                # the recorded librarian_verified_at. Empty for OOS
                # rows (no doc_anchor slot).
                "chain_of_custody_complete",
            ]
        )
        for rid in req_ids:
            # chain_of_custody_complete is a per-requirement attribute
            # (declared in the mapping pack's ``chain_of_custody`` key
            # under the pack's ``librarian_verified_at`` timestamp).
            # Empty for any req whose doc_anchor slot could not be
            # live-verified at the recorded timestamp; "True" otherwise.
            chain_custody_val = chain_of_custody.get(rid, "")
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
                        chain_custody_val,
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
                            chain_custody_val,
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
    # changes. The pass-name → SARIF-path mapping lives on each
    # EnvResultFull.sarif_files; the writer iterates THAT, not the
    # dataclass fields, so non-Terraform frameworks automatically
    # contribute the SARIFs they actually wrote.
    sarif_iter_order = ("plan", "source", "paac", "secrets", "state")
    for er in env_results:
        for pass_name in sarif_iter_order:
            sarif_path = er.sarif_files.get(pass_name)
            if sarif_path is None or not sarif_path.exists():
                continue
            try:
                data = json.loads(sarif_path.read_text(encoding="utf-8"))
                for r in data.get("runs", []):
                    # Tag the run with env/project for downstream tooling.
                    # Names are imported from scanner.frameworks so the
                    # contract is defined ONCE (single source of truth)
                    # and shared with baseline_init._collect_stub_pairs
                    # plus any other downstream consumer.
                    if "properties" not in r:
                        r["properties"] = {}
                    r["properties"][SARIF_PROPERTY_PROJECT] = er.project
                    r["properties"][SARIF_PROPERTY_ENV] = er.env
                    r["properties"][SARIF_PROPERTY_SOURCE_SARIF] = Path(sarif_path).name
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
        "<p class=\"inline-muted\"><em>"
        "Drift is the difference between the planned resource shape "
        "(source .tf + terraform plan) and the live Azure state "
        "(.tfstate pulled from Azure Storage). Investigate every drift "
        "finding before re-running <code>terraform apply</code> &mdash; "
        "it may indicate manual changes that need to be either codified "
        "in source or reverted to match the plan."
        "</em></p>\n"
        "<table>\n"
        "  <tr><th>Resource</th><th>File:Line</th><th>Attribute</th>"
        "<th>Drift Type</th><th>Source &rarr; State</th><th>Severity</th></tr>\n"
        + "\n".join(rows)
        + "\n</table>\n"
    )


def _environment_display_label(project: str, env: str, stack_label: str | None) -> str:
    """Return the canonical human label for one environment identity."""
    label = f"{project}/{env}"
    return f"{label} [{stack_label}]" if stack_label else label


def _count_findings_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Return unsuppressed finding counts grouped for report presentation."""
    return {
        "high_critical": sum(
            not finding.suppressed and finding.severity in ("HIGH", "CRITICAL")
            for finding in findings
        ),
        "medium": sum(
            not finding.suppressed and finding.severity == "MEDIUM"
            for finding in findings
        ),
        "low": sum(
            not finding.suppressed and finding.severity == "LOW"
            for finding in findings
        ),
    }


def _should_upgrade_resource_severity(current: str, prior: str) -> bool:
    """Return True if the current finding's severity should override the prior severity."""
    if current == "CRITICAL":
        return True
    if current == "HIGH" and prior != "CRITICAL":
        return True
    if current == "MEDIUM" and prior == "LOW":
        return True
    return False


def _build_environment_block(result: EnvResult) -> dict:
    """Build the report-model block for one scanned environment."""
    identity = {
        "project": result.project,
        "env": result.env,
        "stack_label": result.stack_label,
        "display_label": _environment_display_label(
            result.project, result.env, result.stack_label
        ),
    }
    environment_findings = [
        {
            "identity_label": identity["display_label"],
            "project": finding.project,
            "env": finding.env,
            "stack_label": result.stack_label,
            "check_id": finding.check_id,
            "severity": finding.severity,
            "resource": finding.resource,
            "file_path": finding.file_path,
            "line": finding.line,
            "message": finding.message,
            "framework": finding.framework,
            "requirements": finding.requirements,
            "suppressed": finding.suppressed,
            "help_uri": finding.help_uri,
        }
        for finding in result.findings
    ]
    severity_counts = _count_findings_by_severity(result.findings)
    return {
        "identity": identity,
        "scan_status": result.scan_status,
        "error": result.error,
        "findings": environment_findings,
        "counts": {
            "total": len(result.findings),
            "high": severity_counts["high_critical"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
        },
    }


def _build_top_lists(findings: list[Finding]) -> tuple[list[dict], list[dict]]:
    """Build sorted resource and rule frequency lists from unsuppressed findings."""
    resource_counts: dict[str, int] = {}
    resource_severity: dict[str, str] = {}
    rule_counts: dict[str, int] = {}
    for finding in findings:
        if finding.resource and not finding.suppressed:
            resource_counts[finding.resource] = resource_counts.get(finding.resource, 0) + 1
            resource_severity.setdefault(finding.resource, "LOW")
            prior_severity = resource_severity[finding.resource]
            if _should_upgrade_resource_severity(finding.severity, prior_severity):
                resource_severity[finding.resource] = finding.severity
        if not finding.suppressed:
            rule_counts[finding.check_id] = rule_counts.get(finding.check_id, 0) + 1
    top_resources = [
        {"resource": resource, "count": count, "severity": resource_severity[resource]}
        for resource, count in sorted(resource_counts.items(), key=lambda item: (-item[1], item[0]))[:15]
    ]
    top_rules = [
        {"check_id": check_id, "count": count}
        for check_id, count in sorted(rule_counts.items(), key=lambda item: (-item[1], item[0]))[:15]
    ]
    return top_resources, top_rules


def _build_report_model(
    env_results: list[EnvResult],
    mapping_data: dict,
    cells: dict,
    out_of_scope: list[dict],
    suppressed_count: int,
    gaps: CoverageGaps,
    drift_findings: list[dict],
    framework_name: str,
    framework_version: str,
) -> dict:
    """Build the complete immutable input contract for browser projections."""
    raw_findings = [
        finding for result in env_results for finding in result.findings
    ]
    environments = [_build_environment_block(result) for result in env_results]
    findings = [
        finding for environment in environments for finding in environment["findings"]
    ]
    top_resources, top_rules = _build_top_lists(raw_findings)
    return {
        "schema_version": 1,
        "framework": {"name": framework_name, "version": framework_version},
        "counts": {
            "total_findings": len(raw_findings),
            **_count_findings_by_severity(raw_findings),
            "suppressed": suppressed_count,
            "environment_count": len(env_results),
        },
        "environments": environments,
        "findings": findings,
        "top_lists": {"resources": top_resources, "rules": top_rules},
        "requirements": mapping_data.get("requirements", []),
        "requirement_mappings": {
            requirement["id"]: requirement.get("checks", [])
            for requirement in mapping_data.get("requirements", [])
            if requirement.get("id")
        },
        "coverage_cells": [
            {"requirement": requirement, "check_id": check_id, "status": status}
            for (requirement, check_id), status in sorted(cells.items())
        ],
        "coverage_gaps": gaps.records,
        "out_of_scope_requirements": out_of_scope,
        "drift_findings": drift_findings,
        "baseline": {"suppressed_count": suppressed_count},
    }


def _severity_css_class(severity: str) -> str:
    """Return the CSS severity modifier used by dashboard count pills."""
    if severity in ("HIGH", "CRITICAL"):
        return "high"
    if severity == "MEDIUM":
        return "medium"
    return ""


def _serialize_report_model(model: dict) -> str:
    """Serialize the inert report model without HTML parsing ambiguity."""
    return (
        json.dumps(model, ensure_ascii=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def write_html_report(
    out: Path,
    env_results: list[EnvResult],
    pci_mapping_path: Path,
    mapping_data: dict,
    cells: dict,
    out_of_scope: list[dict],
    suppressed_count: int,
    gaps: CoverageGaps | None = None,
    remediation_by_check_id: dict[str, list[dict]] | None = None,
    drift_findings: list[dict] | None = None,
    framework_name: str | None = None,
    framework_version: str | None = None,
    remediation_framework_label: str = "terraform",
) -> None:
    """Render a single-page HTML report with degraded-mode banner.

    Out-of-scope rows render with the FULL audit metadata (rationale,
    control_owner, approved_on, expires_on, evidence_link).
    Stale exclusions (expires_on < today) get a STALE badge so the
    auditor can immediately see which need re-approval.

    The optional `remediation_by_check_id` map adds
    the canonical azurerm 4.x fix block inline below the chain-of-custody
    badge for every finding. When empty (YAML missing OR the run's
    framework is not in the terraform family per
    :func:`load_remediation_map`), the report still renders cleanly --
    the per-finding remediation block is skipped. The
    ``remediation_framework_label`` kwarg carries the framework label
    forwarded from the call site (already in scope -- NOT re-derived
    here) so the empty-state stub can name it accurately.

    `framework_name` and `framework_version` are read from the mapping YAML
    if not supplied. Falls back to ("PCI DSS", "4.0.1") for backward
    compatibility with the original PCI-only deployment.

    The optional `drift_findings` list (tier 3 only)
    is rendered as a Drift Findings table before "Findings by Environment".
    Pass [] (or None) for tier 1/2 runs to silently skip the section.

    `gaps` collapses the legacy ``missing_per_req`` + ``gap_records``
    pair into a single :class:`CoverageGaps` instance. Pass ``None``
    (or leave unset) when no coverage-gap data is available -- the
    report renders cleanly without the per-row tooltip and the
    "Coverage gaps" section.
    """
    if gaps is None:
        gaps = CoverageGaps()
    if remediation_by_check_id is None:
        remediation_by_check_id = {}
    if drift_findings is None:
        drift_findings = []
    failed_envs = [er for er in env_results if er.scan_status != "ok"]
    # Per-req URL lookups .
    # The framework (PCI v4.0.1, SOC 2, ...) may have a single shared
    # anchor across all in-scope requirements (PCI SSC's
    # v3.2.1->v4.0 Summary-of-Changes PDF returning HEAD 200 /
    # application/pdf / 477973 bytes on 2026-08-04) OR a per-req
    # anchor. The URL is stored at the TOP level of the mapping pack
    # as ``doc_anchor`` -- there is no per-requirement doc_anchor_url
    # field. We populate source_url_by_req with that anchor for every
    # req id so the per-finding renderer can resolve the right URL in
    # O(1). The chain-of-custody lookup (the render relies on this
    # too) is read-only here so both renders share one dict build.
    pci_anchor = str(mapping_data.get("doc_anchor", "") or "")
    source_url_by_req: dict[str, str] = {}
    approach_by_req: dict[str, str] = {}
    chain_of_custody_by_req: dict[str, str] = {}
    # Resolve chain-of-custody ONCE from the pack so per-finding render
    # and the per-row CSV writer share the same lookup.
    chain_of_custody_table = _resolve_chain_of_custody(mapping_data)
    for _r in mapping_data.get("requirements", []):
        _rid = _r.get("id", "")
        if not _rid:
            continue
        source_url_by_req[_rid] = pci_anchor
        approach_by_req[_rid] = str(_r.get("approach", "") or "")
        chain_of_custody_by_req[_rid] = chain_of_custody_table.get(_rid, "")
    # Pre-resolve librarian metadata once (the per-finding chain-of-custody
    # block reads the display string for the verified-at timestamp).
    librarian_at, _librarian_fingerprint = _resolve_librarian_metadata(mapping_data)
    # Note-token allow-list (driven by the mapping pack). Same lookup
    # as build_coverage_matrix so the heatmap + per-row filter agree
    # on what counts as a "note req".
    note_tokens_html = _resolve_note_tokens(mapping_data)

    # Resolve framework name + version from mapping YAML. Supports any
    # framework (PCI DSS, SOC 2, CIS Azure, NIST 800-53, ISO 27001, ...)
    # via the `framework_name` and `framework_version` top-level keys in
    # the mapping file. Falls back to PCI DSS v4.0.1 for backward compat.
    if framework_name is None:
        framework_name = mapping_data.get("framework_name", "PCI DSS")
    if framework_version is None:
        framework_version = mapping_data.get("framework_version") or mapping_data.get("pci_dss_version", "4.0.1")
    framework_full = f"{framework_name} v{framework_version}"
    report_model = _build_report_model(
        env_results,
        mapping_data,
        cells,
        out_of_scope,
        suppressed_count,
        gaps,
        drift_findings,
        framework_name,
        framework_version,
    )
    report_model_json = _serialize_report_model(report_model)
    total_findings = report_model["counts"]["total_findings"]
    high_critical = report_model["counts"]["high_critical"]
    medium = report_model["counts"]["medium"]
    low = report_model["counts"]["low"]

    banner = ""
    if failed_envs:
        envs_str = ", ".join(
            _environment_display_label(er.project, er.env, er.stack_label)
            for er in failed_envs
        )
        banner = (
            f'<div class="banner-error">'
            f"RED BANNER: state-pull failed for {envs_str}. "
            f"Reports below are based on source-only scan; do not rely on PCI "
            f"compliance claims until re-scan succeeds."
            f"</div>"
        )

    # CSS is held as a plain string (NOT inside an f-string) because Python
    # 3.12+ parses `{...}` greedily inside f-strings -- and CSS has braces.
    CSS_STYLE = """\
  /* ===== Pacioli report -- semantic token contract ===== */
  :root, [data-theme="dark"] {
    color-scheme: dark;
    --color-bg: #121820;
    --color-surface: #1b2532;
    --color-surface-subtle: #253142;
    --color-surface-raised: #202c3b;
    --color-fg: #f3f7fb;
    --color-fg-muted: #b6c2d1;
    --color-nav-bg: #101b2d;
    --color-nav-surface: #172a43;
    --color-nav-fg: #e7f0fb;
    --color-nav-muted: #b8c9dd;
    --color-border: #38475a;
    --color-border-subtle: #2b3849;
    --color-accent: #79b8ff;
    --color-accent-surface: #17395f;
    --color-danger: #ff8a8a;
    --color-danger-surface: #54272f;
    --color-warning: #ffd08a;
    --color-warning-surface: #564222;
    --color-neutral: #bdc7d4;
    --color-success: #86d7a2;
    --color-success-surface: #1d4932;
    --color-code-bg: #0e1724;
    --color-code-fg: #d5ebff;
    --color-focus: #9ecbff;
    --color-shadow: rgba(0, 0, 0, 0.28);
    --color-nav-divider: rgba(231, 240, 251, 0.16);
    --color-nav-hover: rgba(231, 240, 251, 0.08);
    --color-nav-active: rgba(231, 240, 251, 0.16);
    --color-nav-field: rgba(231, 240, 251, 0.1);
    --color-nav-field-hover: rgba(231, 240, 251, 0.2);
    --color-surface-shadow: rgba(0, 0, 0, 0.28);
  }
  [data-theme="light"] {
    color-scheme: light;
    --color-bg: #f5f7fb;
    --color-surface: #ffffff;
    --color-surface-subtle: #eef2f8;
    --color-surface-raised: #fafcff;
    --color-fg: #172033;
    --color-fg-muted: #536276;
    --color-nav-bg: #0a2648;
    --color-nav-surface: #0d3560;
    --color-nav-fg: #eef6ff;
    --color-nav-muted: #c7d8ea;
    --color-border: #ccd5e1;
    --color-border-subtle: #e2e8f0;
    --color-accent: #075cc4;
    --color-accent-surface: #e6f1ff;
    --color-danger: #b42318;
    --color-danger-surface: #fff0f0;
    --color-warning: #9a5d00;
    --color-warning-surface: #fff7e6;
    --color-neutral: #66758a;
    --color-success: #187a3d;
    --color-success-surface: #e9f8ee;
    --color-code-bg: #10223a;
    --color-code-fg: #d5ebff;
    --color-focus: #005fcc;
    --color-shadow: rgba(31, 48, 70, 0.12);
    --color-nav-divider: rgba(238, 246, 255, 0.2);
    --color-nav-hover: rgba(238, 246, 255, 0.12);
    --color-nav-active: rgba(238, 246, 255, 0.2);
    --color-nav-field: rgba(238, 246, 255, 0.12);
    --color-nav-field-hover: rgba(238, 246, 255, 0.24);
    --color-surface-shadow: rgba(31, 48, 70, 0.12);
  }
  [data-theme="system"] { color-scheme: dark light; }
  @media (prefers-color-scheme: light) {
    [data-theme="system"] {
      --color-bg: #f5f7fb; --color-surface: #ffffff; --color-surface-subtle: #eef2f8;
      --color-surface-raised: #fafcff; --color-fg: #172033; --color-fg-muted: #536276;
      --color-nav-bg: #0a2648; --color-nav-surface: #0d3560; --color-nav-fg: #eef6ff;
      --color-nav-muted: #c7d8ea; --color-border: #ccd5e1; --color-border-subtle: #e2e8f0;
      --color-accent: #075cc4; --color-accent-surface: #e6f1ff; --color-danger: #b42318;
      --color-danger-surface: #fff0f0; --color-warning: #9a5d00; --color-warning-surface: #fff7e6;
      --color-neutral: #66758a; --color-success: #187a3d; --color-success-surface: #e9f8ee;
      --color-code-bg: #10223a; --color-code-fg: #d5ebff; --color-focus: #005fcc;
      --color-shadow: rgba(31, 48, 70, 0.12); --color-nav-divider: rgba(238, 246, 255, 0.2);
      --color-nav-hover: rgba(238, 246, 255, 0.12); --color-nav-active: rgba(238, 246, 255, 0.2);
      --color-nav-field: rgba(238, 246, 255, 0.12); --color-nav-field-hover: rgba(238, 246, 255, 0.24);
      --color-surface-shadow: rgba(31, 48, 70, 0.12);
    }
  }
  *, *::before, *::after { box-sizing: border-box; }
  :focus-visible { outline: 3px solid var(--color-focus); outline-offset: 3px; }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; scroll-behavior: auto !important; transition-duration: 0.01ms !important; }
  }
  /* ===== Report layout and components ===== */
  html, body { margin: 0; min-height: 100%; padding: 0; }
  body { background: var(--color-bg); color: var(--color-fg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif; font-size: 14px; line-height: 1.5; }
  a { color: var(--color-accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code { background: var(--color-surface-subtle); border-radius: 3px; font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 0.92em; padding: 0 var(--space-1, 4px); }
  h1, h2, h3, h4 { color: var(--color-fg); font-weight: 600; margin: 0 0 0.5em; }
  h1 { font-size: 1.8em; } h2 { border-bottom: 2px solid var(--color-accent); font-size: 1.4em; padding-bottom: 0.3em; } h3 { color: var(--color-accent); font-size: 1.15em; margin-top: 1.5em; } h4 { font-size: 1em; margin-top: 1em; }
  table { border-collapse: collapse; margin: 1em 0; width: 100%; }
  th, td { border: 1px solid var(--color-border); padding: 6px 10px; text-align: left; } th { background: var(--color-surface-subtle); }
  #app { display: grid; grid-template-columns: 240px minmax(0, 1fr); min-height: 100dvh; }
  #sidebar { background: var(--color-nav-bg); color: var(--color-nav-fg); height: 100dvh; overflow-y: auto; padding: 0; position: sticky; top: 0; }
  .sidebar-brand { border-bottom: 1px solid var(--color-nav-divider); padding: 1.4em 1.2em; }
  .sidebar-brand h1 { color: var(--color-nav-fg); font-size: 1.3em; line-height: 1.1; margin: 0; }
  .sidebar-brand .subtitle, .sidebar-footer { color: var(--color-nav-muted); font-size: 0.78em; line-height: 1.4; }
  .sidebar-brand .subtitle { margin-top: 4px; } .sidebar-footer { border-top: 1px solid var(--color-nav-divider); padding: 1em 1.2em; }
  nav.sidebar-nav { padding: 0.6em 0; } nav.sidebar-nav a { align-items: center; border-left: 3px solid transparent; color: var(--color-nav-fg); display: flex; font-weight: 500; gap: 10px; padding: 0.7em 1.2em; transition: background-color 120ms ease-out, color 120ms ease-out, border-color 120ms ease-out; }
  nav.sidebar-nav a:hover { background: var(--color-nav-hover); color: var(--color-nav-fg); text-decoration: none; } nav.sidebar-nav a.active { background: var(--color-nav-active); border-left-color: var(--color-accent); }
  nav.sidebar-nav a .icon { display: inline-block; font-size: 1.05em; text-align: center; width: 18px; } nav.sidebar-nav a .badge { background: var(--color-danger); border-radius: 10px; color: var(--color-nav-bg); font-size: 0.7em; font-weight: 700; margin-left: auto; padding: 1px 7px; } nav.sidebar-nav a .badge.ok { background: var(--color-success); } nav.sidebar-nav a .badge.warn { background: var(--color-warning); }
  #main { min-width: 0; overflow-x: auto; padding: 1.4em 2em 4em; } .route { display: none; } .route.active { display: block; } .route-header { align-items: flex-end; border-bottom: 1px solid var(--color-border); display: flex; justify-content: space-between; margin-bottom: 1.4em; padding-bottom: 1em; } .route-header h1 { margin: 0; } .route-header .meta { color: var(--color-fg-muted); font-size: 0.85em; line-height: 1.5; text-align: right; }
  .kpi-grid { display: grid; gap: 1em; grid-template-columns: repeat(auto-fit, minmax(min(200px, 100%), 1fr)); margin: 1em 0 1.4em; } .kpi, .top-list, .panel { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 6px; box-shadow: 0 1px 3px var(--color-surface-shadow); padding: 1em 1.2em; } .kpi { overflow: hidden; position: relative; } .kpi::before { background: var(--color-accent); bottom: 0; content: ""; left: 0; position: absolute; top: 0; width: 4px; } .kpi.kpi-high::before { background: var(--color-danger); } .kpi.kpi-medium::before { background: var(--color-warning); } .kpi.kpi-low::before { background: var(--color-neutral); } .kpi.kpi-ok::before { background: var(--color-success); } .kpi-label, .kpi-sub { color: var(--color-fg-muted); } .kpi-label { font-size: 0.78em; letter-spacing: 0.06em; margin-bottom: 6px; text-transform: uppercase; } .kpi-value { color: var(--color-fg); font-size: 2.2em; font-weight: 700; line-height: 1; } .kpi-sub { font-size: 0.85em; margin-top: 6px; }
  .donut-wrap { align-items: center; display: flex; gap: 1.4em; margin: 1em 0; } .donut-legend { display: flex; flex-direction: column; gap: 0.5em; } .donut-legend-row { align-items: center; display: flex; font-size: 0.9em; gap: 0.6em; } .donut-legend-swatch { border-radius: 3px; height: 14px; width: 14px; } .swatch-high { background: var(--color-danger); } .swatch-medium { background: var(--color-warning); } .swatch-low { background: var(--color-neutral); } .swatch-ok { background: var(--color-success); }
  .env-bar-row { align-items: center; background: var(--color-surface); border: 1px solid var(--color-border-subtle); border-radius: 4px; display: flex; gap: 0.8em; margin: 0.4em 0; padding: 0.4em 0.6em; } .env-bar-name { font-size: 0.92em; font-weight: 600; width: 260px; } .env-bar-track { background: var(--color-surface-subtle); border-radius: 3px; display: flex; flex: 1; height: 22px; overflow: hidden; } .env-bar-segment { height: 100%; } .env-bar-segment.high { background: var(--color-danger); } .env-bar-segment.medium { background: var(--color-warning); } .env-bar-segment.low { background: var(--color-neutral); } .env-bar-count { font-size: 0.9em; font-weight: 600; text-align: right; width: 80px; }
  .top-list { margin: 0.6em 0; padding: 0.8em 1em; } .top-list h3 { font-size: 1em; margin: 0 0 0.6em; } .top-list-row { border-bottom: 1px solid var(--color-border-subtle); display: flex; font-size: 0.9em; justify-content: space-between; padding: 0.3em 0; } .top-list-row:last-child { border-bottom: 0; } .count-pill { background: var(--color-surface-subtle); border-radius: 10px; font-weight: 600; padding: 1px 8px; } .count-pill.high { background: var(--color-danger-surface); color: var(--color-danger); } .count-pill.medium { background: var(--color-warning-surface); color: var(--color-warning); }
  .two-col { display: grid; gap: 1.4em; grid-template-columns: 1fr 1fr; margin: 1em 0; } .panel h3 { margin-top: 0; } .finding, .finding-body { background: var(--color-surface-raised); border-left: 4px solid var(--color-neutral); border-radius: 0 4px 4px 0; margin: 0.5em 0; padding: 0.8em 1em; } .finding.HIGH, .finding.CRITICAL, .finding-body.HIGH, .finding-body.CRITICAL { background: var(--color-danger-surface); border-left-color: var(--color-danger); } .finding.MEDIUM, .finding-body.MEDIUM { background: var(--color-warning-surface); border-left-color: var(--color-warning); } .suppressed { opacity: 0.5; text-decoration: line-through; } .req-coverage { color: var(--color-fg-muted); font-size: 0.9em; }
  #filter-ui { align-items: center; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 6px; box-shadow: 0 1px 3px var(--color-surface-shadow); display: flex; flex-wrap: wrap; gap: 8px; margin: 1em 0; padding: 12px; position: sticky; top: 0; z-index: 10; } #filter-ui input[type="search"], #filter-ui select, #theme-select { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 4px; color: var(--color-fg); padding: 6px 10px; } #filter-ui input[type="search"] { width: 240px; } button { font: inherit; } #filter-ui button { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 4px; color: var(--color-fg); cursor: pointer; font-weight: 500; padding: 6px 12px; transition: background-color 120ms ease-out, color 120ms ease-out, border-color 120ms ease-out, transform 120ms ease-out; } #filter-ui button:hover { background: var(--color-surface-raised); } #filter-ui button:active { transform: translateY(1px); } #filter-ui button.active { background: var(--color-accent); border-color: var(--color-accent); color: var(--color-bg); } #finding-count { color: var(--color-accent); font-size: 0.95em; font-weight: 700; margin-left: auto; }
  .count-high { color: var(--color-danger); font-weight: 700; } .count-medium { color: var(--color-warning); font-weight: 600; } .count-low { color: var(--color-neutral); } .badge-row { border-radius: 12px; display: inline-block; font-size: 0.78em; font-weight: 600; padding: 2px 8px; } .badge-row.NON-COMPLIANT, .badge-row.STALE { background: var(--color-danger-surface); color: var(--color-danger); } .badge-row.NOT-SCANNED { background: var(--color-surface-subtle); color: var(--color-fg-muted); } .badge-row.COMPLIANT { background: var(--color-success-surface); color: var(--color-success); } .badge-row.OUT-OF-SCOPE { background: var(--color-accent-surface); color: var(--color-accent); } .badge-row.NO-MATCHING-RESOURCES { background: var(--color-warning-surface); color: var(--color-warning); }
  .heatmap { display: grid; gap: 6px; grid-template-columns: repeat(auto-fill, minmax(min(110px, 100%), 1fr)); margin: 1em 0; } .heatmap-cell { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 4px; cursor: pointer; font-size: 0.85em; padding: 8px 10px; text-align: center; transition: transform 100ms ease-out, box-shadow 100ms ease-out, border-color 100ms ease-out; } .heatmap-cell:hover { border-color: var(--color-accent); box-shadow: 0 4px 8px var(--color-shadow); transform: translateY(-2px); } .heatmap-cell .req-id { color: var(--color-accent); font-weight: 700; } .heatmap-cell .req-count { color: var(--color-fg-muted); font-size: 0.75em; margin-top: 4px; } .heatmap-cell.kpi-high { background: var(--color-danger-surface); border-color: var(--color-danger); } .heatmap-cell.kpi-high .req-id { color: var(--color-danger); } .heatmap-cell.kpi-ok { background: var(--color-success-surface); border-color: var(--color-success); } .heatmap-cell.kpi-ok .req-id { color: var(--color-success); } .heatmap-cell.kpi-medium, .heatmap-cell.kpi-warn { background: var(--color-warning-surface); border-color: var(--color-warning); } .heatmap-cell.filtered { background: var(--color-accent-surface); border-color: var(--color-accent); box-shadow: 0 0 0 3px var(--color-accent), 0 4px 12px var(--color-shadow); transform: translateY(-2px); } .heatmap-cell.filtered .req-id { color: var(--color-accent); } .heatmap-cell.dimmed { opacity: 0.25; } .heatmap-cell.dimmed:hover { opacity: 0.6; }
  .remediation { background: var(--color-accent-surface); border: 1px solid var(--color-accent); border-radius: 4px; margin: 8px 0; padding: 8px 12px; } .remediation h4 { color: var(--color-accent); font-size: 0.95em; margin: 0 0 6px; } .remediation-hcl { background: var(--color-code-bg); border-radius: 4px; color: var(--color-code-fg); font-size: 0.85em; line-height: 1.5; overflow-x: auto; padding: 12px; white-space: pre; } .chain-of-custody { background: var(--color-surface-subtle); border-left: 3px solid var(--color-accent); border-radius: 0 3px 3px 0; color: var(--color-fg-muted); font-size: 0.85em; margin: 4px 0; padding: 4px 8px; } .coc-true { color: var(--color-success); font-weight: 600; } .coc-partial { color: var(--color-warning); font-weight: 600; }
  .banner-error { background: var(--color-danger-surface); border-left: 6px solid var(--color-danger); border-radius: 4px; color: var(--color-danger); font-weight: 600; margin: 0 0 1em; padding: 1em 1.4em; } .banner-info { background: var(--color-accent-surface); border-left: 4px solid var(--color-accent); border-radius: 4px; color: var(--color-accent); margin: 0 0 1em; padding: 0.8em 1.2em; } .pulse-bar { border-radius: 50%; display: inline-block; height: 8px; margin-right: 4px; vertical-align: middle; width: 8px; } .pulse-bar.hot { background: var(--color-danger); } .pulse-bar.warm { background: var(--color-warning); } .pulse-bar.cool { background: var(--color-success); }
  .theme-control { align-items: center; border-top: 1px solid var(--color-nav-divider); display: flex; gap: 8px; padding: 0.8em 1.2em; } .theme-control label { color: var(--color-nav-muted); font-size: 0.85em; } .theme-control #theme-select { background: var(--color-nav-field); border-color: var(--color-nav-divider); color: var(--color-nav-fg); flex: 1; }
  .inline-muted { color: var(--color-fg-muted); } .inline-warning { color: var(--color-warning); } .oos-badge { background: var(--color-accent-surface); border-radius: 3px; color: var(--color-accent); font-weight: 700; padding: 2px 6px; } .oos-badge.stale { background: var(--color-danger-surface); color: var(--color-danger); } .oos-details { font-size: 0.9em; margin: 6px 0 0 1em; } .oos-details dd { margin: 0 0 4px; } .missing-value { color: var(--color-fg-muted); }
  .visually-hidden { height: 1px; margin: -1px; overflow: hidden; padding: 0; position: absolute; width: 1px; clip: rect(0 0 0 0); white-space: nowrap; }
  .filter-notice { align-items: center; background: var(--color-accent-surface); border: 1px solid var(--color-accent); border-radius: 4px; display: none; font-size: 0.9em; margin: 0.4em 0 0.8em; padding: 8px 12px; } .filter-notice-clear, .filter-notice-view { border: 1px solid var(--color-accent); border-radius: 3px; cursor: pointer; font-size: 0.85em; margin-left: 8px; padding: 2px 8px; } .filter-notice-clear { background: var(--color-surface); color: var(--color-accent); } .filter-notice-view { background: var(--color-accent); color: var(--color-bg); margin-left: 4px; }
  .environment-exclusions { border: none; margin: 0; padding: 0.4em 1.2em 0.6em; } .environment-exclusions legend { font-size: 0.75em; font-weight: 600; letter-spacing: 0.06em; padding: 0; text-transform: uppercase; color: var(--color-nav-muted); } .environment-exclusion-actions { align-items: center; display: flex; flex-wrap: wrap; gap: 0.35em; margin-bottom: 0.35em; } .environment-exclusion-actions button { background: var(--color-nav-field); border: 1px solid var(--color-nav-divider); border-radius: 3px; color: var(--color-nav-fg); cursor: pointer; font-size: 0.8em; padding: 3px 8px; } .environment-exclusion-actions button:hover { background: var(--color-nav-field-hover); } .environment-exclusion-options { display: grid; gap: 0.25em; } .environment-exclusion-option { align-items: center; display: flex; gap: 0.35em; font-size: 0.85em; color: var(--color-nav-fg); } .environment-exclusion-option input { accent-color: var(--color-accent); } .environment-exclusion-status { color: var(--color-fg-muted); font-size: 0.8em; } .empty-view { background: var(--color-surface-subtle); border: 1px solid var(--color-border); border-radius: 4px; color: var(--color-fg-muted); font-style: italic; padding: 0.8em; }
  #sidebar-filter { border-bottom: 1px solid var(--color-nav-divider); border-top: 1px solid var(--color-nav-divider); font-size: 0.85em; padding: 0.8em 1.2em; } .sidebar-filter-label, #filter-summary { color: var(--color-nav-muted); font-size: 0.8em; } .sidebar-filter-label { font-size: 0.75em; letter-spacing: 0.06em; margin-bottom: 6px; text-transform: uppercase; } .sidebar-filter-input, .sidebar-filter-select, .sidebar-filter-reset, .gsev-btn { background: var(--color-nav-field); border: 1px solid var(--color-nav-divider); border-radius: 3px; color: var(--color-nav-fg); } .sidebar-filter-input, .sidebar-filter-select { padding: 5px 8px; width: 100%; } .sidebar-filter-input { margin-bottom: 6px; } .sidebar-filter-cluster { display: flex; flex-wrap: wrap; gap: 4px; } .gsev-btn { cursor: pointer; flex: 1; font-size: 0.85em; padding: 3px 8px; } .gsev-btn.active { background: var(--color-accent); border-color: var(--color-accent); color: var(--color-bg); } .gsev-btn:hover, .sidebar-filter-reset:hover { background: var(--color-nav-field-hover); } .sidebar-filter-select, .sidebar-filter-reset { margin-top: 6px; } .sidebar-filter-reset { cursor: pointer; padding: 4px; width: 100%; } #filter-summary { margin-top: 8px; }
  #filter-banner { align-items: center; background: var(--color-accent-surface); border: 1px solid var(--color-accent); border-radius: 4px; display: none; flex-wrap: wrap; font-size: 0.9em; gap: 8px; margin: 0.6em 0; padding: 8px 12px; } #filter-banner strong, .filter-chip, .filter-chip-clear { color: var(--color-accent); } #filter-chips { align-items: center; display: inline-flex; flex-wrap: wrap; gap: 6px; } .filter-chip { align-items: center; background: var(--color-surface); border: 1px solid var(--color-accent); border-radius: 12px; display: inline-flex; font-size: 0.85em; gap: 6px; padding: 3px 8px; } .filter-chip-clear { background: transparent; border: 0; cursor: pointer; font-size: 1.1em; font-weight: 700; line-height: 1; padding: 0 2px; } #filter-banner-clear { background: var(--color-surface); border: 1px solid var(--color-accent); border-radius: 3px; color: var(--color-accent); cursor: pointer; font-weight: 600; margin-left: auto; padding: 4px 10px; }
  @media (max-width: 900px) { #app { grid-template-columns: 1fr; } #sidebar { height: auto; position: relative; } #main { padding: 1em; } .two-col { grid-template-columns: 1fr; } .route-header { align-items: flex-start; flex-direction: column; gap: 0.5em; } .route-header .meta { text-align: left; } }

"""

    # Every server-side projection begins with the same immutable browser model.
    env_stats = [
        {
            "label": environment["identity"]["display_label"],
            "project": environment["identity"]["project"],
            "env": environment["identity"]["env"],
            "stack_label": environment["identity"]["stack_label"],
            "scan_status": environment["scan_status"],
            **environment["counts"],
        }
        for environment in report_model["environments"]
    ]
    top_resources = report_model["top_lists"]["resources"]
    top_rules = report_model["top_lists"]["rules"]
    # Compute percentages for donut
    pct_high = (high_critical / total_findings * 100) if total_findings else 0
    pct_med = (medium / total_findings * 100) if total_findings else 0
    pct_low = (low / total_findings * 100) if total_findings else 0
    pct_sup = (suppressed_count / total_findings * 100) if total_findings else 0
    # Pending coverage gaps count for sidebar badge
    pending_gaps = sum(1 for g in gaps.records if g.get("missing_count", 0) > 0)
    stale_oos = sum(1 for e in out_of_scope if e.get("stale"))

    # Build the SPA shell with sidebar nav. The rest of the report
    # rendering (PCI matrix, findings, OOS, drift) is appended inside
    # <section data-route="…"> containers below so the router can swap
    # views without rewriting the renderer.
    generated_at = datetime.now(timezone.utc).isoformat()
    run_dir_disp = html.escape(str(out.parent))
    theme_bootstrap = """<script>
(function () {
  var key = 'pacioli.report.theme';
  var valid = { dark: true, light: true, system: true };
  var theme = 'dark';
  try {
    var stored = localStorage.getItem(key);
    if (stored && valid[stored]) theme = stored;
  } catch (error) {
    theme = 'dark';
  }
  document.documentElement.dataset.theme = theme;
}());
</script>"""
    body = f"""<!doctype html>
<html lang="en" data-theme="dark"><head>
<meta charset="utf-8">
<meta name="color-scheme" content="dark light">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pacioli {framework_full} Compliance Report</title>
{theme_bootstrap}
<style>
{CSS_STYLE}</style>
</head>
<body>
<script type="application/json" id="pacioli-report-model">{report_model_json}</script>
<div id="app">
<aside id="sidebar">
   <div class="sidebar-brand">
     <h1>Pacioli</h1>
     <div class="subtitle">{framework_full} Compliance Report</div>
   </div>
   <fieldset id="environment-exclusions" class="environment-exclusions">
     <legend>Environments</legend>
      <div class="environment-exclusion-actions">
        <button type="button" id="environment-select-all">Select all</button>
        <button type="button" id="environment-select-none">Select none</button>
      </div>
     <div id="environment-exclusion-status" class="environment-exclusion-status" role="status" aria-live="polite"></div>
     <div id="environment-exclusion-options" class="environment-exclusion-options"></div>
   </fieldset>
    <nav class="sidebar-nav" aria-label="Report sections">
    <a href="#dashboard" data-route="dashboard" class="active">Dashboard</a>
    <a href="#findings" data-route="findings">Findings
       <span class="badge" id="badge-findings">{total_findings}</span></a>
    <a href="#environments" data-route="environments">Environments
       <span class="badge" id="badge-envs">{len(env_results)}</span></a>
    <a href="#coverage" data-route="coverage">PCI Coverage
       <span class="badge {'warn' if pending_gaps else 'ok'}" id="badge-gaps">{pending_gaps}</span></a>
    <a href="#remediation" data-route="remediation">Remediation</a>
    <a href="#oos" data-route="oos">Out-of-Scope
       <span class="badge {'warn' if stale_oos else ''}">{len(out_of_scope)}</span></a>
    <a href="#drift" data-route="drift">Drift
       <span class="badge {'warn' if drift_findings else 'ok'}">{len(drift_findings)}</span></a>
   </nav>
   <div class="theme-control">
     <label for="theme-select">Theme</label>
     <select id="theme-select" name="theme">
       <option value="dark">Dark</option>
       <option value="light">Light</option>
       <option value="system">System</option>
     </select>
   </div>
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
      <div class="kpi-value" id="kpi-total">{total_findings}</div>
       <div class="kpi-sub" id="kpi-total-sub">across {len(env_results)} environment{'' if len(env_results)==1 else 's'}</div></div>
    <div class="kpi kpi-high"><div class="kpi-label">High / Critical</div>
      <div class="kpi-value" id="kpi-high">{high_critical}</div>
       <div class="kpi-sub" id="kpi-high-sub">{pct_high:.1f}% of total</div></div>
    <div class="kpi kpi-medium"><div class="kpi-label">Medium</div>
      <div class="kpi-value" id="kpi-medium">{medium}</div>
       <div class="kpi-sub" id="kpi-medium-sub">{pct_med:.1f}% of total</div></div>
    <div class="kpi kpi-low"><div class="kpi-label">Low</div>
      <div class="kpi-value" id="kpi-low">{low}</div>
       <div class="kpi-sub" id="kpi-low-sub">{pct_low:.1f}% of total</div></div>
    <div class="kpi kpi-ok"><div class="kpi-label">Suppressed</div>
      <div class="kpi-value" id="kpi-suppressed">{suppressed_count}</div>
       <div class="kpi-sub" id="kpi-suppressed-sub">{pct_sup:.1f}% of total · baseline waivers</div></div>
  </div>
  <div class="two-col">
    <div class="panel">
      <h3>Severity Distribution</h3>
      <div class="donut-wrap">
        <svg width="160" height="160" viewBox="0 0 160 160" id="severity-donut">
          <circle cx="80" cy="80" r="60" fill="none" stroke="var(--color-surface-subtle)" stroke-width="24"/>
        </svg>
        <div class="donut-legend" id="severity-donut-legend">
          <div class="donut-legend-row">
            <span class="donut-legend-swatch swatch-high"></span>
            <strong>{high_critical}</strong> High / Critical
          </div>
          <div class="donut-legend-row">
            <span class="donut-legend-swatch swatch-medium"></span>
            <strong>{medium}</strong> Medium
          </div>
          <div class="donut-legend-row">
            <span class="donut-legend-swatch swatch-low"></span>
            <strong>{low}</strong> Low
          </div>
          <div class="donut-legend-row">
            <span class="donut-legend-swatch swatch-ok"></span>
            <strong>{suppressed_count}</strong> Suppressed
          </div>
        </div>
      </div>
    </div>
    <div class="panel">
      <h3>Environment Health</h3>
          <div class="env-bar-list" id="env-health-list">

"""
    # Build env health bars
    if env_stats:
        max_total = max(e["total"] for e in env_stats) or 1
        for e in env_stats:
            w_high = e["high"] / max_total * 100
            w_med = e["medium"] / max_total * 100
            w_low = e["low"] / max_total * 100
            status_class = "kpi-high" if e["high"] > 0 else ("kpi-medium" if e["medium"] > 0 else "kpi-ok")
        body += f"""        <div class="env-bar-row" data-env-bar="{html.escape(e['label'])}" data-identity-label="{html.escape(e['label'])}">
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
    <div class="top-list" id="top-resources">
       <h3>Top Vulnerable Resources</h3>
"""
    for resource_entry in top_resources:
        resource = resource_entry["resource"]
        severity = resource_entry["severity"]
        count = resource_entry["count"]
        severity_class = _severity_css_class(severity)
        body += f'      <div class="top-list-row"><code>{html.escape(resource)}</code><span class="count-pill {severity_class}">{count}</span></div>\n'
    body += """    </div>
    <div class="top-list" id="top-rules">
       <h3>Top Fired Rules</h3>
"""
    for rule_entry in top_rules:
        body += f'      <div class="top-list-row"><code>{html.escape(rule_entry["check_id"])}</code><span class="count-pill">{rule_entry["count"]}</span></div>\n'
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
        stack_label_display = (
            f" <small>[{html.escape(e['stack_label'])}]</small>"
            if e["stack_label"]
            else ""
        )
        _env_table_rows.append(
            f"<tr data-project=\"{html.escape(e['project'])}\" data-env=\"{html.escape(e['env'])}\" data-stack-label=\"{html.escape(e['stack_label'] or '')}\">"
            f"<td><code>{html.escape(e['project'])}</code></td>"
            f"<td><code>{html.escape(e['env'])}</code>{stack_label_display}</td>"
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
    body += "    <thead><tr><th>Project</th><th>Env</th><th>Status</th><th>Total</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>\n"
    body += "    <tbody id=\"environment-table-body\">" + "\n    ".join(_env_table_rows) + "</tbody>\n"
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
    if _unique_rems:
        # Terraform-family run with canonical remediation map loaded.
        # Preserve the historical "Canonical Terraform remediation patterns"
        # header so existing acceptance criteria for terraform scans still
        # match (the 68 azurerm 4.x blocks render unchanged).
        body += "  <p>Canonical Terraform remediation patterns pulled from <code>scanner/terraform_remediation.yaml</code>. "
        body += "Click any check_id to copy the resource_type. Apply the patterns in your <code>env/&lt;project&gt;/&lt;env&gt;</code> directory, then re-run <code>make scan-pci-report</code> to confirm.</p>\n"
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
        # Empty remediation map. Two cases fold into one render:
        #   1. terraform_remediation.yaml missing/malformed (legacy degraded mode)
        #   2. non-Terraform-family framework (CFN/K8s/bicep/...); the
        #      loader returned {} so no azurerm blocks surface here.
        # The framework label was derived once in main() and forwarded
        # as ``remediation_framework_label`` -- we use it as-is.
        body += f"  <p><em>Remediation guidance for {html.escape(remediation_framework_label)} is not yet available.</em></p>\n"
    body += "</section>  <!-- /route-remediation -->\n"

    body += "<section id=\"route-coverage\" class=\"route\">\n"
    body += "  <div class=\"route-header\">\n"
    # Use the framework name from the mapping pack so the H1 reflects
    # whatever framework is loaded (PCI DSS, SOC 2, CIS, NIST, ...).
    body += f"    <h1>{html.escape(framework_full)} Requirement Coverage</h1>\n"
    # The anchor link's destination (and label) is read from the
    # mapping pack. PCI pack points at the PCI SSC summary PDF; SOC 2
    # / CIS / NIST packs point at their own anchor. When the pack
    # omits ``doc_anchor`` the meta block is suppressed so the report
    # still renders cleanly.
    if pci_anchor:
        body += (
            f"    <div class=\"meta\">"
            f"<a href=\"{html.escape(pci_anchor)}\" target=\"_blank\" "
            f"rel=\"noopener noreferrer\">{html.escape(framework_name)} anchor</a></div>\n"
        )
    else:
        body += "    <div class=\"meta\">&nbsp;</div>\n"
    body += "  </div>\n"
    body += f"  <h3>Coverage Heatmap <small class=\"inline-muted\">— click any cell to filter to that {html.escape(framework_name)} req</small></h3>\n"
    body += "  <div id=\"heatmap-active-filter\" class=\"filter-notice\">\n"
    body += "    <strong>Filtered:</strong> <span id=\"heatmap-active-req\"></span>\n"
    body += "    <button id=\"heatmap-clear-btn\" class=\"filter-notice-clear\">Clear</button>\n"
    body += "    <button id=\"heatmap-view-findings\" class=\"filter-notice-view\">View findings →</button>\n"
    body += "  </div>\n"
    body += "  <div class=\"heatmap\" id=\"coverage-heatmap\">\n"
    # Build heatmap cells -- one per in-scope req
    for req in mapping_data.get("requirements", []):
        rid = req["id"]
        title = req.get("title", "")
        req_checks = req.get("checks", [])
        any_non_compliant = any(cells.get((rid, c)) == "non_compliant" for c in req_checks)
        any_compliant = any(cells.get((rid, c)) == "compliant" for c in req_checks)
        any_not_scanned = any(cells.get((rid, c)) == "not_scanned" for c in req_checks)
        any_data = any((rid, c) in cells for c in req_checks)
        finding_count = sum(1 for er in env_results for f in er.findings if rid in (f.requirements or []))
        if any_non_compliant:
            klass = "kpi-high"; label = "FAIL"  # noqa: E702  (intentional one-liner pair)
        elif any_not_scanned:
            klass = "kpi-warn"; label = "PARTIAL"  # noqa: E702
        elif any_compliant:
            klass = "kpi-ok"; label = "PASS"  # noqa: E702
        elif any_data:
            klass = "kpi-ok"; label = "PASS"  # noqa: E702
        else:
            klass = "kpi-warn"; label = "GAP"  # noqa: E702
        body += f'    <div class="heatmap-cell {klass}" title="{html.escape(title)}"><div class="req-id">{html.escape(rid)}</div><div class="req-count">{finding_count} finding{"" if finding_count == 1 else "s"} · {label}</div></div>\n'
    body += f"""  </div>
  <h3>{html.escape(framework_name)} Requirement Status</h3>
   <table id="coverage-status-table">
     <tr><th>{html.escape(framework_name)} Requirement</th><th>Status</th></tr>

"""

    for req in mapping_data.get("requirements", []):
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
        missing_ids = gaps.missing_by_req.get(rid, [])
        missing_count = len(missing_ids)
        # NOTE_TOKENS (see NOTE_TOKENS docstring) are filtered from
        # expected_by_req in build_coverage_matrix so the gap record's
        # expected_count is 0; mirror that here so the HTML tooltip
        # and tip pick the right branch.
        expected_count = len(
            {c for c in req_checks if c not in note_tokens_html}
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
                # - missing == 0 but expected == 0: NOTE_TOKENS
                #   req (see NOTE_TOKENS docstring). The mapping author
                #   declared a symbolic note token + `note:` text to
                #   flag a req with no working Checkov coverage.
                #   Show the note inline + as the tooltip so the
                #   auditor sees the rationale directly in the matrix.
                # - missing == 0 but expected > 0: every mapped check
                #   fired at least once (compliant).
                tip = ""
                if missing_ids and missing_count:
                    missing_inline = " ".join(html.escape(x) for x in missing_ids)
                    tip = (
                        ' <span class="inline-warning" '
                        f'title="missing: {missing_inline}">'
                        f"({missing_count}/{expected_count} mapped checks absent)"
                        "</span>"
                    )
                elif missing_count == 0 and expected_count == 0:
                    # NOTE_TOKENS req -- surface the `note:` text
                    # both inline (visually) and as the tooltip. The
                    # html-render path receives mapping_data; look up the
                    # note from the requirements list.
                    note_text = ""
                    for r in mapping_data.get("requirements", []):
                        if r["id"] == rid and any(
                            c in note_tokens_html for c in r.get("checks", [])
                        ):
                            note_text = r.get("note", "")
                            break
                    if note_text:
                        tip = (
                            ' <span class="inline-muted" '
                            f'title="{html.escape(note_text)}">'
                            f"[note: {html.escape(note_text)}]"
                            "</span>"
                        )
                    else:
                        tip = (
                            ' <span class="inline-muted" '
                            'title="no working Checkov coverage; '
                            'see pci_mapping.yaml note">'
                            "(no working Checkov coverage)"
                            "</span>"
                        )
                elif missing_count == 0 and expected_count > 0:
                    tip = (
                        ' <span class="inline-muted" '
                        "title=\"every mapped check fired at least once - "
                        'all findings compliant (accepted)">'
                        "(all mapped checks ran)</span>"
                    )
                status = "No matching resources in scope" + tip
        body += f'  <tr><td>{rid} <span class="req-coverage">{html.escape(title)}</span></td><td>{status}</td></tr>\n'

    # Render a dedicated coverage-gap section after the in-scope rows,
    # BEFORE the out-of-scope section, so operators see it before
    # reaching the "everything else is excluded" content.
    if gaps.records and any(g["missing_count"] > 0 for g in gaps.records):
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
        for g in gaps.records:
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
                f'<span class="oos-badge stale">OUT OF SCOPE -- '
                f'STALE (expired {-days_to_expiry}d ago)</span>'
            )
        else:
            badge = '<span class="oos-badge">OUT OF SCOPE</span>'

        # Build the audit-trail details: every field below MUST be
        # present for the exclusion to be defensible. They are rendered
        # as a definition list so an auditor can read all of them in
        # one glance.
        details = "<dl class='oos-details'>"
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
                f"<dd>{display or '<em class=\"missing-value\">missing</em>'}</dd>"
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
    body += '  <div id="env-summary-cards" class="env-summary-cards"></div>\n'
    body += (
        '<div id="filter-ui">\n'
        '  <label class="visually-hidden" for="finding-search">Search findings</label>\n'
        '  <input type="search" id="finding-search" '
        'placeholder="Search check_id, resource, file, message…">\n'
        '  <button type="button" data-severity-filter="ALL" class="active">ALL</button>\n'
        '  <button type="button" data-severity-filter="HIGH">HIGH</button>\n'
        '  <button type="button" data-severity-filter="MEDIUM">MEDIUM</button>\n'
        '  <button type="button" data-severity-filter="LOW">LOW</button>\n'
        f'  <label class="visually-hidden" for="{REQUIREMENT_FILTER_ID}">Filter findings by requirement</label>\n'
        f'  <select id="{REQUIREMENT_FILTER_ID}">\n'
        f'    <option value="">All {html.escape(framework_name)} reqs</option>\n'
        f'  </select>\n'
        '  <span id="finding-count">Showing 0 of 0</span>\n'
        '</div>\n'
    )
    body += "<h2>Findings by Environment</h2>\n"

    for er in env_results:
        environment_label = _environment_display_label(
            er.project, er.env, er.stack_label
        )
        if er.scan_status != "ok":
            body += f"<h3 class=\"finding-environment-heading\" data-identity-label=\"{html.escape(environment_label, quote=True)}\">{html.escape(environment_label)} <em>(scan failed: {html.escape(er.error or 'unknown')})</em></h3>\n"
            continue
        body += f"<h3 class=\"finding-environment-heading\" data-identity-label=\"{html.escape(environment_label, quote=True)}\">{html.escape(environment_label)} ({len(er.findings)} findings)</h3>\n"
        for f in er.findings:
            classes = f"finding-body finding {f.severity}"
            if f.suppressed:
                classes += " suppressed"
            req_str = (
                ", ".join(f.requirements) if f.requirements else f"(no {framework_name} mapping)"
            )
            # Resolve the framework source URL for the finding's first mapped
            # req. Findings mapped to multiple reqs use the first
            # (deterministic via the mapping pack's requirements order).
            primary_req = (
                f.requirements[0] if f.requirements else ""
            )
            src_url = source_url_by_req.get(primary_req, "")
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
            # REQUIREMENT_DATA_ATTR (defined in scanner.frameworks) is the
            # single source of truth for the data-attribute name. The
            # JS uses it as the join key for the requirement filter.
            row_attrs = (
                f'class="finding-row" '
                f'data-severity="{html.escape(f.severity, quote=True)}" '
                f'data-check-id="{html.escape(f.check_id, quote=True)}" '
                f'{REQUIREMENT_DATA_ATTR}="{html.escape(primary_req, quote=True)}" '
                f'data-resource="{html.escape(f.resource or "", quote=True)}" '
                f'data-file-path="{html.escape(f.file_path or "", quote=True)}" '
                f'data-project="{html.escape(f.project or "", quote=True)}" '
                f'data-env="{html.escape(f.env or "", quote=True)}" '
                f'data-stack-label="{html.escape(er.stack_label or "", quote=True)}" '
                f'data-identity-label="{html.escape(environment_label, quote=True)}" '
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
                '<em class="inline-warning">(resource address unresolved -- see message + file:line)</em>'
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
            body += f"<small>{html.escape(framework_name)}: {html.escape(req_str)} | {f.framework}</small><br>"
            if f.suppressed:
                body += '<em>(suppressed by baseline)</em><br>'
            body += f"<small>{html.escape(f.message)}</small>"
            # Per-finding links: framework source and Checkov policy helpUri.
            links: list[str] = []
            if src_url:
                links.append(
                    f'<a href="{html.escape(src_url)}" target="_blank" '
                    f'rel="noopener noreferrer">{html.escape(framework_name)} source</a>'
                )
            if f.help_uri:
                links.append(
                    f'<a href="{html.escape(f.help_uri)}" target="_blank" '
                    f'rel="noopener noreferrer">Checkov policy</a>'
                )
            if links:
                body += "<div>" + " | ".join(links) + "</div>"
            # Chain-of-custody badge. Render only
            # for findings with a framework mapping. The cell value
            # "True" means the source URL was live-verified at
            # ``librarian_verified_at``; "partial" means historical
            # verification present but not re-confirmed at write
            # time (operator must manually re-verify the source).
            # Empty cell -> no badge line at all (no mapping).
            # The fingerprint fields only render when the pack ships
            # them (librarian block is empty for SOC 2 / CIS / NIST
            # packs that don't probe a single anchor).
            coc = chain_of_custody_by_req.get(primary_req, "")
            if primary_req and coc:
                coc_class = (
                    "coc-true" if coc == "True" else "coc-partial"
                )
                # Build the fingerprint trailer conditionally. When
                # the pack omits fingerprint metadata, emit only the
                # verified-at timestamp (or none at all when both are
                # empty).
                fp = _librarian_fingerprint
                fp_parts: list[str] = []
                if fp.get("byte_size"):
                    fp_parts.append(f"byte_size={fp['byte_size']}")
                if fp.get("content_type"):
                    fp_parts.append(f"content_type={html.escape(str(fp['content_type']))}")
                if fp.get("past_90d_availability_pct"):
                    fp_parts.append(f"availability={fp['past_90d_availability_pct']:.0f}%/90d")
                fp_str = "; ".join(fp_parts)
                trailer = (
                    f" &mdash; verified against {html.escape(framework_name)} anchor "
                    f"on {html.escape(librarian_at)}"
                )
                if fp_str:
                    trailer += f" ({fp_str})."
                else:
                    trailer += "."
                body += (
                    f'<div class="chain-of-custody">'
                    f'Chain of custody ({html.escape(framework_name)} {html.escape(primary_req)}): '
                    f'<span class="{coc_class}">{html.escape(coc)}</span>'
                    f'{trailer}'
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
                    f'<h4>Fix for {html.escape(framework_name)} {html.escape(primary_req)} '
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
    # applies search/severity/requirement/fix-only filters, hides non-matching
    # rows, and updates the live count badge. Held as a plain string
    # (NOT inside an f-string) because the JS contains literal `{` `}`
    # braces that conflict with f-string parsing in Python 3.12+.
    # Two placeholders are interpolated after the closing `"""` so the
    # remaining JS keeps its literal braces: ``__FRAMEWORK_NAME__`` and
    # ``__FRAMEWORK_NAME__ reqs``.
    FILTER_JS = ("""\
<script>
(function () {
  'use strict';
  const routes = ['dashboard', 'findings', 'environments', 'coverage', 'remediation', 'oos', 'drift'];
  function showRoute(name) {
    const route = routes.includes(name) ? name : 'dashboard';
    document.querySelectorAll('.route').forEach(function (section) {
      section.classList.toggle('active', section.id === 'route-' + route);
    });
    document.querySelectorAll('nav.sidebar-nav a').forEach(function (link) {
      link.classList.toggle('active', link.dataset.route === route);
    });
  }
  function showRouteFromHash() {
    showRoute((location.hash || '#dashboard').slice(1));
  }
  document.querySelectorAll('nav.sidebar-nav a').forEach(function (link) {
    link.addEventListener('click', function () {
      showRoute(link.dataset.route);
    });
  });
  window.addEventListener('hashchange', showRouteFromHash);
  showRouteFromHash();
  const modelElement = document.getElementById('pacioli-report-model');
  let model;
  try { model = JSON.parse(modelElement.textContent); } catch (error) { return; }
  const storageKey = 'pacioli.report.filters';
  const validSeverities = new Set(['ALL', 'HIGH', 'MEDIUM', 'LOW']);
  const identities = model.environments.map(function (environment) { return environment.identity.display_label; });
  const state = { q: '', sev: 'ALL', req: '', excluded: new Set() };
  const storage = {
    get: function () { try { return localStorage.getItem(storageKey); } catch (error) { return null; } },
    set: function (value) { try { localStorage.setItem(storageKey, value); } catch (error) { return; } },
    clearLegacy: function () { try { document.cookie = 'pacioli_req=; path=/; max-age=0'; } catch (error) { return; } },
    legacy: function () { try { const match = document.cookie.match(/(?:^|; )pacioli_req=([^;]*)/); return match ? decodeURIComponent(match[1]) : null; } catch (error) { return null; } },
  };
  function parseState(value) {
    try {
      const candidate = JSON.parse(value);
      if (!candidate || typeof candidate !== 'object') return null;
      return candidate;
    } catch (error) { return null; }
  }
  function restore() {
    const saved = parseState(storage.get());
    if (saved) {
      state.q = typeof saved.q === 'string' ? saved.q : '';
      state.sev = validSeverities.has(saved.sev) ? saved.sev : 'ALL';
      state.req = typeof saved.req === 'string' ? saved.req : '';
      if (Array.isArray(saved.excluded)) saved.excluded = saved.excluded.filter(function (label) { return typeof label === 'string' && identities.includes(label); });
      state.excluded = new Set(saved.excluded || []);
      return;
    }
    const legacyValue = storage.legacy();
    const legacy = legacyValue ? parseState(legacyValue) : null;
    if (legacy) {
      state.q = typeof legacy.q === 'string' ? legacy.q : '';
      state.sev = validSeverities.has(legacy.sev) ? legacy.sev : 'ALL';
      state.req = typeof legacy.req === 'string' ? legacy.req : '';
      if (typeof legacy.env === 'string' && identities.includes(legacy.env)) state.excluded.add(legacy.env);
    }
    storage.clearLegacy();
  }
  function persist() { storage.set(JSON.stringify({ q: state.q, sev: state.sev, req: state.req, excluded: Array.from(state.excluded).sort() })); }
  function make(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
  function visibleEnvironments() { return model.environments.filter(function (environment) { return !state.excluded.has(environment.identity.display_label); }); }
  function filteredFindings(environments) {
    const visible = new Set(environments.map(function (environment) { return environment.identity.display_label; }));
    return model.findings.filter(function (finding) {
      const search = [finding.check_id, finding.resource, finding.file_path, finding.message].join(' ').toLowerCase();
      return visible.has(finding.identity_label) && (!state.q || search.includes(state.q)) && (state.sev === 'ALL' || finding.severity === state.sev) && (!state.req || finding.requirements.includes(state.req));
    });
  }
  function counts(findings) {
    return findings.reduce(function (total, finding) {
      total.total += 1;
      if (finding.suppressed) total.suppressed += 1;
      else if (finding.severity === 'HIGH' || finding.severity === 'CRITICAL') total.high += 1;
      else if (finding.severity === 'MEDIUM') total.medium += 1;
      else total.low += 1;
      return total;
    }, { total: 0, high: 0, medium: 0, low: 0, suppressed: 0 });
  }
  function replaceChildren(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function renderDonut(summary) {
    const svg = document.getElementById('severity-donut');
    const legend = document.getElementById('severity-donut-legend');
    replaceChildren(svg); replaceChildren(legend);
    const slices = [['High / Critical', summary.high, 'var(--color-danger)', 'swatch-high'], ['Medium', summary.medium, 'var(--color-warning)', 'swatch-medium'], ['Low', summary.low, 'var(--color-neutral)', 'swatch-low'], ['Suppressed', summary.suppressed, 'var(--color-success)', 'swatch-ok']];
    const base = document.createElementNS('http://www.w3.org/2000/svg', 'circle'); base.setAttribute('cx', '80'); base.setAttribute('cy', '80'); base.setAttribute('r', '60'); base.setAttribute('fill', 'none'); base.setAttribute('stroke', 'var(--color-surface-subtle)'); base.setAttribute('stroke-width', '24'); svg.appendChild(base);
    const circumference = 2 * Math.PI * 60; let offset = 0;
    slices.forEach(function (slice) {
      const row = make('div', undefined, 'donut-legend-row'); row.appendChild(make('span', '', 'donut-legend-swatch ' + slice[3])); row.appendChild(make('strong', String(slice[1]))); row.appendChild(document.createTextNode(' ' + slice[0])); legend.appendChild(row);
      if (!summary.total || !slice[1]) return;
      const length = slice[1] / summary.total * circumference; const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle'); circle.setAttribute('cx', '80'); circle.setAttribute('cy', '80'); circle.setAttribute('r', '60'); circle.setAttribute('fill', 'none'); circle.setAttribute('stroke', slice[2]); circle.setAttribute('stroke-width', '20'); circle.setAttribute('stroke-dasharray', length + ' ' + (circumference - length)); circle.setAttribute('stroke-dashoffset', String(-offset)); circle.setAttribute('transform', 'rotate(-90 80 80)'); svg.appendChild(circle); offset += length;
    });
    const center = document.createElementNS('http://www.w3.org/2000/svg', 'text'); center.setAttribute('x', '80'); center.setAttribute('y', '85'); center.setAttribute('text-anchor', 'middle'); center.setAttribute('font-size', '18'); center.setAttribute('fill', 'var(--color-fg)'); center.textContent = summary.total ? String(summary.total) : 'No data'; svg.appendChild(center);
  }
  function renderEnvironmentViews(environments) {
    const health = document.getElementById('env-health-list'); const table = document.getElementById('environment-table-body'); replaceChildren(health); replaceChildren(table);
    if (!environments.length) { health.appendChild(make('p', 'No environments are visible. Reset exclusions to restore the full scan.', 'empty-view')); }
    environments.forEach(function (environment) {
      const summary = counts(environment.findings); const row = make('div', undefined, 'env-bar-row'); row.dataset.identityLabel = environment.identity.display_label; row.appendChild(make('div', environment.identity.display_label + ' (' + environment.scan_status + ')', 'env-bar-name')); const track = make('div', undefined, 'env-bar-track'); const denominator = summary.total || 1; [['high', summary.high], ['medium', summary.medium], ['low', summary.low]].forEach(function (part) { const segment = make('div', '', 'env-bar-segment ' + part[0]); segment.style.width = part[1] / denominator * 100 + '%'; track.appendChild(segment); }); row.appendChild(track); row.appendChild(make('div', String(summary.total), 'env-bar-count')); health.appendChild(row);
      const tr = document.createElement('tr'); [environment.identity.project, environment.identity.env + (environment.identity.stack_label ? ' [' + environment.identity.stack_label + ']' : ''), environment.scan_status, String(summary.total), String(summary.high), String(summary.medium), String(summary.low)].forEach(function (value, index) { tr.appendChild(make('td', value, index === 4 ? 'count-high' : index === 5 ? 'count-medium' : index === 6 ? 'count-low' : '')); }); table.appendChild(tr);
    });
    document.querySelectorAll('.finding-environment-heading').forEach(function (heading) { heading.hidden = state.excluded.has(heading.dataset.identityLabel); });
  }
  function renderFindings(environments) {
    const visible = new Set(environments.map(function (environment) { return environment.identity.display_label; }));
    document.querySelectorAll('.finding-row').forEach(function (row) {
      const haystack = [row.dataset.checkId, row.dataset.resource, row.dataset.filePath, row.dataset.message].join(' ').toLowerCase();
      row.hidden = !visible.has(row.dataset.identityLabel) || !!state.q && !haystack.includes(state.q) || state.sev !== 'ALL' && row.dataset.severity !== state.sev || !!state.req && row.dataset.req !== state.req;
    });
    const allVisible = model.findings.filter(function (finding) { return visible.has(finding.identity_label); });
    document.getElementById('finding-count').textContent = 'Showing ' + filteredFindings(environments).length + ' of ' + allVisible.length;
    document.getElementById('badge-findings').textContent = String(allVisible.length);
    document.getElementById('badge-envs').textContent = String(environments.length);
  }
  function renderTopLists(findings) {
    const sources = [['top-resources', 'Top Vulnerable Resources', 'resource'], ['top-rules', 'Top Fired Rules', 'check_id']];
    sources.forEach(function (source) { const target = document.getElementById(source[0]); replaceChildren(target); target.appendChild(make('h3', source[1])); const entries = {}; findings.filter(function (finding) { return !finding.suppressed && finding[source[2]]; }).forEach(function (finding) { entries[finding[source[2]]] = (entries[finding[source[2]]] || 0) + 1; }); Object.keys(entries).sort(function (left, right) { return entries[right] - entries[left] || left.localeCompare(right); }).slice(0, 15).forEach(function (key) { const row = make('div', undefined, 'top-list-row'); row.appendChild(make('code', key)); row.appendChild(make('span', String(entries[key]), 'count-pill')); target.appendChild(row); }); if (!Object.keys(entries).length) target.appendChild(make('p', 'No visible findings.', 'inline-muted')); });
  }
  function requirementStatus(requirement, findings, environments) {
    if (!environments.length) return 'NO VISIBLE ENVIRONMENTS';
    const matching = findings.filter(function (finding) { return finding.requirements.includes(requirement.id); });
    if (matching.some(function (finding) { return !finding.suppressed; })) return 'NON-COMPLIANT';
    if (matching.length) return 'COMPLIANT (suppressed)';
    if (environments.some(function (environment) { return environment.scan_status !== 'ok'; })) return 'NOT SCANNED';
    return 'NO MATCHING RESOURCES IN SCOPE';
  }
  function renderCoverage(environments) {
    const heatmap = document.getElementById('coverage-heatmap'); const table = document.getElementById('coverage-status-table'); replaceChildren(heatmap); while (table.rows.length > 1) table.deleteRow(1);
    const findings = environments.reduce(function (all, environment) { return all.concat(environment.findings); }, []);
    if (!environments.length) heatmap.appendChild(make('p', 'No environments are visible. Reset exclusions to inspect coverage.', 'empty-view'));
    model.requirements.forEach(function (requirement) { const status = requirementStatus(requirement, findings, environments); const cell = make('button', undefined, 'heatmap-cell'); cell.type = 'button'; cell.dataset.req = requirement.id; cell.appendChild(make('div', requirement.id, 'req-id')); cell.appendChild(make('div', findings.filter(function (finding) { return finding.requirements.includes(requirement.id); }).length + ' findings · ' + status, 'req-count')); cell.classList.toggle('filtered', state.req === requirement.id); cell.addEventListener('click', function () { state.req = state.req === requirement.id ? '' : requirement.id; update(); }); heatmap.appendChild(cell); const row = table.insertRow(); row.appendChild(make('td', requirement.id + (requirement.title ? ' ' + requirement.title : ''))); row.appendChild(make('td', status, status === 'NON-COMPLIANT' ? 'count-high' : '')); });
    const gaps = document.querySelector('#route-coverage h3 + p.req-coverage'); if (gaps) gaps.hidden = environments.length !== identities.length;
  }
  function renderDrift(environments) { const visiblePairs = new Set(environments.map(function (environment) { return environment.identity.project + '\u0000' + environment.identity.env; })); document.querySelectorAll('#route-drift tr[data-project]').forEach(function (row) { row.hidden = !visiblePairs.has(row.dataset.project + '\u0000' + row.dataset.env); }); }
  function renderControls(environments) {
    const options = document.getElementById('environment-exclusion-options'); replaceChildren(options); identities.forEach(function (identity) { const label = make('label', undefined, 'environment-exclusion-option'); const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = state.excluded.has(identity); checkbox.value = identity; checkbox.addEventListener('change', function () { checkbox.checked ? state.excluded.add(identity) : state.excluded.delete(identity); update(); }); label.appendChild(checkbox); label.appendChild(document.createTextNode(identity)); options.appendChild(label); }); const hidden = state.excluded.size; document.getElementById('environment-exclusion-status').textContent = hidden ? hidden + ' environment' + (hidden === 1 ? '' : 's') + ' excluded; viewing ' + environments.length + ' of ' + identities.length + ' environments.' : 'Full scan: viewing all ' + identities.length + ' environments.';
  }
  function renderSummary(environments, summary) { const pct = function (value) { return summary.total ? (value / summary.total * 100).toFixed(1) : '0.0'; }; [['total', summary.total, 'across ' + environments.length + ' of ' + identities.length + ' environments'], ['high', summary.high, pct(summary.high) + '% of total'], ['medium', summary.medium, pct(summary.medium) + '% of total'], ['low', summary.low, pct(summary.low) + '% of total'], ['suppressed', summary.suppressed, pct(summary.suppressed) + '% of total · baseline waivers']].forEach(function (entry) { document.getElementById('kpi-' + entry[0]).textContent = String(entry[1]); document.getElementById('kpi-' + entry[0] + '-sub').textContent = entry[2]; }); }
  function renderBanner() { const banner = document.getElementById('filter-banner'); const chips = document.getElementById('filter-chips'); if (!banner || !chips) return; replaceChildren(chips); const labels = []; if (state.q) labels.push('search: ' + state.q); if (state.sev !== 'ALL') labels.push('severity: ' + state.sev); if (state.req) labels.push(model.framework.name + ': ' + state.req); if (state.excluded.size) labels.push(state.excluded.size + ' environment exclusion' + (state.excluded.size === 1 ? '' : 's')); labels.forEach(function (label) { chips.appendChild(make('span', label, 'filter-chip')); }); banner.style.display = labels.length ? 'flex' : 'none'; }
  function syncInputs() { document.querySelectorAll('#finding-search, #global-search').forEach(function (input) { input.value = state.q; }); document.querySelectorAll('[data-severity-filter], .gsev-btn').forEach(function (button) { button.classList.toggle('active', (button.dataset.severityFilter || button.dataset.sev) === state.sev); }); document.querySelectorAll('#req-filter, #global-req').forEach(function (select) { select.value = state.req; }); }
  function update() { const environments = visibleEnvironments(); const findings = environments.reduce(function (all, environment) { return all.concat(environment.findings); }, []); const summary = counts(findings); renderControls(environments); renderSummary(environments, summary); renderDonut(summary); renderEnvironmentViews(environments); renderFindings(environments); renderTopLists(findings); renderCoverage(environments); renderDrift(environments); renderBanner(); syncInputs(); persist(); }
  function reset() { state.q = ''; state.sev = 'ALL'; state.req = ''; state.excluded.clear(); update(); }
  function addRequirementOptions() { const values = model.requirements.map(function (requirement) { return requirement.id; }); document.querySelectorAll('#req-filter, #global-req').forEach(function (select) { values.forEach(function (value) { const option = make('option', value); option.value = value; select.appendChild(option); }); }); }
  restore(); addRequirementOptions();
  document.getElementById('environment-select-visible').addEventListener('click', function () { identities.forEach(function (identity) { state.excluded.add(identity); }); update(); });
  document.getElementById('environment-reset').addEventListener('click', reset);
  document.querySelectorAll('#finding-search').forEach(function (input) { input.addEventListener('input', function () { state.q = input.value.toLowerCase(); update(); }); });
  document.querySelectorAll('[data-severity-filter]').forEach(function (button) { button.addEventListener('click', function () { state.sev = button.dataset.severityFilter; update(); }); });
  document.querySelectorAll('#req-filter').forEach(function (select) { select.addEventListener('change', function () { state.req = select.value; update(); }); });
  document.getElementById('heatmap-clear-btn').addEventListener('click', function () { state.req = ''; update(); });
  document.getElementById('heatmap-view-findings').addEventListener('click', function () { location.hash = '#findings'; });
  update();
}());
</script>
""").replace("__FRAMEWORK_NAME__ reqs", framework_name + " reqs").replace(
        "__FRAMEWORK_NAME__: ", framework_name + ": "
    ).replace("__FRAMEWORK_NAME__", framework_name)
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
    mapping_data: dict,
    remediation_by_check_id: dict[str, list[dict]],
    run_id: str,
) -> None:
    """Emit a developer-friendly fix_list.md.

    Parameters
    ----------
    out           : output path (e.g. <run-dir>/fix_list.md)
    env_results   : list[EnvResult] -- same set fed to write_html_report
    mapping_data  : parsed mapping pack top-level dict; used only to
                    resolve the per-requirement title for the bullet list
    remediation_by_check_id : {check_id: [block, ...]} from load_remediation_map
    run_id        : the run dir name (e.g. 'all-prod-2026-08-05') for the header
    """
    title_by_req: dict[str, str] = {
        r["id"]: r.get("title", "")
        for r in mapping_data.get("requirements", [])
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
    lines.append(f"# Pacioli Fix List \u2014 {run_id} \u2014 {utc_date}")
    lines.append("")
    lines.append(
        "Generated by `make scan-pci-fix-list RUN_DIR=<run_id>`. "
        "Severity-sorted (HIGH first). One section per finding. "
        "Req id, canonical remediation, verification command all inline."
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
            primary_req = f.requirements[0] if f.requirements else ""
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
                    lines.append(f"- **Req**: {primary_req} ({req_title})")
                else:
                    lines.append(f"- **Req**: {primary_req}")
            else:
                lines.append("- **Req**: (no mapping)")
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
                lines.append("- **Suppressed**: yes (baseline or inline skip)")
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

    The SARIF files are stored in ``sarif_files`` keyed by generic
    pass name (``"source"``, ``"paac"``, ``"secrets"``, ``"plan"``,
    ``"state"``) so the same dataclass works for any IaC framework.
    Non-Terraform frameworks can populate only the keys their scan
    tier produces (typically just ``"source"``).
    """

    plan_dir: Path | None = None
    sarif_files: dict[str, Path | None] = field(default_factory=dict)


def _read_environment_metadata(env_dir: Path, directory_project: str, directory_env: str) -> tuple[str, str, str | None]:
    """Return canonical identity from metadata, or legacy directory identity."""
    metadata_path = env_dir / "pacioli_environment.json"
    if not metadata_path.exists():
        return directory_project, directory_env, None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise ValueError(f"invalid environment metadata at {metadata_path}: {error}") from error
    if not isinstance(metadata, dict):
        raise ValueError(f"invalid environment metadata at {metadata_path}: expected object")
    expected_keys = {"schema_version", "project", "env", "stack_label"}
    missing = expected_keys - set(metadata)
    if missing:
        raise ValueError(
            f"invalid environment metadata at {metadata_path}: missing keys {sorted(missing)}"
        )
    if metadata["schema_version"] != 1:
        raise ValueError(
            f"invalid environment metadata at {metadata_path}: unsupported schema_version {metadata['schema_version']!r}"
        )
    project = metadata["project"]
    env = metadata["env"]
    stack_label = metadata["stack_label"]
    if not isinstance(project, str) or not project:
        raise ValueError(f"invalid environment metadata at {metadata_path}: project must be a non-empty string")
    if not isinstance(env, str) or not env:
        raise ValueError(f"invalid environment metadata at {metadata_path}: env must be a non-empty string")
    if stack_label is not None and (not isinstance(stack_label, str) or not stack_label):
        raise ValueError(f"invalid environment metadata at {metadata_path}: stack_label must be a non-empty string or null")
    if project != directory_project:
        raise ValueError(
            f"invalid environment metadata at {metadata_path}: project mismatches directory ({project!r} != {directory_project!r})"
        )
    expected_directory_env = env if stack_label is None else f"{env}-{stack_label}"
    if directory_env != expected_directory_env:
        raise ValueError(
            f"invalid environment metadata at {metadata_path}: env/stack_label mismatches directory ({expected_directory_env!r} != {directory_env!r})"
        )
    return project, env, stack_label


def walk_run_dir(run_dir: Path, projects: list[dict]) -> list[EnvResultFull]:
    """Walk a run dir and produce EnvResultFull per project/env.

    Discovers ``results_*.sarif`` files generically — the pass name
    is inferred from the filename prefix (e.g.,
    ``results_source.sarif`` → ``"source"``). This is the same
    naming contract the orchestrator uses when it writes SARIFs,
    so read and write paths agree.

    Backward compatibility: legacy ``results_terraform_*`` filenames
    are mapped to the generic keys via ``OLD_TO_NEW_FILENAME``. Old
    run-dirs continue to aggregate without the orchestrator needing
    to rewrite them.
    """
    results = []
    for entry in run_dir.iterdir():
        if not entry.is_dir():
            continue
        project = entry.name
        for env_dir in entry.iterdir():
            if not env_dir.is_dir():
                continue
            canonical_project, canonical_env, stack_label = _read_environment_metadata(
                env_dir, project, env_dir.name
            )
            project = canonical_project
            env = canonical_env
            sarif_files: dict[str, Path | None] = {}
            for sarif_path in env_dir.glob("results_*.sarif"):
                pass_name = _sarif_filename_to_pass(sarif_path.name)
                if pass_name is None:
                    continue
                # First writer wins — if both the legacy and new
                # filename exist for the same pass, prefer the new
                # (generic) one so freshly produced run-dirs reflect
                # the orchestrator's contract.
                if (
                    pass_name not in sarif_files
                    or sarif_files[pass_name] is None
                ):
                    sarif_files[pass_name] = sarif_path
            r = EnvResultFull(
                project=project,
                env=env,
                stack_label=stack_label,
                scan_status="ok",
                plan_dir=env_dir,
                sarif_files=sarif_files,
            )
            # Mark the env failed only if literally no SARIF files were
            # written -- a missing plan+secrets pair is normal for tier 1.
            if not any(r.sarif_files.values()):
                r.scan_status = "no_sarif"
                r.error = "no SARIF files written"
            results.append(r)
    return results


# Mapping of legacy SARIF filenames → generic pass-name keys. Single
# source of truth used by both SARIF detection (walk_run_dir) and any
# orchestrator-side writer that still produces the old names. Add new
# aliases here when retiring another legacy filename.
OLD_TO_NEW_FILENAME: dict[str, str] = {
    "results_terraform_plan.sarif": "plan",
    "results_terraform_source.sarif": "source",
    "results_paac.sarif": "paac",
    "results_secrets.sarif": "secrets",
    "results_state.sarif": "state",
}


def _sarif_filename_to_pass(filename: str) -> str | None:
    """Map a SARIF filename to its pass name key.

    Strips the ``results_`` prefix and ``.sarif`` suffix, then
    applies the ``OLD_TO_NEW_FILENAME`` backward-compat mapping.
    Returns ``None`` for filenames that don't match the contract
    (e.g., ``combined.sarif`` from earlier aggregator runs — those
    are out-of-scope for per-env aggregation).
    """
    if not filename.startswith("results_") or not filename.endswith(".sarif"):
        return None
    # Apply legacy alias first; fall back to the literal prefix.
    legacy_key = OLD_TO_NEW_FILENAME.get(filename)
    if legacy_key is not None:
        return legacy_key
    # Generic shape: results_<pass>.sarif → "<pass>".
    stem = filename[len("results_") : -len(".sarif")]
    if not stem:
        return None
    return stem


# Pass-name → Checkov framework label for the NON-source passes.
# Stored on each Finding by ``parse_sarif`` and used downstream for
# framework-family detection (``is_terraform_family``), the HTML
# report's framework label, and the remediation HCL gate. The
# ``source`` pass is intentionally NOT in this dict — its label is
# derived from ``--source-framework`` (or the default ``"terraform"``)
# so non-Terraform scans (cloudformation, kubernetes, …) get the
# correct framework tag on their source findings. Preserves the
# historical ``"plan" -> "terraform_plan"`` alias so the
# pre-existing ``Finding.framework == "terraform_plan"`` contract holds
# for Terraform plan scans. Non-Terraform frameworks fall through to
# the pass name itself, which downstream consumers interpret via
# ``scanner.frameworks``.
PASS_TO_FRAMEWORK: dict[str, str] = {
    "plan": "terraform_plan",
    "paac": "paac",
    "secrets": "secrets",
    "state": "state",
}


def load_findings(
    results: list[EnvResultFull],
    mapping_pack: dict | None = None,
    *,
    source_framework: str = "terraform",
) -> None:
    """Mutate results in place: populate findings lists from SARIFs.

    NOTE: the aggregator MUST load every SARIF the scanner produces,
    not just the tier-2/3 ones. Earlier versions of this loader only
    parsed secrets + terraform_plan, which silently DROPPED every
    source-only finding (the entire results_paac.sarif +
    results_terraform_source.sarif). Those findings account for the
    vast majority of what a tier 1 (source-only) operator scan
    produces, so dropping them made the coverage matrix under-report
    by 90%+. See docs/MAPPING_SCHEMA.md for the field schema.

    ``mapping_pack`` is threaded through to ``parse_sarif`` so per-check
    severity overrides declared in the mapping YAML take effect for
    every SARIF. When ``None`` (the legacy default), severity falls
    through to the install-bundled PCI pack.

    ``source_framework`` (F3 fix — second stage): the framework label
    applied to findings produced by the ``source`` pass only. Defaults
    to ``"terraform"`` for backward compatibility with every caller
    that omits it. The orchestrator passes the active ``--framework``
    flag value here when it differs from the historical default, so a
    ``--framework cloudformation`` scan tags its source findings with
    ``framework="cloudformation"`` instead of the bogus
    ``framework="terraform"`` the previous version emitted. This
    change is what unblocks :func:`is_terraform_family` (and therefore
    :func:`load_remediation_map`) from correctly classifying a CFN
    scan as non-terraform-family and skipping the azurerm remediation
    YAML. Other passes (``plan``/``paac``/``secrets``/``state``) keep
    their fixed labels from :data:`PASS_TO_FRAMEWORK` regardless of
    ``source_framework`` — the paac / plan / state passes are
    Terraform-family only and are not invoked for non-Terraform scans.
    """
    for r in results:
        if r.scan_status != "ok":
            continue
        # Iterate the dict generically — one loop, no per-key branches.
        # The "source" pass is the only one whose framework label comes
        # from the orchestrator-supplied ``source_framework``; every
        # other pass keeps its fixed label from PASS_TO_FRAMEWORK.
        # Unknown passes fall through to the pass name itself.
        for pass_name, sarif_path in r.sarif_files.items():
            if sarif_path is None:
                continue
            if pass_name == "source":
                framework_label = source_framework
            else:
                framework_label = PASS_TO_FRAMEWORK.get(pass_name, pass_name)
            r.findings.extend(
                parse_sarif(
                    sarif_path,
                    r.project,
                    r.env,
                    framework_label,
                    mapping_pack,
                )
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


def _resolve_repo_root_from_env_metadata(run_dir: Path) -> Path | None:
    """Scan *run_dir* for per-env ``pacioli_environment.json`` files and
    extract the ``target_repo`` field.

    Returns the single distinct ``target_repo`` as a ``Path``, or ``None``
    when no metadata files carry the field.  Prints an ERROR and raises
    ``SystemExit(2)`` when multiple *distinct* values are found — the
    caller must treat this as a fatal misconfiguration.
    """
    target_repos: set[str] = set()
    for metadata_path in run_dir.rglob("pacioli_environment.json"):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(metadata, dict):
            continue
        value = metadata.get("target_repo")
        if isinstance(value, str) and value:
            target_repos.add(value)
    if len(target_repos) > 1:
        print(
            "ERROR --scan mixed multiple target_repo values across per-env "
            "dirs; rerun pacioli scan with a consistent --label or run "
            "pacioli aggregate on a single-run-dir",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if len(target_repos) == 1:
        return Path(target_repos.pop())
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-dir", required=True, help="Run dir produced by scan.sh")
    ap.add_argument("--out", help="Output dir (default: <run-dir>/aggregate)")
    ap.add_argument("--scope", default=".pacioli/scope.yaml", help="Scope manifest")
    ap.add_argument("--mapping", default="pci_mapping.yaml", help="PCI mapping")
    ap.add_argument("--baseline", default=".pacioli/baseline.yaml", help="Baseline suppressions")
    ap.add_argument(
        "--source-framework",
        default="terraform",
        help=(
            "Framework label applied to the 'source' pass findings "
            "(F3 fix — second stage). The orchestrator passes the active "
            "--framework value here so non-Terraform scans tag their "
            "source findings with the correct framework (e.g. "
            "'cloudformation', 'kubernetes') instead of the historical "
            "default 'terraform'. Only affects the 'source' pass; the "
            "plan/paac/secrets/state passes keep their fixed labels. "
            "Default 'terraform' preserves backward compatibility for "
            "callers that omit this flag."
        ),
    )
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
    #   2. CLI --scope passed as an absolute path (parent dir = repo_root)
    #   3. Per-env pacioli_environment.json target_repo field
    #   4. Walk up from run_dir looking for a .git directory (legacy
    #      fallback for callers who don't set the env var)
    # The default values for --scope/--mapping/--baseline are bare
    # filenames, which are resolved relative to the resolved root.
    env_target = os.environ.get("PACIOLI_TARGET_REPO", "").strip()
    if env_target and Path(env_target).is_dir():
        repo_root = Path(env_target).resolve()
    elif Path(args.scope).is_absolute():
        # Explicit absolute --scope: trust its parent as repo_root.
        repo_root = Path(args.scope).resolve().parent
    else:
        # Try per-env metadata before falling back to the .git walk-up.
        try:
            metadata_root = _resolve_repo_root_from_env_metadata(run_dir)
        except SystemExit:
            return 2
        if metadata_root is not None:
            repo_root = metadata_root.resolve()
        else:
            # No env metadata found — legacy .git walk-up.
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
        # Default-resolution fallback: when the user did NOT pass --mapping
        # explicitly (i.e. args.mapping is still the bare default
        # "pci_mapping.yaml" resolved relative to repo_root), fall back
        # to the install-bundled mapping shipped via importlib.resources.
        # Mirrors the precedence pattern in scanner/paths.py:resolve_mapping.
        # Use Traversable.is_file() — works for both editable installs and
        # wheel installs (Python 3.9+).
        #
        # CRITICAL: this fallback MUST only fire for the default. If the
        # user passed --mapping <explicit-bad-path> and that file is
        # missing, we must surface the error rather than silently swap in
        # the install-bundled mapping (which would report against the
        # wrong framework and mask the user error).
        if args.mapping == "pci_mapping.yaml":
            try:
                bundled = importlib.resources.files("scanner").joinpath(
                    "mappings/pci_dss_4.0.1.yaml"
                )
                if bundled.is_file():
                    print(f"mapping: (install-bundled fallback) {bundled}")
                    mapping_path = Path(str(bundled))
            except (ModuleNotFoundError, AttributeError, OSError):
                # Traversable lookup can fail in raw-tree execution where the
                # scanner package isn't installed yet; surface the original
                # mapping_path in the error below.
                pass

    if not mapping_path.exists():
        print(
            f"ERROR: pci mapping not found: {mapping_path}\n"
            f"  Hint: pass --mapping <path-to-mapping.yaml> explicitly, or\n"
            f"        run `pip install -e .` to bundle the default mapping.",
            file=sys.stderr,
        )
        return 2

    requirements_map = load_mapping(mapping_path)
    mapping_data = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))
    baseline = load_baseline(baseline_path)

    if not run_dir.iterdir():
        print(f"ERROR: run dir is empty: {run_dir}", file=sys.stderr)
        return 3

    # Walk
    results = walk_run_dir(run_dir, [])
    if not results:
        print(f"ERROR: no project/env subdirs found in {run_dir}", file=sys.stderr)
        return 3

    # Load findings (threading the mapping pack so per-check severity
    # overrides declared in the YAML apply to every SARIF tier).
    load_findings(results, mapping_pack=mapping_data, source_framework=args.source_framework)

    # Detect the run's framework family from per-finding framework tags
    # (Finding.framework is set per finding by parse_sarif). If any
    # finding carries a non-Terraform-family framework, we skip the
    # azurerm remediation loader entirely so no azurerm-specific HCL
    # leaks into a CloudFormation/Kubernetes/etc. report. ``results``
    # is the SAME variable we walk below -- no re-derivation in the
    # renderer.
    run_frameworks: set[str] = set()
    for _r in results:
        for _f in _r.findings:
            if _f.framework:
                run_frameworks.add(_f.framework)
    is_tf_family = all(is_terraform_family(fw) for fw in run_frameworks)

    # Pick a single representative framework label for the HTML stub.
    # Sort for stability: a single-framework run shows that framework;
    # mixed runs show a sorted, comma-joined list. An empty set (no
    # findings) renders as "the current run" so the stub stays useful.
    if run_frameworks:
        rem_html_framework_label = ", ".join(sorted(run_frameworks))
    else:
        rem_html_framework_label = "the current run"

    # Load canonical remediation HCL map once at startup.
    # Used by the per-finding HTML render and by write_fix_list_md().
    # Gated by framework family: returns {} early for non-Terraform
    # runs so the azurerm-specific YAML doesn't pollute a CFN report.
    remediation_by_check_id = load_remediation_map(
        framework="terraform" if is_tf_family else "non-terraform"
    )
    print(
        f"remediation map: {sum(len(v) for v in remediation_by_check_id.values())} "
        f"blocks across {len(remediation_by_check_id)} check_ids "
        f"(frameworks seen: {sorted(run_frameworks) if run_frameworks else '<none>'})"
    )

    # Load inline skips from .tf files
    env_dirs = [r.plan_dir for r in results if r.plan_dir is not None]
    inline_skips = load_inline_skips(env_dirs)
    inline_count = sum(len(v) for v in inline_skips.values())
    if inline_count > 0:
        print(f"inline skips parsed: {inline_count} entries across {len(inline_skips)} check_ids")

    # Apply baseline + inline-skip + mapping
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
        attach_reqs(r.findings, requirements_map)

    # Build coverage matrix
    (
        req_ids,
        check_ids,
        cells,
        out_of_scope,
        oos_errors,
        expected_by_req,
        fired_check_ids,
    ) = build_coverage_matrix(results, mapping_path, mapping_data)

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
    # Thread `note_by_req` so NOTE_TOKENS reqs (see NOTE_TOKENS docstring)
    # carry the mapping pack's `note:` text as their triage_hint.
    note_tokens_main = _resolve_note_tokens(mapping_data)
    note_by_req: dict[str, str] = {
        r["id"]: r["note"]
        for r in mapping_data.get("requirements", [])
        if any(c in note_tokens_main for c in r.get("checks", [])) and r.get("note")
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
        mapping_data,
    )
    write_coverage_gaps_csv(
        out_dir / "coverage_gaps.csv", gap_records, mapping_data
    )
    write_combined_sarif(out_dir / "combined.sarif", results)
    fail_count = write_junit(out_dir / "junit.xml", results, [])
    # Per-req missing-list is now derived from gap_records inside
    # CoverageGaps.from_records(). The derived gaps instance is
    # passed straight to write_html_report (collapsed param).
    coverage_gaps = CoverageGaps.from_records(gap_records)
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
        mapping_data,
        cells,
        out_of_scope,
        suppressed_count,
        gaps=coverage_gaps,
        remediation_by_check_id=remediation_by_check_id,
        drift_findings=drift_findings,
        remediation_framework_label=rem_html_framework_label,
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
            mapping_data,
            remediation_by_check_id,
            run_id=run_dir.name,
        )
        print(f"  fix_list.md:        {fix_list_path} ({fix_list_path.stat().st_size} bytes)")

    # Summary
    print()
    print("=== Aggregation complete ===")
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
        print("  coverage gaps:      0 (every mapped check evaluated)")
    print("  outputs:")
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
