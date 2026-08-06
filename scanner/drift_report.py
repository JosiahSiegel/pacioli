"""Generate a drift report between source plan and state plan.

Reads two JSON files produced by `terraform show -json` (source plan)
and by `tfstate_to_plan.py` (state-as-plan), and writes a concise JSON
drift report at <out>. The report groups findings by:

  1. attribute_drift
     - Same resource, same attribute, different value in source vs state.
     - Indicates ignore_changes is masking real Azure drift; terraform
       apply will reverse the state value.

  2. resource_in_state_only
     - Resource exists in state but not in source plan. Source-side
       ignore_changes cannot suppress deletion; this resource will be
       destroyed on next apply unless a matching block is added.

  3. resource_in_source_only
     - Resource in source plan but not in state. Will be created.

  4. sensitive_attributes
     - Attributes that were <sensitive> in source plan but have actual
       values in state. Surface these for token-rotation review.

Usage:
  python drift_report.py <plan.json> <state_as_plan.json> <out.json>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _index_by_address(plan: dict) -> dict[str, dict]:
    """Build {address: resource} from planned_values + resource_changes.

    Accepts both the canonical terraform show -json shape (with
    planned_values.root_module.resources[*].values) and the state-converter
    shape (with resource_changes[*].change.after as the values dict).
    """
    out = {}
    pv = plan.get("planned_values", {})
    for r in pv.get("root_module", {}).get("resources", []):
        if isinstance(r, dict):
            out[r.get("address", "")] = r
    for m in pv.get("root_module", {}).get("child_modules", []):
        for r in m.get("resources", []):
            if isinstance(r, dict):
                out[r.get("address", "")] = r
    # Fallback: read from resource_changes (state-converter shape)
    for r in plan.get("resource_changes", []):
        if not isinstance(r, dict):
            continue
        addr = r.get("address", "")
        if addr and addr not in out:
            change = r.get("change", {})
            after = change.get("after", {}) if isinstance(change, dict) else {}
            out[addr] = {"address": addr, "values": after}
    return out


def _is_sensitive_marker(v: Any) -> bool:
    """Check if a value is a Terraform <sensitive> marker."""
    return isinstance(v, str) and v == "<sensitive>"


def _values_set_of_interest(values: dict) -> dict:
    """Return attribute subset that is interesting for PCI/security review."""
    keys = (
        "enable_https_traffic_only",
        "min_tls_version",
        "public_network_access_enabled",
        "allow_blob_public_access",
        "enable_purge_protection",
        "enable_soft_delete",
        "soft_delete_retention_days",
        "enabled",
        "public_network_access_enabled",
        "network_acls",
        "default_action",
        "infrastructure_encryption_enabled",
        "customer_managed_key",
        "identity",
        "transparent_data_encryption_enabled",
        "auditing_policy",
        "threat_detection_policy",
        "administrator_login_password",
        "primary_access_key",
        "primary_connection_string",
        "primary_blob_endpoint",
    )
    return {k: v for k, v in (values or {}).items() if k in keys}


def diff_attributes(
    source_attrs: dict, state_attrs: dict, all_keys: list[str]
) -> list[dict]:
    """Return [{"attribute": k, "source": a, "state": b, "note": str}, ...]."""
    out = []
    for k in all_keys:
        a = source_attrs.get(k)
        b = state_attrs.get(k)
        if a == b:
            continue
        note = ""
        if _is_sensitive_marker(a) and not _is_sensitive_marker(b):
            note = "source deferred to state (likely ignore_changes)"
        elif not _is_sensitive_marker(a) and _is_sensitive_marker(b):
            note = "source had value, state marked sensitive"
        elif _is_sensitive_marker(a) and _is_sensitive_marker(b):
            continue  # both sensitive, no signal
        out.append({"attribute": k, "source": a, "state": b, "note": note})
    return out


def build_report(src_plan: dict, state_plan: dict) -> dict:
    """Return a structured drift report dict."""
    src_idx = _index_by_address(src_plan)
    state_idx = _index_by_address(state_plan)

    src_addrs = set(src_idx)
    state_addrs = set(state_idx)

    in_state_only = sorted(state_addrs - src_addrs)
    in_source_only = sorted(src_addrs - state_addrs)
    common = sorted(src_addrs & state_addrs)

    attribute_drift = []
    sensitive_findings = []
    for addr in common:
        s_vals = _index_values(src_idx[addr])
        t_vals = _index_values(state_idx[addr])
        interesting_keys = sorted(set(s_vals) | set(t_vals))
        interesting_keys = [
            k for k in interesting_keys
            if k in (
                "enable_https_traffic_only",
                "min_tls_version",
                "public_network_access_enabled",
                "allow_blob_public_access",
                "enable_purge_protection",
                "enable_soft_delete",
                "soft_delete_retention_days",
                "enabled",
                "default_action",
                "infrastructure_encryption_enabled",
                "transparent_data_encryption_enabled",
            )
        ]
        if not interesting_keys:
            continue
        diffs = diff_attributes(s_vals, t_vals, interesting_keys)
        if diffs:
            attribute_drift.append({"address": addr, "diffs": diffs})

        # Detect sensitive markers that materialize in state
        for k, v in s_vals.items():
            if _is_sensitive_marker(v) and not _is_sensitive_marker(t_vals.get(k)):
                sensitive_findings.append(
                    {
                        "address": addr,
                        "attribute": k,
                        "state_value_type": type(t_vals.get(k)).__name__,
                        "note": "Source plan markers <sensitive>; state has concrete value",
                    }
                )

    # Severity-ish summary
    summary = {
        "addresses_in_state_only": len(in_state_only),
        "addresses_in_source_only": len(in_source_only),
        "addresses_with_attribute_drift": len(attribute_drift),
        "sensitive_attribute_findings": len(sensitive_findings),
        "interpretation": _interpret(len(in_state_only), len(in_source_only), len(attribute_drift)),
    }
    return {
        "summary": summary,
        "address_in_state_only": in_state_only,
        "address_in_source_only": in_source_only,
        "attribute_drift": attribute_drift,
        "sensitive_findings": sensitive_findings,
    }


def _index_values(res: dict) -> dict:
    """Extract the values dict from a planned_values resource entry."""
    return res.get("values", {}) or {}


def _interpret(s: int, so: int, ad: int) -> str:
    if s == 0 and so == 0 and ad == 0:
        return "no drift; source plan matches state"
    if ad > 0:
        return "drift: ignore_changes is masking live changes; review attribute_drift"
    if s > 0:
        return "drift: resources exist in state but not in source; they will be destroyed on next apply"
    if so > 0:
        return "drift: resources in source but not in state; they will be created on next apply"
    return "see details"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source_plan", help="Path to terraform show -json plan.json")
    ap.add_argument("state_plan", help="Path to state_as_plan.json")
    ap.add_argument("out", help="Path to write drift_report.json")
    args = ap.parse_args()

    src = json.loads(Path(args.source_plan).read_text(encoding="utf-8"))
    state = json.loads(Path(args.state_plan).read_text(encoding="utf-8"))
    report = build_report(src, state)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"drift report: {args.out}")
    print(f"  summary: {report['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
