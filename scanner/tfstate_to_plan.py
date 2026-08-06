"""Convert a Terraform state JSON file into the plan JSON shape Checkov expects.

Why: Checkov OSS cannot scan .tfstate files directly (verified Aug 2026;
the `terraform` runner hard-rejects anything that isn't `.tf`/`.hcl`, and
the `terraform_plan` runner requires the post-apply plan schema). However,
the *attributes* in state are the most accurate reflection of Azure reality
(after data sources, refresh, and remote-only changes that bypass Terraform),
which is exactly the ignore_changes drift we want to catch.

This converter reads a state JSON blob, extracts the resource attributes,
and emits a JSON document shaped like a `terraform show -json plan` output:

    {
      "format_version": "1.0",
      "terraform_version": "1.x.x",
      "resource_changes": [
        {
          "address": "module.foo.azurerm_storage_account.bar",
          "type": "azurerm_storage_account",
          "name": "bar",
          "change": { "after": {...attributes...}, "before": null },
          "mode": "managed"
        }
      ],
      "planned_values": {
        "root_module": {
          "resources": [...],
          "child_modules": [...]
        }
      }
    }

The shape is intentionally minimal — enough to satisfy Checkov's parser
without fabricating provider metadata we don't have. We DO set enough
fields that Checkov walks the resource and applies its resource-graph
rules.

Usage:
  python tfstate_to_plan.py <state.tfstate> <out.plan.json> [--source azure]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _walk_state_resources(state: dict) -> list[dict]:
    """Extract resource definitions from a Terraform state JSON object.

    State schema we handle:
      - top-level 'resources' (legacy + flat)
      - 'outputs' (passed through to planned_values.outputs)
    """
    out = []
    for res in state.get("resources", []):
        # Skip data sources (mode == "data")
        if res.get("mode") == "data":
            continue
        module = res.get("module", "")
        for inst in res.get("instances", []):
            # Nested indices: instances may have index_key for count/for_each
            idx_key = inst.get("index_key")
            idx_suffix = (
                f"[{idx_key}]" if idx_key is not None and not isinstance(idx_key, str)
                else f'["{idx_key}"]' if idx_key is not None else ""
            )
            address = f"{module}.{res['type']}.{res['name']}{idx_suffix}".lstrip(".")
            attrs = inst.get("attributes", {}) or {}
            # Flattened attributes (azurerm v4 single-attribute dict wrapping)
            attrs = _flatten_attributes(attrs)
            out.append(
                {
                    "address": address,
                    "mode": "managed",
                    "type": res["type"],
                    "name": res["name"] + idx_suffix,
                    "provider_name": _infer_provider(res["type"]),
                    "schema_version": 0,
                    "values": attrs,
                }
            )
    return out


def _flatten_attributes(attrs: dict) -> dict:
    """Flatten single-key wrapping dictionaries that azurerm v4 sometimes uses.

    Example: {"primary_blob_endpoint": {"value": "https://..."}} -> {"primary_blob_endpoint": "https://..."}
    """
    out = {}
    for k, v in attrs.items():
        if isinstance(v, dict) and len(v) == 1 and "value" in v:
            out[k] = v["value"]
        else:
            out[k] = v
    return out


def _infer_provider(resource_type: str) -> str:
    """Map Terraform resource type to provider name."""
    if resource_type.startswith("azurerm"):
        return "registry.terraform.io/hashicorp/azurerm"
    if resource_type.startswith("azapi"):
        return "registry.terraform.io/azure/azapi"
    if resource_type.startswith("azuread"):
        return "registry.terraform.io/hashicorp/azuread"
    if resource_type.startswith("external"):
        return "registry.terraform.io/hashicorp/external"
    if resource_type.startswith("http"):
        return "registry.terraform.io/hashicorp/http"
    return ""


def _build_resource_changes(planned: list[dict]) -> list[dict]:
    """Mirror planned_values into resource_changes so Checkov graph rules fire."""
    out = []
    for r in planned:
        out.append(
            {
                "address": r["address"],
                "mode": r["mode"],
                "type": r["type"],
                "name": r["name"],
                "provider_name": r["provider_name"],
                "change": {
                    "actions": ["no-op"],
                    "before": None,
                    "after": r["values"],
                    "after_unknown": {},
                },
            }
        )
    return out


def _build_child_modules(root_resources: list[dict]) -> list[dict]:
    """Group resources by module path so Checkov's module graph sees nested deps.

    `module.foo.azurerm_storage_account.bar` -> child_modules[foo] -> resources[]
    """
    modules: dict[str, dict[str, list[dict]]] = {}
    no_module: list[dict] = []
    for r in root_resources:
        addr = r["address"]
        if "." in addr:
            # First component is the module name (or a module path)
            parts = addr.split(".")
            # Convention: if first part starts with "module_", it's a module path
            # but typical azurerm resources don't have that prefix. Easiest:
            # we treat the address itself as opaque and group by ALL leading
            # "module.<name>." prefixes.
            if addr.startswith("module."):
                # module.foo.module.bar.azurerm_x.y
                # parse leading module path
                mod_parts = []
                i = 1  # skip "module"
                while i < len(parts) and parts[i] != r["type"]:
                    mod_parts.append(parts[i])
                    i += 2  # skip "module" markers
                mod_path = ".".join(mod_parts)
                if mod_path not in modules:
                    modules[mod_path] = {}
                res_addr = ".".join(parts[i:])
                modules[mod_path].setdefault(res_addr, []).append(r)
                continue
        no_module.append(r)
    # Build nested module tree
    out = []
    for mod_path, _res_by_addr in modules.items():
        # Keep it flat: one child_module per top-level module path
        # (deeper nesting is rare in this repo)
        out.append(
            {
                "address": f"module.{mod_path}",
                "resources": _res_by_addr,  # may repeat across deeper paths; OK for scan
                "module_address": f"module.{mod_path}",
            }
        )
    return out


def convert(state_path: Path) -> dict:
    """Read a state JSON and return a plan-JSON-shaped dict."""
    state = json.loads(state_path.read_text(encoding="utf-8"))
    planned = _walk_state_resources(state)
    child_modules = _build_child_modules(planned)
    # Resources with no module prefix go to root_module.resources
    root_resources = [r for r in planned if not r["address"].startswith("module.")]

    return {
        "format_version": "1.0",
        "terraform_version": state.get("terraform_version", "1.0.0"),
        "resource_changes": _build_resource_changes(planned),
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": r["address"],
                        "mode": r["mode"],
                        "type": r["type"],
                        "name": r["name"],
                        "provider_name": r["provider_name"],
                        "schema_version": r["schema_version"],
                        "values": r["values"],
                    }
                    for r in root_resources
                ],
                "child_modules": child_modules,
            }
        },
        "configuration": {
            "provider_config": {},
            "root_module": {},
        },
        "outputs": state.get("outputs", {}),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("state", help="Path to .tfstate file")
    ap.add_argument("out", help="Path to write plan-shaped JSON")
    args = ap.parse_args()

    state_path = Path(args.state)
    out_path = Path(args.out)
    if not state_path.exists():
        print(f"ERROR: state file not found: {state_path}", file=sys.stderr)
        return 2

    plan = convert(state_path)
    out_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"converted: {state_path} -> {out_path}")
    print(f"  resources: {len(plan['resource_changes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
