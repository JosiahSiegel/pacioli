"""Framework identity registry — SINGLE SOURCE OF TRUTH.

All framework logic (file patterns, tier eligibility, supported list,
mapping pack scanning) lives here. Other modules MUST import from this
module rather than re-declaring framework literals. Zero new third-party
deps; a broken Checkov import degrades gracefully to a 22-framework
hardcoded fallback rather than crashing the scanner.
"""
from __future__ import annotations

import warnings
from pathlib import Path
from typing import Callable

import yaml

# --- SUPPORTED_FRAMEWORKS ---------------------------------------------------
_HARDCODED_FRAMEWORKS: tuple[str, ...] = (
    "terraform", "terraform_plan", "secrets", "cloudformation", "kubernetes",
    "dockerfile", "arm", "bicep", "helm", "kustomize", "openapi", "serverless",
    "github_configuration", "github_actions", "gitlab_configuration",
    "gitlab_ci", "bitbucket_configuration", "bitbucket_pipelines",
    "circleci_pipelines", "azure_pipelines", "argo_workflows", "ansible",
)


def _load_live_frameworks() -> tuple[str, ...]:
    """Return Checkov's ``checkov_runners`` sorted; fall back to hardcoded list."""
    try:
        from checkov.common.bridgecrew.check_type import checkov_runners  # noqa
    except (ImportError, AttributeError, TypeError):
        warnings.warn("scanner.frameworks: could not import checkov_runners; "
                      "falling back to the 22-framework hardcoded list.", stacklevel=2)
        return _HARDCODED_FRAMEWORKS
    if not isinstance(checkov_runners, (list, tuple, set, frozenset)):
        warnings.warn(f"scanner.frameworks: checkov_runners not iterable "
                      f"({type(checkov_runners).__name__}); falling back.", stacklevel=2)
        return _HARDCODED_FRAMEWORKS
    return tuple(sorted(str(n) for n in checkov_runners))


#: Live tuple of frameworks Checkov supports. Import this everywhere.
SUPPORTED_FRAMEWORKS: tuple[str, ...] = _load_live_frameworks()


# --- TERRAFORM_FAMILY_FRAMEWORKS --------------------------------------------
#: SINGLE SOURCE OF TRUTH for tier eligibility — use is_terraform_family().
TERRAFORM_FAMILY_FRAMEWORKS: frozenset[str] = frozenset(
    {"terraform", "terraform_plan"})

#: Frameworks excluded from auto-detection (``secrets`` has pattern ``("*",)``
#: so every file matches).
_DETECT_EXCLUDED: frozenset[str] = frozenset({"secrets"})


# --- SARIF property name contract ---------------------------------------------
# Single source of truth for the property NAMES emitted on the SARIF
# ``run.properties`` bag by ``write_combined_sarif`` and read by
# ``baseline_init._collect_stub_pairs``. Pre-T7 these were named with a
# ``pci_`` prefix (PCI-specific). The names now describe the data
# generically so SOC 2 / CIS / NIST packs can reuse the same contract.
SARIF_PROPERTY_PROJECT: str = "project"
SARIF_PROPERTY_ENV: str = "env"
SARIF_PROPERTY_SOURCE_SARIF: str = "source_sarif"

# --- HTML report data-attribute / DOM-id name contract ------------------------
# The HTML report uses a single requirement-id field across the
# filter UI, the heatmap, and the cross-filter state. Pre-T7 this was
# named ``pciReq`` (and its DOM siblings ``pci-req-filter``,
# ``global-pci``, ``saved.pci``, ``FILTER.pci``). The single source of
# truth is here so the CSS class, the dataset key, the JS global
# state, and the cookie key all line up. SOC 2 / CIS / NIST packs no
# longer have to fork these names.
REQUIREMENT_DATA_ATTR: str = "data-req"
REQUIREMENT_FILTER_ID: str = "req-filter"
REQUIREMENT_GLOBAL_FILTER_ID: str = "global-req"
REQUIREMENT_FILTER_COOKIE_KEY: str = "pacioli_req"
REQUIREMENT_FILTER_STATE_KEY: str = "req"


def is_terraform_family(framework: str) -> bool:
    """True iff ``framework`` supports the plan/state scan tiers."""
    return framework in TERRAFORM_FAMILY_FRAMEWORKS


# --- FRAMEWORK_FILE_PATTERNS -------------------------------------------------
def _scan_head(path: Path, predicate: Callable[[str], bool], n: int = 40) -> bool:
    """Apply ``predicate`` to each of the first ``n`` lines; return first match."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for _ in range(n):
                line = fh.readline()
                if not line:
                    return False
                if predicate(line):
                    return True
        return False
    except OSError:
        return False


def _sniff_cloudformation(path: Path) -> bool:
    """CFN heuristic: ``AWSTemplateFormatVersion`` or top-level ``Resources:``."""
    return _scan_head(path,
        lambda ln: "AWSTemplateFormatVersion" in ln or ln.lstrip().startswith("Resources:"), n=20)


def _sniff_kubernetes(path: Path) -> bool:
    """K8s heuristic: top-level ``apiVersion:`` or ``kind:``."""
    return _scan_head(path, lambda ln: ln.startswith("apiVersion:") or ln.startswith("kind:"))


def _sniff_argo(path: Path) -> bool:
    """Argo heuristic: contains ``argoproj.io/`` (vs. generic K8s YAML)."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return "argoproj.io/" in fh.read(8192)
    except OSError:
        return False


#: Per-framework ``(glob_patterns, sniff_callable_or_None)``. Sniff resolves
#: ambiguous extensions (e.g. ``.yaml`` is used by both Kubernetes and CFN).
#: Read-only contract — do not mutate at runtime.
FRAMEWORK_FILE_PATTERNS: dict[str, tuple[tuple[str, ...], Callable[[Path], bool] | None]] = {
    "terraform": (("*.tf", "*.tf.json", "*.tfvars"), None),
    "terraform_plan": (("*.tfplan", "tfplan.json"), None),
    "cloudformation": (("*.template.json", "*.template.yaml", "*.template.yml"), _sniff_cloudformation),
    "kubernetes": (("*.yaml", "*.yml"), _sniff_kubernetes),
    "dockerfile": (("Dockerfile*", "*.dockerfile", "Dockerfile.*"), None),
    "arm": (("azuredeploy*.json", "azuredeploy.*.json", "arm*.json"), None),
    "bicep": (("*.bicep",), None),
    "helm": (("Chart.yaml", "values.yaml", "*.tgz"), None),
    "kustomize": (("kustomization.yaml", "kustomization.yml", "kustomization.*.yaml"), None),
    "openapi": (("openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json"), None),
    "serverless": (("serverless.yml", "serverless.yaml", "serverless.json"), None),
    "secrets": (("*",), None),  # secrets scans every text file
    "github_configuration": ((".github/*.yml", ".github/*.yaml", ".github/*.json"), None),
    "github_actions": ((".github/workflows/*.yml", ".github/workflows/*.yaml"), None),
    "gitlab_configuration": ((".gitlab/*.yml", ".gitlab/*.yaml"), None),
    "gitlab_ci": ((".gitlab-ci.yml", ".gitlab-ci.yaml"), None),
    "bitbucket_configuration": (("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"), None),
    "bitbucket_pipelines": (("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"), None),
    "circleci_pipelines": ((".circleci/config.yml", ".circleci/config.yaml"), None),
    "azure_pipelines": (("azure-pipelines.yml", "azure-pipelines.yaml"), None),
    "argo_workflows": (("*.yaml", "*.yml"), _sniff_argo),
    "ansible": (("playbook.yml", "playbook.yaml"), None),
}


# --- detect_frameworks ------------------------------------------------------
def _file_matches_framework(path: Path, framework: str) -> bool:
    """True iff ``path`` is a candidate for ``framework`` (glob + sniff).

    Tilde-prefixed files are excluded — they are stubs, mirroring
    ``discovery._has_real_tf_files`` semantics.
    """
    if path.name.startswith("~"):
        return False
    patterns, sniff = FRAMEWORK_FILE_PATTERNS.get(framework, ((), None))
    if not any(path.match(p) for p in patterns):
        return False
    if sniff is None:
        return True
    try:
        return bool(sniff(path))
    except (OSError, UnicodeDecodeError):
        return False


def detect_frameworks(env_dir: Path) -> set[str]:
    """Return frameworks whose files appear at the top of ``env_dir``.

    The ONLY directory scanner for framework detection. Empty/missing dirs
    return an empty set. Frameworks in :data:`_DETECT_EXCLUDED` (``secrets``)
    are skipped — their ``("*",)`` pattern matches every file.
    """
    env_dir = Path(env_dir)
    if not env_dir.is_dir():
        return set()
    detected: set[str] = set()
    for entry in env_dir.iterdir():
        if entry.is_file():
            for fw in SUPPORTED_FRAMEWORKS:
                if fw not in _DETECT_EXCLUDED and _file_matches_framework(entry, fw):
                    detected.add(fw)
    return detected


# --- scan_mapping_packs -----------------------------------------------------
def scan_mapping_packs(mappings_dir: Path) -> list[dict[str, str]]:
    """Enumerate mapping-pack YAMLs in ``mappings_dir`` for the first-run picker.

    Each returned dict has keys ``key`` (stem), ``label`` (from the pack's
    ``framework_name`` or stem title-cased), ``filename``, and ``status``
    (always ``"shipped"``). Broken YAML is skipped silently.
    """
    mappings_dir = Path(mappings_dir)
    if not mappings_dir.is_dir():
        return []
    packs: list[dict[str, str]] = []
    for yaml_path in sorted(mappings_dir.glob("*.yaml")):
        try:
            with yaml_path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue
        stem = yaml_path.stem
        fw_name = data.get("framework_name")
        if isinstance(fw_name, str) and fw_name.strip():
            label = fw_name
        else:
            label = stem.replace("_", " ").title()
        packs.append({"key": stem, "label": label,
                      "filename": yaml_path.name, "status": "shipped"})
    return packs


__all__ = ["FRAMEWORK_FILE_PATTERNS", "SUPPORTED_FRAMEWORKS",
           "TERRAFORM_FAMILY_FRAMEWORKS", "detect_frameworks",
           "is_terraform_family", "scan_mapping_packs",
           "SARIF_PROPERTY_PROJECT", "SARIF_PROPERTY_ENV",
           "SARIF_PROPERTY_SOURCE_SARIF",
           "REQUIREMENT_DATA_ATTR", "REQUIREMENT_FILTER_ID",
           "REQUIREMENT_GLOBAL_FILTER_ID",
           "REQUIREMENT_FILTER_COOKIE_KEY", "REQUIREMENT_FILTER_STATE_KEY"]
