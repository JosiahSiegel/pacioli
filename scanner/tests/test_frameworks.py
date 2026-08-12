"""Tests for scanner/frameworks.py — the framework identity registry.

Covers:
- SUPPORTED_FRAMEWORKS: live registry, snapshot against Checkov 3.3.9,
  and the 22-framework hardcoded fallback when the live import fails.
- FRAMEWORK_FILE_PATTERNS: shape and key coverage.
- TERRAFORM_FAMILY_FRAMEWORKS: exact membership (terraform + terraform_plan).
- is_terraform_family: tier-eligibility check.
- detect_frameworks: terraform / kubernetes / dockerfile / mixed / empty /
  missing-directory cases; tilde-stub exclusion.
- scan_mapping_packs: well-formed / broken YAML / empty / missing-dir.

The tests are hermetic — no real Checkov subprocess, no Azure subscription,
no network. The fallback test isolates ``_load_live_frameworks`` rather than
mutating :data:`SUPPORTED_FRAMEWORKS` at runtime.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the scanner package importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scanner.frameworks import (  # noqa: E402
    FRAMEWORK_FILE_PATTERNS,
    SUPPORTED_FRAMEWORKS,
    TERRAFORM_FAMILY_FRAMEWORKS,
    _HARDCODED_FRAMEWORKS,
    _load_live_frameworks,
    detect_frameworks,
    is_terraform_family,
    scan_mapping_packs,
)


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SNAPSHOT_PATH = FIXTURES_DIR / "checkov_runners_3.3.9.txt"


# ---------------------------------------------------------------------------
# SUPPORTED_FRAMEWORKS
# ---------------------------------------------------------------------------

def test_supported_frameworks_non_empty():
    """SUPPORTED_FRAMEWORKS must list at least the Checkov 3.3.x stable roster."""
    assert len(SUPPORTED_FRAMEWORKS) >= 20, (
        f"Only {len(SUPPORTED_FRAMEWORKS)} frameworks registered; expected >= 20"
    )


def test_supported_frameworks_includes_core_targets():
    """The four pillars (Terraform, CloudFormation, Kubernetes, Dockerfile) must be present."""
    for required in ("terraform", "cloudformation", "kubernetes", "dockerfile"):
        assert required in SUPPORTED_FRAMEWORKS, (
            f"{required!r} missing from SUPPORTED_FRAMEWORKS"
        )


def test_supported_frameworks_is_tuple_of_strings():
    """Type contract: a stable tuple of strings; safe to serialize and compare."""
    assert isinstance(SUPPORTED_FRAMEWORKS, tuple)
    for name in SUPPORTED_FRAMEWORKS:
        assert isinstance(name, str), f"{name!r} is not a string"


@pytest.mark.skipif(not SNAPSHOT_PATH.is_file(),
                    reason=f"snapshot fixture missing: {SNAPSHOT_PATH}")
def test_snapshot_checkov_runners():
    """Live import must match the snapshot of Checkov 3.3.9's checkov_runners."""
    expected = tuple(line.strip() for line in SNAPSHOT_PATH.read_text(
        encoding="utf-8").splitlines() if line.strip())
    assert SUPPORTED_FRAMEWORKS == expected, (
        f"SUPPORTED_FRAMEWORKS drifted from snapshot.\n"
        f"  got:  {SUPPORTED_FRAMEWORKS}\n"
        f"  want: {expected}\n"
        f"Regenerate fixtures/checkov_runners_3.3.9.txt when intentionally bumping."
    )


# ---------------------------------------------------------------------------
# FRAMEWORK_FILE_PATTERNS
# ---------------------------------------------------------------------------

def test_framework_file_patterns_is_dict():
    """Public FRAMEWORK_FILE_PATTERNS must be a dict[str, tuple[patterns, sniff|None]]."""
    assert isinstance(FRAMEWORK_FILE_PATTERNS, dict)
    for fw, entry in FRAMEWORK_FILE_PATTERNS.items():
        assert isinstance(fw, str)
        assert isinstance(entry, tuple)
        assert len(entry) == 2
        patterns, sniff = entry
        assert isinstance(patterns, tuple)
        for pat in patterns:
            assert isinstance(pat, str), f"non-string pattern in {fw!r}: {pat!r}"
            assert pat, f"empty pattern in {fw!r}"
        assert sniff is None or callable(sniff), f"bad sniff in {fw!r}: {sniff!r}"


def test_framework_file_patterns_contains_core_frameworks():
    """All four pillars must have an entry."""
    for required in ("terraform", "cloudformation", "kubernetes", "dockerfile"):
        assert required in FRAMEWORK_FILE_PATTERNS, (
            f"{required!r} missing from FRAMEWORK_FILE_PATTERNS"
        )


# ---------------------------------------------------------------------------
# TERRAFORM_FAMILY_FRAMEWORKS
# ---------------------------------------------------------------------------

def test_terraform_family_frameworks_is_frozenset():
    """frozenset is the contract — immutable, hashable, set-equivalent semantics."""
    assert isinstance(TERRAFORM_FAMILY_FRAMEWORKS, frozenset)


def test_terraform_family_frameworks_exact_membership():
    """Exactly terraform + terraform_plan. Nothing else."""
    assert TERRAFORM_FAMILY_FRAMEWORKS == frozenset({"terraform", "terraform_plan"})


# ---------------------------------------------------------------------------
# is_terraform_family
# ---------------------------------------------------------------------------

def test_is_terraform_family_true_cases():
    """terraform and terraform_plan are BOTH terraform-family."""
    assert is_terraform_family("terraform") is True
    assert is_terraform_family("terraform_plan") is True


def test_is_terraform_family_false_cases():
    """Non-terraform frameworks return False (not None, not raise)."""
    for non_tf in ("cloudformation", "kubernetes", "dockerfile", "bicep", "secrets"):
        assert is_terraform_family(non_tf) is False, (
            f"{non_tf!r} should not be terraform-family"
        )


def test_is_terraform_family_unknown_framework():
    """Unknown framework name returns False (no KeyError, no AttributeError)."""
    assert is_terraform_family("totally-bogus-framework") is False


# ---------------------------------------------------------------------------
# detect_frameworks
# ---------------------------------------------------------------------------

def test_detect_frameworks_terraform_dir(tmp_path: Path):
    """A dir with .tf files is detected as terraform."""
    (tmp_path / "main.tf").write_text('resource "null_resource" "x" {}')
    assert detect_frameworks(tmp_path) == {"terraform"}


def test_detect_frameworks_kubernetes_manifest(tmp_path: Path):
    """A dir with a *.yaml containing apiVersion: is detected as kubernetes."""
    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n")
    assert "kubernetes" in detect_frameworks(tmp_path)


def test_detect_frameworks_dockerfile(tmp_path: Path):
    """A dir with Dockerfile is detected as dockerfile."""
    (tmp_path / "Dockerfile").write_text("FROM alpine:3\nRUN true\n")
    assert detect_frameworks(tmp_path) == {"dockerfile"}


def test_detect_frameworks_bicep(tmp_path: Path):
    """A dir with a .bicep file is detected as bicep."""
    (tmp_path / "main.bicep").write_text("resource x 'x@2020' = {}")
    assert "bicep" in detect_frameworks(tmp_path)


def test_detect_frameworks_cloudformation_template(tmp_path: Path):
    """A *.template.yaml with AWSTemplateFormatVersion is detected as cloudformation."""
    (tmp_path / "app.template.yaml").write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\n'
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n")
    assert "cloudformation" in detect_frameworks(tmp_path)


def test_detect_frameworks_kubernetes_yaml_does_not_match_cfn(tmp_path: Path):
    """A K8s manifest is NOT classified as cloudformation (sniff disambiguates)."""
    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n")
    detected = detect_frameworks(tmp_path)
    assert "kubernetes" in detected
    assert "cloudformation" not in detected


def test_detect_frameworks_cfn_template_does_not_match_k8s(tmp_path: Path):
    """A CFN template is NOT classified as kubernetes (sniff disambiguates)."""
    (tmp_path / "app.template.yaml").write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\n'
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n")
    detected = detect_frameworks(tmp_path)
    assert "cloudformation" in detected
    assert "kubernetes" not in detected


def test_detect_frameworks_mixed_dir(tmp_path: Path):
    """A dir with .tf + Dockerfile + bicep detects all three."""
    (tmp_path / "main.tf").write_text("")
    (tmp_path / "Dockerfile").write_text("")
    (tmp_path / "main.bicep").write_text("")
    detected = detect_frameworks(tmp_path)
    assert {"terraform", "dockerfile", "bicep"}.issubset(detected)


def test_detect_frameworks_empty_dir(tmp_path: Path):
    """Empty dir returns empty set."""
    sub = tmp_path / "subdir"
    sub.mkdir()
    assert detect_frameworks(sub) == set()


def test_detect_frameworks_missing_dir(tmp_path: Path):
    """Missing dir returns empty set without raising."""
    assert detect_frameworks(tmp_path / "does-not-exist") == set()


def test_detect_frameworks_excludes_tilde_stub(tmp_path: Path):
    """Tilde-prefixed files are stubs (excluded; mirrors discovery.py semantics)."""
    (tmp_path / "~stub.tf").write_text("")
    assert detect_frameworks(tmp_path) == set()


def test_detect_frameworks_unrelated_files(tmp_path: Path):
    """Random non-IaC files produce no false positives."""
    (tmp_path / "README.md").write_text("# nope")
    (tmp_path / "script.py").write_text("print('hi')")
    (tmp_path / "config.json").write_text("{}")
    assert detect_frameworks(tmp_path) == set()


# ---------------------------------------------------------------------------
# scan_mapping_packs
# ---------------------------------------------------------------------------

def test_scan_mapping_packs_real_mappings_dir():
    """The repo's actual mappings/ dir contains the PCI pack."""
    repo_root = Path(__file__).resolve().parents[2]
    packs = scan_mapping_packs(repo_root / "mappings")
    assert packs, "expected at least one pack in repo mappings/"
    pci = next((p for p in packs if p["key"] == "pci_dss_4.0.1"), None)
    assert pci is not None, "PCI DSS v4.0.1 pack not found"
    assert pci["filename"] == "pci_dss_4.0.1.yaml"
    assert pci["status"] == "shipped"
    # label uses framework_name from YAML, not the stem
    assert pci["label"] == "PCI DSS"


def test_scan_mapping_packs_empty_dir(tmp_path: Path):
    """Empty mappings dir returns empty list."""
    assert scan_mapping_packs(tmp_path) == []


def test_scan_mapping_packs_missing_dir(tmp_path: Path):
    """Missing dir returns empty list without raising."""
    assert scan_mapping_packs(tmp_path / "nope") == []


def test_scan_mapping_packs_skips_broken_yaml(tmp_path: Path):
    """Malformed YAML is silently skipped — never raises."""
    (tmp_path / "good.yaml").write_text(
        "framework_name: Good Framework\nversion: 1\n", encoding="utf-8")
    (tmp_path / "broken.yaml").write_text(
        "framework_name: Broken\n: [unterminated\n", encoding="utf-8")
    packs = scan_mapping_packs(tmp_path)
    keys = [p["key"] for p in packs]
    assert "good" in keys
    assert "broken" not in keys


def test_scan_mapping_packs_skips_non_dict_yaml(tmp_path: Path):
    """YAML that parses to a non-dict (e.g., a list) is silently skipped."""
    (tmp_path / "list.yaml").write_text("- a\n- b\n", encoding="utf-8")
    (tmp_path / "dict.yaml").write_text("framework_name: Foo\n", encoding="utf-8")
    packs = scan_mapping_packs(tmp_path)
    keys = [p["key"] for p in packs]
    assert keys == ["dict"], f"expected only the dict pack; got {keys}"


def test_scan_mapping_packs_label_fallback(tmp_path: Path):
    """When framework_name is missing, the stem is title-cased as the label."""
    (tmp_path / "my_custom_pack.yaml").write_text("version: 1\n", encoding="utf-8")
    packs = scan_mapping_packs(tmp_path)
    assert len(packs) == 1
    assert packs[0]["key"] == "my_custom_pack"
    assert packs[0]["label"] == "My Custom Pack"


def test_scan_mapping_packs_sorted_output(tmp_path: Path):
    """Output is sorted alphabetically for stable picker menu rendering."""
    for name in ("zeta.yaml", "alpha.yaml", "mu.yaml"):
        (tmp_path / name).write_text("framework_name: X\n", encoding="utf-8")
    keys = [p["key"] for p in scan_mapping_packs(tmp_path)]
    assert keys == ["alpha", "mu", "zeta"]


def test_scan_mapping_packs_status_shipped(tmp_path: Path):
    """Every discovered pack has status='shipped'."""
    (tmp_path / "a.yaml").write_text("framework_name: A\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("version: 1\n", encoding="utf-8")  # no framework_name
    packs = scan_mapping_packs(tmp_path)
    assert all(p["status"] == "shipped" for p in packs)


# ---------------------------------------------------------------------------
# Fallback behavior (broken live import)
# ---------------------------------------------------------------------------

def test_fallback_on_import_error(monkeypatch: pytest.MonkeyPatch):
    """When checkov_runners import fails, _load_live_frameworks returns the hardcoded list."""
    # Force the import to fail by removing checkov from sys.modules and blocking reimport.
    saved = {k: v for k, v in sys.modules.items() if k.startswith("checkov")}
    monkeypatch.delitem(sys.modules, "checkov.common.bridgecrew.check_type", raising=False)
    # Make the inner ``from checkov.common.bridgecrew.check_type import checkov_runners``
    # raise ImportError on the next attempt.
    import builtins as _b
    real_import = _b.__import__

    def _blocking_import(name, *args, **kwargs):
        if name == "checkov.common.bridgecrew.check_type" or name.startswith(
                "checkov.common.bridgecrew.check_type"):
            raise ImportError("simulated checkov import failure")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(_b, "__import__", _blocking_import)
    try:
        with pytest.warns(UserWarning, match="could not import checkov_runners"):
            result = _load_live_frameworks()
        assert result == _HARDCODED_FRAMEWORKS
    finally:
        # Restore so other tests don't see the monkeypatch.
        for k, v in saved.items():
            sys.modules[k] = v


def test_fallback_on_non_iterable(monkeypatch: pytest.MonkeyPatch):
    """When checkov_runners is not iterable, _load_live_frameworks falls back."""
    class FakeCheckType:
        @staticmethod
        def checkov_runners():
            return None  # not a list/tuple/set — would crash iteration

    fake_module = type(sys)("checkov_fake")
    fake_module.checkov_runners = "not-iterable-string"
    monkeypatch.setitem(sys.modules, "checkov.common.bridgecrew.check_type", fake_module)
    try:
        with pytest.warns(UserWarning, match="not iterable"):
            result = _load_live_frameworks()
        assert result == _HARDCODED_FRAMEWORKS
    finally:
        monkeypatch.delitem(sys.modules, "checkov.common.bridgecrew.check_type", raising=False)
