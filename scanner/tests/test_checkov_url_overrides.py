"""Test the per-rule checkov URL override map.

This is the single source of truth for canonical GitHub source URLs
that the scanner uses to replace the broken docs.prismacloud.io
helpUri in Checkov's SARIF output.
"""
import pytest
from checkov_url_overrides import (
    RULE_SOURCE_URLS,
    get_help_uri,
    build_sed_filter,
)


def test_every_url_is_github():
    """Every override must point to a github.com URL (canonical source)."""
    for rule_id, url in RULE_SOURCE_URLS.items():
        assert url.startswith("https://github.com/"), (
            f"{rule_id} points to {url!r}; expected github.com"
        )


def test_every_url_ends_with_file():
    """Every URL should resolve to a concrete file path, not a directory."""
    for rule_id, url in RULE_SOURCE_URLS.items():
        assert url.endswith((".py", ".yaml", ".yml")), (
            f"{rule_id} URL does not end with a file extension: {url}"
        )


def test_no_duplicate_rule_ids():
    """Each rule_id should appear exactly once."""
    rule_ids = list(RULE_SOURCE_URLS.keys())
    assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs in URL override map"


def test_every_url_is_unique():
    """Two rules sharing a URL is fine (e.g. CKV_SECRET_*), but verify
    that the set of URLs is consistent. Skip count assertion because
    CKV_SECRET_* legitimately share secrets/runner.py."""
    urls = list(RULE_SOURCE_URLS.values())
    # Allow duplicates but verify there's a healthy distribution
    assert len(set(urls)) >= len(urls) * 0.7, "Too many duplicate URLs"


def test_get_help_uri_uses_override():
    """When a rule is mapped, get_help_uri returns the override."""
    url = get_help_uri("CKV_AZURE_212", "https://docs.prismacloud.io/broken")
    assert url.startswith("https://github.com/bridgecrewio/checkov")
    assert url.endswith("StorageAccountHttpsOnly.py")


def test_get_help_uri_falls_back_to_upstream_when_not_prismacloud():
    """When a rule is unmapped and the upstream URL is NOT prismacloud.io,
    we preserve the upstream URL (the link might be valid)."""
    upstream = "https://example.com/rule/CKV_UNMAPPED_RULE"
    assert get_help_uri("CKV_UNMAPPED_RULE", upstream) == upstream


def test_get_help_uri_replaces_prismacloud_upstream_with_github_root():
    """When a rule is unmapped AND the upstream URL is prismacloud.io, we
    deliberately fall through to the GitHub repo root because that
    domain was retired in 2026 and the per-rule deep-links no longer
    resolve. Preserving a dead link would be a worse experience than
    pointing at the repo root."""
    upstream = "https://docs.prismacloud.io/some/rule"
    assert get_help_uri("CKV_UNMAPPED_RULE", upstream) == "https://github.com/bridgecrewio/checkov"


def test_get_help_uri_no_upstream_returns_github_root():
    """When a rule is unmapped AND no upstream, fall back to GitHub repo root."""
    url = get_help_uri("CKV_UNMAPPED_RULE", None)
    assert url == "https://github.com/bridgecrewio/checkov"


def test_sed_filter_rewrites_prismacloud():
    """The sed filter must replace docs.prismacloud.io URLs."""
    filter_expr = build_sed_filter()
    # The escape pattern uses backslashes; check for the host fragment.
    assert "prismacloud" in filter_expr
    assert "github.com" in filter_expr
    assert filter_expr.startswith("s|")  # sed substitution syntax


def test_sed_filter_for_aws_cloud_uses_aws_directory():
    """Generalized filter: AWS prefix must route to the aws/ directory,
    NOT the azure/ directory (the pre-T11 hard-coded fallback)."""
    filter_expr = build_sed_filter(cloud_prefix="AWS")
    assert "/checks/resource/aws/" in filter_expr
    assert "/checks/resource/azure/" not in filter_expr


def test_sed_filter_for_gcp_cloud_uses_gcp_directory():
    """Generalized filter: GCP prefix must route to the gcp/ directory."""
    filter_expr = build_sed_filter(cloud_prefix="GCP")
    assert "/checks/resource/gcp/" in filter_expr
    assert "/checks/resource/azure/" not in filter_expr


def test_sed_filter_for_kubernetes_cloud_uses_kubernetes_directory():
    """Generalized filter: K8S prefix must route to the kubernetes/ directory."""
    filter_expr = build_sed_filter(cloud_prefix="K8S")
    assert "/checks/resource/kubernetes/" in filter_expr
    assert "/checks/resource/azure/" not in filter_expr


def test_sed_filter_for_unknown_cloud_falls_back_to_repo_root():
    """Unknown cloud prefix: fall back to the Checkov GitHub repo root
    (no directory), NOT to the Azure directory."""
    filter_expr = build_sed_filter(cloud_prefix="ZZZ")
    # Repo root path: just the org/repo tree URL, no /checks/resource/<cloud>/
    assert "/checks/resource/" not in filter_expr
    assert "github.com/bridgecrewio/checkov/tree/main" in filter_expr


def test_sed_filter_without_cloud_prefix_still_renders():
    """Backward compat: build_sed_filter() with no args must still return
    a valid sed expression (the call sites in scan.sh / tests pass nothing)."""
    filter_expr = build_sed_filter()
    assert filter_expr.startswith("s|")
    assert filter_expr.endswith("|g")
    # Default (no cloud) -> falls through to repo root, not azure dir.
    assert "/checks/resource/" not in filter_expr or "azure" not in filter_expr


def test_sed_filter_preserves_prismacloud_anchor_for_all_clouds():
    """The upstream-host anchor (docs.prismacloud.io) must be present in
    the filter regardless of cloud prefix - that is the whole point of
    the rewrite."""
    for cloud in ("AWS", "AZURE", "GCP", "K8S", "ZZZ"):
        filter_expr = build_sed_filter(cloud_prefix=cloud)
        assert "prismacloud" in filter_expr, f"missing prisma anchor for {cloud}"


@pytest.mark.parametrize("cloud,expected_dir", [
    ("AWS", "aws"),
    ("AZURE", "azure"),
    ("GCP", "gcp"),
    ("K8S", "kubernetes"),
    ("LIN", "linode"),
    ("OPENSTACK", "openstack"),
])
def test_cloud_to_dir_mapping(cloud, expected_dir):
    """The CLOUD_TO_DIR dict must map the known Checkov cloud prefixes to
    their canonical directory names. The single dict is the single source
    of truth - no parallel string lists anywhere."""
    from checkov_url_overrides import CLOUD_TO_DIR
    assert CLOUD_TO_DIR[cloud] == expected_dir


def test_sed_filter_uses_id_parts_pattern_regex():
    r"""The ID_PARTS_PATTERN imported into checkov_url_overrides must be the
    SAME regex Checkov uses (r'([^_]*)_([^_]*)_(\d+)'). Redefining a local
    copy of the regex is forbidden by the plan - DRY/LIGHTWEIGHT rule (d)."""
    import re
    from checkov_url_overrides import ID_PARTS_PATTERN
    assert isinstance(ID_PARTS_PATTERN, re.Pattern)
    m = ID_PARTS_PATTERN.match("CKV_AZURE_13")
    assert m is not None
    assert m.group(1) == "CKV"
    assert m.group(2) == "AZURE"
    assert m.group(3) == "13"


@pytest.mark.parametrize("rule_id", [
    "CKV_AZURE_13", "CKV_AZURE_212", "CKV_AZURE_71",
    "CKV2_AZURE_21", "CKV_SECRET_3", "CKV_TF_1",
])
def test_smoke_check_known_rules(rule_id):
    """Smoke check: a hand-picked set of rules must resolve to GitHub."""
    url = get_help_uri(rule_id, None)
    assert url.startswith("https://github.com/bridgecrewio/checkov")
