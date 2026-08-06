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


@pytest.mark.parametrize("rule_id", [
    "CKV_AZURE_13", "CKV_AZURE_212", "CKV_AZURE_71",
    "CKV2_AZURE_21", "CKV_SECRET_3", "CKV_TF_1",
])
def test_smoke_check_known_rules(rule_id):
    """Smoke check: a hand-picked set of rules must resolve to GitHub."""
    url = get_help_uri(rule_id, None)
    assert url.startswith("https://github.com/bridgecrewio/checkov")
