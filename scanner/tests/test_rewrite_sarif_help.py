"""Test the SARIF helperUri rewriter.

The rewriter walks a SARIF file and replaces broken docs.prismacloud.io
helpUri values with canonical GitHub source URLs.
"""
import json
from pathlib import Path

import pytest

from rewrite_sarif_help import rewrite_sarif


def _write_sarif(tmp_path: Path, rules: list[dict]) -> Path:
    """Helper: write a SARIF v2.1.0 file with the given rules."""
    path = tmp_path / "test.sarif"
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "checkov",
                        "version": "3.3.9",
                        "rules": rules,
                    }
                },
                "results": [],
            }
        ],
    }
    path.write_text(json.dumps(sarif), encoding="utf-8")
    return path


def test_rewrite_replaces_prismacloud_with_github(tmp_path):
    """A SARIF with broken prismacloud URL gets the canonical GitHub URL."""
    path = _write_sarif(tmp_path, [
        {"id": "CKV_AZURE_212",
         "helpUri": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/azure-policies/bc-azr-general-42"},
    ])
    rewritten, skipped = rewrite_sarif(path)
    assert rewritten == 1
    assert skipped == 0
    data = json.loads(path.read_text())
    uri = data["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]
    assert uri.startswith("https://github.com/bridgecrewio/checkov")
    assert "StorageAccountHttpsOnly.py" in uri


def test_rewrite_keeps_unmapped_rule_uri(tmp_path):
    """An unmapped rule keeps its upstream helpUri."""
    upstream = "https://docs.prismacloud.io/whatever/CKV_FAKE_99"
    path = _write_sarif(tmp_path, [
        {"id": "CKV_FAKE_99", "helpUri": upstream},
    ])
    rewritten, skipped = rewrite_sarif(path)
    assert rewritten == 0
    assert skipped == 1
    data = json.loads(path.read_text())
    assert data["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"] == upstream


def test_rewrite_is_idempotent(tmp_path):
    """Running twice yields the same result."""
    path = _write_sarif(tmp_path, [
        {"id": "CKV_AZURE_212", "helpUri": "https://docs.prismacloud.io/x"},
    ])
    rewrite_sarif(path)
    first = json.loads(path.read_text())
    rewrite_sarif(path)
    second = json.loads(path.read_text())
    assert first == second


def test_rewrite_handles_missing_runs(tmp_path):
    """A SARIF with no 'runs' array is a no-op."""
    path = tmp_path / "bad.sarif"
    path.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")
    rewritten, skipped = rewrite_sarif(path)
    assert rewritten == 0
    assert skipped == 0


def test_rewrite_handles_mixed_rules(tmp_path):
    """A mix of mapped, unmapped, and already-correct rules."""
    path = _write_sarif(tmp_path, [
        {"id": "CKV_AZURE_212", "helpUri": "https://docs.prismacloud.io/x"},
        {"id": "CKV_FAKE_99", "helpUri": "https://docs.prismacloud.io/y"},
        {"id": "CKV_AZURE_44", "helpUri": "https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountMinTlsVersion.py"},
    ])
    rewritten, skipped = rewrite_sarif(path)
    assert rewritten == 1  # CKV_AZURE_212 only
    assert skipped == 2  # CKV_FAKE_99 (unmapped) + CKV_AZURE_44 (already correct)
    data = json.loads(path.read_text())
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["helpUri"].startswith("https://github.com/")
    assert rules[1]["helpUri"] == "https://docs.prismacloud.io/y"
    assert rules[2]["helpUri"].startswith("https://github.com/")


def test_main_with_no_args(tmp_path, monkeypatch, capsys):
    """Calling main with no args prints usage and exits 64."""
    import sys
    monkeypatch.setattr(sys, "argv", ["rewrite_sarif_help"])
    from rewrite_sarif_help import main
    rc = main()
    assert rc == 64
    captured = capsys.readouterr()
    assert "Usage" in captured.err


def test_main_with_missing_file(tmp_path, monkeypatch, capsys):
    """Missing file is an error but doesn't crash."""
    import sys
    monkeypatch.setattr(sys, "argv", ["rewrite_sarif_help", "/nonexistent.sarif"])
    from rewrite_sarif_help import main
    rc = main()
    assert rc == 0  # exits 0 because we just print an error, not raise
    captured = capsys.readouterr()
    assert "does not exist" in captured.err
