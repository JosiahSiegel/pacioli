"""Regression coverage for scan-scope and report-view documentation."""
from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_scope_and_report_view_guides_name_evidence_boundaries() -> None:
    """Document the distinct scan-scope and browser report-view contracts."""
    report_format = (_REPO_ROOT / "docs" / "REPORT_FORMAT.md").read_text(encoding="utf-8")
    operator_guide = (_REPO_ROOT / "docs" / "OPERATOR_GUIDE.md").read_text(encoding="utf-8")
    consuming_guide = (_REPO_ROOT / "docs" / "CONSUMING_GUIDE.md").read_text(encoding="utf-8")

    combined_guides = "\n".join((report_format, operator_guide, consuming_guide))

    assert "structured-only `envs` records" in operator_guide
    assert "omitted at scan time" in combined_guides
    assert "client-side report-view-only exclusion" in combined_guides
    assert "SARIF, CSV, and JUnit evidence remains unchanged" in combined_guides
    assert "Dark default" in report_format
    assert "Dark, Light, and System" in report_format
    assert "browser-local persistence" in report_format
    assert "scan scope" in operator_guide
    assert "report view" in operator_guide
    assert "scan scope" in consuming_guide
    assert "report view" in consuming_guide
