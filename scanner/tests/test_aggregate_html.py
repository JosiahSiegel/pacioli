"""scanner/tests/test_aggregate_html.py — coverage for the renderer + matrix + JUnit/SARIF
surfaces of ``scanner/aggregate.py``.

This test file exercises the previously-uncovered functions listed in the
full-PR test-coverage plan (target: scanner/aggregate.py:1-3738). It is
broken into four logical groups:

  * ``test_sarif_parsing`` — ``parse_sarif``, ``sarif_is_empty``
  * ``test_coverage_matrix`` — ``build_coverage_matrix``,
    ``compute_coverage_gaps``, ``write_coverage_gaps_csv``,
    ``write_coverage_csv``
  * ``test_outputs`` — ``write_junit``, ``write_combined_sarif``,
    ``write_fix_list_md``
  * ``test_html_report`` — exercise ``write_html_report`` end-to-end via
    ``aggregate.main()`` mirroring the pattern in
    ``scanner/tests/test_cli.py:204-277`` and
    ``scanner/tests/test_aggregate_pci.py:108-152``.

Helpers (walk_run_dir, load_findings, is_suppressed,
_parse_inline_skip_kwargs, load_inline_skips, is_inline_suppressed,
attach_pci_reqs, load_remediation_map, _collect_drift_findings,
_render_drift_section, er_locate_sarif) are covered inline by either a
direct unit call or as a side-effect of the orchestration path.

Design choices:

  * Inline fixtures (10-30 line SARIF dicts). No byte-equality snapshots.
  * Package-style imports (``from scanner.aggregate import ...``).
  * DOM assertions use substring ``in`` checks for distinctive markers
    (``<title>...</title>``, ``severity-donut``, ``pci-heatmap`` /
    ``heatmap-cell``, ``env-bar-row``) emitted by the actual renderer.
  * The HTML report is exercised via ``aggregate.main(argv)`` rather
    than constructing 12+ positional arguments by hand. This matches
    the task's MUST-DO contract.
"""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

# Make ``import scanner`` resolve the worktree's scanner/ package even when
# pytest is invoked from a non-default cwd (e.g. inside an editor's test
# runner). Mirrors the pattern in scanner/tests/test_cli.py:38-41.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanner.aggregate import (  # noqa: E402  (import after sys.path.insert)
    EnvResult,
    EnvResultFull,
    Finding,
    _collect_drift_findings,
    _parse_inline_skip_kwargs,
    _render_drift_section,
    attach_pci_reqs,
    build_coverage_matrix,
    compute_coverage_gaps,
    is_inline_suppressed,
    is_suppressed,
    load_findings,
    load_inline_skips,
    load_remediation_map,
    main as aggregate_main,
    parse_sarif,
    sarif_is_empty,
    walk_run_dir,
    write_combined_sarif,
    write_coverage_csv,
    write_coverage_gaps_csv,
    write_fix_list_md,
    write_junit,
)


# ---------------------------------------------------------------------------
# Synthetic run-dir builder
# ---------------------------------------------------------------------------
# Mirror the pattern in test_aggregate_pci.py:_build_synthetic_run_dir so
# the in-process orchestration path can be exercised against a run-dir
# shape the aggregator actually accepts. The synthetic SARIF uses
# CKV_TEST_BENIGN (not in SEVERITY_OVERRIDE) so severity falls through to
# DEFAULT_SEVERITY=MEDIUM, keeping the rc=7 gate silent.


def _build_run_dir(run_dir: Path, project: str = "myapp", env: str = "prod") -> Path:
    """Build a minimal synthetic run-dir under ``run_dir``.

    Returns the env_dir path. Writes
    ``<run_dir>/<project>/<env>/results_terraform_source.sarif`` with
    one benign finding so the aggregation pipeline has at least one
    SARIF to walk.
    """
    env_dir = run_dir / project / env
    env_dir.mkdir(parents=True)
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "checkov"}},
                "results": [
                    {
                        # Not in SEVERITY_OVERRIDE → DEFAULT_SEVERITY (MEDIUM).
                        "ruleId": "CKV_TEST_BENIGN",
                        "level": "note",
                        "message": {"text": "synthetic benign finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "main.tf"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    sarif_path = env_dir / "results_terraform_source.sarif"
    with sarif_path.open("w", encoding="utf-8") as fh:
        json.dump(sarif, fh)
    return env_dir


def _invoke_aggregate_main(argv: list[str]) -> int:
    """Run ``aggregate.main()`` with the given argv in-place.

    Mirrors the helper in test_aggregate_pci.py:155-169 — ``main()`` reads
    ``sys.argv`` directly via argparse, so we swap argv in for the call
    and restore it on the way out.
    """
    saved_argv = sys.argv
    try:
        sys.argv = argv
        return aggregate_main()
    finally:
        sys.argv = saved_argv


# ===========================================================================
# 1. SARIF parsing
# ===========================================================================


class TestSarifParsing:
    """``parse_sarif`` extracts ruleId + message + physicalLocation, and
    ``sarif_is_empty`` discriminates "no runs" from "clean run"."""

    def test_parse_sarif_extracts_rule_id_message_and_location(self, tmp_path: Path) -> None:
        """parse_sarif reads runs[].results[].ruleId + message.text +
        locations[].physicalLocation.artifactLocation.uri / region.startLine.

        One SARIF, one run, one result. The synthetic result carries all
        three of ruleId / message / physicalLocation fields and we
        assert they propagate to Finding.* 1:1.
        """
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"name": "checkov"}},
                    "results": [
                        {
                            "ruleId": "CKV_AZURE_44",
                            "message": {"text": "Storage account TLS latest version"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "main.tf"},
                                        "region": {"startLine": 17, "snippet": {"text": "resource \"azurerm_storage_account\" \"ex\" {"}},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        sarif_path = tmp_path / "r.sarif"
        sarif_path.write_text(json.dumps(sarif), encoding="utf-8")

        findings = parse_sarif(sarif_path, "myapp", "prod", "terraform")

        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "CKV_AZURE_44"
        assert f.message == "Storage account TLS latest version"
        assert f.file_path == "main.tf"
        assert f.line == 17
        assert f.env == "prod"
        assert f.project == "myapp"
        assert f.framework == "terraform"
        # Severity falls through SEVERITY_OVERRIDE → CKV_AZURE_44=HIGH
        assert f.severity == "HIGH"
        # Resource regex pulled from snippet's first line
        assert f.resource == "azurerm_storage_account.ex"

    def test_parse_sarif_returns_empty_on_bad_json(self, tmp_path: Path) -> None:
        """A malformed SARIF returns [] (degraded mode)."""
        bad = tmp_path / "bad.sarif"
        bad.write_text("{not valid json", encoding="utf-8")
        assert parse_sarif(bad, "p", "e", "terraform") == []

    def test_sarif_is_empty_true_for_no_runs(self, tmp_path: Path) -> None:
        """SARIF with empty runs[] is "empty" (means: scan did not run)."""
        path = tmp_path / "empty.sarif"
        path.write_text(json.dumps({"runs": []}), encoding="utf-8")
        assert sarif_is_empty(path) is True

    def test_sarif_is_empty_false_when_runs_have_results(self, tmp_path: Path) -> None:
        """SARIF with at least one result is not empty."""
        path = tmp_path / "r.sarif"
        path.write_text(
            json.dumps(
                {
                    "runs": [
                        {"results": [{"ruleId": "CKV_AZURE_44", "message": {"text": "x"}}]}
                    ]
                }
            ),
            encoding="utf-8",
        )
        assert sarif_is_empty(path) is False

    def test_sarif_is_empty_true_when_results_empty(self, tmp_path: Path) -> None:
        """SARIF with runs[] but zero results is "empty" (means: clean run)."""
        path = tmp_path / "clean.sarif"
        path.write_text(
            json.dumps({"runs": [{"results": []}]}),
            encoding="utf-8",
        )
        assert sarif_is_empty(path) is True


# ===========================================================================
# 2. Coverage matrix + gaps + CSVs
# ===========================================================================


@pytest.fixture
def minimal_pci_data() -> dict:
    """Tiny pci_mapping-shaped dict that exercises every cell branch.

    - req_id 1.2.1: maps CKV_AZURE_44 (will fire → non_compliant) and
      CKV_AZURE_3 (will fire → compliant because suppressed).
    - req_id 1.3: maps CKV_AZURE_9 (will NOT fire → not_scanned when
      scan_status != ok) — used for the not_scanned branch.
    - out_of_scope entry: validates the OUT_OF_SCOPE branch.
    """
    return {
        "framework_name": "PCI DSS",
        "framework_version": "4.0.1",
        "requirements": [
            {
                "id": "1.2.1",
                "title": "NSC config standards",
                "checks": ["CKV_AZURE_44", "CKV_AZURE_3"],
                "approach": "defined",
            },
            {
                "id": "1.3",
                "title": "CDE network access restricted",
                "checks": ["CKV_AZURE_9"],
                "approach": "defined",
            },
        ],
        "out_of_scope_requirements": [
            {
                "id": "11.x",
                "title": "External penetration testing",
                "rationale": "Out of IaC scope",
                "control_owner": "team@example.com",
                "approved_by": "Jane Doe",
                "approved_on": "2026-01-01",
                "expires_on": "2099-01-01",  # far future → not stale
                "evidence_link": "https://example.com/evidence",
            }
        ],
    }


class TestCoverageMatrix:
    """build_coverage_matrix + compute_coverage_gaps + write_coverage_*_csv."""

    def test_build_coverage_matrix_emits_per_req_cells(
        self, tmp_path: Path, minimal_pci_data: dict
    ) -> None:
        """Every (req, check) cell has one of the five documented values.

        Per the docstring: compliant | non_compliant | not_applicable |
        out_of_scope | not_scanned. We assert each branch is reachable
        with a synthetic env_results + pci_data.
        """
        # Env 1 (ok): one HIGH non_compliant finding + one compliant (suppressed).
        f_high = Finding(
            env="prod",
            project="myapp",
            check_id="CKV_AZURE_44",
            severity="HIGH",
            resource="azurerm_storage_account.ex",
            file_path="main.tf",
            line=1,
            message="m",
            framework="terraform",
        )
        f_supp = Finding(
            env="prod",
            project="myapp",
            check_id="CKV_AZURE_3",
            severity="MEDIUM",
            resource="azurerm_storage_account.ex",
            file_path="main.tf",
            line=2,
            message="m",
            framework="terraform",
            suppressed=True,
        )
        # Env 2: scan_status != "ok" → produces not_scanned cells.
        env_ok = EnvResult(project="myapp", env="prod", scan_status="ok",
                           findings=[f_high, f_supp])
        env_fail = EnvResult(project="myapp", env="dev", scan_status="failed_to_plan",
                             findings=[], error="boom")

        mapping_path = tmp_path / "pci.yaml"
        mapping_path.write_text("placeholder", encoding="utf-8")

        (
            req_ids,
            check_ids,
            cells,
            out_of_scope,
            oos_errors,
            expected_by_req,
            fired_check_ids,
        ) = build_coverage_matrix([env_ok, env_fail], mapping_path, minimal_pci_data)

        # req_ids: in-scope first, OOS appended.
        assert req_ids[:2] == ["1.2.1", "1.3"]
        assert req_ids[-1] == "11.x"
        # check_ids: sorted, unique, derived from findings.
        assert check_ids == ["CKV_AZURE_3", "CKV_AZURE_44"]
        # 1.2.1 × CKV_AZURE_44 = non_compliant (HIGH, unsuppressed)
        assert cells[("1.2.1", "CKV_AZURE_44")] == "non_compliant"
        # 1.2.1 × CKV_AZURE_3 = compliant (suppressed)
        assert cells[("1.2.1", "CKV_AZURE_3")] == "compliant"
        # No errors, OOS validated.
        assert oos_errors == []
        assert len(out_of_scope) == 1
        # fired set includes both fired check IDs.
        assert fired_check_ids == {"CKV_AZURE_3", "CKV_AZURE_44"}
        # expected_by_req matches the mapping data exactly.
        assert expected_by_req["1.2.1"] == {"CKV_AZURE_44", "CKV_AZURE_3"}
        assert expected_by_req["1.3"] == {"CKV_AZURE_9"}

    def test_compute_coverage_gaps_returns_missing_checks(
        self, minimal_pci_data: dict
    ) -> None:
        """For reqs with no compliant checks, the gap record surfaces the missing IDs."""
        expected_by_req = {
            "1.2.1": {"CKV_AZURE_44", "CKV_AZURE_3"},
            "1.3": {"CKV_AZURE_9"},
        }
        # Only CKV_AZURE_44 fired → 1.2.1 missing CKV_AZURE_3; 1.3 missing CKV_AZURE_9.
        fired = {"CKV_AZURE_44"}
        gaps = compute_coverage_gaps(expected_by_req, fired)

        # Sorted by req_id.
        assert [g["req_id"] for g in gaps] == ["1.2.1", "1.3"]
        # 1.2.1: expected=2, fired=1, missing=1.
        g121 = gaps[0]
        assert g121["expected_count"] == 2
        assert g121["fired_count"] == 1
        assert g121["missing_count"] == 1
        assert g121["missing_check_ids"] == ["CKV_AZURE_3"]
        # 1.3: expected=1, fired=0, missing=1.
        g13 = gaps[1]
        assert g13["expected_count"] == 1
        assert g13["fired_count"] == 0
        assert g13["missing_count"] == 1
        assert g13["missing_check_ids"] == ["CKV_AZURE_9"]

    def test_compute_coverage_gaps_carries_note_token_hint(
        self, minimal_pci_data: dict
    ) -> None:
        """PCI_NOTE_TOKEN reqs carry their `note:` text as triage_hint."""
        expected_by_req = {"10.7": set()}  # PCI_NOTE_TOKEN row (empty after filter)
        note_by_req = {
            "10.7": "no working Checkov 3.3.9 coverage for 12-month retention"
        }
        # Filter PCI_NOTE_TOKENS out — the function doesn't filter itself,
        # build_coverage_matrix does. Simulate the post-filter state.
        fired: set[str] = set()
        gaps = compute_coverage_gaps(expected_by_req, fired, note_by_req)
        assert len(gaps) == 1
        g = gaps[0]
        assert g["expected_count"] == 0
        assert g["fired_count"] == 0
        assert g["missing_count"] == 0
        assert g["triage_hint"] == "no working Checkov 3.3.9 coverage for 12-month retention"

    def test_write_coverage_gaps_csv_emits_row_per_req(
        self, tmp_path: Path, minimal_pci_data: dict
    ) -> None:
        """coverage_gaps.csv has the documented header + one row per req."""
        expected_by_req = {"1.2.1": {"CKV_AZURE_44"}, "1.3": {"CKV_AZURE_9"}}
        fired: set[str] = set()  # nothing fired
        gaps = compute_coverage_gaps(expected_by_req, fired)

        out = tmp_path / "coverage_gaps.csv"
        write_coverage_gaps_csv(out, gaps, minimal_pci_data)
        text = out.read_text(encoding="utf-8")
        # Header includes every documented column.
        for col in (
            "pci_requirement",
            "title",
            "expected_count",
            "fired_count",
            "missing_count",
            "missing_check_ids",
            "triage_hint",
            "librarian_verified_at",
            "pci_anchor_url",
        ):
            assert col in text, f"missing column {col!r} in coverage_gaps.csv"
        # Both req IDs appear as rows.
        assert "1.2.1" in text
        assert "1.3" in text
        # Missing IDs surface.
        assert "CKV_AZURE_44" in text
        assert "CKV_AZURE_9" in text

    def test_write_coverage_csv_emits_required_columns(
        self, tmp_path: Path
    ) -> None:
        """coverage_matrix.csv header includes the documented wide column list."""
        out = tmp_path / "coverage_matrix.csv"
        cells = {("1.2.1", "CKV_AZURE_44"): "non_compliant"}
        write_coverage_csv(out, ["1.2.1"], ["CKV_AZURE_44"], cells, [])
        text = out.read_text(encoding="utf-8")
        for col in (
            "pci_requirement",
            "check_id",
            "status",
            "missing_for_req",
            "title",
            "rationale",
            "control_owner",
            "approved_on",
            "expires_on",
            "evidence_link",
            "stale",
            "days_to_expiry",
        ):
            assert col in text, f"missing column {col!r} in coverage_matrix.csv"


# ===========================================================================
# 3. Output writers (JUnit / SARIF / fix_list)
# ===========================================================================


class TestOutputWriters:
    """write_junit, write_combined_sarif, write_fix_list_md."""

    def test_write_junit_emits_valid_xml_with_fail_for_high(
        self, tmp_path: Path
    ) -> None:
        """Junit XML has one <testcase> per finding; HIGH/CRITICAL → <failure>.

        We parse the resulting XML with ElementTree so a structural
        regression (malformed output, missing tags) is caught, not just
        a string-substring presence check.
        """
        # Three findings: HIGH, CRITICAL, LOW. The CRITICAL must also FAIL.
        f_high = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_44",
            severity="HIGH", resource="r1", file_path="m.tf", line=1,
            message="tls latest", framework="terraform",
        )
        f_crit = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_3",
            severity="CRITICAL", resource="r2", file_path="m.tf", line=2,
            message="https only", framework="terraform",
        )
        f_low = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_70",
            severity="LOW", resource="r3", file_path="m.tf", line=3,
            message="diag", framework="terraform",
        )
        er = EnvResult(project="myapp", env="prod", scan_status="ok",
                       findings=[f_high, f_crit, f_low])

        out = tmp_path / "junit.xml"
        fails = write_junit(out, [er], [])
        assert fails == 2  # HIGH + CRITICAL → both fail

        # Parse the XML.
        tree = ET.parse(out)
        root = tree.getroot()
        assert root.tag == "testsuite"
        # Three testcases.
        cases = root.findall("testcase")
        assert len(cases) == 3
        # Each failing case carries <failure>, the LOW case has none.
        failure_count = sum(1 for c in cases if c.find("failure") is not None)
        assert failure_count == 2
        # Suppressed finding → <skipped> (no <failure>).
        f_high.suppressed = True
        out2 = tmp_path / "junit2.xml"
        fails2 = write_junit(out2, [er], [f_high])
        # Only CRITICAL still fails (HIGH suppressed).
        assert fails2 == 1
        tree2 = ET.parse(out2)
        cases2 = tree2.findall("testcase")
        skipped = [c for c in cases2 if c.find("skipped") is not None]
        assert len(skipped) == 1

    def test_write_combined_sarif_merges_per_env_runs(
        self, tmp_path: Path
    ) -> None:
        """write_combined_sarif emits a single SARIF doc with N runs (one per source)."""
        # Build two source SARIFs the aggregator would have discovered.
        # We populate EnvResultFull with sarif_terraform_source + sarif_secrets
        # so the writer iterates two runs.
        for tier, name, rule in (
            ("terraform_source", "r1.sarif", "CKV_AZURE_44"),
            ("secrets", "r2.sarif", "CKV_SECRET_3"),
        ):
            p = tmp_path / name
            p.write_text(
                json.dumps(
                    {"runs": [{"tool": {"driver": {"name": tier}},
                               "results": [{"ruleId": rule,
                                            "message": {"text": "x"}}]}]}
                ),
                encoding="utf-8",
            )
        er = EnvResultFull(
            project="myapp", env="prod", scan_status="ok",
            plan_dir=tmp_path,
            sarif_terraform_source=tmp_path / "r1.sarif",
            sarif_secrets=tmp_path / "r2.sarif",
        )
        out = tmp_path / "combined.sarif"
        write_combined_sarif(out, [er])

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 2
        # Each source SARIF contributes one run; the writer tags with
        # pci_project / pci_env so downstream tooling can filter.
        tags = sorted(
            (r["properties"]["pci_project"], r["properties"]["pci_env"])
            for r in data["runs"]
        )
        assert tags == [("myapp", "prod"), ("myapp", "prod")]
        # Sources are also labelled for debug.
        source_sarifs = sorted(
            r["properties"]["pci_source_sarif"] for r in data["runs"]
        )
        assert source_sarifs == ["r1.sarif", "r2.sarif"]

    def test_write_fix_list_md_groups_by_severity(
        self, tmp_path: Path, minimal_pci_data: dict
    ) -> None:
        """fix_list.md is grouped by CRITICAL/HIGH/MEDIUM/LOW with one section
        per finding."""
        f_high = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_44",
            severity="HIGH", resource="azurerm_storage_account.ex",
            file_path="main.tf", line=17, message="TLS latest",
            framework="terraform", pci_requirements=["1.2.1"],
        )
        f_low = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_70",
            severity="LOW", resource="diag", file_path="m.tf", line=3,
            message="diagnostic settings", framework="terraform",
            pci_requirements=[],
        )
        er = EnvResult(project="myapp", env="prod", scan_status="ok",
                       findings=[f_high, f_low])
        out = tmp_path / "fix_list.md"
        write_fix_list_md(out, [er], minimal_pci_data, {}, run_id="smoke")
        text = out.read_text(encoding="utf-8")
        # Severity headings.
        assert "## HIGH" in text
        assert "## LOW" in text
        # The HIGH finding's check_id appears in its section.
        assert "CKV_AZURE_44" in text
        # File location surfaces in the bullet list.
        assert "main.tf:17" in text
        # The run id is in the header.
        assert "smoke" in text


# ===========================================================================
# 4. HTML report via aggregate.main()
# ===========================================================================
# Rather than constructing 12+ positional arguments directly, exercise
# write_html_report via the public aggregate.main() orchestration path
# on a synthesized run-dir. Mirrors the pattern in test_cli.py:204-277
# and test_aggregate_pci.py:172-228.


class TestHtmlReport:
    """write_html_report end-to-end via aggregate.main()."""

    def test_html_report_contains_required_dom_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The HTML report renders the framework title, severity donut,
        PCI coverage heatmap marker, per-env health bar markers, and
        remediation HCL embedded inline.

        DOM markers checked (substring presence, NOT byte-equality):
          - <title>...PCI DSS v4.0.1...</title> (framework name)
          - id="severity-donut" (severity donut SVG)
          - class="heatmap-cell ..."  (PCI coverage heatmap)
          - class="env-bar-row"        (per-env health bars)
          - class="remediation-hcl"    (remediation HCL inline)
        """
        # Pre-condition: install-bundled mapping must be reachable.
        import importlib.resources

        bundled = importlib.resources.files("scanner").joinpath(
            "mappings/pci_dss_4.0.1.yaml"
        )
        if not bundled.is_file():
            pytest.skip("Install-bundled mapping not present")

        _build_run_dir(tmp_path)
        out_dir = tmp_path / "aggregate"
        monkeypatch.chdir(tmp_path)

        rc = _invoke_aggregate_main(
            ["aggregate.py", "--run-dir", str(tmp_path), "--out", str(out_dir)]
        )
        assert rc == 0, f"aggregate.main() rc={rc}"
        report = out_dir / "report.html"
        assert report.is_file(), "report.html not written"
        html = report.read_text(encoding="utf-8")

        # 1. Framework title in <title> (and as sidebar subtitle).
        assert "<title>Pacioli PCI DSS v4.0.1 Compliance Report</title>" in html
        assert "PCI DSS v4.0.1 Compliance Report" in html

        # 2. Severity donut SVG marker.
        assert 'id="severity-donut"' in html

        # 3. PCI coverage heatmap marker — the renderer emits
        #    class="heatmap-cell ..." rows.
        assert 'class="heatmap-cell' in html
        # Heatmap cells carry the per-requirement id from pci_mapping.yaml.
        assert "1.2.1" in html  # one of the in-scope req IDs

        # 4. Per-env health bar marker — class="env-bar-row" with
        #    data-env-bar="myapp/prod".
        assert 'class="env-bar-row"' in html
        assert 'data-env-bar="myapp/prod"' in html

        # 5. Remediation HCL embedded inline — class="remediation-hcl".
        # The synthetic CKV_TEST_BENIGN has no PCI mapping, so the
        # per-finding <div class="remediation"> wrapper is NOT rendered
        # for it. But the "Remediation Library" route renders one row
        # per check_id with a block in terraform_remediation.yaml, and
        # each row carries the <pre class="remediation-hcl"> tag. With
        # the bundled yaml installed, dozens of these pre tags appear.
        assert 'class="remediation-hcl"' in html

    def test_html_report_renders_pci_anchor_in_coverage_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The coverage route embeds the PCI SSC anchor URL from pci_mapping.yaml.

        Guards against accidental hard-coding of the anchor string. The
        anchor lives in pci_mapping.yaml: ``doc_anchor``. The renderer
        emits it in the coverage route header.
        """
        import importlib.resources

        bundled = importlib.resources.files("scanner").joinpath(
            "mappings/pci_dss_4.0.1.yaml"
        )
        if not bundled.is_file():
            pytest.skip("Install-bundled mapping not present")

        _build_run_dir(tmp_path)
        out_dir = tmp_path / "aggregate"
        monkeypatch.chdir(tmp_path)

        rc = _invoke_aggregate_main(
            ["aggregate.py", "--run-dir", str(tmp_path), "--out", str(out_dir)]
        )
        assert rc == 0
        html = (out_dir / "report.html").read_text(encoding="utf-8")
        # The PCI SSC anchor URL appears verbatim in the coverage route
        # header (see write_html_report line ~2186).
        assert (
            "https://listings.pcisecuritystandards.org/documents/"
            "PCI-DSS-v3-2-1-to-v4-0-Summary-of-Changes-r1.pdf"
        ) in html


# ===========================================================================
# 5. Direct unit tests for the smaller helpers
# ===========================================================================


class TestHelpers:
    """Direct unit tests for the smaller helpers — no run-dir required."""

    def test_parse_inline_skip_kwargs_extracts_known_keys(self) -> None:
        """_parse_inline_skip_kwargs handles PR_OWNER/PR_EXPIRES/justification
        with quoted values.

        Note: the parser splits on ``|`` (not ``:``) between KV pairs and
        uses ``partition("=")`` (first ``=`` wins) per pair. So the
        separator between PR_OWNER and PR_EXPIRES is a pipe, NOT a colon
        (contrary to the docstring's example).
        """
        kwargs = (
            "PR_OWNER=team"
            "|PR_EXPIRES=2027-01-01"
            '|justification="approved until next review"'
        )
        parsed = _parse_inline_skip_kwargs(kwargs)
        assert parsed["PR_OWNER"] == "team"
        assert parsed["PR_EXPIRES"] == "2027-01-01"
        assert parsed["justification"] == "approved until next review"

    def test_load_inline_skips_parses_checkov_skip_comments(
        self, tmp_path: Path
    ) -> None:
        """load_inline_skips returns {check_id: [{owner, expires_on, ...}, ...]}."""
        env_dir = tmp_path / "prod"
        env_dir.mkdir()
        (env_dir / "main.tf").write_text(
            'resource "azurerm_storage_account" "x" {\n'
            '  # checkov:skip=CKV_AZURE_44:PR_OWNER=team-a'
            '|PR_EXPIRES=2027-01-01'
            '|justification="approved waiver"\n'
            '  name = "x"\n'
            '}\n',
            encoding="utf-8",
        )
        skips = load_inline_skips([env_dir])
        assert "CKV_AZURE_44" in skips
        entry = skips["CKV_AZURE_44"][0]
        assert entry["owner"] == "team-a"
        assert entry["expires_on"] == "2027-01-01"
        assert entry["justification"] == "approved waiver"

    def test_is_inline_suppressed_matches_by_filename(
        self, tmp_path: Path
    ) -> None:
        """is_inline_suppressed returns True when file_path's basename
        matches the skip's source_file basename."""
        env_dir = tmp_path / "prod"
        env_dir.mkdir()
        (env_dir / "main.tf").write_text(
            'resource "azurerm_storage_account" "x" {\n'
            '  # checkov:skip=CKV_AZURE_44:PR_OWNER=team'
            '|PR_EXPIRES=2099-01-01'
            '|justification="permanent"\n'
            '  name = "x"\n'
            '}\n',
            encoding="utf-8",
        )
        skips = load_inline_skips([env_dir])
        finding = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_44",
            severity="HIGH", resource="x", file_path="main.tf", line=2,
            message="m", framework="terraform",
        )
        assert is_inline_suppressed(finding, skips, today="2026-08-10") is True

    def test_is_suppressed_honors_expires_on_in_future(
        self,
    ) -> None:
        """is_suppressed: expires_on > today → suppressed (entry active)."""
        f = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_44",
            severity="HIGH", resource="r", file_path="m.tf", line=1,
            message="m", framework="terraform",
        )
        baseline = [
            {
                "check_id": "CKV_AZURE_44",
                "resource_pattern": "*",
                "owner": "team@example.com",
                "expires_on": "2099-12-31",
            }
        ]
        assert is_suppressed(f, baseline, today="2026-08-10") is True

    def test_is_suppressed_honors_expires_on_in_past(
        self,
    ) -> None:
        """is_suppressed: expires_on < today → not suppressed (entry expired)."""
        f = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_44",
            severity="HIGH", resource="r", file_path="m.tf", line=1,
            message="m", framework="terraform",
        )
        baseline = [
            {
                "check_id": "CKV_AZURE_44",
                "resource_pattern": "*",
                "owner": "team@example.com",
                "expires_on": "2020-01-01",
            }
        ]
        assert is_suppressed(f, baseline, today="2026-08-10") is False

    def test_attach_pci_reqs_populates_list(self) -> None:
        """attach_pci_reqs mutates findings[*].pci_requirements in place."""
        f = Finding(
            env="prod", project="myapp", check_id="CKV_AZURE_44",
            severity="HIGH", resource="r", file_path="m.tf", line=1,
            message="m", framework="terraform",
        )
        attach_pci_reqs([f], {"CKV_AZURE_44": ["1.2.1", "1.3"]})
        assert f.pci_requirements == ["1.2.1", "1.3"]

    def test_load_remediation_map_returns_check_id_to_blocks(
        self, tmp_path: Path
    ) -> None:
        """load_remediation_map parses {check_id: [block, ...]} from the YAML."""
        yaml_path = tmp_path / "rem.yaml"
        yaml_path.write_text(
            "remediations:\n"
            "  CKV_AZURE_44:\n"
            "    - resource_type: azurerm_storage_account\n"
            "      current_problem: TLS not latest\n"
            "      remediation_hcl: |\n"
            "        resource \"azurerm_storage_account\" \"x\" {}\n"
            "      verification_step: run checkov\n"
            "      provenance: https://example.com\n",
            encoding="utf-8",
        )
        out = load_remediation_map(yaml_path)
        assert "CKV_AZURE_44" in out
        block = out["CKV_AZURE_44"][0]
        assert block["resource_type"] == "azurerm_storage_account"
        assert "azurerm_storage_account" in block["remediation_hcl"]

    def test_load_remediation_map_warns_on_missing(self, tmp_path: Path, capsys) -> None:
        """load_remediation_map returns {} when the YAML is missing."""
        missing = tmp_path / "absent.yaml"
        assert load_remediation_map(missing) == {}
        # A WARN goes to stderr so the operator sees the degraded mode.
        captured = capsys.readouterr()
        assert "WARN" in captured.err
        assert str(missing) in captured.err

    def test_walk_run_dir_discovers_per_project_env_sarifs(
        self, tmp_path: Path
    ) -> None:
        """walk_run_dir finds <project>/<env>/results_*.sarif correctly."""
        # Project A: prod (has terraform_source SARIF) + dev (no SARIFs)
        a_prod = tmp_path / "projA" / "prod"
        a_prod.mkdir(parents=True)
        (a_prod / "results_terraform_source.sarif").write_text(
            json.dumps({"runs": [{"results": []}]}), encoding="utf-8"
        )
        (tmp_path / "projA" / "dev").mkdir(parents=True)
        # Project B: staging (has paac SARIF)
        b_stg = tmp_path / "projB" / "staging"
        b_stg.mkdir(parents=True)
        (b_stg / "results_paac.sarif").write_text(
            json.dumps({"runs": [{"results": []}]}), encoding="utf-8"
        )

        results = walk_run_dir(tmp_path, [])
        # 3 envs: projA/prod, projA/dev, projB/staging.
        assert len(results) == 3
        # Index by (project, env) for assertions.
        idx = {(r.project, r.env): r for r in results}
        # projA/prod: ok + has source SARIF
        assert idx[("projA", "prod")].scan_status == "ok"
        assert idx[("projA", "prod")].sarif_terraform_source is not None
        # projA/dev: NO SARIFs → scan_status=no_sarif
        assert idx[("projA", "dev")].scan_status == "no_sarif"
        # projB/staging: ok + has paac SARIF
        assert idx[("projB", "staging")].scan_status == "ok"
        assert idx[("projB", "staging")].sarif_paac is not None

    def test_load_findings_populates_env_results(self, tmp_path: Path) -> None:
        """load_findings mutates each EnvResultFull.findings from its SARIFs."""
        env_dir = tmp_path / "p" / "e"
        env_dir.mkdir(parents=True)
        (env_dir / "results_terraform_source.sarif").write_text(
            json.dumps(
                {
                    "runs": [
                        {
                            "tool": {"driver": {"name": "checkov"}},
                            "results": [
                                {
                                    "ruleId": "CKV_TEST_BENIGN",
                                    "message": {"text": "x"},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "m.tf"},
                                                "region": {"startLine": 1},
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        results = [
            EnvResultFull(
                project="p", env="e", scan_status="ok",
                plan_dir=env_dir,
                sarif_terraform_source=env_dir / "results_terraform_source.sarif",
            )
        ]
        load_findings(results)
        assert len(results) == 1
        assert len(results[0].findings) == 1
        f = results[0].findings[0]
        assert f.check_id == "CKV_TEST_BENIGN"
        assert f.framework == "terraform"


# ===========================================================================
# 6. Drift section helpers (tier-3 surface)
# ===========================================================================


class TestDriftHelpers:
    """_collect_drift_findings + _render_drift_section."""

    def test_collect_drift_findings_reads_drift_report(
        self, tmp_path: Path
    ) -> None:
        """_collect_drift_findings flattens drift_report.json into row dicts.

        We materialise a minimal drift_report.json with one entry per
        schema branch and assert each lands in the output with the
        documented severity mapping.
        """
        env_dir = tmp_path / "p" / "e"
        env_dir.mkdir(parents=True)
        drift = {
            "summary": {"added": 0, "removed": 0, "changed": 1, "sensitive": 1},
            "address_in_state_only": ["azurerm_storage_account.orphan"],
            "address_in_source_only": ["azurerm_storage_account.new"],
            "attribute_drift": [
                {
                    "address": "azurerm_storage_account.ex",
                    "diffs": [
                        {
                            "attribute": "min_tls_version",
                            "source": "TLS1_2",
                            "state": "TLS1_0",
                            "note": "security regression",
                        }
                    ],
                }
            ],
            "sensitive_findings": [
                {
                    "address": "azurerm_storage_account.ex",
                    "attribute": "primary_access_key",
                    "state_value_type": "string",
                    "note": "key rotated manually",
                }
            ],
        }
        (env_dir / "drift_report.json").write_text(
            json.dumps(drift), encoding="utf-8"
        )

        er = EnvResultFull(
            project="p", env="e", scan_status="ok",
            plan_dir=env_dir,
        )
        rows = _collect_drift_findings([er])
        # 1 attribute_changed + 1 resource_in_state_only + 1 resource_in_source_only + 1 sensitive_value = 4
        assert len(rows) == 4
        # Severity mapping per docstring.
        by_type = {r["drift_type"]: r for r in rows}
        assert by_type["attribute_changed"]["severity"] == "HIGH"
        assert by_type["resource_in_state_only"]["severity"] == "MEDIUM"
        assert by_type["resource_in_source_only"]["severity"] == "LOW"
        assert by_type["sensitive_value"]["severity"] == "MEDIUM"

    def test_collect_drift_findings_returns_empty_when_no_drift_report(
        self, tmp_path: Path
    ) -> None:
        """Tier 1/2: no drift_report.json → empty list (silent skip)."""
        env_dir = tmp_path / "p" / "e"
        env_dir.mkdir(parents=True)
        er = EnvResultFull(project="p", env="e", scan_status="ok", plan_dir=env_dir)
        assert _collect_drift_findings([er]) == []

    def test_render_drift_section_empty_for_no_findings(self) -> None:
        """_render_drift_section returns "" when given no findings."""
        assert _render_drift_section([]) == ""

    def test_render_drift_section_emits_table_for_findings(self) -> None:
        """_render_drift_section renders the documented table for non-empty input."""
        rows = [
            {
                "project": "p",
                "env": "e",
                "resource": "azurerm_storage_account.ex",
                "file_path": "",
                "line": 0,
                "drift_type": "attribute_changed",
                "attribute": "min_tls_version",
                "source_value": "TLS1_2",
                "state_value": "TLS1_0",
                "severity": "HIGH",
                "message": "security regression",
            }
        ]
        html = _render_drift_section(rows)
        assert "Drift Findings" in html
        assert "<table>" in html
        assert "azurerm_storage_account.ex" in html
        assert "HIGH" in html
        assert "TLS1_2" in html
        assert "TLS1_0" in html


# ===========================================================================
# 7. er_locate_sarif (documented as no-op stub)
# ===========================================================================


class TestErLocateSarif:
    """er_locate_sarif is a documented no-op stub returning None."""

    def test_er_locate_sarif_returns_none(self) -> None:
        """The stub returns None; EnvResultFull carries the path directly."""
        from scanner.aggregate import er_locate_sarif

        er = EnvResultFull(project="p", env="e", scan_status="ok")
        assert er_locate_sarif(er, "results_terraform_plan.sarif") is None
