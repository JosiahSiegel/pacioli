"""Smoke tests for the mapping YAML loader.

These tests verify that the schema is realistic and the loader handles
edge cases. They do NOT verify the upstream Checkov mapping content
itself (that's a living document; live tests are in the runbook).
"""
import json
import sys
from pathlib import Path

import pytest

# Make ``import scanner`` resolve the worktree's scanner/ package even when
# pytest is invoked from a non-default cwd (e.g. inside an editor's test
# runner). Mirrors the pattern in scanner/tests/test_cli.py.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanner.aggregate import load_pci_mapping, load_pci_baseline, main as aggregate_main


def test_load_pci_mapping_parses_top_level_keys():
    """The real pci_mapping.yaml must load with the expected top-level keys."""
    # Use the file shipped with the repo.
    mapping_path = Path(__file__).resolve().parents[3] / "pci_mapping.yaml"
    if not mapping_path.exists():
        pytest.skip(f"{mapping_path} not present (CI may not have the full repo)")
    mapping = load_pci_mapping(mapping_path)
    assert isinstance(mapping, dict)
    # The mapping is {check_id: [req_ids, ...]} — inverted for fast lookup.
    # Should have at least one check mapped
    assert len(mapping) > 0
    for check_id, req_ids in mapping.items():
        assert isinstance(check_id, str)
        assert check_id.startswith("CKV"), f"{check_id} doesn't start with CKV"
        assert isinstance(req_ids, list)
        assert all(isinstance(r, str) for r in req_ids)
        # Each req_id should look like a PCI req number (e.g. "1.2.1", "10.7")
        assert all(any(ch.isdigit() for ch in r) for r in req_ids)


def test_load_pci_mapping_unknown_path(tmp_path):
    """Loading a nonexistent file returns an empty dict (degraded mode)."""
    mapping = load_pci_mapping(tmp_path / "nonexistent.yaml")
    assert mapping == {}


def test_load_pci_baseline_returns_list():
    """Baseline file loads as a list of dicts."""
    baseline_path = Path(__file__).resolve().parents[3] / "pci_baseline.yaml"
    if not baseline_path.exists():
        pytest.skip(f"{baseline_path} not present")
    baseline = load_pci_baseline(baseline_path)
    assert isinstance(baseline, list)
    # Empty file or all entries may be stub; assert type only
    for entry in baseline:
        assert isinstance(entry, dict)


def test_validate_oos_requires_nine_fields():
    """Out-of-scope rows must have 9 fields; the validator refuses if any is missing."""
    from aggregate import validate_out_of_scope_entries
    bad = [{"id": "1.2.1", "title": "x", "rationale": "r", "control_owner": "o"}]
    errors, _enriched = validate_out_of_scope_entries(bad, today_iso="2026-08-06")
    assert len(errors) > 0  # missing fields = errors


def test_validate_oos_accepts_complete_entry():
    """A fully-populated OOS row passes validation."""
    from aggregate import validate_out_of_scope_entries
    good = [{
        "id": "1.2.1",
        "title": "Test req",
        "rationale": "Test rationale",
        "control_owner": "team@example.com",
        "approved_by": "Approver Name",
        "approved_on": "2026-01-01",
        "expires_on": "2027-01-01",
        "evidence_link": "https://example.com/evidence",
    }]
    errors, _enriched = validate_out_of_scope_entries(good, today_iso="2026-08-06")
    assert errors == []


def test_validate_oos_rejects_invalid_date():
    """Bad ISO date in expires_on is rejected."""
    from aggregate import validate_out_of_scope_entries
    bad = [{
        "id": "1.2.1",
        "title": "Test",
        "rationale": "r",
        "control_owner": "o",
        "approved_by": "Jane",
        "approved_on": "2026-01-01",
        "expires_on": "not-a-date",
        "evidence_link": "https://example.com",
    }]
    errors, _enriched = validate_out_of_scope_entries(bad, today_iso="2026-08-06")
    assert len(errors) > 0


# ---------------------------------------------------------------------------
# Install-bundled mapping fallback
# ---------------------------------------------------------------------------


def test_aggregate_main_falls_back_to_install_bundled_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``aggregate.main()`` falls back to the install-bundled mapping.

    When the user does NOT pass ``--mapping`` and the run-dir lives in a
    tmpdir (no ``.git`` ancestor, no ``pci_mapping.yaml`` alongside),
    aggregate must locate the mapping shipped via
    ``importlib.resources.files("scanner").joinpath(
    "mappings/pci_dss_4.0.1.yaml")`` and complete end-to-end.

    Setup: a minimal synthetic run-dir under ``tmp_path`` containing one
    SARIF file (``<project>/<env>/results_terraform_source.sarif``).
    No ``.git`` dir, no ``pci_mapping.yaml`` anywhere — exercises the
    fallback branch added to ``main()``.
    """
    # Sanity: the install-bundled mapping must be reachable for this
    # test to make sense. If the wheel is missing the mapping (i.e.
    # setuptools package-data config was dropped), skip with a clear
    # message rather than failing with a confusing error.
    import importlib.resources

    bundled = importlib.resources.files("scanner").joinpath(
        "mappings/pci_dss_4.0.1.yaml"
    )
    if not bundled.is_file():
        pytest.skip(
            "Install-bundled mapping not present at "
            "scanner/mappings/pci_dss_4.0.1.yaml; check "
            "[tool.setuptools.package-data] in pyproject.toml"
        )

    # Build a synthetic run-dir: <tmp_path>/<project>/<env>/results_terraform_source.sarif
    project = "myapp"
    env = "prod"
    env_dir = tmp_path / project / env
    env_dir.mkdir(parents=True)

    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "checkov"}},
                "results": [
                    {
                        # Use a non-existent rule_id so severity falls
                        # through to DEFAULT_SEVERITY (MEDIUM) — keeps
                        # the test focused on the fallback path
                        # without triggering aggregate's rc=7 gate
                        # (HIGH/CRITICAL -> exit 7).
                        "ruleId": "CKV_TEST_BENIGN",
                        "level": "note",
                        "message": {"text": "synthetic finding"},
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

    # aggregate.main() reads sys.argv directly. Run from tmp_path so the
    # walk-up-to-.git logic terminates at tmp_path.parent (no .git
    # found) and the install-bundled fallback fires.
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "aggregate_out"
    saved_argv = sys.argv
    try:
        sys.argv = [
            "aggregate.py",
            "--run-dir",
            str(tmp_path),
            "--out",
            str(out_dir),
        ]
        rc = aggregate_main()
    finally:
        sys.argv = saved_argv

    # Aggregate must succeed; the install-bundled fallback path was
    # the one that located the mapping. report.html is the visible
    # signal that the full pipeline (load_pci_mapping + walk_run_dir
    # + load_findings + HTML render) completed.
    assert rc == 0, (
        f"aggregate.main() returned rc={rc}; "
        "fallback path likely failed silently"
    )
    report = out_dir / "report.html"
    assert report.is_file(), (
        f"aggregate did not write {report}; "
        f"contents of out_dir: {sorted(p.name for p in out_dir.iterdir())}"
    )
    assert report.stat().st_size > 0, "report.html is empty"


def test_aggregate_main_does_not_silently_overwrite_explicit_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Passing ``--mapping <bad-path>`` must surface the error, not swap in
    the install-bundled mapping.

    Regression guard for an over-eager fallback: when ``mapping_path``
    doesn't exist, ``aggregate.main()`` historically reached for the
    install-bundled ``mappings/pci_dss_4.0.1.yaml`` and emitted a
    report against the wrong framework. That fallback must only fire
    when the user did NOT pass ``--mapping`` explicitly (i.e. when
    ``args.mapping`` is still the argparse default ``"pci_mapping.yaml"``).

    Setup: a minimal synthetic run-dir under ``tmp_path`` (no .git
    ancestor) and a clearly-missing mapping path under tmp_path.
    Expected: ``rc=2`` with the ERROR log mentioning the user-supplied
    path AND the ``--mapping`` hint. The install-bundled fallback must
    NOT have printed its sentinel line.
    """
    # Build a synthetic run-dir so the aggregator reaches the mapping
    # resolution branch (otherwise it returns 2 earlier on an empty
    # run-dir).
    project = "myapp"
    env = "prod"
    env_dir = tmp_path / project / env
    env_dir.mkdir(parents=True)
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "checkov"}},
                "results": [
                    {
                        "ruleId": "CKV_TEST_BENIGN",
                        "level": "note",
                        "message": {"text": "synthetic finding"},
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

    # Deliberately missing mapping path. The path lives under tmp_path
    # (not tmp_path's parent) so it can't be confused with any system
    # file the fallback might happen to locate.
    bad_mapping = tmp_path / "nonexistent" / "foo.yaml"
    assert not bad_mapping.exists(), "pre-condition: bad mapping must not exist"

    monkeypatch.chdir(tmp_path)
    saved_argv = sys.argv
    try:
        sys.argv = [
            "aggregate.py",
            "--run-dir",
            str(tmp_path),
            "--mapping",
            str(bad_mapping),
        ]
        rc = aggregate_main()
    finally:
        sys.argv = saved_argv

    captured = capsys.readouterr()
    assert rc == 2, (
        f"aggregate.main() should return rc=2 for a missing explicit "
        f"--mapping; got rc={rc}; stdout={captured.out!r}; "
        f"stderr={captured.err!r}"
    )
    # The ERROR log must surface the user-supplied path AND the
    # --mapping hint so the operator can fix the call.
    assert str(bad_mapping) in captured.err, (
        f"expected the user-supplied mapping path {bad_mapping} in stderr; "
        f"got {captured.err!r}"
    )
    assert "--mapping" in captured.err, (
        f"expected an actionable --mapping hint in stderr; got {captured.err!r}"
    )
    # The install-bundled fallback sentinel must NOT have printed. If it
    # did, the test fails — that means aggregate silently swapped in the
    # wrong mapping and would have produced a report against the wrong
    # framework.
    assert "install-bundled fallback" not in captured.out, (
        f"install-bundled fallback fired despite an explicit --mapping "
        f"argument; stdout={captured.out!r}"
    )
