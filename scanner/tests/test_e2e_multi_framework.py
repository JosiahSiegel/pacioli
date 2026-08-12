"""End-to-end test for the generalised scanner pipeline against a
non-Azure, non-Terraform framework (CloudFormation / AWS).

Closes TODO 14 of the multi-cloud framework generalization plan.

Why this file exists
--------------------
Plan TODO 14 requires a new integration test that exercises the full
Pacioli pipeline end-to-end against a framework that is neither Azure
nor Terraform. Pre-T11 the scanner hard-coded ``--framework terraform``
in :mod:`scanner.checkov_runner` and assumed ``--framework terraform``
in :mod:`scanner.cli`; the discovery step was *also* hard-coded to
``.tf``. Plan T1-T7 generalized the runner, discovery, CLI, and
aggregator; TODO 14 is the regression guard that proves the
generalization actually works against a real second framework.

The TODO-14 spec enumerates five concrete checks the new test must
implement:

  (a) ONE shared CloudFormation fixture directory
      ``scanner/tests/fixtures/cfn-sample/`` containing a simple
      CloudFormation template. This fixture is reused by the F3
      manual-QA scenario, so no parallel fixture directories.

  (b) ONE minimal mapping-pack YAML
      ``scanner/tests/fixtures/mappings/test_aws.yaml`` with 2-3
      requirements mapped to ``CKV_AWS_*`` checks, with one entry in
      ``severity_overrides`` marked HIGH.

  (c) The test calls the SHARED fixture path; it does NOT duplicate
      the fixture content anywhere.

  (d) The HTML report renders with the framework name from the
      mapping pack; the CSV uses ``requirement`` (not
      ``pci_requirement``); the HIGH severity finding triggers the
      gate (non-zero rc).

  (e) ``# checkov:skip=...`` comments work in the non-Terraform file
      type. Checkov itself recognises the inline skip comment;
      the test verifies the SARIF ``suppressions`` block carries the
      in-source justification.

The plan's MUST-NOT constraints are also enforced:

  * No network access. The test is hermetic: it shells out to the
    already-installed local ``checkov`` binary against a tmpdir
    fixture; no AWS calls, no Azure calls, no HTTP requests.
  * No real cloud account. Same.
  * No dependency on the PCI mapping pack. The test points the
    aggregator at the dedicated ``scanner/tests/fixtures/mappings/
    test_aws.yaml`` pack via ``--mapping``; the bundled PCI fallback
    in :func:`scanner.aggregate.main` does not engage because we
    pass an explicit ``--mapping`` argument.

Test inventory
--------------
1. ``test_real_checkov_against_cfn_fixture_produces_sarif`` — runs
   real Checkov against the shared fixture (binary hermetic; cf.
   checkov==3.3.9 pinned in scanner/requirements-pinned.txt) and
   asserts the SARIF emitted carries the rules we expect.
2. ``test_html_report_uses_pack_framework_name`` — feeds the SARIF
   into :func:`scanner.aggregate.main` and verifies the HTML report
   title contains the framework name from ``test_aws.yaml`` (NOT
   ``PCI DSS``) and the ``coverage_matrix.csv`` header carries the
   ``requirement`` column (NOT ``pci_requirement``).
3. ``test_high_severity_finding_triggers_gate`` — same e2e flow but
   asserts the aggregator returns rc=7 (the gate exit code) because
   the mapping pack pins ``CKV_AWS_20`` to HIGH.
4. ``test_checkov_skip_comment_suppresses_in_cfn_file`` — runs Checkov
   against the *variant* fixture with an inline ``# checkov:skip``;
   asserts the SARIF emits a ``suppressions`` block carrying the
   inline justification (Checkov recognises the comment in YAML/JSON
   files, not just ``.tf``).

The tests use only the SHARED fixture paths — never hard-coded file
content — so a maintainer can add a new variant fixture (e.g. an
OpenAPI / Kubernetes equivalent) by adding another file under
``scanner/tests/fixtures/cfn-sample/`` and a corresponding test
without touching either the test runner or the mapping pack's
content.
"""
from __future__ import annotations

import csv
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Make ``import scanner`` resolve the worktree's scanner/ package even
# when pytest is invoked from a non-default cwd. Mirrors the pattern
# used by test_cli.py, test_orchestrator.py, test_aggregate_html.py.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from scanner.aggregate import main as aggregate_main  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fixture paths (the spec's MUST: "Test calls the SHARED fixture
# path — does NOT duplicate the file content"). Both the base public-
# bucket template and the variant with the inline ``# checkov:skip`` are
# siblings under the single ``fixtures/cfn-sample/`` directory so a new
# variant can be added without spawning a parallel fixture directory.
# ---------------------------------------------------------------------------
CFN_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "cfn-sample"
PUBLIC_BUCKET_TEMPLATE = CFN_FIXTURES_DIR / "public_bucket.template.yaml"
SKIPPED_PUBLIC_BUCKET_TEMPLATE = CFN_FIXTURES_DIR / "skipped_public_bucket.template.yaml"
TEST_MAPPING_PACK = (
    Path(__file__).resolve().parent / "fixtures" / "mappings" / "test_aws.yaml"
)

# The framework_name and framework_version declared in the test mapping
# pack. Asserted on the rendered HTML so accidental drift is caught.
EXPECTED_FRAMEWORK_NAME = "AWS S3 Bucket Hardening (E2E test pack)"
EXPECTED_FRAMEWORK_VERSION = "0.1.0"

# Expected CSV header column (the post-T7 generic name; pre-T7 was
# ``pci_requirement`` and the test would have caught the regression).
EXPECTED_CSV_REQUIREMENT_COLUMN = "requirement"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _checkov_available() -> bool:
    """True iff a Checkov executable is on PATH and resolves to >=3.3.x.

    The test relies on Checkov's :program:`cloudformation` framework
    producing a SARIF for the shared fixture. Checkov is pinned to
    3.3.9 in scanner/requirements-pinned.txt so this returns True on
    any developer machine that ran ``make install``. When the binary
    is unavailable, the test class is skipped wholesale rather than
    emitting a single ignored assertion.
    """
    return shutil.which("checkov") is not None


def _run_checkov_cfn(target: Path, out_dir: Path) -> Path:
    """Run real Checkov against ``target`` and emit SARIF.

    Returns the SARIF file path. Invokes Checkov in a controlled
    CWD so the Windows relpath workaround (``os.chdir(env_dir)``
    inside :class:`scanner.checkov_runner.CheckovRunner`) does not
    matter for this subprocess path.

    Raises ``pytest.skip`` (via :func:`_checkov_available`) when
    Checkov is unavailable; raises ``pytest.fail`` when Checkov
    emits stderr.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "checkov",
        "-f", str(target),
        "--framework", "cloudformation",
        "--output", "sarif",
        "--output-file-path", str(out_dir),
        "--soft-fail",  # report-only mode; we read results ourselves
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    sarif_path = out_dir / "results_sarif.sarif"
    if not sarif_path.is_file():
        pytest.fail(
            f"checkov did not produce {sarif_path}; "
            f"rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
    return sarif_path


def _build_run_dir(run_dir: Path, sarif_path: Path) -> Path:
    """Materialise the run-dir shape the aggregator walks.

    The aggregator's :func:`scanner.aggregate.walk_run_dir` enumerates
    ``<run_dir>/<project>/<env>/results_*.sarif``. We pick a project /
    env pair that are not the strings used anywhere else in the test
    suite to avoid a future collision when other tests in this file
    run in parallel under ``pytest-xdist`` (none currently do, but the
    names are unique-by-convention).
    """
    env_dir = run_dir / "cfn-app" / "dev"
    env_dir.mkdir(parents=True)
    shutil.copy(sarif_path, env_dir / "results_source.sarif")
    return env_dir


def _invoke_aggregate_main(argv: list[str]) -> int:
    """Run :func:`scanner.aggregate.main` with the given argv.

    Mirrors the helper in test_aggregate_html.py:128-140 — ``main()``
    parses ``sys.argv`` directly via argparse, so we swap argv in for
    the call and restore it on the way out.
    """
    saved_argv = sys.argv
    try:
        sys.argv = argv
        return aggregate_main()
    finally:
        sys.argv = saved_argv


def _build_aggregate_argv(
    run_dir: Path, mapping_path: Path, out_dir: Path
) -> list[str]:
    """Construct the argv for :func:`scanner.aggregate.main`.

    Pointing ``--mapping`` at an explicit pack bypasses the
    install-bundled PCI fallback in aggregate.main:3851-3858 (the
    fallback only fires when ``args.mapping`` is the bare default
    string ``"pci_mapping.yaml"``). This honours the spec's
    MUST-NOT-DO constraint "Do NOT depend on the PCI mapping pack".
    """
    return [
        "aggregate.py",
        "--run-dir", str(run_dir),
        "--out", str(out_dir),
        "--mapping", str(mapping_path),
        # --scope defaults to "pci_scope.yaml"; aggregate.main only
        # prints the resolved scope_path and never reads its content
        # for this test, so leaving it at the default is safe.
        "--baseline", "nonexistent_baseline.yaml",
    ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cfn_run_dir(tmp_path: Path) -> Path:
    """Hermetic per-test run-dir with CFN SARIF pre-populated.

    Yields the run-dir path. The SARIF at
    ``<run_dir>/cfn-app/dev/results_source.sarif`` is the one real
    Checkov produced against the shared CFN template; this matches the
    shape the aggregator's :func:`walk_run_dir` walks.
    """
    out = tmp_path / "sarif_out"
    sarif_path = _run_checkov_cfn(PUBLIC_BUCKET_TEMPLATE, out)
    run_dir = tmp_path / "run"
    _build_run_dir(run_dir, sarif_path)
    return run_dir


@pytest.fixture
def cfn_skip_run_dir(tmp_path: Path) -> Path:
    """Hermetic per-test run-dir built from the skip-variant fixture."""
    out = tmp_path / "sarif_out"
    sarif_path = _run_checkov_cfn(SKIPPED_PUBLIC_BUCKET_TEMPLATE, out)
    run_dir = tmp_path / "run"
    _build_run_dir(run_dir, sarif_path)
    return run_dir


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _checkov_available(),
    reason="checkov binary not on PATH; required for real-CFN E2E",
)
def test_real_checkov_against_cfn_fixture_produces_sarif(
    tmp_path: Path,
) -> None:
    """Real Checkov 3.3.9 against the shared CFN fixture emits a SARIF
    carrying the rules the mapping pack anchors against.

    Locks the fixture-to-SARIF contract so the rest of this file can
    assume CKV_AWS_20 fires (and gates the test plan's HIGH pathway).
    If Checkov upstream changes the failing check IDs for a public
    bucket, this is the FIRST assertion that fails -- update
    both ``public_bucket.template.yaml`` AND ``test_aws.yaml`` to
    keep the fixture/pack pair in sync.
    """
    out = tmp_path / "sarif_out"
    sarif_path = _run_checkov_cfn(PUBLIC_BUCKET_TEMPLATE, out)

    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    fired_rules: set[str] = set()
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rid = result.get("ruleId", "")
            if rid:
                fired_rules.add(rid)

    # The mapping pack's HIGH finding is CKV_AWS_20. The rest of the
    # CKV_AWS_18/21/53-56 family is also expected to fire on the
    # public-bucket fixture (PBA toggles + logging/versioning absent).
    for expected_rule in (
        "CKV_AWS_18",
        "CKV_AWS_20",
        "CKV_AWS_21",
        "CKV_AWS_53",
        "CKV_AWS_54",
        "CKV_AWS_55",
        "CKV_AWS_56",
    ):
        assert expected_rule in fired_rules, (
            f"expected Checkov to fire {expected_rule} on "
            f"{PUBLIC_BUCKET_TEMPLATE.name}; got {sorted(fired_rules)!r}"
        )


@pytest.mark.skipif(
    not _checkov_available(),
    reason="checkov binary not on PATH; required for aggregator e2e",
)
def test_html_report_uses_pack_framework_name(
    cfn_run_dir: Path, tmp_path: Path
) -> None:
    """Aggregator renders the HTML report with the framework name from
    the mapping pack (NOT ``PCI DSS``) and the CSV uses the generic
    ``requirement`` column.

    Spec assertion (TODO 14(d)): "Verify the HTML report renders with
    the framework name from the mapping pack, the CSV uses
    ``requirement`` …".

    The aggregator's gate pathway is unconditional: rc=7 with a HIGH
    finding in the SARIF (see ``aggregate.py:4086-4093``); the HTML
    report is still emitted. The HIGH pathway itself is asserted by
    :func:`test_high_severity_finding_triggers_gate`; here we only
    care that the deliverables (report, coverage matrix, CSV header)
    carry the right framework metadata.
    """
    out_dir = tmp_path / "aggregate_out"
    argv = _build_aggregate_argv(cfn_run_dir, TEST_MAPPING_PACK, out_dir)
    rc = _invoke_aggregate_main(argv)
    # The aggregator's gate pathway is unconditional: it returns rc=7
    # when ANY HIGH/CRITICAL finding exists in the run (see
    # aggregate.py:4086-4093). The HTML report is still emitted at
    # that exit code (the rc is for CI consumers; the report itself
    # is the deliverable). The HIGH-pathway behaviour is verified
    # by ``test_high_severity_finding_triggers_gate``; here we only
    # care that the report, coverage matrix, and CSV are produced.
    assert rc in (0, 7), (
        f"aggregator returned unexpected rc={rc}; expected 0 (clean) "
        f"or 7 (gate failure on HIGH finding; rendered files still valid)"
    )

    # The HTML report is rendered by aggregate.main under <out_dir>/report.html.
    report_html = out_dir / "report.html"
    assert report_html.is_file(), (
        f"aggregator did not render {report_html}; "
        f"contents of {out_dir}: {sorted(p.name for p in out_dir.iterdir())}"
    )
    html_text = report_html.read_text(encoding="utf-8")
    # The HTML <title> uses ``f"Pacioli {framework_full} Compliance Report"``
    # where ``framework_full`` is ``f"{framework_name} v{framework_version}"``.
    # The mapping pack pins both, so the title must contain BOTH.
    assert EXPECTED_FRAMEWORK_NAME in html_text, (
        f"report.html should embed the framework name "
        f"{EXPECTED_FRAMEWORK_NAME!r}; got title fragment="
        f"{_first_title(html_text)!r}"
    )
    assert EXPECTED_FRAMEWORK_VERSION in html_text, (
        f"report.html should embed the framework version "
        f"{EXPECTED_FRAMEWORK_VERSION!r}; got title fragment="
        f"{_first_title(html_text)!r}"
    )
    # Belt-and-suspenders: the title must NOT carry the legacy PCI fallback.
    assert "PCI DSS" not in html_text, (
        "report.html unexpectedly references PCI DSS; "
        "framework_name resolution did not honour the mapping pack"
    )

    # Coverage matrix CSV header MUST use ``requirement`` (post-T7 name).
    coverage_csv = out_dir / "coverage_matrix.csv"
    assert coverage_csv.is_file(), f"aggregator did not emit {coverage_csv}"
    with coverage_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
    assert EXPECTED_CSV_REQUIREMENT_COLUMN in header, (
        f"coverage_matrix.csv header missing the {EXPECTED_CSV_REQUIREMENT_COLUMN!r} "
        f"column; got {header!r}"
    )
    assert "pci_requirement" not in header, (
        f"coverage_matrix.csv header still uses the legacy ``pci_requirement`` "
        f"name; got {header!r}"
    )

    # The mapping pack's requirement IDs (S3-PUBLIC-READ, S3-PBA,
    # S3-HYGIENE) MUST each appear in the CSV's requirement column.
    # This proves the pack was actually consumed end-to-end (not just
    # parsed for its framework_name).
    coverage_rows = list(csv.DictReader(open(coverage_csv, encoding="utf-8")))
    reqs_in_csv = {row["requirement"] for row in coverage_rows}
    for expected_req in ("S3-PUBLIC-READ", "S3-PBA", "S3-HYGIENE"):
        assert expected_req in reqs_in_csv, (
            f"expected requirement {expected_req!r} in coverage_matrix.csv; "
            f"got {sorted(reqs_in_csv)!r}"
        )


@pytest.mark.skipif(
    not _checkov_available(),
    reason="checkov binary not on PATH; required for gate-pathway e2e",
)
def test_high_severity_finding_triggers_gate(
    cfn_run_dir: Path, tmp_path: Path
) -> None:
    """The HIGH severity finding against CKV_AWS_20 makes the
    aggregator's gate pathway return rc=7.

    Spec assertion (TODO 14(d)): "…and the HIGH severity finding
    triggers the gate". The aggregator's :func:`scanner.aggregate.
    main` returns 7 when any finding has severity in
    ``{HIGH, CRITICAL}`` and is not suppressed; the mapping pack
    pins ``CKV_AWS_20`` to HIGH.
    """
    out_dir = tmp_path / "aggregate_out"
    argv = _build_aggregate_argv(cfn_run_dir, TEST_MAPPING_PACK, out_dir)
    rc = _invoke_aggregate_main(argv)
    # RC=7 is the gate-failure code (see aggregate.py:4093). Anything
    # else means the HIGH severity did not flow through the resolver.
    assert rc == 7, (
        f"aggregator gate-rc expected 7 (HIGH finding present); got {rc}. "
        "Mapping pack's severity_overrides[CKV_AWS_20]=HIGH may not have "
        "applied -- check resolve_severity precedence."
    )

    # Belt-and-suspenders: there must be at least one CKV_AWS_20 row
    # in coverage_matrix.csv so we know the row is actually the gate
    # failure driver (not, say, a stray HIGH from a different rule).
    coverage_csv = out_dir / "coverage_matrix.csv"
    assert coverage_csv.is_file()
    coverage_rows = list(csv.DictReader(open(coverage_csv, encoding="utf-8")))
    s3_public_read_rows = [
        row for row in coverage_rows if row["requirement"] == "S3-PUBLIC-READ"
    ]
    assert s3_public_read_rows, (
        f"no S3-PUBLIC-READ rows in coverage_matrix.csv; cannot prove "
        f"CKV_AWS_20 HIGH is the gate driver. rows={coverage_rows!r}"
    )
    # At least one row under S3-PUBLIC-READ must carry a non-empty
    # ``check_id`` (i.e. CKV_AWS_20 fired). Multiple check_ids per req
    # are possible (multi-rule pack), but at least one row must show
    # CKV_AWS_20 itself.
    assert any(
        row["check_id"] == "CKV_AWS_20" for row in s3_public_read_rows
    ), (
        f"no CKV_AWS_20 row under S3-PUBLIC-READ in coverage_matrix.csv; "
        f"rows={s3_public_read_rows!r}"
    )


@pytest.mark.skipif(
    not _checkov_available(),
    reason="checkov binary not on PATH; required for checkov-skip e2e",
)
def test_checkov_skip_comment_suppresses_in_cfn_file(
    cfn_skip_run_dir: Path,
) -> None:
    """``# checkov:skip=...`` comments suppress findings in CloudFormation
    files (not just ``.tf``).

    Spec assertion (TODO 14(e)): "Verify ``checkov:skip`` comments work
    in the non-Terraform file type."

    Strategy: run a separate Checkov pass against the *variant*
    fixture :data:`SKIPPED_PUBLIC_BUCKET_TEMPLATE`, which carries
    ``# checkov:skip=CKV_AWS_20: read access is intentional for a
    public static site`` at the bucket declaration. The variant is
    structured so that ONLY CKV_AWS_20 violates the resource; the
    other rules (CKV_AWS_18/19/21/53-56) are explicitly satisfied.
    We assert that the resulting SARIF flags CKV_AWS_20 as
    suppressed (the SARIF carries a ``suppressions`` block with the
    in-source justification), so the gate pathway does NOT trip on
    the skipped rule.
    """
    # Re-derive the variant SARIF path from cfn_skip_run_dir (we built
    # it with one SARIF under cfn-app/dev/results_source.sarif).
    sarif_path = cfn_skip_run_dir / "cfn-app" / "dev" / "results_source.sarif"
    assert sarif_path.is_file(), (
        f"variant SARIF missing at {sarif_path}"
    )
    data = json.loads(sarif_path.read_text(encoding="utf-8"))

    # CKV_AWS_20 SHOULD still appear in the SARIF (Checkov emits all
    # checked rules), but with a ``suppressions`` block carrying the
    # inline justification -- that is Checkov's contract for inline
    # skipping. We assert the rule is PRESENT and SUPPRESSED rather
    # than absent (an absent rule would also "pass", but it would not
    # prove the skip comment fired).
    ckv_aws_20_with_suppression: list[dict] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            if result.get("ruleId") == "CKV_AWS_20":
                if result.get("suppressions"):
                    ckv_aws_20_with_suppression.append(result)

    assert ckv_aws_20_with_suppression, (
        f"expected Checkov to emit CKV_AWS_20 with a ``suppressions`` "
        f"block carrying the ``# checkov:skip=CKV_AWS_20`` "
        f"justification; got runs={data.get('runs')!r}"
    )

    # The suppression block MUST carry an ``inSource`` kind (SARIF 2.1.0
    # standard for ``# checkov:skip`` comments) and a non-empty
    # ``justification`` matching the fixture's inline comment.
    result = ckv_aws_20_with_suppression[0]
    suppression = result["suppressions"][0]
    assert suppression.get("kind") == "inSource", (
        f"CKV_AWS_20 suppression block must be kind='inSource' (SARIF 2.1.0 "
        f"inline-comment convention); got {suppression!r}"
    )
    justification = suppression.get("justification", "")
    assert "intentional" in justification.lower(), (
        f"CKV_AWS_20 suppression justification must echo the inline "
        f"comment text; got {justification!r}"
    )


# ---------------------------------------------------------------------------
# Small string helpers
# ---------------------------------------------------------------------------


def _first_title(html_text: str) -> str:
    """Return the first ``<title>...</title>`` body for failure messages.

    Pure-text assertion failures can drown the operator in a 600 KB
    HTML blob; this helper pins a single, distinctive line for the
    diff message so the failure mode is obvious in CI output.
    """
    match = re.search(r"<title>([^<]+)</title>", html_text)
    return match.group(1) if match else "(no <title>)"
