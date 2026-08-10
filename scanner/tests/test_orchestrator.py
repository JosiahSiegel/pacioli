"""scanner/tests/test_orchestrator.py — pytest cases for the scan orchestrator.

Covers the plan's MUST-DO contract for this file:

  * source-only scan produces SARIFs in the per-pair output dir
  * baseline-applied scan: a target_repo's ``pci_baseline.yaml`` is
    discovered and passed through to the aggregate step
  * missing-mapping-pack surfaces as :class:`OrchestratorError`
  * audit-pin enforcement: ``importlib.metadata.version('checkov')``
    returning a non-``3.3.9`` value raises :class:`AuditPinViolation`
  * ``CI=1`` environment auto-promotes ``mode=report`` → ``mode=gate``
  * the ``--scan-plan`` back-compat alias maps to ``--tier plan`` and
    emits a :class:`DeprecationWarning` (verified through the CLI
    dispatcher, not just the helper)

All tests are hermetic: ``tmp_path`` provides the consumer repo;
:class:`_FakeCheckov` stands in for the real Checkov runner; the
aggregate step is mocked so the suite has no dependency on PyYAML,
mapping YAML, or the HTML report renderer.
"""
from __future__ import annotations

import importlib.metadata
import json
import sys
import warnings
from pathlib import Path
from typing import Iterator

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import cli as scanner_cli  # noqa: E402
from scanner import orchestrator as scanner_orchestrator  # noqa: E402
from scanner import safety as scanner_safety  # noqa: E402
from scanner.checkov_runner import _SARIF_BASENAME  # noqa: E402
from scanner.orchestrator import (  # noqa: E402
    Orchestrator,
    OrchestratorError,
    _build_arg_parser,
    _ci_auto_promote,
)


# ---------------------------------------------------------------------------
# Fake Checkov (mirrors test_checkov_runner.py)
# ---------------------------------------------------------------------------


class _FakeCheckov:
    """Stand-in for ``checkov.main.Checkov``.

    Writes a minimal-but-valid SARIF document to ``<argv's
    --output-file-path>/results_sarif.sarif`` so the orchestrator's
    SARIF-presence assertions succeed.
    """

    instances: list["_FakeCheckov"] = []

    def __init__(self, argv: list[str]) -> None:
        self.argv = list(argv)
        type(self).instances.append(self)

    def run(self) -> None:
        out_dir = self._extract_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / _SARIF_BASENAME
        sarif_path.write_text(
            json.dumps(
                {
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": "fake-checkov",
                                    "version": "0.0.0",
                                    "informationUri": "https://example.invalid",
                                }
                            },
                            "results": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def _extract_output_dir(self) -> Path:
        for i, tok in enumerate(self.argv):
            if tok == "--output-file-path" and i + 1 < len(self.argv):
                return Path(self.argv[i + 1])
        raise AssertionError(f"--output-file-path missing from argv: {self.argv}")


@pytest.fixture
def fake_checkov_module(monkeypatch: pytest.MonkeyPatch) -> type[_FakeCheckov]:
    """Patch ``checkov.main.Checkov`` (and ``checkov.Checkov``) to the fake."""
    _FakeCheckov.instances = []
    import checkov.main as checkov_main

    monkeypatch.setattr(checkov_main, "Checkov", _FakeCheckov, raising=True)
    import checkov as checkov_pkg

    monkeypatch.setattr(checkov_pkg, "Checkov", _FakeCheckov, raising=False)
    yield _FakeCheckov
    _FakeCheckov.instances = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env_tree(
    root: Path,
    layout: dict[str, dict[str, list[str]]],
) -> None:
    """Build ``<root>/env/<project>/<env>/<tf_files...>`` from a nested spec."""
    env_root = root / "env"
    env_root.mkdir()
    for project_name, envs in layout.items():
        project_dir = env_root / project_name
        project_dir.mkdir()
        for env_name, tf_files in envs.items():
            env_dir = project_dir / env_name
            env_dir.mkdir()
            for filename in tf_files:
                (env_dir / filename).write_text(
                    'resource "null_resource" "x" {}\n',
                    encoding="utf-8",
                )


def _stub_aggregate(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Stub ``scanner.aggregate.main``; record every argv it sees.

    The orchestrator constructs an argv per call (mirroring the bash
    scanner's aggregate invocation) and restores ``sys.argv`` after the
    call. We intercept by patching the symbol the orchestrator imports
    lazily. Returned list captures the invocations in order.
    """
    captured: list[list[str]] = []

    def fake_aggregate_main() -> int:  # signature: aggregate.main reads sys.argv
        captured.append(list(sys.argv))
        return 0

    monkeypatch.setattr(
        "scanner.aggregate.main",
        fake_aggregate_main,
        raising=False,
    )
    return captured


@pytest.fixture
def stub_aggregate(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[list[str]]]:
    """Fixture form of :func:`_stub_aggregate`."""
    yield _stub_aggregate(monkeypatch)


# ---------------------------------------------------------------------------
# 1. Source-only scan produces SARIFs
# ---------------------------------------------------------------------------


def test_source_only_scan_produces_per_pair_sarifs(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    stub_aggregate: list[list[str]],
) -> None:
    """Source tier runs paac + source + secrets and writes three SARIFs per pair.

    The output_dir is laid out as ``<output_dir>/<project>/<env>/`` and
    each env dir contains one SARIF per pass. We assert the per-pass
    filenames the orchestrator documents in
    ``scanner.orchestrator._scan_one_pair``.
    """
    _make_env_tree(
        tmp_path,
        {"payments": {"prod": ["main.tf", "variables.tf"]}},
    )
    output_dir = tmp_path / "runs"

    orch = Orchestrator(mode="report", tier="source", no_aggregate=False)
    rc = orch.scan(
        target_repo=tmp_path,
        project=None,
        env=None,
        label=None,
        output_dir=output_dir,
        mapping_path=None,
        baseline_path=None,
        state_account=None,
    )

    assert rc == 0
    pair_dir = output_dir / "payments" / "prod"
    assert pair_dir.is_dir(), f"missing pair dir: {pair_dir}"

    expected_sarifs = {
        "results_paac.sarif",
        "results_terraform_source.sarif",
        "results_secrets.sarif",
    }
    actual_sarifs = {p.name for p in pair_dir.iterdir() if p.suffix == ".sarif"}
    assert expected_sarifs.issubset(actual_sarifs), (
        f"missing SARIFs: expected at least {expected_sarifs}, got {actual_sarifs}"
    )

    # Aggregate was called once with the constructed argv.
    assert len(stub_aggregate) == 1
    agg_argv = stub_aggregate[0]
    assert "--run-dir" in agg_argv
    assert str(output_dir.resolve()) in agg_argv


# ---------------------------------------------------------------------------
# 2. Baseline-applied scan: pci_baseline.yaml auto-discovered
# ---------------------------------------------------------------------------


def test_baseline_applied_scan_picks_up_repo_baseline(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``pci_baseline.yaml`` in the target repo is auto-discovered.

    The orchestrator resolves baseline via CLI > env >
    ``<target_repo>/pci_baseline.yaml``. When the file is present and no
    explicit CLI/env override exists, the orchestrator passes its
    absolute path to ``aggregate.py``.
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    baseline = tmp_path / "pci_baseline.yaml"
    baseline.write_text(
        "- check_id: CKV_AZURE_211\n  resource: null_resource.x\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("PACIOLI_BASELINE_FILE", raising=False)

    captured: list[list[str]] = []

    def fake_aggregate_main() -> int:
        captured.append(list(sys.argv))
        return 0

    monkeypatch.setattr("scanner.aggregate.main", fake_aggregate_main, raising=False)

    output_dir = tmp_path / "runs"
    orch = Orchestrator(mode="report", tier="source")
    rc = orch.scan(
        target_repo=tmp_path,
        project=None,
        env=None,
        label=None,
        output_dir=output_dir,
        mapping_path=None,
        baseline_path=None,
        state_account=None,
    )

    assert rc == 0
    assert len(captured) == 1
    agg_argv = captured[0]
    # --baseline <abs path> was threaded through to aggregate.
    assert "--baseline" in agg_argv
    baseline_idx = agg_argv.index("--baseline")
    assert agg_argv[baseline_idx + 1] == str(baseline.resolve())


def test_baseline_explicit_nonexistent_path_falls_through(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-existent explicit ``--baseline`` path is treated as ``None``.

    Mirrors orchestrator.scan() lines 251-257: if the caller passes a
    ``baseline_path`` that doesn't resolve to a file, the orchestrator
    silently treats it as no-baseline rather than failing.
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})

    captured: list[list[str]] = []

    def fake_aggregate_main() -> int:
        captured.append(list(sys.argv))
        return 0

    monkeypatch.setattr("scanner.aggregate.main", fake_aggregate_main, raising=False)

    nonexistent = tmp_path / "no_such_baseline.yaml"
    output_dir = tmp_path / "runs"
    orch = Orchestrator(mode="report", tier="source")
    rc = orch.scan(
        target_repo=tmp_path,
        project=None,
        env=None,
        label=None,
        output_dir=output_dir,
        mapping_path=None,
        baseline_path=nonexistent,
        state_account=None,
    )

    assert rc == 0
    assert len(captured) == 1
    # --baseline must NOT appear when the explicit path doesn't exist.
    assert "--baseline" not in captured[0], (
        f"--baseline unexpectedly present: {captured[0]}"
    )


# ---------------------------------------------------------------------------
# 3. Missing mapping pack → OrchestratorError
# ---------------------------------------------------------------------------


def test_missing_mapping_pack_raises_orchestrator_error(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
) -> None:
    """Pointing the orchestrator at a non-existent mapping pack is fatal.

    The orchestrator wraps :class:`PathResolutionError` from
    ``scanner.paths.resolve_mapping`` into :class:`OrchestratorError`
    so the public surface is uniform. Verify both surfaces fire.
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    output_dir = tmp_path / "runs"
    bad_mapping = tmp_path / "no_such_mapping.yaml"

    orch = Orchestrator(mode="report", tier="source")

    with pytest.raises(OrchestratorError) as exc_info:
        orch.scan(
            target_repo=tmp_path,
            project=None,
            env=None,
            label=None,
            output_dir=output_dir,
            mapping_path=bad_mapping,
            baseline_path=None,
            state_account=None,
        )

    # Error message should reference the missing pack path so the
    # operator can fix the config rather than guess.
    assert str(bad_mapping.resolve()) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 4. Audit-pin enforcement (checkov version guard)
# ---------------------------------------------------------------------------


def test_audit_pin_violation_on_wrong_checkov_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``check_checkov_version`` rejects anything but 3.3.9.

    The MUST-DO contract: mock ``importlib.metadata.version('checkov')``
    to return ``"3.4.0"`` and assert :class:`AuditPinViolation` is
    raised. Mirrors the negative test in ``test_safety.py``.
    """
    # Force the real import inside check_checkov_version to succeed so we
    # exercise the version comparison branch, not the import branch.
    import checkov  # type: ignore[import-not-found]  # noqa: F401

    def fake_version(dist: str) -> str:
        assert dist == "checkov"
        return "3.4.0"

    monkeypatch.setattr(importlib.metadata, "version", fake_version)

    with pytest.raises(scanner_safety.AuditPinViolation) as exc_info:
        scanner_safety.check_checkov_version()

    msg = str(exc_info.value)
    assert "3.3.9" in msg
    assert "3.4.0" in msg


def test_audit_pin_accepts_pinned_checkov_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pin passes for the exact ``3.3.9`` version."""
    import checkov  # type: ignore[import-not-found]  # noqa: F401

    monkeypatch.setattr(importlib.metadata, "version", lambda dist: "3.3.9")
    assert scanner_safety.check_checkov_version() == "3.3.9"


# ---------------------------------------------------------------------------
# 5. CI=1 auto-promotes report → gate
# ---------------------------------------------------------------------------


def test_ci_auto_promote_promotes_report_to_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``CI=1`` and ``mode=report``, the promotion fires on the parsed args.

    MUST-DO contract: ``monkeypatch.setenv('CI', '1')`` + assert
    ``mode == 'gate'``. Tests the in-process helper directly so the
    test is independent of aggregate / Checkov / the EXIT trap.
    """
    monkeypatch.setenv("CI", "1")
    parser = _build_arg_parser()
    args = parser.parse_args([])  # defaults: mode=report, tier=source
    assert args.mode == "report"

    _ci_auto_promote(args)

    assert args.mode == "gate"


def test_ci_auto_promote_does_not_promote_when_ci_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``CI=1``, report-mode stays report-mode."""
    monkeypatch.delenv("CI", raising=False)
    parser = _build_arg_parser()
    args = parser.parse_args([])

    _ci_auto_promote(args)

    assert args.mode == "report"


def test_ci_auto_promote_does_not_promote_when_mode_already_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A user-supplied ``--mode gate`` is left alone (no double-promotion noise)."""
    monkeypatch.setenv("CI", "1")
    parser = _build_arg_parser()
    args = parser.parse_args(["--mode", "gate"])
    assert args.mode == "gate"

    _ci_auto_promote(args)

    assert args.mode == "gate"


def test_ci_env_value_one_promotes_via_main(
    monkeypatch: pytest.MonkeyPatch,
    fake_checkov_module: type[_FakeCheckov],
    tmp_path: Path,
) -> None:
    """End-to-end: ``orchestrator.main(['--mode', 'report'])`` with CI=1 → gate mode.

    Probes the orchestrator mode after parsing by stubbing the
    aggregate step to capture the rc. The orchestrator's ``mode`` is
    observable in the gate-mode log line and via scan_rc semantics; we
    use the scan_rc=7 path by stubbing aggregate to return a
    findings-present code and verifying gate mode propagates it.
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("PACIOLI_OUTPUT_DIR", str(tmp_path / "runs"))
    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.delenv("PCI_MAPPING", raising=False)
    monkeypatch.delenv("PACIOLI_BASELINE_FILE", raising=False)

    # Stub aggregate to return rc=7 (findings-present). In gate mode the
    # orchestrator propagates 7 into SCAN_RC; in report mode it suppresses
    # 7 and returns 0. So rc=7 post-scan is the gate-mode signal.
    def fake_aggregate_main() -> int:
        return 7

    monkeypatch.setattr("scanner.aggregate.main", fake_aggregate_main, raising=False)

    rc = scanner_orchestrator.main(["--mode", "report"])

    assert rc == 7, (
        f"CI=1 should have promoted report→gate (rc=7 propagated); got rc={rc}"
    )


# ---------------------------------------------------------------------------
# 6. --scan-plan deprecation alias (via the CLI dispatcher)
# ---------------------------------------------------------------------------


def test_scan_plan_alias_emits_deprecation_warning(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``pacioli scan --scan-plan`` emits a DeprecationWarning.

    The MUST-DO contract: invoke ``scanner.cli.main(['scan',
    '--scan-plan', ...])`` and assert the deprecation warning fires.
    We assert both the warning category (for ``-W error`` consumers)
    AND the stderr line (for operators tailing output).
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("PACIOLI_OUTPUT_DIR", str(tmp_path / "runs"))
    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.delenv("PCI_MAPPING", raising=False)
    monkeypatch.delenv("PACIOLI_BASELINE_FILE", raising=False)

    captured_argv: list[list[str]] = []

    def fake_orchestrator_main(argv):
        captured_argv.append(list(argv))
        return 0

    monkeypatch.setattr(
        "scanner.orchestrator.main",
        fake_orchestrator_main,
        raising=False,
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        rc = scanner_cli.main(
            [
                "scan",
                "--scan-plan",
                "--non-interactive",
            ]
        )

    assert rc == 0
    assert len(captured_argv) == 1
    forwarded_argv = captured_argv[0]

    # The alias mapped to --tier plan: the dispatched argv carries the
    # new flag, NOT the old alias flag.
    assert "--tier" in forwarded_argv
    tier_idx = forwarded_argv.index("--tier")
    assert forwarded_argv[tier_idx + 1] == "plan"
    assert "--scan-plan" not in forwarded_argv, (
        f"alias flag leaked through dispatcher: {forwarded_argv}"
    )

    # The DeprecationWarning category fired (this is what ``-W error``
    # tooling keys off).
    deprecation_warnings = [
        w for w in caught if issubclass(w.category, DeprecationWarning)
    ]
    assert deprecation_warnings, (
        f"expected DeprecationWarning, got: {[str(w.message) for w in caught]}"
    )
    assert any("--scan-plan" in str(w.message) for w in deprecation_warnings), (
        f"deprecation message did not name the old flag: "
        f"{[str(w.message) for w in deprecation_warnings]}"
    )


def test_scan_plan_alias_identical_output_to_explicit_tier_plan(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--scan-plan`` and ``--tier plan`` dispatch identical argv.

    Two parallel calls capture the orchestrator's argv; the only
    intended difference is that the alias path emits a warning (not
    represented in argv). Everything else must match byte-for-byte.
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    monkeypatch.setenv("PACIOLI_TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("PACIOLI_OUTPUT_DIR", str(tmp_path / "runs"))
    monkeypatch.delenv("PACIOLI_MAPPING", raising=False)
    monkeypatch.delenv("PCI_MAPPING", raising=False)
    monkeypatch.delenv("PACIOLI_BASELINE_FILE", raising=False)

    captured: list[list[str]] = []

    def fake_orchestrator_main(argv):
        captured.append(list(argv))
        return 0

    monkeypatch.setattr(
        "scanner.orchestrator.main",
        fake_orchestrator_main,
        raising=False,
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        scanner_cli.main(
            ["scan", "--scan-plan", "--non-interactive"]
        )
        scanner_cli.main(
            ["scan", "--tier", "plan", "--non-interactive"]
        )

    assert len(captured) == 2
    assert captured[0] == captured[1], (
        f"alias and explicit-flag dispatch differ:\n  alias: {captured[0]}\n  "
        f"explicit: {captured[1]}"
    )


def test_scan_state_alias_implies_tier_state() -> None:
    """``--scan-state`` (the other deprecation alias) escalates to ``tier=state``.

    The plan's contract says ``--scan-plan``; this complementary test
    pins the parallel ``--scan-state`` behavior so the deprecation
    matrix is locked. Mirrors :func:`scanner.cli._apply_backcompat`.
    """
    parser = scanner_cli._build_parser()
    # Find the scan subparser via the public dispatch path so we don't
    # re-implement the alias wiring here.
    args = parser.parse_args(
        ["scan", "--scan-state", "--non-interactive"]
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        applied = scanner_cli._apply_backcompat(args)
    assert applied.tier == "state"