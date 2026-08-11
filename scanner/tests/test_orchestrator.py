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
  * ``tier=plan`` invokes ``_discover_public_ip`` via the whitelist
    helper and produces ``tfplan.binary`` + ``plan.json`` per pair
  * ``tier=state`` invokes the state-blob subprocess pipeline under
    the ``safety.refuse_if_mutating`` guard and emits
    ``state.tfstate`` / ``state_as_plan.json`` / ``drift_report.json``
  * ``_register_cleanup_trap`` wires the EXIT trap on tier=plan/state
    and the cleanup closure runs the whitelist + shred steps in order
  * ``_discover_public_ip`` short-circuits on a healthy IMDS response
    and falls back to ipify on a failure

All tests are hermetic: ``tmp_path`` provides the consumer repo;
:class:`_FakeCheckov` stands in for the real Checkov runner; the
aggregate step is mocked so the suite has no dependency on PyYAML,
mapping YAML, or the HTML report renderer. Tier=plan/state tests mock
the Azure / terraform subprocesses (``_alert_network_required``,
``_run_terraform_init`` / ``_run_terraform_plan``,
``_download_state_blob`` / ``_convert_state_to_plan`` /
``_scan_state_as_plan`` / ``_emit_drift_report``) so no terraform
binary is invoked.
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


# ---------------------------------------------------------------------------
# 7. tier=plan: _discover_public_ip invoked, tfplan.binary + plan.json produced
# ---------------------------------------------------------------------------


def test_tier_plan_invokes_discover_public_ip_and_emits_plan_artifacts(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``tier=plan`` reaches the plan-prep pipeline and writes tfplan.binary + plan.json.

    Patches the four subprocess entry points
    (``_alert_network_required``, ``_run_terraform_init``, ``_run_terraform_plan``,
    ``_run_terraform_show``) to be hermetic. ``_alert_network_required``
    replaces the prior firewall-whitelist helper; the fake records the
    call and returns True so the plan-prep pipeline proceeds (the
    production helper always returns False and bails out fail-closed).

    Per-pair artifacts verified:
      * ``tfplan.binary`` — written by ``_run_terraform_plan``
      * ``plan.json`` — written by ``_run_terraform_show`` and required
        by the ``terraform_plan`` Checkov pass.
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    output_dir = tmp_path / "runs"
    state_account = "mystorageacct"

    # Track which subprocess paths were reached.
    calls: list[str] = []

    def fake_alert_network_required(self, state, account):  # noqa: ANN001 — test stub
        calls.append("alert_network_required")
        # Mimic real behavior: write the .whitelist_ip marker so the
        # cleanup trap would have something to remove.
        (state.env_run_dir / ".whitelist_ip").write_text("203.0.113.42", encoding="utf-8")
        return True

    def fake_terraform_init(self, state):  # noqa: ANN001 — test stub
        calls.append("terraform_init")
        return True

    def fake_terraform_plan(self, state):  # noqa: ANN001 — test stub
        calls.append("terraform_plan")
        # Create the tfplan.binary so downstream _emit_plan_pass finds it.
        state.plan_bin = state.env_run_dir / "tfplan.binary"
        state.plan_bin.write_bytes(b"\x00\x01\x02plan-bytes")
        return True

    def fake_terraform_show(self, state):  # noqa: ANN001 — test stub
        calls.append("terraform_show")
        # Create plan.json; _emit_plan_pass only runs if this file is present.
        state.plan_json = state.env_run_dir / "plan.json"
        state.plan_json.write_text(
            json.dumps(
                {
                    "format_version": "1.2",
                    "terraform_version": "1.5.0",
                    "resource_changes": [],
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_alert_network_required",
        fake_alert_network_required,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_init",
        fake_terraform_init,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_plan",
        fake_terraform_plan,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_show",
        fake_terraform_show,
    )
    # Mock the PCI 10.7 hygiene shred so the artifacts survive for
    # post-scan assertion (production shreds them, but we want to
    # verify they were written in the first place).
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_shred_plan_artifacts",
        lambda self, state: None,
    )
    monkeypatch.setattr("scanner.aggregate.main", lambda: 0, raising=False)

    orch = Orchestrator(mode="report", tier="plan")
    rc = orch.scan(
        target_repo=tmp_path,
        project=None,
        env=None,
        label=None,
        output_dir=output_dir,
        mapping_path=None,
        baseline_path=None,
        state_account=state_account,
    )

    assert rc == 0
    pair_dir = output_dir / "payments" / "prod"
    assert pair_dir.is_dir(), f"missing pair dir: {pair_dir}"

    # All four plan-prep subprocesses fired in the right order.
    assert calls == [
        "alert_network_required",
        "terraform_init",
        "terraform_plan",
        "terraform_show",
    ], f"unexpected subprocess sequence: {calls}"

    # Per-pair plan artifacts written.
    plan_bin = pair_dir / "tfplan.binary"
    plan_json = pair_dir / "plan.json"
    assert plan_bin.is_file(), f"missing tfplan.binary: {plan_bin}"
    assert plan_bin.read_bytes() == b"\x00\x01\x02plan-bytes"
    assert plan_json.is_file(), f"missing plan.json: {plan_json}"
    parsed = json.loads(plan_json.read_text(encoding="utf-8"))
    assert parsed["format_version"] == "1.2"


def test_tier_plan_falls_back_when_whitelist_fails(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the network-required alert fires (returns False), the per-pair plan passes are skipped.

    Mirrors orchestrator._run_plan_tier() lines 552-558: when
    ``_alert_network_required`` returns False the pair is skipped
    (tier_rc=-1), so ``terraform init`` / ``terraform plan`` /
    ``terraform show`` must NOT fire and no plan artifacts may be
    written. (This test is the negative-path counterpart to the
    ``test_tier_plan_invokes_discover_public_ip`` success path.)
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    output_dir = tmp_path / "runs"
    state_account = "mystorageacct"

    plan_calls: list[str] = []

    def fake_alert_network_required(self, state, account):  # noqa: ANN001 — test stub
        return False  # network access not available; bail out

    def fake_terraform_init(self, state):  # noqa: ANN001 — test stub
        plan_calls.append("init")
        return True

    def fake_terraform_plan(self, state):  # noqa: ANN001 — test stub
        plan_calls.append("plan")
        return True

    def fake_terraform_show(self, state):  # noqa: ANN001 — test stub
        plan_calls.append("show")

    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_alert_network_required",
        fake_alert_network_required,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_init",
        fake_terraform_init,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_plan",
        fake_terraform_plan,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_show",
        fake_terraform_show,
    )
    monkeypatch.setattr("scanner.aggregate.main", lambda: 0, raising=False)

    orch = Orchestrator(mode="report", tier="plan")
    rc = orch.scan(
        target_repo=tmp_path,
        project=None,
        env=None,
        label=None,
        output_dir=output_dir,
        mapping_path=None,
        baseline_path=None,
        state_account=state_account,
    )

    assert rc == 0  # scan_rc stays 0 in report mode
    pair_dir = output_dir / "payments" / "prod"
    # Pair dir is still created (the SARIF passes still run), but no
    # plan artifacts were written.
    assert pair_dir.is_dir()
    assert not (pair_dir / "tfplan.binary").exists()
    assert not (pair_dir / "plan.json").exists()
    assert plan_calls == [], f"plan subprocess fired despite whitelist failure: {plan_calls}"


# ---------------------------------------------------------------------------
# 8. tier=state: state.tfstate + state_as_plan.json + drift_report.json
# ---------------------------------------------------------------------------


def test_tier_state_emits_state_artifacts_and_calls_safety_guard(
    tmp_path: Path,
    fake_checkov_module: type[_FakeCheckov],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``tier=state`` runs the 4-helper state-blob pipeline under safety.refuse_if_mutating.

    Per-pair artifacts verified:
      * ``state.tfstate``         — written by ``_download_state_blob``
      * ``state_as_plan.json``    — written by ``_convert_state_to_plan``
      * ``drift_report.json``     — written by ``_emit_drift_report``

    Also verifies ``safety.refuse_if_mutating`` fires at the subprocess
    gate (orchestrator.py line 925-928) and the 4 helpers fire in the
    documented order. The tier=plan prep mocks are reused so this test
    only exercises the state-blob delta on top of tier=plan.
    """
    _make_env_tree(tmp_path, {"payments": {"prod": ["main.tf"]}})
    output_dir = tmp_path / "runs"
    state_account = "mystorageacct"

    # Make refuse_if_mutating observable.
    safety_calls: list[str] = []
    real_refuse = scanner_safety.SafetyGuard.refuse_if_mutating

    def recording_refuse(self, cmd):  # noqa: ANN001 — test stub
        safety_calls.append(cmd)
        return real_refuse(self, cmd)

    monkeypatch.setattr(
        scanner_safety.SafetyGuard,
        "refuse_if_mutating",
        recording_refuse,
    )

    state_pipeline_calls: list[str] = []

    # tier=plan prep mocks — return True and create the plan artifacts
    # so the state-blob pipeline has the inputs it expects.
    def fake_alert_network_required(self, state, account):  # noqa: ANN001 — test stub
        (state.env_run_dir / ".whitelist_ip").write_text("203.0.113.42", encoding="utf-8")
        return True

    def fake_terraform_init(self, state):  # noqa: ANN001 — test stub
        return True

    def fake_terraform_plan(self, state):  # noqa: ANN001 — test stub
        state.plan_bin = state.env_run_dir / "tfplan.binary"
        state.plan_bin.write_bytes(b"\x00plan")
        return True

    def fake_terraform_show(self, state):  # noqa: ANN001 — test stub
        state.plan_json = state.env_run_dir / "plan.json"
        state.plan_json.write_text(
            json.dumps(
                {
                    "format_version": "1.2",
                    "terraform_version": "1.5.0",
                    "resource_changes": [],
                }
            ),
            encoding="utf-8",
        )

    # tier=state state-blob mocks — create the three required files.
    def fake_download_state_blob(self, account, key, state_local):  # noqa: ANN001
        state_pipeline_calls.append("download_state_blob")
        # Mimic the real blob — the converter only cares that the file
        # exists and is non-empty.
        state_local.write_text(
            json.dumps(
                {
                    "version": 4,
                    "serial": 1,
                    "outputs": {},
                    "resources": [],
                }
            ),
            encoding="utf-8",
        )
        return True

    def fake_convert_state_to_plan(self, state_local, state_plan_json):  # noqa: ANN001
        state_pipeline_calls.append("convert_state_to_plan")
        state_plan_json.write_text(
            json.dumps(
                {
                    "format_version": "1.2",
                    "terraform_version": "1.5.0",
                    "resource_changes": [],
                }
            ),
            encoding="utf-8",
        )
        return True

    def fake_scan_state_as_plan(self, runner, state, state_plan_json):  # noqa: ANN001
        state_pipeline_calls.append("scan_state_as_plan")

    def fake_emit_drift_report(self, state, state_plan_json, drift_report):  # noqa: ANN001
        state_pipeline_calls.append("emit_drift_report")
        drift_report.write_text(
            json.dumps(
                {
                    "summary": {"added": 0, "changed": 0, "removed": 0},
                    "items": [],
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_alert_network_required",
        fake_alert_network_required,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_init",
        fake_terraform_init,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_plan",
        fake_terraform_plan,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_run_terraform_show",
        fake_terraform_show,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_download_state_blob",
        fake_download_state_blob,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_convert_state_to_plan",
        fake_convert_state_to_plan,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_scan_state_as_plan",
        fake_scan_state_as_plan,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_emit_drift_report",
        fake_emit_drift_report,
    )
    # Mock the PCI 10.7 hygiene shreds so the state artifacts survive
    # for post-scan assertion (production shreds them).
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_shred_plan_artifacts",
        lambda self, state: None,
    )
    monkeypatch.setattr(
        scanner_orchestrator.Orchestrator,
        "_shred_state_plan",
        lambda cls, path: None,
    )
    monkeypatch.setattr("scanner.aggregate.main", lambda: 0, raising=False)

    orch = Orchestrator(mode="report", tier="state")
    rc = orch.scan(
        target_repo=tmp_path,
        project=None,
        env=None,
        label=None,
        output_dir=output_dir,
        mapping_path=None,
        baseline_path=None,
        state_account=state_account,
    )

    assert rc == 0
    pair_dir = output_dir / "payments" / "prod"
    assert pair_dir.is_dir(), f"missing pair dir: {pair_dir}"

    # Per the MUST-DO contract: all three state artifacts in the per-pair dir.
    state_tfstate = pair_dir / "state.tfstate"
    state_as_plan = pair_dir / "state_as_plan.json"
    drift_report = pair_dir / "drift_report.json"
    assert state_tfstate.is_file(), f"missing state.tfstate: {state_tfstate}"
    assert state_as_plan.is_file(), f"missing state_as_plan.json: {state_as_plan}"
    assert drift_report.is_file(), f"missing drift_report.json: {drift_report}"

    # The 4 state-blob helpers fired in order.
    assert state_pipeline_calls == [
        "download_state_blob",
        "convert_state_to_plan",
        "scan_state_as_plan",
        "emit_drift_report",
    ], f"unexpected state pipeline order: {state_pipeline_calls}"

    # safety.refuse_if_mutating fired at the tier=state subprocess gate.
    # The plan-prep whitelist MyIP call also fires the guard (storage
    # account network-rule add is an ALLOWED_EXCEPTION so the guard
    # returns normally). For the state-blob download the cmd must
    # contain "az storage blob download" so we verify at least one
    # refuse_if_mutating call landed with that signature.
    download_calls = [c for c in safety_calls if "storage blob download" in c]
    assert download_calls, (
        f"refuse_if_mutating did not fire on blob-download cmd; got: {safety_calls}"
    )


def test_tier_state_safety_guard_refuses_mutating_command() -> None:
    """Defense-in-depth: ``safety.refuse_if_mutating`` rejects a mutating az command.

    Pins the contract that the tier=state subprocess gate actually
    invokes the safety guard and the guard rejects any non-allowed
    mutation. We don't go through ``Orchestrator.scan`` here — we
    exercise the SafetyGuard directly because the orchestrator's
    state-blob command (``az storage blob download ...``) is itself an
    ALLOWED_EXCEPTION and would pass silently. This test pins the
    negative case so future refactors that remove the guard fail loud.
    """
    guard = scanner_safety.SafetyGuard()
    with pytest.raises(scanner_safety.MutatingOperationRefused) as exc_info:
        guard.refuse_if_mutating("terraform apply -auto-approve")

    msg = str(exc_info.value)
    assert "terraform apply" in msg
    # The blob download command itself must NOT be refused (it's in
    # ALLOWED_EXCEPTIONS) — that is what makes the tier=state path safe.
    assert guard.refuse_if_mutating(
        "az storage blob download --account-name mystorageacct "
        "--container-name iac --name CR_Prod_payments.tfstate"
    ) is None


# ---------------------------------------------------------------------------
# 9. _discover_public_ip (direct)
# ---------------------------------------------------------------------------


def test_discover_public_ip_returns_first_successful_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_discover_public_ip`` returns the IP from the first URL that responds.

    Monkeypatches :func:`urllib.request.urlopen` so the IMDS endpoint
    answers with a known IP. Verifies the IP is returned unchanged and
    no fallback URL is tried.
    """
    expected_ip = "203.0.113.42"

    class _FakeResponse:
        def __init__(self, payload: str) -> None:
            self._payload = payload.encode("utf-8")

        def read(self) -> bytes:
            return self._payload

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    captured_urls: list[str] = []

    def fake_urlopen(req, timeout=5):  # noqa: ANN001 — urllib.request signature
        captured_urls.append(req.full_url)
        return _FakeResponse(expected_ip)

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_urlopen,
    )

    ip = scanner_orchestrator._discover_public_ip()

    assert ip == expected_ip
    # At minimum the IMDS endpoint was tried; ipify may also be tried if
    # we count retries — but since the first attempt returns truthy, the
    # loop returns immediately.
    assert any("169.254.169.254" in u for u in captured_urls), (
        f"IMDS endpoint not tried; got urls={captured_urls}"
    )


def test_discover_public_ip_falls_back_to_ipify_on_imds_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the IMDS endpoint raises, ``_discover_public_ip`` falls back to ipify.

    Two URL handlers: the first one (IMDS) raises a generic exception,
    the second one (ipify) returns the known IP. The test asserts the
    fallback path runs AND the discovered IP is returned (not None).
    """
    expected_ip = "198.51.100.7"

    class _FakeResponse:
        def __init__(self, payload: str) -> None:
            self._payload = payload.encode("utf-8")

        def read(self) -> bytes:
            return self._payload

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    captured_urls: list[str] = []

    def fake_urlopen(req, timeout=5):  # noqa: ANN001 — urllib.request signature
        captured_urls.append(req.full_url)
        if "169.254.169.254" in req.full_url:
            raise OSError("IMDS unreachable (not on Azure VM)")
        return _FakeResponse(expected_ip)

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_urlopen,
    )

    ip = scanner_orchestrator._discover_public_ip()

    assert ip == expected_ip
    # Both candidates were tried in order: IMDS first, then ipify.
    assert len(captured_urls) == 2, (
        f"expected 2 urlopen calls (IMDS + ipify), got {captured_urls}"
    )
    assert "169.254.169.254" in captured_urls[0]
    assert "api.ipify.org" in captured_urls[1]


# ---------------------------------------------------------------------------
# 10. _register_cleanup_trap ordering
# ---------------------------------------------------------------------------


def test_register_cleanup_trap_runs_whitelist_then_shred(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``_register_cleanup_trap`` closure runs the whitelist cleanup before shred.

    Replaces :func:`scanner.trap.register_traps` with a recorder that
    captures the cleanup callable. We then invoke the cleanup callable
    directly and assert:
      1. ``cleanup_ip_whitelist`` is called first (storage firewall
         must be reverted before local artifacts are shredded, so a
         crash mid-shred still leaves the firewall reverted)
      2. ``shred_plan_artifacts`` is called second
      3. Both are called with the captured output_dir + state_account
    """
    state_account = "mystorageacct"
    output_dir = tmp_path / "runs"
    output_dir.mkdir()

    cleanup_callable_captured: list = []

    def fake_register_traps(cleanup_fn):  # noqa: ANN001 — trap.register_traps signature
        cleanup_callable_captured.append(cleanup_fn)

    monkeypatch.setattr(
        "scanner.orchestrator.register_traps",
        fake_register_traps,
    )

    # Track the order of the two real cleanup helpers.
    call_order: list[str] = []
    cleanup_calls: list[tuple] = []

    def fake_cleanup_ip_whitelist(run_dir, account, **kw):  # noqa: ANN001
        call_order.append("cleanup_ip_whitelist")
        cleanup_calls.append((run_dir, account))
        return True

    def fake_shred_plan_artifacts(run_dir, **kw):  # noqa: ANN001
        call_order.append("shred_plan_artifacts")
        cleanup_calls.append(run_dir)
        return True

    monkeypatch.setattr(
        "scanner.orchestrator.cleanup_ip_whitelist",
        fake_cleanup_ip_whitelist,
    )
    monkeypatch.setattr(
        "scanner.orchestrator.shred_plan_artifacts",
        fake_shred_plan_artifacts,
    )

    scanner_orchestrator._register_cleanup_trap(output_dir, state_account)

    # The trap was wired.
    assert len(cleanup_callable_captured) == 1, (
        "register_traps was not called by _register_cleanup_trap"
    )

    # Invoke the captured cleanup callable directly to verify ordering
    # without firing atexit / signal handlers.
    cleanup_callable_captured[0]()

    assert call_order == ["cleanup_ip_whitelist", "shred_plan_artifacts"], (
        f"cleanup ran in wrong order: {call_order}"
    )
    # cleanup_ip_whitelist saw the captured state_account.
    assert cleanup_calls[0] == (output_dir, state_account)
    # shred_plan_artifacts saw the captured output_dir (single-arg helper).
    assert cleanup_calls[1] == output_dir


def test_register_cleanup_trap_skips_whitelist_when_no_state_account(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """With ``state_account=None``, the cleanup closure skips the firewall revert.

    Mirrors ``_register_cleanup_trap`` lines 1465-1467: the whitelist
    cleanup is gated on ``captured_account`` being truthy. The shred
    step still runs (the run dir may have plan artifacts even when no
    storage account was configured).
    """
    output_dir = tmp_path / "runs"
    output_dir.mkdir()

    cleanup_callable_captured: list = []

    def fake_register_traps(cleanup_fn):  # noqa: ANN001
        cleanup_callable_captured.append(cleanup_fn)

    monkeypatch.setattr(
        "scanner.orchestrator.register_traps",
        fake_register_traps,
    )

    call_order: list[str] = []

    def fake_cleanup_ip_whitelist(run_dir, account, **kw):  # noqa: ANN001
        call_order.append("cleanup_ip_whitelist")

    def fake_shred_plan_artifacts(run_dir, **kw):  # noqa: ANN001
        call_order.append("shred_plan_artifacts")

    monkeypatch.setattr(
        "scanner.orchestrator.cleanup_ip_whitelist",
        fake_cleanup_ip_whitelist,
    )
    monkeypatch.setattr(
        "scanner.orchestrator.shred_plan_artifacts",
        fake_shred_plan_artifacts,
    )

    scanner_orchestrator._register_cleanup_trap(output_dir, None)

    assert len(cleanup_callable_captured) == 1
    cleanup_callable_captured[0]()

    assert call_order == ["shred_plan_artifacts"], (
        f"expected only shred to fire when state_account is None, got: {call_order}"
    )