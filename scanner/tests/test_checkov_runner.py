"""Tests for scanner.checkov_runner.CheckovRunner.

Covers the four behaviors called out in the worktree plan:

  * CWD at scan dispatch equals ``env_dir`` (Windows relpath workaround)
  * CWD is restored after the run, even when Checkov raises
  * ``--skip-path`` flags are still applied for ``aztfexport`` files
  * SARIF is emitted to the correct path (with a ``runs`` array) and
    a partial run leaves no SARIF at the destination.

Checkov is mocked per-test via :class:`_FakeCheckov` so the suite has
no dependency on a real Checkov install, an Azure subscription, or
network access. The fake writes the SARIF artifact that ``_run``
expects (``<tmp_dir>/results_sarif.sarif``) and captures ``os.getcwd()``
at the moment ``run()`` is called.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scanner.checkov_runner import AZTFEXPORT_FILES, CheckovRunner, _SARIF_BASENAME


# ---------------------------------------------------------------------------
# Fake Checkov
# ---------------------------------------------------------------------------


class _FakeCheckov:
    """Stand-in for :class:`checkov.main.Checkov`.

    Records ``os.getcwd()`` at run-time, writes a minimal-but-valid
    SARIF document to ``<argv's --output-file-path>/results_sarif.sarif``,
    and returns ``None`` like a clean Checkov run.

    Set ``.raise_in_run`` to make ``run()`` raise — the partial-run
    test relies on this to confirm the ``finally`` cleanup runs.
    """

    # Captured state across all instantiations in a single test.
    instances: list["_FakeCheckov"] = []

    def __init__(self, argv: list[str]) -> None:
        self.argv = list(argv)
        self.cwd_at_run: str | None = None
        self.raise_in_run: bool = False
        type(self).instances.append(self)

    def run(self) -> None:
        self.cwd_at_run = os.getcwd()
        if self.raise_in_run:
            raise RuntimeError("simulated checkov failure mid-run")
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
        return None  # Checkov's clean-run return.

    def _extract_output_dir(self) -> Path:
        """Pull ``--output-file-path`` out of the argv list."""
        for i, tok in enumerate(self.argv):
            if tok == "--output-file-path" and i + 1 < len(self.argv):
                return Path(self.argv[i + 1])
        raise AssertionError(f"--output-file-path missing from argv: {self.argv}")


@pytest.fixture
def fake_checkov_module(monkeypatch: pytest.MonkeyPatch):
    """Patch ``checkov.main.Checkov`` to :class:`_FakeCheckov`.

    The runner imports lazily: ``from checkov.main import Checkov``.
    We patch both the ``checkov`` module attribute and the name bound
    inside ``checkov.main`` so either path is covered.
    """
    _FakeCheckov.instances = []
    import checkov.main as checkov_main

    monkeypatch.setattr(checkov_main, "Checkov", _FakeCheckov, raising=True)
    # Defensive: also patch the parent module in case ``from checkov.main
    # import Checkov`` was already executed at import time elsewhere.
    import checkov as checkov_pkg

    monkeypatch.setattr(checkov_pkg, "Checkov", _FakeCheckov, raising=False)
    yield _FakeCheckov
    _FakeCheckov.instances = []


# ---------------------------------------------------------------------------
# CWD = env_dir during the run
# ---------------------------------------------------------------------------


def test_cwd_equals_env_dir_during_run(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """The runner must ``os.chdir(env_dir)`` before Checkov runs.

    This is the Windows relpath workaround documented in
    :mod:`scanner.checkov_runner` — if the CWD sits on a different
    drive than the scanned file, Checkov 3.3.9 raises
    ``ValueError: path is on mount 'C:', start on mount 'S:'``.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"
    outside_cwd = os.getcwd()

    rc = CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    assert rc == 0
    assert len(fake_checkov_module.instances) == 1
    captured = fake_checkov_module.instances[0].cwd_at_run
    assert captured is not None, "FakeCheckov.run() was never invoked"
    # ``os.chdir`` uses the resolved path on Windows for drive-relative paths,
    # so compare resolved paths rather than the literal Path object.
    assert Path(captured).resolve() == env_dir.resolve()
    # And — critically — the CWD is no longer where we started.
    assert Path(captured).resolve() != Path(outside_cwd).resolve()


# ---------------------------------------------------------------------------
# CWD restored after the run
# ---------------------------------------------------------------------------


def test_cwd_restored_after_clean_run(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"
    saved_cwd = os.getcwd()

    CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    assert os.getcwd() == saved_cwd, f"CWD not restored: {os.getcwd()!r} != {saved_cwd!r}"


def test_cwd_restored_when_checkov_raises(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """A mid-run exception must not leak the new CWD to the caller."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"
    saved_cwd = os.getcwd()

    fake_checkov_module.instances.clear()
    # Arm the next fake to raise from .run().
    original_init = fake_checkov_module.__init__

    def armed_init(self, argv: list[str]) -> None:
        original_init(self, argv)
        self.raise_in_run = True

    fake_checkov_module.__init__ = armed_init  # type: ignore[assignment]
    try:
        runner = CheckovRunner(mode="report")
        with pytest.raises(RuntimeError, match="simulated checkov failure"):
            runner.run_source(env_dir, sarif_out)
    finally:
        fake_checkov_module.__init__ = original_init  # type: ignore[assignment]

    assert os.getcwd() == saved_cwd


# ---------------------------------------------------------------------------
# aztfexport skip-path still applied
# ---------------------------------------------------------------------------


def test_aztfexport_files_become_skip_path_flags(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """Files named in ``AZTFEXPORT_FILES`` must be passed via ``--skip-path``.

    Mirrors ``find_aztfexport_files`` in ``scan.sh``: the scanner
    must not waste Checkov cycles on machine-authored files.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    # Plant *some* but not all aztfexport files — the runner should
    # only emit a flag for files that actually exist on disk.
    planted = ("terraform.aztfexport.tf", "main.aztfexport.tf")
    for name in planted:
        (env_dir / name).write_text("# aztfexport\n", encoding="utf-8")
    # Also a real .tf so the source pass has something to look at.
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"

    CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    argv = fake_checkov_module.instances[0].argv
    skip_targets = []
    for i, tok in enumerate(argv):
        if tok == "--skip-path" and i + 1 < len(argv):
            skip_targets.append(argv[i + 1])

    # Every planted aztfexport filename is referenced; unplanted ones are not.
    for name in planted:
        assert name in skip_targets, f"missing --skip-path {name}; got {skip_targets}"
    for name in AZTFEXPORT_FILES:
        if name not in planted:
            assert name not in skip_targets, (
                f"unexpected --skip-path {name} for non-existent file; got {skip_targets}"
            )


def test_no_skip_path_flags_when_no_aztfexport_files(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"

    CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    argv = fake_checkov_module.instances[0].argv
    assert "--skip-path" not in argv, f"unexpected --skip-path in argv: {argv}"


# ---------------------------------------------------------------------------
# SARIF emission
# ---------------------------------------------------------------------------


def test_sarif_written_to_given_path_with_runs_array(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"

    CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    assert sarif_out.is_file(), f"SARIF not written to {sarif_out}"
    data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert isinstance(data.get("runs"), list), "SARIF missing 'runs' array"
    assert len(data["runs"]) >= 1


def test_sarif_destination_parent_is_created(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``sarif_out.parent`` may not exist yet — the runner must mkdir it."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    # Deeply nested, definitely absent path.
    sarif_out = tmp_path / "a" / "b" / "c" / "results.sarif"
    assert not sarif_out.parent.exists()

    CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    assert sarif_out.is_file()


def test_existing_sarif_is_not_clobbered_on_partial_run(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """A partial/failed scan must leave any pre-existing SARIF untouched.

    The runner writes Checkov's output to a scratch directory and only
    ``shutil.move``-s it to ``sarif_out`` on success. A mid-run
    exception therefore cannot overwrite a SARIF that the caller
    already had on disk.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"
    sarif_out.parent.mkdir(parents=True, exist_ok=True)
    sentinel = '{"$schema":"sentinel","version":"2.1.0","runs":[]}'
    sarif_out.write_text(sentinel, encoding="utf-8")

    # Arm the fake to raise mid-run.
    original_init = fake_checkov_module.__init__
    fake_checkov_module.instances.clear()

    def armed_init(self, argv: list[str]) -> None:
        original_init(self, argv)
        self.raise_in_run = True

    fake_checkov_module.__init__ = armed_init  # type: ignore[assignment]
    try:
        runner = CheckovRunner(mode="report")
        with pytest.raises(RuntimeError, match="simulated checkov failure"):
            runner.run_source(env_dir, sarif_out)
    finally:
        fake_checkov_module.__init__ = original_init  # type: ignore[assignment]

    # Sentinel must still be on disk, byte-for-byte.
    assert sarif_out.is_file()
    assert sarif_out.read_text(encoding="utf-8") == sentinel


def test_partial_run_leaves_no_sarif_at_destination(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """If Checkov raises before producing SARIF, the destination stays empty.

    This is the contract that lets the caller safely ``if sarif_out.is_file()``
    to decide whether the pass produced findings.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"
    sarif_out.parent.mkdir(parents=True, exist_ok=True)
    assert not sarif_out.exists()

    # Arm the fake to raise mid-run, before any SARIF write.
    original_init = fake_checkov_module.__init__
    fake_checkov_module.instances.clear()

    def armed_init(self, argv: list[str]) -> None:
        original_init(self, argv)
        self.raise_in_run = True

    fake_checkov_module.__init__ = armed_init  # type: ignore[assignment]
    try:
        runner = CheckovRunner(mode="report")
        with pytest.raises(RuntimeError, match="simulated checkov failure"):
            runner.run_source(env_dir, sarif_out)
    finally:
        fake_checkov_module.__init__ = original_init  # type: ignore[assignment]

    assert not sarif_out.exists(), (
        f"partial run unexpectedly produced SARIF at {sarif_out}"
    )


# ---------------------------------------------------------------------------
# Cleanup hygiene
# ---------------------------------------------------------------------------


def test_scratch_dir_is_cleaned_up(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """The ``pacioli_ckv_*`` scratch dir must not survive a successful run."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out_parent = tmp_path / "out"
    sarif_out = sarif_out_parent / "results.sarif"

    CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    leftovers = [p for p in sarif_out_parent.iterdir() if p.name.startswith("pacioli_ckv_")]
    assert leftovers == [], f"scratch dir not cleaned: {leftovers}"


# ---------------------------------------------------------------------------
# Framework-agnostic dispatch (T4 — multi-cloud-framework-generalization)
# ---------------------------------------------------------------------------


def _extract_argv_value(argv: list[str], flag: str) -> str | None:
    """Return the value following ``flag`` in argv, or ``None`` if absent."""
    for i, tok in enumerate(argv):
        if tok == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


def test_run_framework_passes_cloudformation_flag(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``run_framework(env_dir, sarif_out, framework='cloudformation')`` must
    emit ``--framework cloudformation`` in the Checkov argv.

    This is the T4 acceptance criterion: any framework accepted by Checkov
    (not just the legacy ``terraform``/``terraform_plan``/``secrets`` set)
    flows through the generic dispatcher with no per-framework argv
    duplication.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    # CloudFormation template — content passes the CFN sniff heuristic.
    (env_dir / "template.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n",
        encoding="utf-8",
    )

    sarif_out = tmp_path / "out" / "results.sarif"

    rc = CheckovRunner(mode="report").run_framework(
        env_dir, sarif_out, framework="cloudformation"
    )

    assert rc == 0
    assert len(fake_checkov_module.instances) == 1
    argv = fake_checkov_module.instances[0].argv
    fw_value = _extract_argv_value(argv, "--framework")
    assert fw_value == "cloudformation", (
        f"--framework cloudformation missing; got argv={argv}"
    )


def test_run_framework_omits_external_checks_dir_for_non_terraform(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``--external-checks-dir`` must NOT be added for non-terraform-family.

    The custom PaaC checks under ``scanner/checks/`` subclass
    Terraform's ``BaseResourceCheck`` — they cannot be applied to
    CloudFormation, Kubernetes, Dockerfile, etc. The gate is encoded
    once via :func:`scanner.frameworks.is_terraform_family`.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "template.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n", encoding="utf-8"
    )

    sarif_out = tmp_path / "out" / "results.sarif"

    # Pass a checks_dir that exists on disk so the gate is meaningful.
    checks_dir = tmp_path / "checks"
    checks_dir.mkdir()
    CheckovRunner(mode="report", checks_dir=checks_dir).run_framework(
        env_dir, sarif_out, framework="cloudformation"
    )

    argv = fake_checkov_module.instances[0].argv
    assert "--external-checks-dir" not in argv, (
        f"--external-checks-dir must be omitted for cloudformation; got argv={argv}"
    )


def test_run_framework_adds_external_checks_dir_for_terraform(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``--external-checks-dir`` IS added for terraform-family frameworks."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"

    checks_dir = tmp_path / "checks"
    checks_dir.mkdir()
    CheckovRunner(mode="report", checks_dir=checks_dir).run_framework(
        env_dir, sarif_out, framework="terraform"
    )

    argv = fake_checkov_module.instances[0].argv
    ec_dir = _extract_argv_value(argv, "--external-checks-dir")
    assert ec_dir is not None, f"--external-checks-dir missing for terraform; got argv={argv}"
    # The resolved checks_dir should be passed.
    assert Path(ec_dir).resolve() == checks_dir.resolve()


def test_run_paac_delegates_to_run_framework_with_terraform(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``run_paac`` is now a thin delegate — emits ``--framework terraform``."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"

    checks_dir = tmp_path / "checks"
    checks_dir.mkdir()
    CheckovRunner(mode="report", checks_dir=checks_dir).run_paac(env_dir, sarif_out)

    argv = fake_checkov_module.instances[0].argv
    assert _extract_argv_value(argv, "--framework") == "terraform"
    assert _extract_argv_value(argv, "--external-checks-dir") is not None


def test_run_secrets_delegates_to_run_framework_with_secrets(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``run_secrets`` delegates with ``framework='secrets'`` and omits external-checks-dir."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"

    # Even with checks_dir present, secrets must NOT get --external-checks-dir.
    checks_dir = tmp_path / "checks"
    checks_dir.mkdir()
    CheckovRunner(mode="report", checks_dir=checks_dir).run_secrets(env_dir, sarif_out)

    argv = fake_checkov_module.instances[0].argv
    assert _extract_argv_value(argv, "--framework") == "secrets"
    assert "--external-checks-dir" not in argv, (
        f"--external-checks-dir must be omitted for secrets; got argv={argv}"
    )


def test_run_source_delegates_to_run_framework_with_terraform(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``run_source`` delegates with ``framework='terraform'``."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    sarif_out = tmp_path / "out" / "results.sarif"

    CheckovRunner(mode="report").run_source(env_dir, sarif_out)

    argv = fake_checkov_module.instances[0].argv
    assert _extract_argv_value(argv, "--framework") == "terraform"


def test_run_plan_uses_file_mode_and_terraform_plan_framework(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``run_plan`` emits ``-f <plan.json> --framework terraform_plan``."""
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    plan_json = env_dir / "plan.json"
    plan_json.write_text('{"format_version": "1.0"}', encoding="utf-8")
    sarif_out = tmp_path / "out" / "results.sarif"

    CheckovRunner(mode="report").run_plan(plan_json, sarif_out)

    argv = fake_checkov_module.instances[0].argv
    assert _extract_argv_value(argv, "--framework") == "terraform_plan"
    # File mode, not directory mode.
    assert _extract_argv_value(argv, "-f") == str(plan_json.resolve())
    assert _extract_argv_value(argv, "-d") is None


def test_run_paac_early_returns_when_checks_dir_missing(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """``run_paac`` must short-circuit (return 0) when checks_dir does not exist.

    Preserves the historical bash guard ``if [[ -d "$PCI_CHECKS_DIR" ]]``.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    sarif_out = tmp_path / "out" / "results.sarif"
    # checks_dir defaults to scanner/checks/ which may or may not exist on
    # a given test machine — use an explicit non-existent path.
    missing = tmp_path / "no_such_checks_dir"

    rc = CheckovRunner(mode="report", checks_dir=missing).run_paac(env_dir, sarif_out)

    assert rc == 0
    assert fake_checkov_module.instances == [], (
        "Checkov must not be invoked when checks_dir is missing"
    )


def test_init_accepts_frameworks_parameter() -> None:
    """The new ``frameworks`` constructor param is stored verbatim."""
    r = CheckovRunner(mode="report", frameworks=["cloudformation", "kubernetes"])
    assert r.frameworks == ("cloudformation", "kubernetes")
    # Default is None (auto-detect per call).
    r2 = CheckovRunner(mode="report")
    assert r2.frameworks is None


def test_detect_frameworks_instance_method_delegates_to_shared_helper(
    tmp_path: Path,
) -> None:
    """``CheckovRunner.detect_frameworks`` is a thin pass-through to
    :func:`scanner.frameworks.detect_frameworks`."""
    from scanner.frameworks import detect_frameworks

    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")

    runner = CheckovRunner(mode="report")
    via_runner = runner.detect_frameworks(env_dir)
    via_helper = detect_frameworks(env_dir)
    assert via_runner == via_helper
    assert "terraform" in via_runner


def test_run_framework_does_not_validate_framework_name(
    tmp_path: Path, fake_checkov_module: type[_FakeCheckov]
) -> None:
    """Pacioli does NOT validate framework names — Checkov itself does.

    Pass a bogus framework; the runner must hand the argv to the mocked
    Checkov, which accepts everything (it's a fake). This codifies that
    the runner is intentionally a thin wrapper.
    """
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    sarif_out = tmp_path / "out" / "results.sarif"

    rc = CheckovRunner(mode="report").run_framework(
        env_dir, sarif_out, framework="definitely_not_a_real_framework"
    )

    assert rc == 0
    argv = fake_checkov_module.instances[0].argv
    assert _extract_argv_value(argv, "--framework") == "definitely_not_a_real_framework"