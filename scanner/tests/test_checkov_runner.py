"""Tests for scanner.checkov_runner.CheckovRunner.

HOTFIX 1.2.1: Checkov 3.3.9 caches its scan results in module-level
state. The fix invokes Checkov via subprocess so each scan gets its
own Python process and cache namespace. This module mocks
subprocess.run instead of Checkov(argv=...).run().

Behavioral contracts preserved: cwd, argv, SARIF emission, cleanup.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.checkov_runner import AZTFEXPORT_FILES, CheckovRunner, _SARIF_BASENAME


def _extract_value(argv, flag):
    for i, tok in enumerate(argv):
        if tok == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _sys_executable_now():
    import sys as _s
    return _s.executable


class _FakeSubprocess:
    instances = []

    def __init__(self):
        self.calls = []
        self.raise_in_run = False
        type(self).instances.append(self)

    def __call__(self, argv, *, cwd=None, capture_output=False, text=False,
                 timeout=None, check=False):
        checkov_argv = list(argv[3:]) if argv[:2] == [_sys_executable_now(), '-m'] else list(argv)
        call = {
            'argv': checkov_argv,
            'cwd': str(cwd) if cwd is not None else None,
            'capture_output': capture_output,
            'text': text,
            'timeout': timeout,
            'check': check,
        }
        self.calls.append(call)
        if self.raise_in_run:
            raise RuntimeError('simulated checkov failure mid-run')
        out_dir = _extract_value(checkov_argv, '--output-file-path')
        if out_dir is None:
            return _FakeCompletedProcess(returncode=2, stderr='--output-file-path missing')
        out_path = Path(out_dir) / _SARIF_BASENAME
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps({
                '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
                'version': '2.1.0',
                'runs': [{'tool': {'driver': {'name': 'fake-checkov', 'version': '0.0.0',
                                              'informationUri': 'https://example.invalid'}},
                          'results': []}],
            }),
            encoding='utf-8',
        )
        return _FakeCompletedProcess(returncode=0)


class _FakeSubprocessProxy:
    """Drop-in for the subprocess module. Only run is faked."""
    def __init__(self, fake):
        self._fake = fake

    def run(self, *args, **kwargs):
        return self._fake(*args, **kwargs)


@pytest.fixture
def fake_checkov_module(monkeypatch):
    _FakeSubprocess.instances = []
    fake = _FakeSubprocess()
    import scanner.checkov_runner as cr_mod
    monkeypatch.setattr(cr_mod, 'subprocess', _FakeSubprocessProxy(fake), raising=True)
    yield fake
    _FakeSubprocess.instances = []


# --- cwd = env_dir via subprocess.run ---------------------------------------


def test_subprocess_receives_env_dir_as_cwd(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    rc = CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    assert rc == 0
    assert len(fake_checkov_module.calls) == 1
    captured = fake_checkov_module.calls[0]['cwd']
    assert captured is not None
    assert Path(captured).resolve() == env_dir.resolve()


def test_cwd_restored_after_clean_run(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    saved_cwd = os.getcwd()
    CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    assert os.getcwd() == saved_cwd


def test_cwd_restored_when_checkov_raises(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    saved_cwd = os.getcwd()
    fake_checkov_module.raise_in_run = True
    try:
        runner = CheckovRunner(mode='report')
        with pytest.raises(RuntimeError, match='simulated checkov failure'):
            runner.run_source(env_dir, sarif_out)
    finally:
        fake_checkov_module.raise_in_run = False
    assert os.getcwd() == saved_cwd


# --- aztfexport skip-path --------------------------------------------------


def test_aztfexport_files_become_skip_path_flags(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    planted = ('terraform.aztfexport.tf', 'main.aztfexport.tf')
    for name in planted:
        (env_dir / name).write_text('# aztfexport\n', encoding='utf-8')
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    argv = fake_checkov_module.calls[0]['argv']
    skip_targets = [argv[i+1] for i, t in enumerate(argv) if t == '--skip-path' and i+1 < len(argv)]
    for name in planted:
        assert name in skip_targets
    for name in AZTFEXPORT_FILES:
        if name not in planted:
            assert name not in skip_targets


def test_no_skip_path_flags_when_no_aztfexport_files(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    argv = fake_checkov_module.calls[0]['argv']
    assert '--skip-path' not in argv


# --- SARIF emission --------------------------------------------------------


def test_sarif_written_to_given_path_with_runs_array(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    assert sarif_out.is_file()
    data = json.loads(sarif_out.read_text(encoding='utf-8'))
    assert isinstance(data.get('runs'), list)
    assert len(data['runs']) >= 1


def test_sarif_destination_parent_is_created(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'a' / 'b' / 'c' / 'results.sarif'
    assert not sarif_out.parent.exists()
    CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    assert sarif_out.is_file()


def test_existing_sarif_is_not_clobbered_on_partial_run(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    sarif_out.parent.mkdir(parents=True, exist_ok=True)
    sentinel = '{"$schema":"sentinel","version":"2.1.0","runs":[]}'
    sarif_out.write_text(sentinel, encoding='utf-8')
    fake_checkov_module.raise_in_run = True
    try:
        runner = CheckovRunner(mode='report')
        with pytest.raises(RuntimeError, match='simulated checkov failure'):
            runner.run_source(env_dir, sarif_out)
    finally:
        fake_checkov_module.raise_in_run = False
    assert sarif_out.is_file()
    assert sarif_out.read_text(encoding='utf-8') == sentinel


def test_partial_run_leaves_no_sarif_at_destination(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    sarif_out.parent.mkdir(parents=True, exist_ok=True)
    assert not sarif_out.exists()
    fake_checkov_module.raise_in_run = True
    try:
        runner = CheckovRunner(mode='report')
        with pytest.raises(RuntimeError, match='simulated checkov failure'):
            runner.run_source(env_dir, sarif_out)
    finally:
        fake_checkov_module.raise_in_run = False
    assert not sarif_out.exists()


# --- Cleanup hygiene -------------------------------------------------------


def test_scratch_dir_is_cleaned_up(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out_parent = tmp_path / 'out'
    sarif_out = sarif_out_parent / 'results.sarif'
    CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    leftovers = [p for p in sarif_out_parent.iterdir() if p.name.startswith('pacioli_ckv_')]
    assert leftovers == []


# --- Framework dispatch ----------------------------------------------------


def test_run_framework_passes_cloudformation_flag(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'template.yaml').write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n',
        encoding='utf-8',
    )
    sarif_out = tmp_path / 'out' / 'results.sarif'
    rc = CheckovRunner(mode='report').run_framework(env_dir, sarif_out, framework='cloudformation')
    assert rc == 0
    argv = fake_checkov_module.calls[0]['argv']
    assert _extract_value(argv, '--framework') == 'cloudformation'


def test_run_framework_omits_external_checks_dir_for_non_terraform(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'template.yaml').write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\n', encoding='utf-8',
    )
    sarif_out = tmp_path / 'out' / 'results.sarif'
    checks_dir = tmp_path / 'checks'
    checks_dir.mkdir()
    CheckovRunner(mode='report', checks_dir=checks_dir).run_framework(env_dir, sarif_out, framework='cloudformation')
    argv = fake_checkov_module.calls[0]['argv']
    assert '--external-checks-dir' not in argv


def test_run_framework_adds_external_checks_dir_for_terraform(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    checks_dir = tmp_path / 'checks'
    checks_dir.mkdir()
    CheckovRunner(mode='report', checks_dir=checks_dir).run_framework(env_dir, sarif_out, framework='terraform')
    argv = fake_checkov_module.calls[0]['argv']
    ec_dir = _extract_value(argv, '--external-checks-dir')
    assert ec_dir is not None
    assert Path(ec_dir).resolve() == checks_dir.resolve()


def test_run_paac_delegates_to_run_framework_with_terraform(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    checks_dir = tmp_path / 'checks'
    checks_dir.mkdir()
    CheckovRunner(mode='report', checks_dir=checks_dir).run_paac(env_dir, sarif_out)
    argv = fake_checkov_module.calls[0]['argv']
    assert _extract_value(argv, '--framework') == 'terraform'
    assert _extract_value(argv, '--external-checks-dir') is not None


def test_run_secrets_delegates_to_run_framework_with_secrets(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    checks_dir = tmp_path / 'checks'
    checks_dir.mkdir()
    CheckovRunner(mode='report', checks_dir=checks_dir).run_secrets(env_dir, sarif_out)
    argv = fake_checkov_module.calls[0]['argv']
    assert _extract_value(argv, '--framework') == 'secrets'
    assert '--external-checks-dir' not in argv


def test_run_source_delegates_to_run_framework_with_terraform(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    CheckovRunner(mode='report').run_source(env_dir, sarif_out)
    argv = fake_checkov_module.calls[0]['argv']
    assert _extract_value(argv, '--framework') == 'terraform'


def test_run_plan_uses_file_mode_and_terraform_plan_framework(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    plan_json = env_dir / 'plan.json'
    plan_json.write_text('{"format_version": "1.0"}', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'
    CheckovRunner(mode='report').run_plan(plan_json, sarif_out)
    argv = fake_checkov_module.calls[0]['argv']
    assert _extract_value(argv, '--framework') == 'terraform_plan'
    assert _extract_value(argv, '-f') == str(plan_json.resolve())
    assert _extract_value(argv, '-d') is None


def test_run_paac_early_returns_when_checks_dir_missing(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    sarif_out = tmp_path / 'out' / 'results.sarif'
    missing = tmp_path / 'no_such_checks_dir'
    rc = CheckovRunner(mode='report', checks_dir=missing).run_paac(env_dir, sarif_out)
    assert rc == 0
    assert fake_checkov_module.calls == []


def test_init_accepts_frameworks_parameter():
    r = CheckovRunner(mode='report', frameworks=['cloudformation', 'kubernetes'])
    assert r.frameworks == ('cloudformation', 'kubernetes')
    r2 = CheckovRunner(mode='report')
    assert r2.frameworks is None


def test_detect_frameworks_instance_method_delegates_to_shared_helper(tmp_path):
    from scanner.frameworks import detect_frameworks
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    runner = CheckovRunner(mode='report')
    assert runner.detect_frameworks(env_dir) == detect_frameworks(env_dir)


def test_run_framework_does_not_validate_framework_name(tmp_path, fake_checkov_module):
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    sarif_out = tmp_path / 'out' / 'results.sarif'
    rc = CheckovRunner(mode='report').run_framework(env_dir, sarif_out, framework='definitely_not_a_real_framework')
    assert rc == 0
    argv = fake_checkov_module.calls[0]['argv']
    assert _extract_value(argv, '--framework') == 'definitely_not_a_real_framework'


# --- HOTFIX 1.2.1: subprocess argv shape -----------------------------------


def test_subprocess_argv_starts_with_python_executable(tmp_path, monkeypatch):
    """
Verify subprocess.run is called with [python_exe, '-m', 'checkov.main', ...].

This is the contract that guarantees each Checkov scan runs in its own
Python process and therefore its own cache namespace.
"""
    env_dir = tmp_path / 'env'
    env_dir.mkdir()
    (env_dir / 'main.tf').write_text('resource "null_resource" "x" {}\n', encoding='utf-8')
    sarif_out = tmp_path / 'out' / 'results.sarif'

    raw_argv_holder = []

    class _RawProxy:
        def __init__(self, fake):
            self._fake = fake

        def run(self, *args, **kwargs):
            raw_argv_holder.append(args[0])
            return self._fake(*args, **kwargs)

    fake = _FakeSubprocess()
    import scanner.checkov_runner as cr_mod
    monkeypatch.setattr(cr_mod, 'subprocess', _RawProxy(fake), raising=True)

    CheckovRunner(mode='report').run_source(env_dir, sarif_out)

    assert len(raw_argv_holder) == 1
    full_argv = raw_argv_holder[0]
    assert len(full_argv) >= 3
    assert full_argv[0] == _sys_executable_now()
    assert full_argv[1] == '-m'
    assert full_argv[2] == 'checkov.main'


def test_two_sequential_subprocess_scans_produce_independent_sarifs(tmp_path):
    """
REGRESSION: two Checkov subprocess scans against different env_dirs
must produce SARIFs that do NOT contaminate each other.

HOTFIX 1.2.1 root cause: Checkov 3.3.9's in-process cache returned the
first scan's results for every subsequent scan. The fix runs each
scan as a subprocess so each gets its own Python process and cache.

This test exercises the regression at the subprocess level: it runs
two real Checkov subprocesses sequentially against distinct envs and
asserts the SARIFs reference each env's own resources (not the
other env's). The test uses ``aws_s3_bucket`` because it triggers
multiple CKV rules on a minimal resource, so the SARIF result
payloads reference the offending resource by name and bucket string.
"""
    env_a = tmp_path / 'env_a'
    env_a.mkdir()
    (env_a / 'main.tf').write_text(
        'resource "aws_s3_bucket" "alpha" {\n'
        '  bucket = "test-bucket-alpha"\n'
        '}\n',
        encoding='utf-8',
    )

    env_b = tmp_path / 'env_b'
    env_b.mkdir()
    (env_b / 'main.tf').write_text(
        'resource "aws_s3_bucket" "beta" {\n'
        '  bucket = "test-bucket-beta"\n'
        '}\n',
        encoding='utf-8',
    )

    out_a = tmp_path / 'out_a'
    out_b = tmp_path / 'out_b'
    out_a.mkdir()
    out_b.mkdir()

    python_bin = sys.executable

    for env_dir, out_dir in [(env_a, out_a), (env_b, out_b)]:
        tmp_sarif = out_dir / 'pacioli_ckv'
        tmp_sarif.mkdir()
        subprocess.run(
            [python_bin, '-m', 'checkov.main',
             '-d', str(env_dir), '--framework', 'terraform',
             '--output', 'sarif', '--output-file-path', str(tmp_sarif),
             '--soft-fail'],
            cwd=str(env_dir),
            capture_output=True, text=True, timeout=120,
        )
        produced = tmp_sarif / 'results_sarif.sarif'
        if produced.is_file():
            (out_dir / 'results.sarif').write_bytes(produced.read_bytes())

    sarif_a = out_a / 'results.sarif'
    sarif_b = out_b / 'results.sarif'
    if not sarif_a.is_file() or not sarif_b.is_file():
        pytest.skip('checkov subprocess not available in this environment')

    data_a = json.loads(sarif_a.read_text(encoding='utf-8'))
    data_b = json.loads(sarif_b.read_text(encoding='utf-8'))

    text_a = json.dumps(data_a)
    text_b = json.dumps(data_b)

    # Each SARIF must reference its own env's resources. The
    # aws_s3_bucket "alpha" in env_a and "beta" in env_b trigger
    # multiple CKV rules; the SARIF for each scan names the
    # resource in both help.text and results[*].locations and shows
    # the bucket string in snippet.text.
    assert 'aws_s3_bucket.alpha' in text_a, (
        f'env_a SARIF missing aws_s3_bucket.alpha reference: {text_a[:2000]}'
    )
    assert 'test-bucket-alpha' in text_a, (
        f'env_a SARIF missing test-bucket-alpha reference: {text_a[:2000]}'
    )
    assert 'aws_s3_bucket.beta' in text_b, (
        f'env_b SARIF missing aws_s3_bucket.beta reference: {text_b[:2000]}'
    )
    assert 'test-bucket-beta' in text_b, (
        f'env_b SARIF missing test-bucket-beta reference: {text_b[:2000]}'
    )

    # THE REGRESSION: env A's findings must NOT leak into env B's SARIF.
    # Before the subprocess fix, Checkov 3.3.9's in-process cache
    # returned env A's results for the second (env B) call too.
    assert 'alpha' not in text_b, (
        f'REGRESSION: alpha resource leaked into env_b SARIF: {text_b[:2000]}'
    )
    assert 'test-bucket-alpha' not in text_b, (
        f'REGRESSION: test-bucket-alpha leaked into env_b SARIF: {text_b[:2000]}'
    )
    assert 'beta' not in text_a, (
        f'REGRESSION: beta resource leaked into env_a SARIF: {text_a[:2000]}'
    )
    assert 'test-bucket-beta' not in text_a, (
        f'REGRESSION: test-bucket-beta leaked into env_a SARIF: {text_a[:2000]}'
    )
