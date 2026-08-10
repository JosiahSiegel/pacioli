"""Tests for scanner.url_rewrite — the in-process SARIF + stream URL rewriter.

Covers every public function in scanner/url_rewrite.py:
  - rewrite_text (pure text rewriter)
  - URLRewriteStream.write (stream wrapper)
  - redirect_stdout_stderr (context manager that restores on exception)
  - _load_sarif (SARIF file loader)
  - _validate_sarif_path (path sanitization)
  - _write_sarif_atomic (atomic write)
  - rewrite_sarif_file (end-to-end SARIF rewriter)
  - _smoke_test (end-to-end smoke test)

Test style mirrors scanner/tests/test_rewrite_sarif_help.py but uses the
package-style import (``from scanner.url_rewrite import ...``) since the
project root is on sys.path via scanner/tests/conftest.py.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from scanner.url_rewrite import (
    PRISMA_DOCS_HOST,
    URLRewriteStream,
    _load_sarif,
    _smoke_test,
    _validate_sarif_path,
    _write_sarif_atomic,
    redirect_stdout_stderr,
    rewrite_sarif_file,
    rewrite_text,
)
from scanner.checkov_url_overrides import RULE_SOURCE_URLS


# ---------------------------------------------------------------------------
# rewrite_text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            f"see https://{PRISMA_DOCS_HOST}/some/deep/link for details",
            "see https://github.com/bridgecrewio/checkov for details",
            id="rewrites-prisma-url",
        ),
        pytest.param(
            "https://github.com/bridgecrewio/checkov is the canonical repo",
            "https://github.com/bridgecrewio/checkov is the canonical repo",
            id="leaves-valid-github-url",
        ),
        pytest.param(
            "no urls here, just plain text",
            "no urls here, just plain text",
            id="no-url-passthrough",
        ),
        pytest.param(
            "",
            "",
            id="empty-input",
        ),
        pytest.param(
            f"https://{PRISMA_DOCS_HOST}/a and https://{PRISMA_DOCS_HOST}/b",
            "https://github.com/bridgecrewio/checkov and https://github.com/bridgecrewio/checkov",
            id="multiple-prisma-urls",
        ),
        pytest.param(
            f"see https://{PRISMA_DOCS_HOST}/x\nthen https://example.com/y",
            "see https://github.com/bridgecrewio/checkov\nthen https://example.com/y",
            id="newline-between-urls",
        ),
    ],
)
def test_rewrite_text(text: str, expected: str) -> None:
    """rewrite_text prisma→github, leaves valid URLs alone, handles empty."""
    assert rewrite_text(text) == expected


# ---------------------------------------------------------------------------
# URLRewriteStream.write
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "must_contain", "must_not_contain"),
    [
        pytest.param(
            f"docs: https://{PRISMA_DOCS_HOST}/path/to/rule\n",
            "github.com/bridgecrewio/checkov",
            PRISMA_DOCS_HOST,
            id="rewrites-then-flushes",
        ),
        pytest.param(
            "plain output, no urls\n",
            "plain output, no urls",
            "",
            id="plain-passthrough",
        ),
        pytest.param(
            "",
            "",
            "",
            id="empty-write-returns-zero",
        ),
    ],
)
def test_url_rewrite_stream_write_proxies_and_returns_char_count(
    payload: str,
    must_contain: str,
    must_not_contain: str,
) -> None:
    """URLRewriteStream.write proxies to the wrapped stream, flushes, and
    returns the character count of the rewritten payload."""
    buf = io.StringIO()
    stream = URLRewriteStream(buf)
    written = stream.write(payload)
    # The wrapped stream's write() returns the count of characters written.
    # rewrite_text() shortens the payload (prisma URL → github repo root),
    # so the char count matches the rewritten length, not the input length.
    assert written == len(stream._wrapped.getvalue())  # noqa: SLF001 — test introspection
    if must_contain:
        assert must_contain in buf.getvalue()
    if must_not_contain:
        assert must_not_contain not in buf.getvalue()


def test_url_rewrite_stream_flush_delegates_to_wrapped() -> None:
    """URLRewriteStream.flush() forwards to the wrapped stream's flush()."""
    sentinel = {"flushed": False}

    class _FlushingStream(io.TextIOBase):
        def writable(self) -> bool:
            return True

        def write(self, s: str) -> int:  # type: ignore[override]
            return 0

        def flush(self) -> None:
            sentinel["flushed"] = True

    stream = URLRewriteStream(_FlushingStream())
    stream.flush()
    assert sentinel["flushed"] is True


def test_url_rewrite_stream_writable_delegates() -> None:
    """URLRewriteStream.writable() forwards to the wrapped stream."""

    class _WritableStream(io.TextIOBase):
        def writable(self) -> bool:
            return True

        def write(self, s: str) -> int:  # type: ignore[override]
            return 0

    stream = URLRewriteStream(_WritableStream())
    assert stream.writable() is True


def test_url_rewrite_stream_wrapped_property() -> None:
    """The .wrapped property exposes the underlying stream."""
    buf = io.StringIO()
    stream = URLRewriteStream(buf)
    assert stream.wrapped is buf


# ---------------------------------------------------------------------------
# redirect_stdout_stderr (context manager)
# ---------------------------------------------------------------------------


def test_redirect_stdout_stderr_restores_on_normal_exit() -> None:
    """On clean exit, sys.stdout/stderr are restored to the entry values."""
    real_stdout, real_stderr = sys.stdout, sys.stderr
    sentinel_out = io.StringIO()
    sentinel_err = io.StringIO()
    sys.stdout, sys.stderr = sentinel_out, sentinel_err
    try:
        with redirect_stdout_stderr() as (out_w, err_w):
            assert isinstance(sys.stdout, URLRewriteStream)
            assert isinstance(sys.stderr, URLRewriteStream)
            assert out_w.wrapped is sentinel_out
            assert err_w.wrapped is sentinel_err
            print(f"see https://{PRISMA_DOCS_HOST}/x")
        # After exit: streams restored to whatever they were at entry.
        assert sys.stdout is sentinel_out
        assert sys.stderr is sentinel_err
        # And the URL was rewritten inside the StringIO.
        assert "github.com/bridgecrewio/checkov" in sentinel_out.getvalue()
        assert PRISMA_DOCS_HOST not in sentinel_out.getvalue()
    finally:
        sys.stdout, sys.stderr = real_stdout, real_stderr


def test_redirect_stdout_stderr_restores_on_exception() -> None:
    """Even when the body raises, the context manager restores the streams."""
    real_stdout, real_stderr = sys.stdout, sys.stderr
    sentinel_out = io.StringIO()
    sentinel_err = io.StringIO()
    sys.stdout, sys.stderr = sentinel_out, sentinel_err
    try:
        with pytest.raises(RuntimeError, match="boom"):
            with redirect_stdout_stderr():
                # Inside the block, the wrappers are installed.
                assert isinstance(sys.stdout, URLRewriteStream)
                assert isinstance(sys.stderr, URLRewriteStream)
                raise RuntimeError("boom")
        # After the with-block (despite the raise), streams are restored.
        assert sys.stdout is sentinel_out
        assert sys.stderr is sentinel_err
    finally:
        sys.stdout, sys.stderr = real_stdout, real_stderr


# ---------------------------------------------------------------------------
# _load_sarif
# ---------------------------------------------------------------------------


def test_load_sarif_returns_dict_on_valid_json(tmp_path: Path) -> None:
    """A well-formed SARIF JSON file loads to its parsed dict."""
    sarif_path = tmp_path / "valid.sarif"
    payload = {"version": "2.1.0", "runs": []}
    sarif_path.write_text(json.dumps(payload), encoding="utf-8")
    assert _load_sarif(sarif_path) == payload


def test_load_sarif_returns_none_on_invalid_json(tmp_path: Path) -> None:
    """Garbage in the SARIF file returns None (not a crash)."""
    sarif_path = tmp_path / "garbage.sarif"
    sarif_path.write_text("this is not json {", encoding="utf-8")
    assert _load_sarif(sarif_path) is None


# ---------------------------------------------------------------------------
# _validate_sarif_path
# ---------------------------------------------------------------------------


def test_validate_sarif_path_accepts_tmp_path_sarif(tmp_path: Path) -> None:
    """A `.sarif` file under tmp_path (a tmp dir) is allowed."""
    target = tmp_path / "out.sarif"
    resolved = _validate_sarif_path(target)
    assert resolved == target.resolve()


def test_validate_sarif_path_rejects_wrong_suffix(tmp_path: Path) -> None:
    """A non-`.sarif` suffix is rejected with ValueError."""
    target = tmp_path / "out.json"
    with pytest.raises(ValueError, match=r"suffix must be \.sarif"):
        _validate_sarif_path(target)


def test_validate_sarif_path_rejects_path_outside_allowed_roots(
    tmp_path: Path,
) -> None:
    """A `.sarif` file under a non-allowed root (e.g. /etc/passwd) is rejected."""
    # On Windows, /etc/passwd resolves to a real path but is not under CWD,
    # home, or tmp. Use a path that is definitely outside all allowed roots.
    bad = Path("/etc/passwd.sarif")
    with pytest.raises(ValueError, match=r"refusing to rewrite SARIF outside"):
        _validate_sarif_path(bad)


def test_validate_sarif_path_suffix_check_is_case_insensitive(
    tmp_path: Path,
) -> None:
    """The suffix check is case-insensitive (matches the suffix.lower() guard)."""
    target = tmp_path / "out.SARIF"
    resolved = _validate_sarif_path(target)
    assert resolved == target.resolve()


# ---------------------------------------------------------------------------
# _write_sarif_atomic
# ---------------------------------------------------------------------------


def test_write_sarif_atomic_rejects_bad_suffix(tmp_path: Path) -> None:
    """A non-`.sarif` suffix raises ValueError — no I/O happens."""
    target = tmp_path / "out.json"
    with pytest.raises(ValueError, match=r"suffix must be \.sarif"):
        _write_sarif_atomic(target, {"runs": []})


def test_write_sarif_atomic_writes_and_replaces(tmp_path: Path) -> None:
    """On success: `.tmp` sibling is created, then os.replace()d; the `.tmp`
    file is gone after the call (atomic write semantics)."""
    target = tmp_path / "out.sarif"
    data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}}]}
    _write_sarif_atomic(target, data)
    # The target file exists with the right content.
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8")) == data
    # The .tmp sibling does NOT exist — it was os.replace()d onto the target.
    tmp_sibling = target.with_suffix(target.suffix + ".tmp")
    assert not tmp_sibling.exists()


def test_write_sarif_atomic_overwrites_existing(tmp_path: Path) -> None:
    """An existing .sarif file is overwritten in place."""
    target = tmp_path / "out.sarif"
    target.write_text(json.dumps({"old": True}), encoding="utf-8")
    new_data = {"version": "2.1.0", "runs": [{"new": True}]}
    _write_sarif_atomic(target, new_data)
    assert json.loads(target.read_text(encoding="utf-8")) == new_data


# ---------------------------------------------------------------------------
# rewrite_sarif_file (end-to-end)
# ---------------------------------------------------------------------------


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


@pytest.mark.parametrize(
    "rule_id",
    [
        pytest.param(rid, id=rid)
        for rid in (
            "CKV_AZURE_13",
            "CKV_AZURE_212",
            "CKV2_AZURE_1",
            "CKV_SECRET_3",
            "CKV_TF_1",
        )
    ],
)
def test_rewrite_sarif_file_rewrites_known_rule_help_uri(
    tmp_path: Path, rule_id: str
) -> None:
    """rewrite_sarif_file rewrites helpUri to the canonical GitHub URL
    for every rule ID in the real checkov_url_overrides.RULE_SOURCE_URLS
    table — using the table directly (no hardcoded URL substrings)."""
    expected_url = RULE_SOURCE_URLS[rule_id]
    upstream = f"https://{PRISMA_DOCS_HOST}/en/enterprise-edition/policy-reference/x"
    path = _write_sarif(tmp_path, [{"id": rule_id, "helpUri": upstream}])

    rewritten, skipped = rewrite_sarif_file(path)

    assert rewritten == 1
    assert skipped == 0
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    actual = reloaded["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]
    assert actual == expected_url


def test_rewrite_sarif_file_returns_counts_for_mixed_rules(tmp_path: Path) -> None:
    """Mixed rule set: known mapped (rewritten) + unknown with non-prisma
    upstream (skipped). The function returns (rewritten, skipped) counts."""
    path = _write_sarif(
        tmp_path,
        [
            {"id": "CKV_AZURE_13", "helpUri": f"https://{PRISMA_DOCS_HOST}/x"},
            {"id": "CKV_FAKE_99", "helpUri": "https://example.com/rule/x"},
        ],
    )
    rewritten, skipped = rewrite_sarif_file(path)
    assert rewritten == 1
    assert skipped == 1


def test_rewrite_sarif_file_returns_zero_zero_on_invalid_json(
    tmp_path: Path,
) -> None:
    """An invalid-JSON SARIF yields (0, 0) — no crash."""
    path = tmp_path / "garbage.sarif"
    path.write_text("not json", encoding="utf-8")
    assert rewrite_sarif_file(path) == (0, 0)


def test_rewrite_sarif_file_returns_zero_zero_on_missing_runs(
    tmp_path: Path,
) -> None:
    """A SARIF with no 'runs' array yields (0, 0) — no crash."""
    path = tmp_path / "noruns.sarif"
    path.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")
    assert rewrite_sarif_file(path) == (0, 0)


# ---------------------------------------------------------------------------
# _smoke_test (end-to-end)
# ---------------------------------------------------------------------------


def test_smoke_test_returns_zero() -> None:
    """The end-to-end smoke test exits 0 (catches every URL rewriter bug)."""
    assert _smoke_test() == 0