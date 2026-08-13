"""Browser smoke test for the generated static HTML report."""
from __future__ import annotations

from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING

import pytest

from test_aggregate_html import _build_run_dir, _invoke_aggregate_main

if TYPE_CHECKING:
    from playwright.sync_api import Page


@pytest.fixture
def static_report_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[str]:
    """Generate a report and serve it from an isolated loopback origin."""
    _build_run_dir(tmp_path)
    output_dir = tmp_path / "aggregate"
    monkeypatch.chdir(tmp_path)

    result = _invoke_aggregate_main(
        ["aggregate.py", "--run-dir", str(tmp_path), "--out", str(output_dir)],
    )
    assert result == 0
    assert (output_dir / "report.html").is_file()

    handler = partial(SimpleHTTPRequestHandler, directory=str(output_dir))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    try:
        yield f"http://127.0.0.1:{port}/report.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.browser
def test_static_report_loads_in_chromium(
    page: Page,
    static_report_url: str,
) -> None:
    """Given a generated report, Chromium loads it over loopback HTTP."""
    from playwright.sync_api import expect

    page.goto(static_report_url, wait_until="domcontentloaded")

    expect(page).to_have_title("Pacioli PCI DSS v4.0.1 Compliance Report")
