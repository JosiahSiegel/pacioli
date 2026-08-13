"""Browser smoke test for the generated static HTML report."""
from __future__ import annotations

from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING

import pytest

from scanner.aggregate import EnvResultFull, Finding, write_html_report
from test_aggregate_html import _build_run_dir, _invoke_aggregate_main


EVIDENCE_DIR = Path(__file__).resolve().parents[2] / ".omo" / "evidence" / "environment-exclusion" / "task-8-screenshots"

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


@pytest.fixture
def exclusion_report_url(tmp_path: Path) -> Iterator[str]:
    """Render three stack identities and serve them from loopback."""
    findings = [
        Finding(project="payments", env="prod", check_id="CKV_AZURE_44", severity="HIGH", resource="blue", file_path="blue.tf", line=1, message="blue", framework="terraform", requirements=["1.2.1"]),
        Finding(project="payments", env="prod", check_id="CKV_AZURE_3", severity="MEDIUM", resource="green", file_path="green.tf", line=1, message="green", framework="terraform", requirements=["1.2.1"]),
        Finding(project="orders", env="dev", check_id="CKV_AZURE_70", severity="LOW", resource="dev", file_path="dev.tf", line=1, message="dev", framework="terraform", requirements=["1.2.1"]),
    ]
    environments = [
        EnvResultFull(project="payments", env="prod", stack_label="blue", scan_status="ok", findings=findings[:1]),
        EnvResultFull(project="payments", env="prod", stack_label="green", scan_status="ok", findings=findings[1:2]),
        EnvResultFull(project="orders", env="dev", scan_status="ok", findings=findings[2:]),
    ]
    mapping = {"framework_name": "PCI DSS", "framework_version": "4.0.1", "requirements": [{"id": "1.2.1", "title": "Network", "checks": ["CKV_AZURE_44", "CKV_AZURE_3", "CKV_AZURE_70"]}]}
    output_dir = tmp_path / "aggregate"
    output_dir.mkdir()
    write_html_report(output_dir / "report.html", environments, tmp_path / "mapping.yaml", mapping, {}, [], 0)
    handler = partial(SimpleHTTPRequestHandler, directory=str(output_dir))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/report.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.browser
def test_environment_exclusions_recompute_and_persist(
    page: Page,
    exclusion_report_url: str,
) -> None:
    """Native checkboxes project the immutable model and survive a reload."""
    page.goto(exclusion_report_url, wait_until="domcontentloaded")
    checkboxes = page.locator('#environment-exclusions input[type="checkbox"]')
    assert checkboxes.count() == 3

    checkboxes.nth(0).focus()
    page.keyboard.press("Space")
    checkboxes.nth(1).check()

    assert "2 environments excluded; viewing 1 of 3 environments." in page.locator("#environment-exclusion-status").inner_text()
    assert page.locator("#kpi-total").inner_text() == "1"
    assert page.locator("#badge-envs").inner_text() == "1"
    assert page.locator("#environment-table-body tr").count() == 1
    assert page.locator("#env-health-list .env-bar-row").count() == 1
    assert page.locator("#top-resources").inner_text().find("dev") >= 0
    assert page.locator("#top-resources").inner_text().find("blue") == -1

    page.reload(wait_until="domcontentloaded")
    assert page.locator('#environment-exclusions input[type="checkbox"]:checked').count() == 2
    assert page.locator("#kpi-total").inner_text() == "1"

    page.get_by_role("button", name="Full-report reset").click()
    assert page.locator("#environment-exclusion-status").inner_text() == "Full scan: viewing all 3 environments."
    assert page.locator("#kpi-total").inner_text() == "3"

    checkboxes.nth(0).check()
    checkboxes.nth(1).check()
    checkboxes.nth(2).check()
    assert page.locator("#kpi-total").inner_text() == "0"
    assert page.locator("#env-health-list .empty-view").count() == 1
    assert "NO VISIBLE ENVIRONMENTS" in page.locator("#coverage-status-table").inner_text()


@pytest.mark.browser
def test_report_visual_evidence_at_responsive_theme_and_motion_contracts(
    page: Page,
    exclusion_report_url: str,
) -> None:
    """Generated report renders every required view without browser errors."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    page.on("pageerror", lambda error: pytest.fail(f"page error: {error}"))
    console_errors: list[str] = []
    page.on(
        "console",
        lambda message: console_errors.append(message.text)
        if message.type == "error"
        else None,
    )

    for width in (375, 768, 1280):
        page.set_viewport_size({"width": width, "height": 900})
        page.emulate_media(color_scheme="dark", reduced_motion="no-preference")
        page.goto(exclusion_report_url, wait_until="domcontentloaded")
        page.evaluate("localStorage.removeItem('pacioli.report.theme')")
        page.reload(wait_until="domcontentloaded")
        assert page.locator("html").get_attribute("data-theme") == "dark"
        assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--color-bg').trim()") == "#121820"
        page.screenshot(path=str(EVIDENCE_DIR / f"{width}-dark.png"), full_page=True)

        page.evaluate("localStorage.setItem('pacioli.report.theme', 'light')")
        page.reload(wait_until="domcontentloaded")
        assert page.locator("html").get_attribute("data-theme") == "light"
        assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--color-bg').trim()") == "#f5f7fb"
        page.screenshot(path=str(EVIDENCE_DIR / f"{width}-light.png"), full_page=True)

        page.evaluate("localStorage.setItem('pacioli.report.theme', 'system')")
        page.emulate_media(color_scheme="light", reduced_motion="no-preference")
        page.reload(wait_until="domcontentloaded")
        assert page.locator("html").get_attribute("data-theme") == "system"
        assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--color-bg').trim()") == "#f5f7fb"
        page.screenshot(path=str(EVIDENCE_DIR / f"{width}-system.png"), full_page=True)

        page.emulate_media(color_scheme="dark", reduced_motion="reduce")
        assert page.evaluate(
            "Number.parseFloat(getComputedStyle(document.querySelector('#theme-select')).transitionDuration) <= 0.00001",
        )
        page.locator("#theme-select").focus()
        page.screenshot(
            path=str(EVIDENCE_DIR / f"{width}-reduced-motion.png"),
            full_page=True,
        )

    page.emulate_media(color_scheme="dark", reduced_motion="no-preference")
    page.goto(exclusion_report_url + "#environments", wait_until="domcontentloaded")
    environment_rows = page.locator("#environment-table-body tr")
    assert environment_rows.nth(0).locator("td").nth(0).inner_text() == "payments"
    assert environment_rows.nth(0).locator("td").nth(1).inner_text() == "prod [blue]"
    assert environment_rows.nth(1).locator("td").nth(0).inner_text() == "payments"
    assert environment_rows.nth(1).locator("td").nth(1).inner_text() == "prod [green]"
    page.screenshot(path=str(EVIDENCE_DIR / "labeled-stack.png"), full_page=True)

    checkboxes = page.locator('#environment-exclusions input[type="checkbox"]')
    for index in range(checkboxes.count()):
        checkboxes.nth(index).check()
    assert page.locator("#env-health-list .empty-view").count() == 1
    assert "NO VISIBLE ENVIRONMENTS" in page.locator("#coverage-status-table").inner_text()
    assert '"excluded"' in page.evaluate("localStorage.getItem('pacioli.report.filters')")
    page.screenshot(path=str(EVIDENCE_DIR / "all-environments-excluded.png"), full_page=True)

    page.reload(wait_until="domcontentloaded")
    assert page.locator('#environment-exclusions input[type="checkbox"]:checked').count() == 3
    page.get_by_role("button", name="Full-report reset").click()
    assert page.locator('#environment-exclusions input[type="checkbox"]:checked').count() == 0
    assert console_errors == []


@pytest.mark.browser
def test_report_theme_defaults_dark_when_local_storage_is_denied(
    page: Page,
    exclusion_report_url: str,
) -> None:
    """Storage-denied reports remain functional with the dark first-render fallback."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    page_errors: list[str] = []
    console_errors: list[str] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    page.on(
        "console",
        lambda message: console_errors.append(message.text)
        if message.type == "error"
        else None,
    )
    page.add_init_script(
        """
        for (const name of ['getItem', 'setItem']) {
          Object.defineProperty(Storage.prototype, name, {
            configurable: true,
            value: function () { throw new DOMException('denied', 'SecurityError'); },
          });
        }
        """,
    )

    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(exclusion_report_url, wait_until="domcontentloaded")
    assert page.locator("html").get_attribute("data-theme") == "dark"
    assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--color-bg').trim()") == "#121820"
    page.screenshot(path=str(EVIDENCE_DIR / "local-storage-denied-dark.png"), full_page=True)
    assert page_errors == []
    assert console_errors == []


@pytest.mark.browser
def test_static_report_loads_in_chromium(
    page: Page,
    static_report_url: str,
) -> None:
    """Given a generated report, Chromium loads it over loopback HTTP."""
    from playwright.sync_api import expect

    page.goto(static_report_url, wait_until="domcontentloaded")

    expect(page).to_have_title("Pacioli PCI DSS v4.0.1 Compliance Report")
