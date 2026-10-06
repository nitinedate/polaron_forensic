"""Capture Aetheris UI screenshots for operator PDF guides.

Signs in through the login form with the documented firm seed account.
Credentials are not printed.
"""
from __future__ import annotations

import os
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "guides" / "assets" / "ui"
BASE = os.environ.get("AETHERIS_UI", "http://localhost:3000")
ORG = os.environ.get("AETHERIS_FIRM_ORG", "aetheris")
EMAIL = os.environ.get("AETHERIS_FIRM_EMAIL", "admin@aetheris.in")
PASSWORD = os.environ.get("AETHERIS_FIRM_PASSWORD", "admin@123456789")

PAGES = [
    ("dashboard", "/"),
    ("jobs-list", "/forensic/jobs"),
    ("job-new", "/forensic/jobs/new"),
    ("image-evidence", "/forensic/image-evidence"),
    ("reports", "/forensic/reports"),
    ("evidence-search", "/forensic/evidence-search"),
    ("mobile-list", "/forensic/mobile"),
    ("mobile-new", "/forensic/mobile/new"),
    ("mobile-acquire", "/forensic/mobile/acquire"),
    ("vuln-dashboards", "/vuln/dashboards"),
    ("vuln-ops", "/vuln/ops"),
    ("vuln-scanners", "/vuln/scanners"),
    ("vuln-agents", "/vuln/agents"),
    ("vuln-policies", "/vuln/policies"),
    ("vuln-credentials", "/vuln/credentials"),
    ("vuln-scans", "/vuln/scans"),
    ("vuln-findings", "/vuln/findings"),
    ("vuln-remediation", "/vuln/remediation"),
    ("vuln-exceptions", "/vuln/exceptions"),
    ("vuln-timeline", "/vuln/timeline"),
    ("vuln-reports", "/vuln/reports"),
    ("vuln-risk", "/vuln/risk"),
]


def shot(page, name: str) -> None:
    page.wait_for_timeout(900)
    dest = OUT / f"{name}.png"
    page.screenshot(path=str(dest), full_page=True)
    print(f"saved {dest.name} ({dest.stat().st_size})")


def click_if(page, selectors: list[str]) -> bool:
    for sel in selectors:
        loc = page.locator(sel).first
        try:
            if loc.is_visible(timeout=1200):
                loc.click()
                return True
        except Exception:
            continue
    return False


def ui_login(page) -> None:
    page.goto(f"{BASE}/login", wait_until="networkidle")
    page.wait_for_timeout(400)
    shot(page, "login")
    page.locator("input").nth(0).fill(ORG)
    page.locator("input[type='email']").fill(EMAIL)
    page.get_by_text("Password sign-in", exact=True).click()
    page.wait_for_timeout(250)
    shot(page, "login-password")
    page.locator("input[type='password']").fill(PASSWORD)
    page.get_by_role("button", name="Sign in with password").click()
    page.wait_for_timeout(2500)
    if "login" in page.url:
        err = ""
        try:
            err = page.locator("p.text-red-600").first.inner_text(timeout=800)
        except Exception:
            pass
        raise SystemExit(f"UI login stayed on /login{': ' + err if err else ''}")


def extra_job_pages(page) -> None:
    page.goto(f"{BASE}/forensic/jobs", wait_until="networkidle")
    page.wait_for_timeout(800)
    href = None
    for a in page.locator("a[href*='/forensic/jobs/']").all():
        try:
            h = a.get_attribute("href") or ""
        except Exception:
            continue
        if "/new" in h:
            continue
        parts = [p for p in h.split("/") if p]
        if "jobs" in parts and parts[-1] not in {"jobs", "new"}:
            href = h
            break
    if not href:
        print("no existing forensic job — skipping job-detail shots")
        return
    if href.startswith("/"):
        href = BASE + href
    base_job = href.split("?")[0].rstrip("/")
    for suffix, name in (
        ("", "job-detail"),
        ("/intake", "job-intake"),
        ("/select-artifacts", "job-artifacts-select"),
        ("/artifacts", "job-artifacts"),
        ("/report", "job-report"),
    ):
        page.goto(base_job + suffix, wait_until="networkidle")
        shot(page, name)


def extra_modals(page) -> None:
    page.goto(f"{BASE}/vuln/scans", wait_until="networkidle")
    page.wait_for_timeout(600)
    if click_if(page, ["button:has-text('Launch scan')", "text=Launch scan"]):
        page.wait_for_timeout(500)
        shot(page, "vuln-launch-scan")
        page.keyboard.press("Escape")
    if click_if(page, ["button:has-text('New case')"]):
        page.wait_for_timeout(400)
        shot(page, "vuln-new-case")
        page.keyboard.press("Escape")
    page.goto(f"{BASE}/vuln/scanners", wait_until="networkidle")
    if click_if(page, ["button:has-text('Add scanner')"]):
        page.wait_for_timeout(400)
        shot(page, "vuln-add-scanner")
        page.keyboard.press("Escape")
    page.goto(f"{BASE}/vuln/policies", wait_until="networkidle")
    if click_if(page, ["button:has-text('New policy')"]):
        page.wait_for_timeout(400)
        shot(page, "vuln-new-policy")
        page.keyboard.press("Escape")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        page = context.new_page()
        ui_login(page)
        for name, path in PAGES:
            page.goto(BASE + path, wait_until="networkidle")
            shot(page, name)
        extra_job_pages(page)
        extra_modals(page)
        browser.close()


if __name__ == "__main__":
    main()
