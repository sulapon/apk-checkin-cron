#!/usr/bin/env python3
"""APK.TW cloud check-in for GitHub Actions.

Differs from the local version:
- Credentials come from env vars (APK_USER_1/APK_PASS_1, APK_USER_2/APK_PASS_2)
  instead of config.json, so secrets stay in GitHub Secrets.
- No persistent cookie profile: the runner is ephemeral, so we always do a fresh
  login. To avoid re-signing every hour, we check the server-side state: if the
  check-in button is absent on forum.php, today is already signed -> skip.

Output: one JSON line per account. Exit 0 when all signed/skipped, 1 otherwise.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import time

from PIL import Image
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

BASE = "https://apk.tw"
MAX_ATTEMPTS = 20
SILENT = os.environ.get("APK_SILENT", "1") == "1"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# ── CAPTCHA ───────────────────────────────────────────────────────────────────
_ocr = None
_ocr_beta = None
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def solve_captcha(png_bytes: bytes, variant: int = 0) -> str:
    """Read the CAPTCHA with ddddocr; default and beta models alternate."""
    global _ocr, _ocr_beta
    import ddddocr

    if _ocr is None:
        _ocr = ddddocr.DdddOcr(show_ad=False)
    raw = _ocr.classification(png_bytes)
    if variant % 2 == 1:
        if _ocr_beta is None:
            _ocr_beta = ddddocr.DdddOcr(show_ad=False, beta=True)
        alt = re.sub(r"[^A-Za-z0-9]", "", _ocr_beta.classification(png_bytes))
        if 3 <= len(alt) <= 6:
            return alt
    code = re.sub(r"[^A-Za-z0-9]", "", raw)
    if 3 <= len(code) <= 6:
        return code
    gray = Image.open(io.BytesIO(png_bytes)).convert("L")
    big = gray.resize((gray.width * 5, gray.height * 5), Image.LANCZOS)
    tmp = "/tmp/_captcha.png"
    big.save(tmp)
    text = subprocess.run(
        ["tesseract", tmp, "stdout", "--psm", "7",
         "-c", f"tessedit_char_whitelist={ALNUM}"],
        capture_output=True, text=True, timeout=30).stdout
    return re.sub(r"[^A-Za-z0-9]", "", text)[:6]


def is_logged_in(page) -> bool:
    return page.locator('a[href*="action=logout"]').count() > 0


def _chrome_present() -> bool:
    """Detect a system Google Chrome install (for playwright channel='chrome')."""
    for p in ("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
              "/opt/google/chrome/chrome"):
        if os.path.exists(p):
            return True
    return False


# ── login ─────────────────────────────────────────────────────────────────────
def do_login(page, username: str, password: str) -> tuple[bool, str]:
    page.goto(f"{BASE}/member.php?mod=logging&action=login",
              wait_until="domcontentloaded", timeout=60000)
    for attempt in range(MAX_ATTEMPTS):
        try:
            page.wait_for_selector('input[name="username"]', timeout=15000)
        except PWTimeout:
            if is_logged_in(page):
                return True, "already logged in"
            return False, "login form not found"
        page.fill('input[name="username"]', username)
        page.focus('input[name="password"]')
        page.fill('input[name="password"]', password)
        cb = page.locator('input[name="cookietime"]')
        if cb.count():
            cb.check()
        page.wait_for_timeout(1200)   # captcha loads lazily after focus

        cap = page.locator('img[src*="seccode"], img[id*="seccode"]').first
        if cap.count() == 0:
            log("no captcha shown - submitting directly")
        else:
            code = solve_captcha(cap.screenshot(), attempt)
            log(f"attempt {attempt + 1}: captcha -> '{code}'")
            if not code:
                page.goto(f"{BASE}/member.php?mod=logging&action=login",
                          wait_until="domcontentloaded")
                continue
            page.fill('input[name="seccodeverify"]', code)

        page.locator('button[name="loginsubmit"]').click()
        page.wait_for_load_state("domcontentloaded")
        page.wait_for_timeout(2500)
        if is_logged_in(page):
            return True, f"logged in on attempt {attempt + 1}"
        body = page.locator("body").inner_text()
        reason = next((ln.strip() for ln in body.splitlines()
                       if any(k in ln for k in ("抱歉", "錯誤", "失敗", "鎖定", "密碼"))), "?")
        log(f"login rejected ({username}): {reason}")
        if "密碼" in reason:
            return False, f"password problem: {reason}"
        page.goto(f"{BASE}/member.php?mod=logging&action=login",
                  wait_until="domcontentloaded")
    return False, f"captcha/login failed after {MAX_ATTEMPTS} tries"


# ── check-in ──────────────────────────────────────────────────────────────────
def checkin_state(page) -> str:
    """Return 'needs' if the check-in button is present, else 'done'."""
    page.goto(f"{BASE}/forum.php", wait_until="domcontentloaded", timeout=60000)
    html = page.content()
    if re.search(r"ajaxget\('(plugin\.php\?id=dsu_amupper:pper[^']*)'", html):
        return "needs"
    el = page.locator("#my_amupper")
    if el.count():
        return "already shown"
    return "done"


def do_checkin(page) -> tuple[bool, str]:
    """Sign via the AJAX link on forum.php (#my_amupper element)."""
    page.goto(f"{BASE}/forum.php", wait_until="domcontentloaded", timeout=60000)
    html = page.content()
    m = re.search(r"ajaxget\('(plugin\.php\?id=dsu_amupper:pper[^']*)'", html)
    if not m:
        el = page.locator("#my_amupper")
        if el.count():
            return True, f"already checked in ({el.inner_text().strip()[:20]})"
        return True, "already checked in (no button)"
    url = f"{BASE}/{m.group(1).replace('&amp;', '&')}"
    log(f"check-in ajax: {url}")
    resp = page.request.get(url)
    if resp.status != 200:
        return False, f"check-in ajax returned {resp.status}"
    page.goto(f"{BASE}/forum.php", wait_until="domcontentloaded", timeout=60000)
    if re.search(r"ajaxget\('(plugin\.php\?id=dsu_amupper:pper[^']*)'", page.content()):
        return False, "button still present after check-in attempt"
    return True, "checked in successfully"


def run_account(pw, idx: int) -> dict:
    uname = os.environ.get(f"APK_USER_{idx}")
    pwd = os.environ.get(f"APK_PASS_{idx}")
    if not uname or not pwd:
        return {"account": f"account{idx}", "date": time.strftime("%Y-%m-%d"),
                "ok": True, "login": "skipped (no credentials)", "action": "skip"}
    result = {"account": uname, "date": time.strftime("%Y-%m-%d")}
    launch_kwargs = dict(headless=True,
                         args=["--no-sandbox", "--disable-dev-shm-usage"])
    if os.environ.get("APK_NO_CHROME") == "1" or not _chrome_present():
        launch_kwargs["channel"] = "chromium"
    else:
        launch_kwargs["channel"] = "chrome"
    ctx = pw.chromium.launch(**launch_kwargs)
    page = ctx.new_page()
    try:
        page.goto(BASE, wait_until="domcontentloaded", timeout=60000)
        if not is_logged_in(page):
            ok, msg = do_login(page, uname, pwd)
            result["login"] = msg
            if not ok:
                result["ok"] = False
                result["action"] = "login-failed"
                return result
        else:
            result["login"] = "session alive"
        state = checkin_state(page)
        if state == "done":
            result["checkin"] = "already checked in"
            result["action"] = "skip"
            result["ok"] = True
            return result
        ok, msg = do_checkin(page)
        result["checkin"] = msg
        result["action"] = "signed" if ok else "sign-failed"
        result["ok"] = ok
        return result
    finally:
        ctx.close()


def main() -> int:
    all_ok = True
    any_signed = False
    any_failed = False
    with sync_playwright() as pw:
        for idx in (1, 2):
            try:
                result = run_account(pw, idx)
            except Exception as exc:
                log(f"account{idx} crashed: {exc}")
                result = {"account": f"account{idx}", "date": time.strftime("%Y-%m-%d"),
                          "ok": False, "error": str(exc)[:200], "action": "crash"}
            all_ok &= bool(result.get("ok"))
            if result.get("action") == "signed":
                any_signed = True
            if not result.get("ok"):
                any_failed = True
            print(json.dumps(result, ensure_ascii=False), flush=True)

    if SILENT:
        if any_failed:
            print("NOTIFY_ALERT", flush=True)
        elif any_signed:
            print("NOTIFY_SIGNED", flush=True)
        else:
            print("NOTIFY_NONE", flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())