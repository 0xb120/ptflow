"""Deterministic HTTP form-login probe (Playwright) for default-credential testing.

Reused by the internal pipeline's ``creds_test_forms`` stage. Provider-agnostic — no LLM / no Anthropic
key (unlike Brutus's ``--experimental-ai``). Success detection is a conservative heuristic, so findings
are lead-grade unless a strong signal (redirect + session cookie / dashboard marker) fires. Targets are
internal (private) by design, so the SSRF guard runs with ``allow_private=True``.
"""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
from dataclasses import dataclass
from typing import Any

from ptflow.core.agents.research import _validate_fetch_url
from ptflow.core.log import get_logger

log = get_logger()

_ERROR_MARKERS = ("invalid", "incorrect", "failed", "denied", "try again", "wrong",
                  "not authorized", "authentication error")
_DASHBOARD_MARKERS = ("logout", "sign out", "signout", "dashboard", "welcome")
_USERNAME_SELECTORS = ("input[type=email]", "input[name*=user i]", "input[name*=login i]",
                       "input[name*=email i]", "input[id*=user i]", "input[type=text]")
_SUBMIT_SELECTORS = ("button[type=submit]", "input[type=submit]", "button")


@dataclass(frozen=True)
class PageState:
    url: str
    has_password_field: bool
    cookie_names: tuple[str, ...]
    body_text: str


@dataclass(frozen=True)
class LoginOutcome:
    applicable: bool
    success: bool
    confidence: str
    reason: str


def _same_path(a: str, b: str) -> bool:
    return a.split("?", 1)[0].rstrip("/") == b.split("?", 1)[0].rstrip("/")


def judge_login(before: PageState, after: PageState) -> LoginOutcome:
    """Conservative success heuristic from the before/after page state. Pure."""
    body = after.body_text.casefold()
    if after.has_password_field and _same_path(before.url, after.url):
        return LoginOutcome(applicable=True, success=False, confidence="", reason="still_on_login")
    if any(m in body for m in _ERROR_MARKERS):
        return LoginOutcome(applicable=True, success=False, confidence="", reason="error_marker")
    new_cookie = bool(set(after.cookie_names) - set(before.cookie_names))
    url_changed = not _same_path(before.url, after.url)
    password_gone = not after.has_password_field
    if password_gone and url_changed and (new_cookie or any(m in body for m in _DASHBOARD_MARKERS)):
        return LoginOutcome(applicable=True, success=True, confidence="probable", reason="redirect+session")
    if password_gone and (url_changed or new_cookie):
        return LoginOutcome(applicable=True, success=True, confidence="lead", reason="password_gone")
    return LoginOutcome(applicable=True, success=False, confidence="", reason="no_success_signal")


class FormLoginProbe:
    """Navigate a login panel, submit one credential pair, and judge success. Best-effort."""

    def __init__(self, *, timeout_ms: int = 15000, settle_ms: int = 1000) -> None:
        self.available = importlib.util.find_spec("playwright") is not None
        self._timeout_ms = timeout_ms
        self._settle_ms = settle_ms

    def _username_field(self, page) -> Any:  # noqa: ANN001 - playwright Page
        for sel in _USERNAME_SELECTORS:
            if (el := page.query_selector(sel)) is not None:
                return el
        return None

    def _submit(self, page, password_el) -> None:  # noqa: ANN001
        for sel in _SUBMIT_SELECTORS:
            if (btn := page.query_selector(sel)) is not None:
                btn.click()
                return
        password_el.press("Enter")

    def attempt(self, url: str, username: str, password: str) -> LoginOutcome:
        if not self.available:
            return LoginOutcome(applicable=False, success=False, confidence="", reason="playwright_absent")
        try:
            _validate_fetch_url(url, allow_private=True)
        except ValueError:
            return LoginOutcome(applicable=False, success=False, confidence="", reason="invalid_url")
        try:
            return self._drive(url, username, password)
        except Exception as exc:  # noqa: BLE001 - best-effort; any browser error → no finding
            log.debug("  · form login on %s failed: %s", url, exc)
            return LoginOutcome(applicable=True, success=False, confidence="", reason="browser_error")

    def _drive(self, url: str, username: str, password: str) -> LoginOutcome:
        api = importlib.import_module("playwright.sync_api")
        with api.sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True)
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_default_timeout(self._timeout_ms)
                page.goto(url, wait_until="domcontentloaded")
                password_el = page.query_selector("input[type=password]")
                if password_el is None:
                    return LoginOutcome(applicable=False, success=False, confidence="", reason="no_form")
                before = PageState(url=page.url, has_password_field=True,
                                   cookie_names=tuple(c["name"] for c in context.cookies()), body_text="")
                if (user_el := self._username_field(page)) is not None:
                    user_el.fill(username)
                password_el.fill(password)
                self._submit(page, password_el)
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=self._timeout_ms)
                page.wait_for_timeout(self._settle_ms)
                after = PageState(url=page.url, has_password_field=page.query_selector("input[type=password]") is not None,
                                  cookie_names=tuple(c["name"] for c in context.cookies()), body_text=page.content())
                return judge_login(before, after)
            finally:
                browser.close()
