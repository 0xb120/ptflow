import importlib.util

from ptflow.core.agents.form_login import FormLoginProbe, PageState, judge_login


def _state(url: str, has_pw: bool, *, cookies: tuple[str, ...] = (), body: str = "") -> PageState:  # noqa: FBT001
    return PageState(url=url, has_password_field=has_pw, cookie_names=tuple(cookies), body_text=body)


def test_judge_still_on_login_is_failure() -> None:
    before = _state("https://h/login", has_pw=True)
    after = _state("https://h/login", has_pw=True, body="please sign in")
    assert judge_login(before, after).success is False


def test_judge_error_marker_is_failure() -> None:
    before = _state("https://h/login", has_pw=True)
    after = _state("https://h/dashboard", has_pw=False, cookies=("session",), body="Invalid credentials")
    out = judge_login(before, after)
    assert out.success is False
    assert out.reason == "error_marker"


def test_judge_redirect_plus_cookie_is_probable() -> None:
    before = _state("https://h/login", has_pw=True)
    after = _state("https://h/dashboard", has_pw=False, cookies=("session",), body="Welcome, admin — Logout")
    out = judge_login(before, after)
    assert out.success is True
    assert out.confidence == "probable"


def test_judge_password_gone_only_is_lead() -> None:
    before = _state("https://h/login", has_pw=True, cookies=("csrf",))
    after = _state("https://h/home", has_pw=False, cookies=("csrf",), body="home")
    out = judge_login(before, after)
    assert out.success is True
    assert out.confidence == "lead"


def test_probe_unavailable_without_playwright(monkeypatch) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda _: None)
    probe = FormLoginProbe()
    assert probe.available is False
    outcome = probe.attempt("http://10.0.0.5/", "admin", "admin")
    assert outcome.applicable is False
    assert outcome.reason == "playwright_absent"
