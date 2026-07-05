from ptflow.cli import render_steps
from ptflow.pipelines import load_pipeline


def test_render_steps_all_active():
    out = render_steps(load_pipeline("example"), frozenset())
    assert "example — 3 step" in out
    assert "● discover" in out and "● scope_scan" in out and "● enum" in out  # noqa: PT018
    assert "○ discover" not in out and "○ scope_scan" not in out and "○ enum" not in out  # noqa: PT018


def test_render_steps_marks_disabled_and_impacted():
    out = render_steps(load_pipeline("example"), frozenset({"discover"}))
    assert "(1 disabilitati)" in out
    assert "○ discover" in out
    # scope_scan needs discover → it shows up in the impacted-dependents warning
    assert "scope_scan" in out.split("input assenti:")[1]


def test_render_steps_verbose_shows_needs_and_scope():
    out = render_steps(load_pipeline("example"), frozenset(), verbose=True)
    assert "needs=discover" in out
    assert "per_app" in out and "activity" in out  # noqa: PT018
