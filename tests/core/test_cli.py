from ptflow.cli import render_steps
from ptflow.pipelines import load_pipeline


def test_render_steps_all_active():
    out = render_steps(load_pipeline("example"), frozenset())
    assert "example — 3 step" in out
    assert "● discover" in out
    assert "● scope_scan" in out
    assert "● enum" in out
    assert "○ discover" not in out
    assert "○ scope_scan" not in out
    assert "○ enum" not in out


def test_render_steps_marks_disabled_and_impacted():
    out = render_steps(load_pipeline("example"), frozenset({"discover"}))
    assert "(1 disabilitati)" in out
    assert "○ discover" in out
    # scope_scan needs discover → it shows up in the impacted-dependents warning
    assert "scope_scan" in out.split("input assenti:")[1]


def test_render_steps_verbose_shows_needs_and_scope():
    out = render_steps(load_pipeline("example"), frozenset(), verbose=True)
    assert "needs=discover" in out
    assert "per_app" in out
    assert "activity" in out


def test_render_steps_places_checkpoint_after_its_loop():
    from types import SimpleNamespace

    from ptflow.core.stage import Stage

    pipeline = SimpleNamespace(name="p", stages=[
        Stage("loop2", lambda *_: None, per_app=True, phase=2),
        Stage("checkpoint", lambda *_: None, after_phase=2, net=False),
        Stage("loop3", lambda *_: None, per_app=True, phase=3),
    ])
    out = render_steps(pipeline, frozenset(), verbose=True)
    assert out.index("loop:2") < out.index("checkpoint:2") < out.index("loop:3")
    assert "after_phase=2" in out
