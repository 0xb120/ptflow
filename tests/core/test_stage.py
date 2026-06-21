import pytest

from pipt.core.stage import Stage


def test_stage_fields():
    s = Stage(name="resolve", run=lambda *_: None, needs=("expand",), per_app=False)
    assert s.name == "resolve"
    assert s.needs == ("expand",)
    assert s.per_app is False


def test_stage_defaults():
    s = Stage("expand", lambda *_: None)
    assert s.needs == ()
    assert s.per_app is False


def test_load_pipeline_unknown_raises():
    from pipt.pipelines import load_pipeline

    with pytest.raises(ValueError, match="unknown pipeline"):
        load_pipeline("does-not-exist")
