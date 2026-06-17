import pytest

from pipt.core.stage import Mode, Stage


def test_stage_fields():
    s = Stage(name="discover", mode=Mode.BREADTH, run=lambda eng, targets: None, produces=("hosts",))  # noqa: ARG005
    assert s.mode is Mode.BREADTH
    assert s.produces == ("hosts",)


def test_load_pipeline_unknown_raises():
    from pipt.pipelines import load_pipeline

    with pytest.raises(ValueError, match="unknown pipeline"):
        load_pipeline("does-not-exist")
