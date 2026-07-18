import pytest

from ptflow.core.stage import Stage


def test_stage_fields():
    s = Stage(name="resolve", run=lambda *_: None, needs=("expand",), per_app=False)
    assert s.name == "resolve"
    assert s.needs == ("expand",)
    assert s.per_app is False


def test_stage_defaults():
    s = Stage("expand", lambda *_: None)
    assert s.needs == ()
    assert s.per_app is False
    assert s.phase == 1  # first per-app loop by default
    assert s.spanning is False
    assert s.after_phase is None


def test_load_pipeline_unknown_raises():
    from ptflow.pipelines import load_pipeline

    with pytest.raises(ValueError, match="unknown pipeline"):
        load_pipeline("does-not-exist")


def test_stage_band_classifies():
    from ptflow.core.stage import Stage, stage_band
    assert stage_band(Stage("a", lambda *_: None)) == "breadth"
    assert stage_band(Stage("b", lambda *_: None, spanning=True)) == "spanning"
    assert stage_band(Stage("c", lambda *_: None, cluster_scope=True)) == "post-cluster"
    assert stage_band(Stage("d", lambda *_: None, per_app=True, phase=2)) == "loop:2"
    assert stage_band(Stage("e", lambda *_: None, after_phase=2)) == "checkpoint:2"


def test_checkpoint_stage_rejects_incompatible_shapes():
    with pytest.raises(ValueError, match="activity-scope"):
        Stage("bad", lambda *_: None, per_app=True, after_phase=2)
    with pytest.raises(ValueError, match=">= 1"):
        Stage("bad", lambda *_: None, after_phase=0)


def test_enabled_stages_filters():
    from ptflow.core.stage import Stage, enabled_stages
    stages = [Stage("a", lambda *_: None), Stage("b", lambda *_: None)]
    assert [s.name for s in enabled_stages(stages, {"a"})] == ["b"]


def test_impacted_dependents_transitive():
    from ptflow.core.stage import Stage, impacted_dependents
    a = Stage("a", lambda *_: None)
    b = Stage("b", lambda *_: None, needs=("a",))
    c = Stage("c", lambda *_: None, needs=("b",))
    d = Stage("d", lambda *_: None)  # independent
    assert impacted_dependents([a, b, c, d], {"a"}) == ["b", "c"]


def test_impacted_dependents_none_when_independent():
    from ptflow.core.stage import Stage, impacted_dependents
    assert impacted_dependents([Stage("a", lambda *_: None), Stage("b", lambda *_: None)], {"a"}) == []


def test_resume_contract_fingerprint_is_stable_and_sensitive_to_graph_callable_and_epoch():
    from types import SimpleNamespace

    from ptflow.core.stage import resume_contract_fingerprint

    def run_a(*_args):
        return None

    def run_b(*_args):
        return None

    def cluster_a(*_args):
        return []

    def cluster_b(*_args):
        return []

    def pipeline(*, epoch=1, run=run_a, needs=(), cluster=cluster_a):
        return SimpleNamespace(
            name="demo", resume_epoch=epoch, cluster=cluster,
            stages=(Stage("scan", run, needs=needs, spanning=True, net=False),),
        )

    baseline = resume_contract_fingerprint(pipeline())
    assert baseline == resume_contract_fingerprint(pipeline())
    assert baseline != resume_contract_fingerprint(pipeline(epoch=2))
    assert baseline != resume_contract_fingerprint(pipeline(run=run_b))
    assert baseline != resume_contract_fingerprint(pipeline(needs=("discover",)))
    assert baseline != resume_contract_fingerprint(pipeline(cluster=cluster_b))


def test_resume_contract_rejects_invalid_epoch():
    from types import SimpleNamespace

    from ptflow.core.stage import resume_contract

    pipeline = SimpleNamespace(name="demo", resume_epoch=0, stages=())
    with pytest.raises(ValueError, match="positive integer"):
        resume_contract(pipeline)
