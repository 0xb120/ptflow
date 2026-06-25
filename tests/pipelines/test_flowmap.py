from pipt.core import flowmap
from pipt.pipelines.recon import flowmeta
from pipt.pipelines.recon.pipeline import PIPELINE


def test_flowmeta_covers_every_stage():
    """The dev gate's guard against a stale map: every Stage MUST have a StepMeta. If this fails,
    add the new step to FLOWMETA in pipelines/recon/flowmeta.py."""
    missing = [s.name for s in PIPELINE.stages if s.name not in flowmeta.FLOWMETA]
    assert missing == []


def test_render_contains_every_stage_and_key_outputs():
    out = flowmap.render(PIPELINE.stages, flowmeta.SPEC)
    for s in PIPELINE.stages:
        assert s.name in out, s.name
    # the fixpoint's new artifacts and the structural nodes are present
    assert "content_discovery.jsonl" in out
    assert "responses/discovered/round*/" in out
    assert "scans/&lt;app_id&gt;/" in out          # pivot heading (html-escaped)
    assert "findings/hypotheses.jsonl" in out      # fan-in
    assert out.lstrip().startswith("<!doctype html>")


def test_render_is_deterministic():
    # no timestamps / nondeterminism → git diff tracks only real flow changes
    assert flowmap.render(PIPELINE.stages, flowmeta.SPEC) == flowmap.render(PIPELINE.stages, flowmeta.SPEC)


def test_layer_puts_parallel_stages_on_one_level():
    """Loop 1: passive_probe/subenum (no needs) share level 0; crawl (needs passive_probe) is
    level 1; takeover (needs crawl+subenum) is level 2. (screenshot is now post-cluster, not loop 1.)"""
    loop1 = [s for s in PIPELINE.stages if s.per_app and s.phase == 1]
    levels = flowmap._layer(loop1)
    names = [sorted(s.name for s in lv) for lv in levels]
    assert names[0] == ["passive_probe", "subenum"]
    assert "crawl" in names[1]
    assert "takeover" in names[-1]


def test_main_writes_file(tmp_path):
    dest = tmp_path / "map.html"
    flowmeta.main(str(dest))
    text = dest.read_text(encoding="utf-8")
    assert "content_discovery" in text
    assert "pipt · pipeline recon" in text
