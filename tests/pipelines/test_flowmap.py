from pipt.core import flowmap, mermaidmap
from pipt.pipelines.external import flowmeta
from pipt.pipelines.external.pipeline import PIPELINE


def test_flowmeta_covers_every_stage():
    """The dev gate's guard against a stale map: every Stage MUST have a StepMeta. If this fails,
    add the new step to FLOWMETA in pipelines/external/flowmeta.py."""
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
    """Phase 1 (explorable surface): api_spec/passive_probe/subenum (no needs) share level 0; crawl
    (needs passive_probe) is level 1; request_catalog (the surface-catalog tail) is the deepest level."""
    phase1 = [s for s in PIPELINE.stages if s.per_app and s.phase == 1]
    levels = flowmap._layer(phase1)
    names = [sorted(s.name for s in lv) for lv in levels]
    assert names[0] == ["api_spec", "passive_probe", "subenum"]
    assert "crawl" in names[1]
    assert "request_catalog" in names[-1]


def test_main_writes_file(tmp_path):
    dest = tmp_path / "map.html"
    flowmeta.main(str(dest))
    text = dest.read_text(encoding="utf-8")
    assert "content_discovery" in text
    assert "pipt · pipeline external" in text


def test_main_also_writes_concept_maps(tmp_path):
    """The regen hook keeps all three artifacts in sync — main() writes the concept maps beside
    pipeline-flow.html so a command/order change regenerates them too."""
    dest = tmp_path / "map.html"
    flowmeta.main(str(dest))
    assert (tmp_path / "pipeline-map.html").exists()
    assert (tmp_path / "pipeline-map.md").exists()


def test_mermaid_graph_has_every_stage_and_structure():
    graph = mermaidmap.mermaid_graph(PIPELINE.stages, flowmeta.SPEC)
    for s in PIPELINE.stages:
        assert s.name in graph, s.name
    # structural nodes + a barrier between the per-app loops, derived from the Stage objects
    assert "CLUSTER" in graph
    assert "FANIN" in graph
    assert "BARRIERA" in graph
    assert graph.startswith("flowchart TD")


def test_mermaid_markdown_avoids_html_tags_in_labels():
    """The Markdown flavour renders on GitHub's stricter Mermaid, so node labels use <br> only —
    no <b>/<code>/<span> (which would show as raw tags)."""
    md = mermaidmap.render_markdown(PIPELINE.stages, flowmeta.SPEC)
    assert "```mermaid" in md
    assert "<code>" not in md
    assert "<b>" not in md


def test_mermaid_render_is_deterministic():
    a = mermaidmap.render_html(PIPELINE.stages, flowmeta.SPEC)
    b = mermaidmap.render_html(PIPELINE.stages, flowmeta.SPEC)
    assert a == b
