"""The flow-map dev gate — now a STANDARD across pipelines.

Every registered pipeline except the deliberate stub (`example`) must expose a `flowmap_spec()` hook
whose `StepMeta` table covers every one of its stages, and must render to all three deterministic doc
views. The checks are parametrized over `PIPELINE_NAMES`, so a new pipeline that forgets its flow map
(or a new stage without a `StepMeta`) fails here. See `ptflow.core.flowdocs`.
"""

import pytest

from ptflow.core import flowdocs, flowmap, mermaidmap
from ptflow.pipelines import PIPELINE_NAMES, load_pipeline

# The flow-map standard applies to every real pipeline; `example` is the dependency-free stub the test
# suite exercises and is exempt (it declares no flowmap_spec, so flowdocs skips it too).
_STUB = frozenset({"example"})
_MAPPED = [name for name in PIPELINE_NAMES if name not in _STUB]


def _spec(name):
    return load_pipeline(name).flowmap_spec()


@pytest.mark.parametrize("name", _MAPPED)
def test_pipeline_declares_a_flowmap(name):
    """The standard: every non-stub pipeline exposes the duck-typed flowmap_spec() hook."""
    hook = getattr(load_pipeline(name), "flowmap_spec", None)
    assert callable(hook), f"{name} must expose flowmap_spec() (the flow-map standard; see core/flowdocs.py)"


@pytest.mark.parametrize("name", _MAPPED)
def test_flowmeta_covers_every_stage(name):
    """The guard against a stale map: every Stage MUST have a StepMeta in its pipeline's flowmeta.py."""
    pipeline = load_pipeline(name)
    missing = [s.name for s in pipeline.stages if s.name not in pipeline.flowmap_spec().steps]
    assert missing == [], f"{name}: add a StepMeta for {missing} in its flowmeta.py"


@pytest.mark.parametrize("name", _MAPPED)
def test_render_contains_every_stage(name):
    pipeline = load_pipeline(name)
    out = flowmap.render(pipeline.stages, pipeline.flowmap_spec())
    for s in pipeline.stages:
        assert s.name in out, s.name
    assert out.lstrip().startswith("<!doctype html>")


@pytest.mark.parametrize("name", _MAPPED)
def test_render_is_deterministic(name):
    # no timestamps / nondeterminism → git diff tracks only real flow changes
    pipeline, spec = load_pipeline(name), _spec(name)
    assert flowmap.render(pipeline.stages, spec) == flowmap.render(pipeline.stages, spec)


@pytest.mark.parametrize("name", _MAPPED)
def test_mermaid_graph_has_every_stage_and_structure(name):
    pipeline = load_pipeline(name)
    graph = mermaidmap.mermaid_graph(pipeline.stages, pipeline.flowmap_spec())
    for s in pipeline.stages:
        assert s.name in graph, s.name
    # structural nodes + a barrier between the per-app loops, derived from the Stage objects
    assert "CLUSTER" in graph
    assert "FANIN" in graph
    assert "BARRIERA" in graph
    assert graph.startswith("flowchart TD")


@pytest.mark.parametrize("name", _MAPPED)
def test_mermaid_markdown_avoids_html_tags_in_labels(name):
    """The Markdown flavour renders on GitHub's stricter Mermaid, so node labels use <br> only —
    no <b>/<code>/<span> (which would show as raw tags)."""
    md = mermaidmap.render_markdown(load_pipeline(name).stages, _spec(name))
    assert "```mermaid" in md
    assert "<code>" not in md
    assert "<b>" not in md


@pytest.mark.parametrize("name", _MAPPED)
def test_mermaid_render_is_deterministic(name):
    pipeline, spec = load_pipeline(name), _spec(name)
    assert mermaidmap.render_html(pipeline.stages, spec) == mermaidmap.render_html(pipeline.stages, spec)


def test_external_structural_nodes_and_fixpoint():
    """External-specific spot-checks: the content-discovery fixpoint artifacts + the structural nodes."""
    pipeline, spec = load_pipeline("external"), _spec("external")
    out = flowmap.render(pipeline.stages, spec)
    assert "content_discovery.jsonl" in out
    assert "responses/discovered/round*/" in out
    assert "scans/&lt;app_id&gt;/" in out          # pivot heading (html-escaped)
    assert "findings/hypotheses.jsonl" in out      # fan-in


def test_internal_map_reflects_subnet_pivot():
    """Internal-specific spot-check: the pivot heading + a per-subnet finding artifact."""
    pipeline, spec = load_pipeline("internal"), _spec("internal")
    out = flowmap.render(pipeline.stages, spec)
    assert "scans/&lt;subnet&gt;/" in out          # pivot heading (html-escaped)
    assert "web_targets.txt" in out                # consolidate fan-in output
    assert "ptflow · pipeline internal" in out


def test_layer_puts_parallel_stages_on_one_level():
    """Phase 1 (explorable surface): api_spec/passive_probe/subenum (no needs) share level 0; crawl
    (needs passive_probe) is level 1; request_catalog (the surface-catalog tail) is the deepest level."""
    phase1 = [s for s in load_pipeline("external").stages if s.per_app and s.phase == 1]
    levels = flowmap._layer(phase1)
    names = [sorted(s.name for s in lv) for lv in levels]
    assert names[0] == ["api_spec", "passive_probe", "subenum"]
    assert "crawl" in names[1]
    assert "request_catalog" in names[-1]


def test_flowdocs_generate_all_writes_prefixed_files(tmp_path):
    """The shared driver writes docs/<name>-pipeline-{flow.html,map.html,map.md} for every pipeline
    with the hook, skips the stub, and points each Markdown's cross-links at its own siblings."""
    written = flowdocs.generate_all(tmp_path)
    assert set(written) == set(_MAPPED)
    assert "example" not in written                # the stub has no hook → skipped
    for name in _MAPPED:
        flow_html, map_html, map_md = flowdocs.doc_names(name)
        assert (tmp_path / flow_html).exists()
        assert (tmp_path / map_html).exists()
        md = (tmp_path / map_md).read_text(encoding="utf-8")
        assert f"[`{map_html}`]({map_html})" in md   # cross-link is the pipeline's own map.html
        assert f"[`{flow_html}`]({flow_html})" in md
