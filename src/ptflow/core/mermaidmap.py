"""Generic Mermaid flow-map generator → a pan/zoom HTML + a Markdown view of a Pipeline's DAG.

Companion to `flowmap.py` (the detailed band "spec sheet"). Same inputs — the `Stage` objects +
a `MapSpec` — but a different output: a topological **flowchart** (Mermaid) you can pan/zoom/scroll,
with one node per step showing the commands it runs. The graph STRUCTURE (bands, phases, barriers,
spanning lane, parallelism) is DERIVED FROM the Stage attributes (`needs`/`phase`/`per_app`/
`spanning`/`cluster_scope`/`after_phase`/`net`), so a change to a step's commands or to the execution order
regenerates the map (the same hook that keeps the `docs/<name>-pipeline-*` views in sync).

Output is DETERMINISTIC (no timestamps). The HTML embeds Mermaid from a CDN and renders client-side;
the Markdown embeds the same graph in a ```mermaid block (renders on GitHub). Two label flavours: a
rich one (`<b>`/`<code>`, securityLevel "loose") for the HTML, a plain one (`<br>` only) for the
Markdown so GitHub's stricter Mermaid doesn't show raw tags.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from ptflow.core.flowmap import MapSpec, StepMeta
    from ptflow.core.stage import Stage

_GENERATOR = "ptflow.core.flowdocs"  # default module label shown in the generated files

# dark-theme node styles (fill, stroke, text) — band/phase encodes color, matching the HTML legend.
_STYLE_BREADTH = ("#0d2f54", "#4f9be6", "#dbe9fb")
_STYLE_SPAN = ("#2e2147", "#a98ee0", "#ece4fb")
_STYLE_PIVOT = ("#073b42", "#34d3e6", "#d6fbff")
_STYLE_BAR = ("#3a424c", "#8a96a3", "#eef2f6")
_STYLE_CHECKPOINT = ("#3a2f06", "#e6c247", "#f8edc2")
_STYLE_FANIN = ("#10331c", "#54d07a", "#dcf6e3")
_PHASE_STYLES = (
    ("#10331c", "#4cc46b", "#dcf6e3"),   # phase 1 · green
    ("#3a2f06", "#e6c247", "#f8edc2"),   # phase 2 · amber
    ("#3a0f23", "#ef6a9b", "#fbd9e6"),   # phase 3 · pink
    ("#3a1a08", "#f08a4c", "#fbe2d2"),   # phase 4 · orange
    ("#0d2f54", "#4f9be6", "#dbe9fb"),   # phase 5+ · blue (cycles)
)


def _phase_style(phase: int) -> tuple[str, str, str]:
    return _PHASE_STYLES[(phase - 1) % len(_PHASE_STYLES)]


def _mesc(text: str) -> str:
    """Escape dynamic text for a Mermaid node label (kept distinct from the literal `<b>`/`<br>`
    tags the builder adds itself)."""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _rect(nid: str, label: str) -> str:
    return nid + '["' + label + '"]'


def _stadium(nid: str, label: str) -> str:
    return nid + '(["' + label + '"])'


def _hexagon(nid: str, label: str) -> str:
    return nid + '{{"' + label + '"}}'


def _subroutine(nid: str, label: str) -> str:
    return nid + '[["' + label + '"]]'


def _node_label(stage: Stage, steps: Mapping[str, StepMeta], *, rich: bool) -> str:
    """A step node's label: name + its commands. Rich (HTML, styled) or plain (`<br>` only, for
    GitHub Markdown). Commands come straight from the StepMeta, so they track the code."""
    meta = steps[stage.name]
    name = _mesc(stage.name)
    cmds = [_mesc(c.rstrip()) for c in meta.commands]
    if rich:
        flags = "" if stage.net else "<br/><span class='r'>net=False</span>"
        body = "<br/><code>" + "<br/>".join(cmds) + "</code>" if cmds else ""
        return "<b>" + name + "</b>" + flags + body
    head = name if stage.net else name + "  ·  net=False"
    return "<br>".join([head, *cmds])


def _breadth_block(activity: Sequence[Stage], spec: MapSpec, *, rich: bool) -> list[str]:
    names = {s.name for s in activity}
    out = [
        'subgraph BREADTH["① BREADTH · activity scope — una volta su tutto lo scope"]',
        "direction TB",
    ]
    out += [_rect(s.name, _node_label(s, spec.steps, rich=rich)) for s in activity]
    out.append("end")
    for s in activity:
        intra = [n for n in s.needs if n in names]
        out += [n + " --> " + s.name for n in intra]
        if not intra:  # a breadth root hangs off the scope source (offline prep gets a ∥ edge)
            out.append("scope " + ("-->" if s.net else "-.->|∥ offline|") + " " + s.name)
    return out


def _spanning_block(spanning: Sequence[Stage], spec: MapSpec, *, rich: bool) -> list[str]:
    if not spanning:
        return []
    span_names = {s.name for s in spanning}
    out = [
        'subgraph SPAN["SPANNING · ∥ cluster + tutti i loop — join al fan-in"]',
        "direction TB",
    ]
    out += [_rect(s.name, _node_label(s, spec.steps, rich=rich)) for s in spanning]
    out.append("end")
    for s in spanning:  # intra-spanning needs are solid; a need on a breadth stage is a ∥ launch
        for n in s.needs:
            out.append(n + (" --> " if n in span_names else " -.->|∥| ") + s.name)
    return out


def _phase_blocks(
    stages: Sequence[Stage], spec: MapSpec, phases: list[int], start: str, *, rich: bool,
) -> list[str]:
    out: list[str] = []
    prev = start
    for pos, ph in enumerate(phases):
        subset = [s for s in stages if s.per_app and s.phase == ph]
        sub_names = {s.name for s in subset}
        if pos > 0:  # global barrier between successive loops
            bar = f"BAR{ph}"
            out.append(_subroutine(bar, f"━━ BARRIERA: FASE {phases[pos - 1]} → FASE {ph} ━━"))
            out.append(prev + " ==> " + bar)
            prev = bar
        bid = f"P{ph}"
        label = _mesc(spec.phase_labels.get(ph, f"loop {ph}"))
        prefix = "③ PER-APP · " if pos == 0 else ""
        out.append(f'subgraph {bid}["{prefix}FASE {ph} · {label}"]')
        out.append("direction TB")
        out += [_rect(s.name, _node_label(s, spec.steps, rich=rich)) for s in subset]
        out.append("end")
        for s in subset:
            out += [n + " --> " + s.name for n in s.needs if n in sub_names]
        out.append(prev + " ==> " + bid)
        prev = bid
        checkpoints = [s for s in stages if s.after_phase == ph]
        if checkpoints:
            checkpoint_names = {s.name for s in checkpoints}
            checkpoint_id = f"CP{ph}"
            out.append(f'subgraph {checkpoint_id}["CHECKPOINT · DOPO FASE {ph}"]')
            out.append("direction TB")
            out += [_rect(s.name, _node_label(s, spec.steps, rich=rich)) for s in checkpoints]
            out.append("end")
            for stage in checkpoints:
                out += [
                    dependency + " --> " + stage.name
                    for dependency in stage.needs
                    if dependency in checkpoint_names
                ]
            out.append(prev + " ==> " + checkpoint_id)
            prev = checkpoint_id
    return out


def _cdef(name: str, style: tuple[str, str, str], *, bold: bool = False) -> str:
    fill, stroke, color = style
    extra = ",font-weight:bold" if bold else ""
    return f"classDef {name} fill:{fill},stroke:{stroke},color:{color}{extra};"


def _class_blocks(stages: Sequence[Stage], spec: MapSpec) -> list[str]:
    """The Mermaid `classDef`/`class` lines that color nodes by band/phase (derived from `stages`).
    All classDefs are emitted unconditionally (an unused one is harmless), keeping branching low."""
    activity = [s for s in stages
                if not s.per_app and not s.spanning and not s.cluster_scope
                and s.after_phase is None]
    span = [s for s in stages if s.spanning or s.cluster_scope]
    checkpoints = [s for s in stages if s.after_phase is not None]
    phases = sorted({s.phase for s in stages if s.per_app})

    out = [
        _cdef("breadth", _STYLE_BREADTH), _cdef("span", _STYLE_SPAN), _cdef("pivot", _STYLE_PIVOT),
        _cdef("bar", _STYLE_BAR, bold=True), _cdef("fanin", _STYLE_FANIN, bold=True),
    ]
    if checkpoints:
        out.append(_cdef("checkpoint", _STYLE_CHECKPOINT, bold=True))
    out += [_cdef(f"phase{ph}", _phase_style(ph)) for ph in phases]

    groups = [(activity, "breadth"), (span, "span"), (checkpoints, "checkpoint")]
    groups += [([s for s in stages if s.per_app and s.phase == ph], f"phase{ph}") for ph in phases]
    out += [f"class {','.join(s.name for s in g)} {cls}" for g, cls in groups if g]

    if spec.pivot is not None:
        out.append("class CLUSTER pivot")
    bars = [f"BAR{ph}" for ph in phases[1:]]
    if bars:
        out.append("class " + ",".join(bars) + " bar")
    if spec.fanin is not None:
        out.append("class FANIN fanin")
    return out


def mermaid_graph(stages: Sequence[Stage], spec: MapSpec, *, rich: bool = True) -> str:
    """Build the Mermaid `flowchart TD` definition for `stages` using `spec`. Pure + deterministic."""
    stages = list(stages)
    activity = [s for s in stages
                if not s.per_app and not s.spanning and not s.cluster_scope
                and s.after_phase is None]
    spanning = [s for s in stages if s.spanning]
    cluster_scope = [s for s in stages if s.cluster_scope]
    phases = sorted({s.phase for s in stages if s.per_app})
    br = "<br/>" if rich else "<br>"

    lines = ["flowchart TD", _stadium("scope", "scope.txt")]
    lines += _breadth_block(activity, spec, rich=rich)

    have_pivot = spec.pivot is not None
    if have_pivot:
        heading = spec.pivot[0]  # type: ignore[index]
        lines.append(_hexagon("CLUSTER", "② CLUSTER · pivot fan-out" + br + "→ " + _mesc(heading)))
        lines.append("BREADTH ==> CLUSTER")
    start = "CLUSTER" if have_pivot else "BREADTH"

    lines += _spanning_block(spanning, spec, rich=rich)
    for s in cluster_scope:
        lines.append(_rect(s.name, _node_label(s, spec.steps, rich=rich)))
        if have_pivot:
            lines.append("CLUSTER -.->|∥ loop| " + s.name)

    lines += _phase_blocks(stages, spec, phases, start, rich=rich)
    last_phase = phases[-1] if phases else None
    last = (
        f"CP{last_phase}"
        if last_phase is not None and any(s.after_phase == last_phase for s in stages)
        else f"P{last_phase}" if last_phase is not None else start
    )

    have_fanin = spec.fanin is not None
    if have_fanin:
        heading = spec.fanin[0]  # type: ignore[index]
        lines.append(_subroutine("FANIN", "④ FAN-IN · " + _mesc(heading) + br + "findings/&lt;tipo&gt;.jsonl"))
        lines.append(last + " ==> FANIN")
        for s in spanning:  # spanning sinks (nothing else spanning needs them) join at the fan-in
            if not any(s.name in o.needs for o in spanning):
                lines.append(s.name + " -.->|join| FANIN")
        for s in cluster_scope:
            lines.append(s.name + " -.->|join| FANIN")

    lines += _class_blocks(stages, spec)
    return "\n".join(lines)


def render_html(stages: Sequence[Stage], spec: MapSpec, *, generator: str = _GENERATOR) -> str:
    """Full self-contained pan/zoom HTML (Mermaid via CDN). Deterministic."""
    graph = mermaid_graph(stages, spec, rich=True)
    return (
        _HTML.replace("__TITLE__", _mesc(spec.title))
        .replace("__GENERATOR__", _mesc(generator))
        .replace(
            "__CHECKPOINT_LEGEND__",
            ('\n    <span class="k"><span class="sw" style="background:#e6c247"></span>'
             "checkpoint</span>")
            if any(stage.after_phase is not None for stage in stages) else "",
        )
        .replace("__MERMAID_GRAPH_JSON__", json.dumps(graph))
    )


def render_markdown(
    stages: Sequence[Stage],
    spec: MapSpec,
    *,
    map_html: str = "pipeline-map.html",
    flow_html: str = "pipeline-flow.html",
    generator: str = _GENERATOR,
) -> str:
    """The same flowchart as a Markdown ```mermaid block (renders on GitHub). Deterministic.
    `map_html`/`flow_html` are the sibling doc filenames the cross-links point at (per-pipeline)."""
    graph = mermaid_graph(stages, spec, rich=False)
    return (
        _MD.replace("__TITLE__", spec.title)
        .replace("__GENERATOR__", generator)
        .replace("__MAP_HTML__", map_html)
        .replace("__FLOW_HTML__", flow_html)
        .replace("__MERMAID_GRAPH__", graph)
    )


_MD = """# __TITLE__ — mappa concettuale (flowchart)

> **Auto-generata** da `__GENERATOR__` — **non modificare a mano**: un hook la
> rigenera a ogni modifica sotto `src/ptflow/pipelines/`, quindi i comandi e l'ordine qui sotto
> seguono il codice. Versione interattiva pan/zoom: [`__MAP_HTML__`](__MAP_HTML__).
> Spec dettagliata per-step (summary/output/note): [`__FLOW_HTML__`](__FLOW_HTML__).

```mermaid
__MERMAID_GRAPH__
```
"""

_HTML = """<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · mappa</title>
<!-- AUTO-GENERATA da __GENERATOR__ — non modificare a mano (un hook la rigenera).
     Unica dipendenza esterna: mermaid via CDN (serve connessione quando apri il file). -->
<style>
  :root { --bg:#0f1419; --panel:#161b22; --ink:#e6edf3; --muted:#9aa7b4; --line:#2a3340;
    --breadth:#4f9be6; --span:#a98ee0; --pivot:#34d3e6; --bar:#8a96a3;
    --p1:#4cc46b; --p2:#e6c247; --p3:#ef6a9b; --p4:#f08a4c; }
  * { box-sizing: border-box; }
  html, body { margin:0; height:100%; background:var(--bg); color:var(--ink);
    font:14px/1.45 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
  header { position:fixed; top:0; left:0; right:0; z-index:10; display:flex; align-items:center;
    gap:14px; flex-wrap:wrap; padding:8px 14px; background:rgba(22,27,34,.96);
    border-bottom:1px solid var(--line); backdrop-filter:blur(4px); }
  header h1 { font-size:15px; margin:0; font-weight:650; }
  header h1 small { color:var(--muted); font-weight:400; }
  .ctrls { display:flex; gap:6px; align-items:center; }
  .ctrls button { background:var(--panel); color:var(--ink); border:1px solid var(--line);
    border-radius:7px; padding:5px 10px; cursor:pointer; font-size:13px; }
  .ctrls button:hover { border-color:#4b5763; background:#1e2530; }
  .legend { display:flex; gap:10px; flex-wrap:wrap; align-items:center; color:var(--muted); font-size:12px; }
  .legend .k { display:inline-flex; align-items:center; gap:5px; }
  .legend .sw { width:12px; height:12px; border-radius:3px; display:inline-block; }
  .hint { color:var(--muted); font-size:12px; }
  #canvas { position:absolute; inset:0; overflow:auto; cursor:grab; padding-top:86px; }
  #canvas.grabbing { cursor:grabbing; }
  #diagram { transform-origin:0 0; width:max-content; padding:26px 40px 80px; }
  #diagram svg { max-width:none !important; height:auto !important; }
  #diagram .nodeLabel b { font-weight:700; font-size:14px; }
  #diagram .nodeLabel .r { color:#cfd8e0; font-size:12px; }
  #diagram .nodeLabel code { display:inline-block; margin-top:3px; font-size:11px;
    font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color:#b9c4cf; white-space:normal; }
  .loading { padding:120px 40px; color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>__TITLE__ &nbsp;<small>mappa concettuale (scroll · pan · zoom)</small></h1>
  <div class="ctrls">
    <button id="zin" title="Zoom +">+</button>
    <button id="zout" title="Zoom out">&minus;</button>
    <button id="zreset" title="100%">100%</button>
    <button id="zfit" title="Adatta alla larghezza">Fit</button>
    <span class="hint">trascina per spostarti · ctrl/⌘ + rotella per zoomare</span>
  </div>
  <div class="legend">
    <span class="k"><span class="sw" style="background:var(--breadth)"></span>breadth</span>
    <span class="k"><span class="sw" style="background:var(--span)"></span>spanning ∥</span>
    <span class="k"><span class="sw" style="background:var(--pivot)"></span>cluster</span>
    <span class="k"><span class="sw" style="background:var(--p1)"></span>fase 1</span>
    <span class="k"><span class="sw" style="background:var(--p2)"></span>fase 2</span>
    <span class="k"><span class="sw" style="background:var(--p3)"></span>fase 3</span>
    <span class="k"><span class="sw" style="background:var(--p4)"></span>fase 4</span>__CHECKPOINT_LEGEND__
    <span class="k"><span class="sw" style="background:var(--bar)"></span>barriera</span>
  </div>
</header>

<div id="canvas"><div id="diagram"><div class="loading">Rendering del diagramma…</div></div></div>

<script type="module">
import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';

const graph = __MERMAID_GRAPH_JSON__;

mermaid.initialize({
  startOnLoad:false, securityLevel:'loose', theme:'dark',
  flowchart:{ htmlLabels:true, nodeSpacing:45, rankSpacing:60, curve:'basis' },
});

const diagram = document.getElementById('diagram');
const canvas = document.getElementById('canvas');
try {
  const { svg } = await mermaid.render('ptflowGraph', graph);
  diagram.innerHTML = svg;
} catch (e) {
  diagram.innerHTML = '<div class="loading">Errore nel rendering Mermaid: ' + e + '</div>';
}

let zoom = 1;
const apply = () => { diagram.style.transform = 'scale(' + zoom + ')'; };
const clamp = z => Math.min(12, Math.max(0.05, z));
const setZoom = z => { zoom = clamp(z); apply(); };

document.getElementById('zin').onclick = () => setZoom(zoom * 1.2);
document.getElementById('zout').onclick = () => setZoom(zoom / 1.2);
document.getElementById('zreset').onclick = () => setZoom(1);
document.getElementById('zfit').onclick = () => {
  const svg = diagram.querySelector('svg');
  if (!svg) return;
  const w = svg.getBoundingClientRect().width / zoom;
  setZoom((canvas.clientWidth - 90) / w);
};

canvas.addEventListener('wheel', (e) => {
  if (!(e.ctrlKey || e.metaKey)) return;
  e.preventDefault();
  const prev = zoom;
  setZoom(zoom * (e.deltaY < 0 ? 1.1 : 1 / 1.1));
  const f = zoom / prev;
  canvas.scrollLeft = (canvas.scrollLeft + e.clientX) * f - e.clientX;
  canvas.scrollTop = (canvas.scrollTop + e.clientY) * f - e.clientY;
}, { passive:false });

let down = false, sx = 0, sy = 0, ox = 0, oy = 0;
canvas.addEventListener('mousedown', (e) => {
  if (e.button !== 0) return;
  down = true; canvas.classList.add('grabbing');
  sx = e.clientX; sy = e.clientY; ox = canvas.scrollLeft; oy = canvas.scrollTop;
});
window.addEventListener('mousemove', (e) => {
  if (!down) return;
  canvas.scrollLeft = ox - (e.clientX - sx);
  canvas.scrollTop = oy - (e.clientY - sy);
});
window.addEventListener('mouseup', () => { down = false; canvas.classList.remove('grabbing'); });
</script>
</body>
</html>
"""
