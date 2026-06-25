"""Generic pipeline flow-map renderer → a self-contained HTML map of a Pipeline's DAG.

The STRUCTURE (bands, phases, parallelism, barriers) is DERIVED from the Stage objects
(`name`/`needs`/`phase`/`per_app`/`spanning`) via longest-path layering — stages at the same
dependency depth within a scope run in parallel and render side by side. Per-step prose, commands
and outputs come from a caller-supplied `StepMeta` table (see `pipelines/recon/flowmeta.py`).

Output is DETERMINISTIC (no timestamps) so a git diff of the rendered file tracks exactly how the
flow changed. A test (`tests/pipelines/test_flowmap.py`) asserts every Stage has a `StepMeta`, so a
newly added step can't silently drift out of the map — the dev gate fails until it's documented.

No pipeline is imported here: the renderer depends only on the `Stage` attributes + `StepMeta`, so
it stays generic. The recon entrypoint wires `PIPELINE` + its metadata and writes the file.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from pipt.core.stage import Stage

# blueprint-terminal palette — band/phase encodes color (the same identity as the published map).
_PHASE_TONES = ("#7bd88f", "#ff4d9d", "#f5a3c7", "#8fd0ff", "#f0b429")  # phase 1, 2, 3, …(cycles)
_TONE_BREADTH = "#4fd6c8"
_TONE_SPAN = "#f0b429"
_TONE_PIVOT = "#cdd8e8"
_TONE_FANIN = "#8b8fa3"


@dataclass(frozen=True)
class StepMeta:
    """Per-step description that can't be derived from the Stage object: a one-line summary, the
    external commands it runs, the canonical artifacts it writes, and optional extra notes."""

    summary: str
    commands: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class MapSpec:
    """Everything the renderer needs beyond the Stage list: titles, the per-step metadata table,
    human phase labels, and the two structural nodes that aren't Stages (the cluster pivot and the
    terminal fan-in)."""

    title: str
    thesis: str
    steps: Mapping[str, StepMeta]
    phase_labels: Mapping[int, str] = field(default_factory=dict)
    pivot: tuple[str, StepMeta] | None = None   # (heading, meta) — inserted before the first loop
    fanin: tuple[str, StepMeta] | None = None   # (heading, meta) — appended after the last loop


def _esc(text: str) -> str:
    return html.escape(text, quote=False)


def _phase_tone(phase: int) -> str:
    return _PHASE_TONES[(phase - 1) % len(_PHASE_TONES)]


def _layer(subset: list[Stage]) -> list[list[Stage]]:
    """Longest-path layering over `needs` (edges within `subset` only): level 0 = no deps, level
    N = 1 + max(level of deps). Stages on the same level have no path between them ⇒ run in parallel.
    Input order is preserved within a level (deterministic)."""
    by_name = {s.name: s for s in subset}
    level: dict[str, int] = {}

    def lvl(stage: Stage) -> int:
        if stage.name in level:
            return level[stage.name]
        deps = [by_name[n] for n in stage.needs if n in by_name]
        level[stage.name] = 1 + max((lvl(d) for d in deps), default=-1)
        return level[stage.name]

    for stage in subset:
        lvl(stage)
    depth = max(level.values(), default=-1)
    return [[s for s in subset if level[s.name] == lv] for lv in range(depth + 1)]


def _node(name: str, idx: str, meta: StepMeta, *, needs: tuple[str, ...], parallel: bool) -> str:
    """One step card. `idx` is the pipeline-order number ('' for structural nodes)."""
    if needs:
        tag, cls = "needs " + ", ".join(needs), "tag"
    else:
        tag, cls = "∥ no needs", "tag par-tag"
    if parallel and needs:
        tag, cls = "∥ " + tag, "tag par-tag"
    cmd = ('<div class="cmd">' + "\n".join(_esc(c) for c in meta.commands) + "</div>"
           if meta.commands else "")
    out = ("".join(f'<span class="art">{_esc(o)}</span>' for o in meta.outputs))
    out = f'<div class="out">{out}</div>' if out else ""
    notes = ('<ul class="notes">' + "".join(f"<li>{_esc(n)}</li>" for n in meta.notes) + "</ul>"
             if meta.notes else "")
    idx_html = f'<span class="idx">{_esc(idx)}</span>' if idx else ""
    return (
        f'<div class="node">'
        f'<div class="top">{idx_html}<h3>{_esc(name)}</h3><span class="{cls}">{_esc(tag)}</span></div>'
        f"<p>{_esc(meta.summary)}</p>{cmd}{out}{notes}</div>"
    )


def _levels(subset: list[Stage], idx_of: dict[str, str], steps: Mapping[str, StepMeta]) -> str:
    """Render a scope's stages as stacked parallel levels with ▼ connectors between them."""
    rows: list[str] = []
    for layer in _layer(subset):
        parallel = len(layer) > 1
        cards = "".join(
            _node(s.name, idx_of.get(s.name, ""), steps[s.name], needs=s.needs, parallel=parallel)
            for s in layer
        )
        rows.append(f'<div class="lvl">{cards}</div>')
    return '<span class="down">▼</span>'.join(rows)


def _band(num: str, name: str, sub: str, tone: str, body: str) -> str:
    num_html = f'<span class="n">{_esc(num)}</span>' if num else ""
    return (
        f'<section class="band" style="--tone:{tone}">'
        f'<h2 class="band-h">{num_html}<span class="t">{_esc(name)}</span>'
        f'<span class="sub">{_esc(sub)}</span></h2>{body}</section>'
    )


def render(stages: Sequence[Stage], spec: MapSpec) -> str:
    """Render the full self-contained HTML map for `stages` using `spec`. Pure + deterministic."""
    stages = list(stages)
    idx_of = {s.name: f"{i:02d}" for i, s in enumerate(stages)}
    activity = [s for s in stages if not s.per_app and not s.spanning and not s.cluster_scope]
    spanning = [s for s in stages if s.spanning]
    cluster_scope = [s for s in stages if s.cluster_scope]
    phases = sorted({s.phase for s in stages if s.per_app})

    parts = [_band("01", "breadth", "asset discovery · intero scope · DAG pre-cluster",
                   _TONE_BREADTH, _levels(activity, idx_of, spec.steps))]

    for s in spanning:
        sub = "parte dopo i suoi needs · gira ∥ a cluster + tutti i loop · join al fan-in"
        body = f'<div class="lvl">{_node(s.name, idx_of[s.name], spec.steps[s.name], needs=s.needs, parallel=False)}</div>'
        parts.append(_band("", "spanning", sub, _TONE_SPAN, body))

    if spec.pivot is not None:
        heading, meta = spec.pivot
        body = f"<div class=\"lvl\">{_node(heading, '', meta, needs=(), parallel=False)}</div>"
        parts.append(_band("", "⬡ pivot", "fan-out — raggruppa le vhost in application-group",
                           _TONE_PIVOT, body))

    if cluster_scope:
        sub = "una volta dopo il cluster (1 candidato/gruppo) · gira ∥ ai loop · join al fan-in"
        cards = "".join(_node(s.name, idx_of[s.name], spec.steps[s.name], needs=s.needs, parallel=True)
                        for s in cluster_scope)
        parts.append(_band("", "post-cluster ∥", sub, _TONE_SPAN, f'<div class="lvl">{cards}</div>'))

    for pos, phase in enumerate(phases):
        subset = [s for s in stages if s.per_app and s.phase == phase]
        label = spec.phase_labels.get(phase, f"loop {phase}")
        if pos > 0:
            parts.append('<div class="barrier">▭ barriera globale — ogni app finisce il loop '
                         f"{phases[pos - 1]} prima che inizi il loop {phase}</div>")
        parts.append(_band(f"{pos + 2:02d}", f"loop {phase} · {label}",
                           f"per-app · phase {phase}", _phase_tone(phase),
                           _levels(subset, idx_of, spec.steps)))

    if spec.fanin is not None:
        heading, meta = spec.fanin
        body = f"<div class=\"lvl\">{_node(heading, '', meta, needs=(), parallel=False)}</div>"
        parts.append(_band("", "fan-in", "join dello spanning, poi l'agente terminale",
                           _TONE_FANIN, body))

    return _DOC.format(
        title=_esc(spec.title),
        css=_CSS,
        eyebrow=_esc(spec.title),
        thesis=_esc(spec.thesis),
        body="".join(parts),
    )


_CSS = """
:root{
  --ground:#0b0f17; --ground-2:#111726; --inset:#0c111c;
  --ink:#c7d2e1; --ink-dim:#8794ab; --ink-faint:#566179; --line:#22304a;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);line-height:1.5;
  background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);
  background-size:48px 48px;background-position:center;}
body::before{content:"";position:fixed;inset:0;background:var(--ground);opacity:.86;z-index:-1;}
.wrap{max-width:1160px;margin:0 auto;padding:44px 22px 72px;}
.masthead{border:1px solid var(--line);background:linear-gradient(180deg,#0e1422,#0b0f17);padding:28px 28px 24px;border-radius:4px;}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:.32em;text-transform:uppercase;color:var(--ink-faint);margin:0 0 12px;}
h1{font-family:var(--mono);font-weight:600;font-size:clamp(26px,5vw,46px);margin:0;letter-spacing:-.01em;line-height:1.04;}
h1 .sep{color:#ff4d9d;}
.thesis{max-width:74ch;color:var(--ink-dim);margin:14px 0 0;font-size:14.5px;}
.thesis b{color:var(--ink);font-weight:600;}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:20px;padding-top:18px;border-top:1px dashed var(--line);font-family:var(--mono);font-size:11.5px;color:var(--ink-dim);}
.legend .k{display:inline-flex;align-items:center;gap:7px;white-space:nowrap;}
.swatch{width:11px;height:11px;border-radius:2px;box-shadow:0 0 6px -1px currentColor;}
.sym{color:var(--ink);font-weight:600;}
.band{margin-top:36px;}
.band-h{display:flex;align-items:baseline;gap:13px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.15em;font-size:13px;margin:0 0 18px;padding-bottom:9px;border-bottom:1px solid var(--line);}
.band-h .n{font-size:21px;letter-spacing:0;color:var(--tone,var(--ink));font-weight:600;}
.band-h .t{color:var(--tone,var(--ink));}
.band-h .sub{color:var(--ink-faint);letter-spacing:.03em;text-transform:none;font-size:12px;margin-left:auto;}
.lvl{display:flex;gap:16px;align-items:stretch;overflow-x:auto;padding-bottom:4px;}
.lvl>.node{flex:1;min-width:248px;}
.down{display:block;text-align:center;color:var(--ink-faint);font-size:15px;padding:6px 0;}
.node{background:var(--ground-2);border:1px solid var(--line);border-left:3px solid var(--tone,var(--ink-faint));border-radius:4px;padding:12px 14px 13px;}
.node .top{display:flex;align-items:baseline;gap:9px;margin-bottom:8px;}
.node .idx{font-family:var(--mono);font-size:12px;color:var(--tone);font-weight:600;}
.node h3{font-family:var(--mono);font-size:15px;margin:0;font-weight:600;letter-spacing:-.01em;}
.node .tag{margin-left:auto;font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-faint);border:1px solid var(--line);border-radius:3px;padding:2px 6px;white-space:nowrap;}
.node .tag.par-tag{color:var(--tone);border-color:color-mix(in srgb,var(--tone) 45%,var(--line));}
.node p{margin:0 0 9px;font-size:12.5px;color:var(--ink-dim);}
.cmd{font-family:var(--mono);font-size:11.5px;background:var(--inset);border:1px solid var(--line);border-radius:3px;padding:8px 10px;margin:0 0 9px;color:var(--ink-dim);white-space:pre;overflow-x:auto;line-height:1.6;}
.out{display:flex;flex-wrap:wrap;gap:6px;}
.art{font-family:var(--mono);font-size:11px;color:var(--ink);background:#0e1626;border:1px solid var(--line);border-radius:3px;padding:3px 7px;white-space:nowrap;}
.art::before{content:"→ ";color:var(--tone);}
.notes{margin:9px 0 0;padding-left:16px;font-family:var(--mono);font-size:11px;color:var(--ink-dim);line-height:1.55;}
.notes li::marker{color:var(--tone);}
.barrier{display:flex;align-items:center;gap:14px;margin:26px 0 4px;font-family:var(--mono);font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-faint);}
.barrier::before,.barrier::after{content:"";flex:1;border-top:1px dashed var(--line);}
.band[style*="8b8fa3"] .node{border-style:dashed;}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);font-family:var(--mono);font-size:11px;color:var(--ink-faint);}
a:focus-visible{outline:2px solid var(--ink);outline-offset:2px;}
@media (max-width:560px){.wrap{padding:28px 13px 52px;}.masthead{padding:20px 16px;}}
"""

_DOC = """<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
<header class="masthead">
<p class="eyebrow">{eyebrow}</p>
<h1>signal <span class="sep">/</span> flow</h1>
<p class="thesis">{thesis}</p>
<div class="legend" aria-label="legenda">
<span class="k"><span class="swatch" style="color:#4fd6c8;background:#4fd6c8"></span>breadth</span>
<span class="k"><span class="swatch" style="color:#f0b429;background:#f0b429"></span>spanning</span>
<span class="k"><span class="swatch" style="color:#7bd88f;background:#7bd88f"></span>loop 1</span>
<span class="k"><span class="swatch" style="color:#ff4d9d;background:#ff4d9d"></span>loop 2</span>
<span class="k"><span class="swatch" style="color:#8b8fa3;background:#8b8fa3"></span>fan-in</span>
<span class="k"><span class="sym">∥</span> parallelo</span>
<span class="k"><span class="sym">▼</span> needs</span>
<span class="k"><span class="sym">▭</span> barriera</span>
</div>
</header>
{body}
<footer>generato da <b>pipt.pipelines.recon.flowmeta</b> · non modificare a mano · struttura derivata dagli Stage objects</footer>
</div>
</body>
</html>
"""
