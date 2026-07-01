"""Shared flow-map doc generator — the ONE entrypoint that writes every pipeline's flow docs.

Any pipeline exposing a duck-typed ``flowmap_spec() -> MapSpec`` hook (the same convention as
``requirements()``/``consolidate()``/``preflight()`` — read via ``getattr``, off the Protocol) gets
three self-contained, always-current views under ``docs/``:

    docs/<name>-pipeline-flow.html   # the detailed band "spec sheet" (core.flowmap.render)
    docs/<name>-pipeline-map.html    # the pan/zoom Mermaid flowchart   (core.mermaidmap.render_html)
    docs/<name>-pipeline-map.md      # the same flowchart, GitHub-renderable (…render_markdown)

A pipeline WITHOUT the hook (the ``example`` stub) is skipped gracefully. Per-step prose lives in each
pipeline's ``flowmeta.py`` (the ``StepMeta`` table bundled into its ``MapSpec``); the STRUCTURE (bands,
phases, barriers, parallelism) is derived from the ``Stage`` objects, so a code change regenerates the
maps. Output is DETERMINISTIC (no timestamps) → a git diff of any file shows exactly how the flow moved.

This replaces external's private ``main()``; the ``.claude`` hook and the dev gate both drive it.

Run:  uv run python -m ptflow.core.flowdocs
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ptflow.core.flowmap import render
from ptflow.core.log import get_logger
from ptflow.core.mermaidmap import render_html, render_markdown
from ptflow.pipelines import PIPELINE_NAMES, load_pipeline

if TYPE_CHECKING:
    from ptflow.core.flowmap import MapSpec

log = get_logger()

_GENERATOR = "ptflow.core.flowdocs"
# core/flowdocs.py → parents: [0]=core [1]=ptflow [2]=src [3]=repo root
_DOCS = Path(__file__).resolve().parents[3] / "docs"


def flowmap_spec_of(pipeline: object) -> MapSpec | None:
    """The pipeline's flow-map spec via the duck-typed ``flowmap_spec()`` hook, or None if it has
    none (a stub pipeline that opts out of the flow-map standard)."""
    hook = getattr(pipeline, "flowmap_spec", None)
    return hook() if callable(hook) else None


def doc_names(name: str) -> tuple[str, str, str]:
    """The three per-pipeline doc filenames: (flow.html, map.html, map.md)."""
    return (
        f"{name}-pipeline-flow.html",
        f"{name}-pipeline-map.html",
        f"{name}-pipeline-map.md",
    )


def generate(name: str, docs: Path) -> bool:
    """Write ``name``'s three flow docs into ``docs`` (True), or skip a hook-less pipeline (False)."""
    pipeline = load_pipeline(name)
    spec = flowmap_spec_of(pipeline)
    if spec is None:
        return False
    flow_html, map_html, map_md = doc_names(name)
    docs.mkdir(parents=True, exist_ok=True)
    (docs / flow_html).write_text(render(pipeline.stages, spec, generator=_GENERATOR), encoding="utf-8")
    (docs / map_html).write_text(
        render_html(pipeline.stages, spec, generator=_GENERATOR), encoding="utf-8")
    (docs / map_md).write_text(
        render_markdown(pipeline.stages, spec, map_html=map_html, flow_html=flow_html,
                        generator=_GENERATOR),
        encoding="utf-8")
    log.info("flow map → %s (%d stages)", name, len(pipeline.stages))
    return True


def generate_all(docs: Path | None = None) -> list[str]:
    """Generate the flow docs for every registered pipeline that declares the hook. Returns the names
    actually written (hook-less pipelines are skipped)."""
    dest = docs if docs is not None else _DOCS
    return [name for name in PIPELINE_NAMES if generate(name, dest)]


def main() -> None:
    """Regenerate every pipeline's flow docs under ``docs/`` (the manual + hook entrypoint)."""
    written = generate_all()
    log.info("flow docs written for: %s", ", ".join(written) or "none")


if __name__ == "__main__":
    main()
