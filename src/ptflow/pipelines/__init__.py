"""Pluggable pipelines registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ptflow.core.stage import Pipeline

# Every registered pipeline, in a stable order — the single source of truth iterated by the CLI help,
# the flow-map doc generator (core/flowdocs.py) and its gate (tests/pipelines/test_flowmap.py).
PIPELINE_NAMES: tuple[str, ...] = ("example", "external", "internal", "webscan")


def load_pipeline(name: str) -> Pipeline:
    if name == "example":
        from ptflow.pipelines.example.pipeline import PIPELINE  # noqa: PLC0415

        return PIPELINE
    if name == "external":
        from ptflow.pipelines.external.pipeline import PIPELINE  # noqa: PLC0415

        return PIPELINE
    if name == "internal":
        from ptflow.pipelines.internal.pipeline import PIPELINE  # noqa: PLC0415

        return PIPELINE
    if name == "webscan":
        from ptflow.pipelines.webscan.pipeline import PIPELINE  # noqa: PLC0415

        return PIPELINE
    msg = f"unknown pipeline: {name!r}"
    raise ValueError(msg)
