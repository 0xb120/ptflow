"""Pluggable pipelines registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipt.core.stage import Pipeline


def load_pipeline(name: str) -> Pipeline:
    if name == "example":
        from pipt.pipelines.example.pipeline import PIPELINE  # noqa: PLC0415

        return PIPELINE
    msg = f"unknown pipeline: {name!r}"
    raise ValueError(msg)
