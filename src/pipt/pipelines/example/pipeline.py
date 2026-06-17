"""Temporary stub — the real example pipeline is built in Task 12.

Exists only so `ty` can resolve the lazy import in pipt.pipelines.load_pipeline
and the Pipeline protocol reference. Importing it raises, so a premature
`load_pipeline("example")` fails loudly instead of returning None.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipt.core.stage import Pipeline


def _unbuilt() -> Pipeline:
    msg = "example pipeline not built yet (replaced in Task 12)"
    raise NotImplementedError(msg)


PIPELINE: Pipeline = _unbuilt()
