"""The example Pipeline object."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from pipt.core.agent import HypothesisProvider, StubProvider
from pipt.core.ingest import Handler
from pipt.core.stage import Mode, Stage
from pipt.pipelines.example import tasks

_SCHEMA = Path(__file__).parent / "schema.sql"


class ExamplePipeline:
    name = "example"
    stages: Sequence[Stage] = (
        Stage(name="discover", mode=Mode.BREADTH, run=tasks.discover, produces=("hosts",)),
        Stage(name="enum", mode=Mode.DEPTH, run=tasks.enum, produces=("services",)),
    )

    def extension_schema(self) -> str:
        return _SCHEMA.read_text(encoding="utf-8")

    def ingest_handlers(self) -> dict[str, Handler]:
        return {}

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ExamplePipeline()
