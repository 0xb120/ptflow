"""The example Pipeline object."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from pipt.core.agent import HypothesisProvider, StubProvider
from pipt.core.stage import Mode, Stage
from pipt.pipelines.example import tasks

if TYPE_CHECKING:
    from pipt.core.paths import Activity


class ExamplePipeline:
    name = "example"
    stages: Sequence[Stage] = (
        Stage(name="discover", mode=Mode.BREADTH, run=tasks.discover, produces=("hosts",)),
        Stage(name="enum", mode=Mode.DEPTH, run=tasks.enum, produces=("services",)),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ExamplePipeline()
