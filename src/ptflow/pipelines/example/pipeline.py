"""The example Pipeline object."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from ptflow.core.agent import HypothesisProvider, StubProvider
from ptflow.core.stage import Stage
from ptflow.pipelines.example import tasks

if TYPE_CHECKING:
    from ptflow.core.paths import Activity


class ExamplePipeline:
    name = "example"
    resume_epoch = 1
    stages: Sequence[Stage] = (
        Stage("discover", tasks.discover),                                   # activity scope
        Stage("scope_scan", tasks.scope_scan, needs=("discover",), spanning=True),  # ∥ everything
        Stage("enum", tasks.enum, per_app=True),                             # per app group
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ExamplePipeline()
