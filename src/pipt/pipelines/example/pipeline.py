"""The example Pipeline object."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from pipt.core.agent import HypothesisProvider, StubProvider
from pipt.core.stage import Stage
from pipt.pipelines.example import tasks

if TYPE_CHECKING:
    from pipt.core.paths import Activity


class ExamplePipeline:
    name = "example"
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
