"""The recon Pipeline object (real ProjectDiscovery toolchain)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from pipt.core.agent import HypothesisProvider, StubProvider
from pipt.core.stage import Mode, Stage
from pipt.pipelines.recon import tasks

if TYPE_CHECKING:
    from pipt.core.paths import Activity


class ReconPipeline:
    name = "recon"
    stages: Sequence[Stage] = (
        Stage(
            name="asset_discovery",
            mode=Mode.BREADTH,
            run=tasks.asset_discovery,
            produces=("subdomains", "httpx_metadata", "services"),
        ),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ReconPipeline()
