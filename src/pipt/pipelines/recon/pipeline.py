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

    def cluster(self, activity: Activity) -> list[str]:  # noqa: ARG002
        # Clustering (surfagr.sh port: group httpx vhosts by Title + Content-Length
        # + Webserver into scans/<app_id>/) lands in a later round — no app groups yet.
        return []

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ReconPipeline()
