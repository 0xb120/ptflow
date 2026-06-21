"""The recon Pipeline object (real ProjectDiscovery toolchain), as a dependency DAG."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from pipt.core.agent import HypothesisProvider, StubProvider
from pipt.core.stage import Stage
from pipt.pipelines.recon import tasks

if TYPE_CHECKING:
    from pipt.core.paths import Activity


class ReconPipeline:
    name = "recon"
    stages: Sequence[Stage] = (
        # activity scope (whole-scope asset discovery)
        Stage("expand", tasks.expand),
        Stage("resolve", tasks.resolve, needs=("expand",)),
        Stage("portscan", tasks.portscan, needs=("resolve",)),
        Stage("httpx", tasks.httpx_fingerprint, needs=("portscan",)),
        Stage("nerva", tasks.nerva_fingerprint, needs=("portscan",)),  # ∥ httpx
        # per-app scope (after cluster fan-out)
        Stage("passive_probe", tasks.passive_probe, per_app=True),
        Stage("crawl", tasks.crawl, needs=("passive_probe",), per_app=True),
        Stage("subenum", tasks.subenum, per_app=True),  # ∥ passive_probe/crawl
        Stage("takeover", tasks.takeover, needs=("crawl", "subenum"), per_app=True),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ReconPipeline()
