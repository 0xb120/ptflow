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
        Stage(name="expand", mode=Mode.BREADTH, run=tasks.expand, produces=("scope_dns", "tlsx_raw")),
        Stage(name="resolve", mode=Mode.BREADTH, run=tasks.resolve,
              produces=("subdomains", "unique_ips", "domain_ip_map")),
        Stage(name="portscan", mode=Mode.BREADTH, run=tasks.portscan,
              produces=("naabu_1k", "honeypots", "naabu_full")),
        Stage(name="fingerprint", mode=Mode.BREADTH, run=tasks.fingerprint,
              produces=("httpx_metadata", "nerva_metadata", "unique_webapps")),
        # depth: per app group (passive_probe -> crawl -> subenum -> takeover)
        Stage(name="passive_probe", mode=Mode.DEPTH, run=tasks.passive_probe,
              produces=("endpoints_passive",)),
        Stage(name="crawl", mode=Mode.DEPTH, run=tasks.crawl, produces=("endpoints",)),
        Stage(name="subenum", mode=Mode.DEPTH, run=tasks.subenum, produces=("subs",)),
        Stage(name="takeover", mode=Mode.DEPTH, run=tasks.takeover, produces=("takeover",)),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ReconPipeline()
