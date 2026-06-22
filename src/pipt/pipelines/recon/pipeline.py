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
        Stage("takeover_scope", tasks.takeover_scope, needs=("resolve",)),  # nuclei takeover, ∥ portscan/httpx
        # per-app LOOP 1 — enumeration (after cluster fan-out)
        Stage("screenshot", tasks.screenshot, per_app=True, phase=1),  # root-page shot (∥ entry)
        Stage("passive_probe", tasks.passive_probe, per_app=True, phase=1),
        Stage("crawl", tasks.crawl, needs=("passive_probe",), per_app=True, phase=1),
        Stage("subenum", tasks.subenum, per_app=True, phase=1),  # ∥ passive_probe/crawl
        Stage("takeover", tasks.takeover, needs=("crawl", "subenum"), per_app=True, phase=1),
        # per-app LOOP 2 — content discovery (reads loop-1 artifacts across the barrier)
        Stage("wordlist", tasks.build_wordlist, per_app=True, phase=2),
        Stage("fetch_delta", tasks.fetch_delta, per_app=True, phase=2),  # ∥ wordlist
        Stage("mine_responses", tasks.mine_responses, needs=("fetch_delta",), per_app=True, phase=2),
        Stage("tech_enum", tasks.tech_enum, needs=("wordlist",), per_app=True, phase=2),
        Stage("content_discovery", tasks.content_discovery,
              needs=("wordlist", "tech_enum", "mine_responses"), per_app=True, phase=2),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ReconPipeline()
