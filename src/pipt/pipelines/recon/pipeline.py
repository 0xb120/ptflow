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
        Stage("provision_wl", tasks.provision_wl),  # resolve global wordlist roles → wl_global/ (∥)
        Stage("expand", tasks.expand),
        Stage("resolve", tasks.resolve, needs=("expand",)),
        Stage("portscan", tasks.portscan, needs=("resolve",)),
        Stage("httpx", tasks.httpx_fingerprint, needs=("portscan",)),
        # full 65535-port scan + non-HTTP fingerprint — SPANNING: ∥ clustering + all per-app loops,
        # joined at the fan-in. httpx only needs the fast top-1k web set (naabu_web.txt), so the
        # expensive full scan no longer serializes in front of the breadth→cluster→loops path.
        Stage("portscan_full", tasks.portscan_full, needs=("portscan",), spanning=True),
        Stage("nerva", tasks.nerva_fingerprint, needs=("portscan_full",), spanning=True),
        # whole-scope nuclei — spanning: runs ∥ clustering + all per-app loops, joined at the fan-in
        Stage("nuclei_scope", tasks.nuclei_scope, needs=("httpx",), spanning=True),
        # post-cluster spanning — ONE batched screenshot run (1 host/group) → unified gallery, ∥ loops
        Stage("screenshot", tasks.screenshot_all, cluster_scope=True),
        # per-app LOOP 1 — enumeration (after cluster fan-out)
        Stage("passive_probe", tasks.passive_probe, per_app=True, phase=1),
        Stage("crawl", tasks.crawl, needs=("passive_probe",), per_app=True, phase=1),
        # gated TIER-1 headless crawl — runs only on the JS-rendered bucket (∥ takeover)
        Stage("crawl_headless", tasks.crawl_headless, needs=("crawl",), per_app=True, phase=1),
        Stage("subenum", tasks.subenum, per_app=True, phase=1),  # ∥ passive_probe/crawl
        Stage("takeover", tasks.takeover, needs=("crawl", "subenum"), per_app=True, phase=1),
        # per-app LOOP 2 — content discovery (reads loop-1 artifacts across the barrier)
        Stage("wordlist", tasks.build_wordlist, per_app=True, phase=2),
        Stage("fetch_delta", tasks.fetch_delta, per_app=True, phase=2),  # ∥ wordlist
        Stage("mine_responses", tasks.mine_responses, needs=("fetch_delta",), per_app=True, phase=2),
        Stage("tech_enum", tasks.tech_enum, needs=("wordlist",), per_app=True, phase=2),
        Stage("content_discovery", tasks.content_discovery,
              needs=("wordlist", "tech_enum", "mine_responses"), per_app=True, phase=2),
        # per-app LOOP 3 — deep enumeration: hidden-parameter discovery (feeds the planned DAST).
        # Reads loop-2 endpoint artifacts across the barrier (no cross-loop needs).
        Stage("param_fuzz", tasks.param_fuzz, per_app=True, phase=3),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()

    def preflight(self) -> None:
        """Log present/missing external tools at run start (best-effort, never aborts)."""
        tasks.preflight()


PIPELINE = ReconPipeline()
