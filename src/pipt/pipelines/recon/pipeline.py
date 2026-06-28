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
        Stage("provision_wl", tasks.provision_wl, net=False),  # wordlist roles → wl_global/ (offline, ∥)
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
        # ── per-app PHASE 1 — EXPLORABLE SURFACE (OSINT + crawl, NO guessing) ────────────────────────
        # Map only what's really there: passive/crawl/headless + API specs, mine the corpus offline, and
        # assemble the surface request catalog (requests.jsonl). No fuzzing/guessing in this phase.
        Stage("passive_probe", tasks.passive_probe, per_app=True, phase=1),
        Stage("crawl", tasks.crawl, needs=("passive_probe",), per_app=True, phase=1),
        # gated TIER-1 headless crawl — runs only on the JS-rendered bucket (∥ takeover)
        Stage("crawl_headless", tasks.crawl_headless, needs=("crawl",), per_app=True, phase=1),
        Stage("subenum", tasks.subenum, per_app=True, phase=1),  # ∥ passive_probe/crawl
        Stage("takeover", tasks.takeover, needs=("crawl", "subenum"), per_app=True, phase=1),
        # download the OSINT/crawley delta, then mine the corpus offline (extract + jsluice endpoints)
        Stage("fetch_delta", tasks.fetch_delta, needs=("crawl_headless",), per_app=True, phase=1),
        # API spec discovery (OpenAPI/Swagger/GraphQL) → requests_api.jsonl (∥; reads hosts only)
        Stage("api_spec", tasks.api_spec, per_app=True, phase=1),
        Stage("mine_responses", tasks.mine_responses, needs=("fetch_delta",), per_app=True, phase=1,
              net=False),  # offline: extract + jsluice the stored corpus, no network
        # surface request catalog — crawl/headless/API + shapes mined from the crawl corpus, NO guessed
        # surface (content_discovery/recrawl run later). The full-request DAST input for phase 2.
        Stage("request_catalog", tasks.request_catalog,
              needs=("crawl_headless", "mine_responses", "api_spec"), per_app=True, phase=1, net=False),
        # ── per-app PHASE 2 — DAST the explorable surface (low-hanging fruit) ────────────────────────
        # nuclei -dast over the surface catalog (observed params) — fast, high-signal findings on the
        # real attack surface BEFORE sinking hours into fuzzing. Reads requests.jsonl across the barrier.
        Stage("dast", tasks.dast, per_app=True, phase=2),
        # CVE lookup over the explorable-surface enumerated software (web server + tech + service banners
        # + corpus libs) — OFFLINE correlation (net=False, no target traffic), runs ∥ dast (same phase,
        # no needs). Records the covered (product,version) set so the phase-4 pass reports only the delta.
        Stage("cve_lookup", tasks.cve_lookup, per_app=True, phase=2, net=False),
        # ── per-app PHASE 3 — guessing / surface expansion ──────────────────────────────────────────
        # build the fuzzing seed offline (JS/body/seed parsing), run the per-stack surface scanners, then
        # the content-discovery fixpoint; recrawl re-seeds katana on new-territory entry points it found.
        Stage("wordlist", tasks.build_wordlist, per_app=True, phase=3, net=False),
        Stage("tech_enum", tasks.tech_enum, needs=("wordlist",), per_app=True, phase=3),
        Stage("content_discovery", tasks.content_discovery, needs=("wordlist", "tech_enum"),
              per_app=True, phase=3),
        Stage("recrawl", tasks.recrawl, needs=("content_discovery",), per_app=True, phase=3),
        # ── per-app PHASE 4 — DAST the guessed surface (detailed) ───────────────────────────────────
        # rebuild the catalog INCLUDING the guessed surface (requests_full.jsonl), discover hidden params,
        # then DAST only the DELTA vs phase 2 + the param-injection requests (no re-DAST of the surface).
        Stage("request_catalog_full", tasks.request_catalog_full, per_app=True, phase=4, net=False),
        Stage("param_fuzz", tasks.param_fuzz, needs=("request_catalog_full",), per_app=True, phase=4),
        Stage("dast_full", tasks.dast_full, needs=("request_catalog_full", "param_fuzz"),
              per_app=True, phase=4),
        # CVE lookup over the EXPANDED enumeration (the phase-3 crawl grew the corpus) — OFFLINE, runs ∥
        # dast_full; reports only the delta vs the phase-2 pass (raw/cve/seen.txt).
        Stage("cve_lookup_full", tasks.cve_lookup_full, per_app=True, phase=4, net=False),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def provider(self) -> HypothesisProvider:
        return StubProvider()

    def preflight(self) -> None:
        """Log present/missing external tools at run start (best-effort, never aborts)."""
        tasks.preflight()


PIPELINE = ReconPipeline()
