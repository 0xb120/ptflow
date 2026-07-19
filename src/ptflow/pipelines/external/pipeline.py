"""The external Pipeline object (real ProjectDiscovery toolchain), as a dependency DAG."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ptflow.core.agent import HypothesisProvider, StubProvider
from ptflow.core.ai.client import stage_enabled
from ptflow.core.stage import Followup, Stage
from ptflow.pipelines.external import ai, tasks

if TYPE_CHECKING:
    from ptflow.core.flowmap import MapSpec
    from ptflow.core.paths import Activity
    from ptflow.core.requirements import Requirement


_AI = os.getenv("PTFLOW_AI", "").strip().lower() in {"1", "on", "true", "yes"}
_AI_STAGES = ai.per_app_stages()


class ExternalPipeline:
    name = "external"
    resume_epoch = 3
    stages: Sequence[Stage] = (
        # activity scope (whole-scope asset discovery)
        Stage("provision_wl", tasks.provision_wl, net=False),  # wordlist roles → wl_global/ (offline, ∥)
        Stage("expand", tasks.expand),
        # Passive wildcard enum completes in expand; active DNS bruteforce then consumes the
        # provisioned subdomains role only for explicit *.domain scope entries.
        Stage("subdomain_bruteforce", tasks.subdomain_bruteforce,
              needs=("expand", "provision_wl")),
        Stage("resolve", tasks.resolve, needs=("subdomain_bruteforce",)),
        Stage("scope_gate", tasks.scope_gate, needs=("resolve",), net=False),  # RoE authorization gate
        Stage("portscan", tasks.portscan, needs=("scope_gate",)),
        # Predictable common barrier: curated web ports + deadline-bounded top-1000. httpx/nerva feed
        # the main cluster immediately; exhaustive coverage is the spanning incremental tail below.
        Stage("portscan_full", tasks.portscan_full, needs=("portscan",)),
        Stage("httpx", tasks.httpx_fingerprint, needs=("portscan_full",)),
        Stage("nerva", tasks.nerva_fingerprint, needs=("portscan_full",)),
        # Exhaustive-only tail: the tasks are stable no-ops in balanced mode. The full scan runs ∥
        # cluster/loops; httpx_late identifies new web apps, then fingerprint_late + cve_late cover the
        # remaining non-HTTP sockets before the CLI starts the depth-only webscan follow-up.
        Stage("portscan_exhaustive", tasks.portscan_exhaustive,
              needs=("portscan_full",), spanning=True),
        Stage("httpx_late", tasks.httpx_late, needs=("portscan_exhaustive",), spanning=True),
        Stage("fingerprint_late", tasks.fingerprint_late, needs=("httpx_late",), spanning=True),
        Stage("cve_late", tasks.cve_late, needs=("fingerprint_late",), spanning=True, net=False),
        # whole-scope nuclei — spanning: runs ∥ clustering + all per-app loops, joined at the fan-in
        Stage("nuclei_scope", tasks.nuclei_scope, needs=("httpx",), spanning=True),
        # post-cluster spanning — ONE batched screenshot run (1 host/group) → unified gallery, ∥ loops
        Stage("screenshot", tasks.screenshot_all, cluster_scope=True),
        # ── per-app PHASE 1 — EXPLORABLE SURFACE (OSINT + crawl, NO guessing) ────────────────────────
        # Map only what's really there: passive/crawl/headless + API specs, mine the corpus offline, and
        # assemble the surface request catalog (requests.jsonl). No fuzzing/guessing in this phase.
        Stage("passive_probe", tasks.passive_probe, per_app=True, phase=1),
        Stage("crawl", tasks.crawl, needs=("passive_probe",), per_app=True, phase=1),
        # always-on TIER-1 browser crawl for every app group (bounded process-wide; ∥ takeover)
        Stage("crawl_headless", tasks.crawl_headless, needs=("crawl",), per_app=True, phase=1),
        Stage("subenum", tasks.subenum, per_app=True, phase=1),  # ∥ passive_probe/crawl
        Stage("takeover", tasks.takeover, needs=("crawl", "subenum"), per_app=True, phase=1),
        # download the OSINT/crawley delta, then mine the corpus offline (extract + jsluice endpoints)
        Stage("fetch_delta", tasks.fetch_delta, needs=("crawl_headless",), per_app=True, phase=1),
        # API spec discovery → request shapes + version-pinned software observations (∥; hosts only)
        Stage("api_spec", tasks.api_spec, per_app=True, phase=1),
        Stage("mine_responses", tasks.mine_responses, needs=("fetch_delta",), per_app=True, phase=1,
              net=False),  # offline: extract + jsluice the stored corpus, no network
        # surface request catalog — crawl/headless/API + shapes mined from the crawl corpus, NO guessed
        # surface (content_discovery/recrawl run later). The full-request DAST input for phase 2.
        Stage("request_catalog", tasks.request_catalog,
              needs=("crawl_headless", "mine_responses", "api_spec"), per_app=True, phase=1, net=False),
        # ── per-app PHASE 2 — DAST the explorable surface (low-hanging fruit) ────────────────────────
        # cross-group catalog first: pulls in peer groups' explorable-surface request SHAPES whose host
        # belongs to THIS group, rebases them onto this group's full scheme+authority, and drops plain
        # passive fetches (JS/MJS/CSS stay eligible). dast/xss/sqli cover the useful cross-group surface. Safe: the
        # 1→2 barrier means every group finished phase 1 already (race-free read).
        Stage("xref_catalog", tasks.xref_catalog, per_app=True, phase=2, net=False),
        # nuclei -dast over the surface catalog (observed params) — fast, high-signal findings on the
        # real attack surface BEFORE sinking hours into fuzzing. Reads requests.jsonl across the barrier.
        Stage("dast", tasks.dast, needs=("xref_catalog",), per_app=True, phase=2),
        # dedicated vuln scanners over the explorable surface (full requests, every param location) —
        # dalfox (XSS) ∥ sqlmap (SQLi), each tool's own engine decides (no gf-style name routing). The
        # high-signal complement to nuclei -dast's generic templates. Best-effort; run ∥ dast/cve_lookup.
        Stage("xss", tasks.xss, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("sqli", tasks.sqli, needs=("xref_catalog",), per_app=True, phase=2),
        # CVE lookup over versioned server/tech/banner/corpus/OpenAPI observations — OFFLINE correlation.
        # The explicit edges document both structured observation producers (the phase barrier has
        # already completed all phase-1 work). Records covered pairs so phase 4 reports only the delta.
        Stage("cve_lookup", tasks.cve_lookup, needs=("api_spec", "mine_responses"), per_app=True,
              phase=2, net=False),
        # Global barrier checkpoint: snapshot every mature surface finding and publish the early
        # deterministic report before the expensive guessing/deep loops start.
        Stage("surface_checkpoint", tasks.surface_checkpoint, after_phase=2, net=False),
        # ── per-app PHASE 3 — guessing / surface expansion ──────────────────────────────────────────
        # build the fuzzing seed offline (JS/body/seed parsing), run the per-stack surface scanners, then
        # the content-discovery fixpoint; recrawl re-seeds katana on new-territory entry points it found.
        Stage("wordlist", tasks.build_wordlist, per_app=True, phase=3, net=False),
        Stage("tech_enum", tasks.tech_enum, needs=("wordlist",), per_app=True, phase=3),
        Stage("content_discovery", tasks.content_discovery, needs=("wordlist", "tech_enum"),
              per_app=True, phase=3),
        Stage("recrawl", tasks.recrawl, needs=("content_discovery",), per_app=True, phase=3),
        # cloud-storage exposure — mine the corpus for S3/GCS/Azure refs + probe apex-derived candidate
        # bucket names for public listability (∥ the rest of loop 3; reads the corpus, no needs).
        Stage("cloud_assets", tasks.cloud_assets, per_app=True, phase=3),
        # ── per-app PHASE 4 — freeze the complete guessed-surface catalog ───────────────────────────
        # Every app builds requests_full.jsonl before the phase-5 scanners calculate engagement-wide
        # budgets. This barrier makes cross-app redistribution deterministic and race-free.
        Stage("request_catalog_full", tasks.request_catalog_full, per_app=True, phase=4, net=False),
        # CVE lookup over the EXPANDED enumeration — OFFLINE; independent of request budgeting.
        Stage("cve_lookup_full", tasks.cve_lookup_full, per_app=True, phase=4, net=False),
        # finding-only per-stack vuln scanners (gated on detected tech), also catalog-independent.
        Stage("tech_vulnscan", tasks.tech_vulnscan, per_app=True, phase=4),
        # ── per-app PHASE 5 — risk-budgeted hidden-parameter discovery ──────────────────────────────
        # Uses every completed full catalog to redistribute query/body/header budgets deterministically.
        Stage("param_fuzz", tasks.param_fuzz, per_app=True, phase=5),
        # ── per-app PHASE 6 — risk-budgeted deep scanners ───────────────────────────────────────────
        # The 5→6 barrier freezes params for every app, so demand is the exact delta + synthesized params.
        Stage("dast_full", tasks.dast_full, per_app=True, phase=6),
        # dedicated vuln scanners over the GUESSED-surface delta + discovered params (the dalfox/sqlmap
        # analog of dast_full): fuzz only what phase 2 didn't already cover. Need the full catalog + params.
        Stage("xss_full", tasks.xss_full, per_app=True, phase=6),
        Stage("sqli_full", tasks.sqli_full, per_app=True, phase=6),
        *(_AI_STAGES if _AI else ()),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def consolidate(self, activity: Activity) -> dict[str, int]:
        """Deterministic terminal fan-in: lift per-app findings into <activity>/findings/<type>.jsonl
        (one file per finding type). The orchestrator calls this if present (the dormant agent seam
        stays in place beside it)."""
        return tasks.consolidate(activity)

    def followups(self, activity: Activity) -> list[Followup]:
        """Exhaustive mode: depth-scan only the new web apps found by the spanning full-port tail."""
        return tasks.external_followups(activity)

    def provider(self) -> HypothesisProvider:
        return ai.LLMHypothesisProvider() if _AI and stage_enabled("triage") else StubProvider()

    def report(self, activity: Activity) -> None:
        """Optional AI report hook (duck-typed, called by the orchestrator terminal fan-in). No-op
        when AI is off/unavailable."""
        ai.report(activity)

    def preflight(self) -> None:
        """Log present/missing external tools at run start (best-effort, never aborts)."""
        tasks.preflight()

    def requirements(self) -> list[Requirement]:
        """Host requirement manifest (tools + datasets) that `ptflow doctor` checks. Duck-typed hook,
        like preflight/consolidate — read via getattr, so it stays off the Protocol."""
        return tasks.requirements()

    def flowmap_spec(self) -> MapSpec:
        """Flow-map metadata for the doc generator (duck-typed hook; see core/flowdocs.py). Lazy
        import keeps the doc-only prose off the normal run's import path."""
        from ptflow.pipelines.external.flowmeta import SPEC  # noqa: PLC0415

        return SPEC


PIPELINE = ExternalPipeline()
