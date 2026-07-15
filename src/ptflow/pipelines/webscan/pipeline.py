"""The `webscan` Pipeline — external's web-DEPTH loops over a PRE-AGGREGATED web target list.

This is the dedicated "external profile" the internal pipeline hands off to (via `Followup`): it takes an
already-known list of web services (`scheme://host[:port]`, e.g. `<internal-activity>/web_targets.txt`)
and runs external's crawl → catalog → DAST → fuzz depth on them, **skipping**:
  - scope EXPANSION — `expand`/`resolve` (subdomain/DNS/TLS/OSINT enumeration);
  - active NETWORK scan — `portscan`/`portscan_full`/`nerva`/`nuclei_scope`;
  - per-app OSINT — `passive_probe`/`subenum`/`takeover`/`fetch_delta` (gau/urlfinder/subfinder/DNS).

It reuses external's task and AI functions unchanged — only the breadth is replaced by a single
`ingest` step (httpx over the target list, honouring the input scheme) and the stage graph is curated.
Dropped stages' artifacts are simply absent; external's tolerant reads (`read_lines`/`read_jsonl` →
`[]`) degrade cleanly, so the depth loops run without them. external itself is untouched. With AI
enabled, webscan has the same contextual-wordlist, secret-triage, terminal-triage and report hooks as
external.

Egress note: with the OSINT stages gone this is largely egress-free, but two external internals still call
out — `content_discovery`'s trufflehog runs `--results=verified` (validates hits against the credential's
PROVIDER) and nuclei/CVE read local data only. On a strictly air-gapped engagement, mind trufflehog.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING

from ptflow.core.agent import HypothesisProvider, StubProvider
from ptflow.core.ai.client import stage_enabled
from ptflow.core.stage import Stage
from ptflow.pipelines.external import ai
from ptflow.pipelines.external import tasks as external

if TYPE_CHECKING:
    from ptflow.core.flowmap import MapSpec
    from ptflow.core.paths import Activity
    from ptflow.core.requirements import Requirement

# webscan runs external's DEPTH loops only — these are the four tools it can't work without (ingest/
# crawl/forced-browse/DAST). Every other tool in external's manifest is breadth/OSINT (naabu, subfinder,
# dnsx, …) that webscan never invokes, so doctor must NOT fail the gate on it → it's demoted to optional.
# This set is the only hand-maintained bit; keep it in step with the stages above.
_DEPTH_CORE = frozenset({"httpx", "katana", "feroxbuster", "nuclei"})
_AI = os.getenv("PTFLOW_AI", "").strip().lower() in {"1", "on", "true", "yes"}
_AI_STAGES = ai.per_app_stages()


class WebscanPipeline:
    name = "webscan"
    stages: Sequence[Stage] = (
        # BREADTH — minimal: no expansion, no active network scan. Just fingerprint the given targets.
        Stage("provision_wl", external.provision_wl, net=False),
        Stage("ingest", external.ingest_httpx, needs=("provision_wl",)),  # httpx over the aggregated list
        # post-cluster spanning — unified screenshot gallery (∥ the loops), as in external
        Stage("screenshot", external.screenshot_all, cluster_scope=True),
        # ── LOOP 1 — EXPLORABLE SURFACE (crawl only; OSINT stages dropped) ───────────────────────────
        Stage("crawl", external.crawl, per_app=True, phase=1),
        Stage("crawl_headless", external.crawl_headless, needs=("crawl",), per_app=True, phase=1),
        Stage("api_spec", external.api_spec, per_app=True, phase=1),
        # mine the crawl corpus offline (fetch_delta is dropped → it mines only katana's -srd store)
        Stage("mine_responses", external.mine_responses, needs=("crawl_headless",), per_app=True, phase=1,
              net=False),
        Stage("request_catalog", external.request_catalog,
              needs=("crawl_headless", "mine_responses", "api_spec"), per_app=True, phase=1, net=False),
        # ── LOOP 2 — DAST the explorable surface ─────────────────────────────────────────────────────
        # Peer request shapes are rebased onto the destination group's full authority; plain passive
        # assets are excluded from xref/DAST, while JS/MJS/CSS stay eligible for dynamic reflections.
        Stage("xref_catalog", external.xref_catalog, per_app=True, phase=2, net=False),
        Stage("dast", external.dast, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("xss", external.xss, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("sqli", external.sqli, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("cve_lookup", external.cve_lookup, needs=("api_spec", "mine_responses"),
              per_app=True, phase=2, net=False),
        Stage("surface_checkpoint", external.surface_checkpoint, after_phase=2, net=False),
        # ── LOOP 3 — guessing / surface expansion ────────────────────────────────────────────────────
        Stage("wordlist", external.build_wordlist, per_app=True, phase=3, net=False),
        Stage("tech_enum", external.tech_enum, needs=("wordlist",), per_app=True, phase=3),
        Stage("content_discovery", external.content_discovery, needs=("wordlist", "tech_enum"),
              per_app=True, phase=3),
        Stage("recrawl", external.recrawl, needs=("content_discovery",), per_app=True, phase=3),
        Stage("cloud_assets", external.cloud_assets, per_app=True, phase=3),  # S3/GCS/Azure exposure
        # ── LOOP 4 — DAST the guessed surface ────────────────────────────────────────────────────────
        Stage("request_catalog_full", external.request_catalog_full, per_app=True, phase=4, net=False),
        Stage("param_fuzz", external.param_fuzz, needs=("request_catalog_full",), per_app=True, phase=4),
        Stage("dast_full", external.dast_full, needs=("request_catalog_full", "param_fuzz"),
              per_app=True, phase=4),
        Stage("xss_full", external.xss_full, needs=("request_catalog_full", "param_fuzz"),
              per_app=True, phase=4),
        Stage("sqli_full", external.sqli_full, needs=("request_catalog_full", "param_fuzz"),
              per_app=True, phase=4),
        Stage("cve_lookup_full", external.cve_lookup_full, per_app=True, phase=4, net=False),
        Stage("tech_vulnscan", external.tech_vulnscan, per_app=True, phase=4),
        *(_AI_STAGES if _AI else ()),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return external.cluster(activity)

    def consolidate(self, activity: Activity) -> dict[str, int]:
        return external.consolidate(activity)

    def preflight(self) -> None:
        external.preflight()

    def requirements(self) -> list[Requirement]:
        """Host requirement manifest for `ptflow doctor`, NARROWED to webscan's depth toolchain: only
        `_DEPTH_CORE` (httpx/katana/feroxbuster/nuclei) stay CORE — the loops fail without them —
        while external's breadth/OSINT tools are demoted to optional so a webscan-only host doesn't
        FAIL for tools webscan never runs. Same coverage as external, reclassified (nothing dropped);
        datasets keep their kind (already optional)."""
        return [
            replace(r, kind="core" if r.name in _DEPTH_CORE else "optional")
            if r.category == "tool" else r
            for r in external.requirements()
        ]

    def flowmap_spec(self) -> MapSpec:
        """Flow-map metadata for the doc generator (duck-typed hook; see core/flowdocs.py). Lazy
        import keeps the doc-only prose off the normal run's import path."""
        from ptflow.pipelines.webscan.flowmeta import SPEC  # noqa: PLC0415

        return SPEC

    def provider(self) -> HypothesisProvider:
        return ai.LLMHypothesisProvider() if _AI and stage_enabled("triage") else StubProvider()

    def report(self, activity: Activity) -> None:
        """Write the optional evidence-grounded AI report using external's shared implementation."""
        ai.report(activity)


PIPELINE = WebscanPipeline()
