"""Webscan pipeline flow-map metadata.

webscan runs external's web-DEPTH task functions unchanged, so its per-step prose IS external's
`FLOWMETA` — we only add the one webscan-only step (`ingest`, which replaces external's whole breadth)
and give the map its own title/thesis. The pivot (cluster) and terminal fan-in (consolidate) are the
same as external's, so we reuse external's structural nodes and phase labels verbatim.

The pipeline exposes `SPEC` via its `flowmap_spec()` hook; `ptflow.core.flowdocs` renders the three
`docs/webscan-pipeline-*` views. Add a `StepMeta` here only when webscan gains a step external lacks.

Regenerate manually:  uv run python -m ptflow.core.flowdocs
"""

from __future__ import annotations

from ptflow.core.flowmap import MapSpec, StepMeta
from ptflow.pipelines.external import flowmeta as _ext

FLOWMETA: dict[str, StepMeta] = {
    **_ext.FLOWMETA,
    # the ONLY webscan-specific step — it stands in for external's entire breadth
    # (expand/subdomain_bruteforce/resolve/
    # portscan/httpx): httpx over a pre-aggregated web-target list, honouring the input scheme.
    "ingest": StepMeta(
        summary="BREADTH (minimale) — httpx sulla lista di target web PRE-AGGREGATA, ONORANDO lo scheme "
                "di input (-nfs): niente expansion/OSINT/scan di rete, solo il fingerprint dei target dati. "
                "Produce lo stesso httpx_full_metadata.jsonl che cluster()/i loop di external consumano.",
        commands=("httpx -nfs -sc -cl -td -title -ip -hash sha256 -favicon -location -fr -irh -j",
                  "# -nfs (no-fallback-scheme): rispetta http/https + porta ESPLICITI di ogni target"),
        outputs=("httpx_full_metadata.jsonl", "unique_webapps.txt"),
        notes=("input = <internal-activity>/web_targets.txt (o qualsiasi lista scheme://host[:port])",
               "-nfs è l'inverso del default-https della discovery external: qui ogni target ha scheme+porta",
               "gli stage di expansion/OSINT/scan di rete sono ASSENTI → i read tolleranti di external degradano puliti"),
    ),
}

SPEC = MapSpec(
    title="ptflow · pipeline webscan",
    thesis="Le loop di web-DEPTH di external su una lista di target web PRE-AGGREGATA "
           "(scheme://host[:port]): salta scope expansion, scan di rete attivo e OSINT per-app. Un solo "
           "step di breadth (ingest: httpx che onora lo scheme), poi crawl → catalogo → DAST → fuzz "
           "identici a external (ne riusa le funzioni immutate). È il profilo 'external web' a cui la "
           "pipeline internal fa hand-off. Ogni stage comunica solo via file su disco.",
    steps=FLOWMETA,
    phase_labels=_ext.SPEC.phase_labels,
    pivot=_ext.SPEC.pivot,
    fanin=_ext.SPEC.fanin,
)
