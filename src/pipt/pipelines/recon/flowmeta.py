"""Recon flow-map metadata + the generator entrypoint.

`FLOWMETA` is the per-step description (summary/commands/outputs/notes) the generic renderer
(`pipt.core.flowmap`) can't derive from the Stage objects; `SPEC` bundles it with the titles, phase
labels and the two non-Stage structural nodes (cluster pivot, agent fan-in). `main()` renders the
self-contained map to `docs/pipeline-flow.html`.

When you add or change a step in `pipeline.py`/`tasks.py`, add/adjust its `StepMeta` here — a test
(`tests/pipelines/test_flowmap.py`) fails the dev gate if any Stage is missing one, and a hook
regenerates `docs/pipeline-flow.html` whenever a file under `src/pipt/pipelines/` changes.

Run manually:  uv run python -m pipt.pipelines.recon.flowmeta
"""

from __future__ import annotations

from pathlib import Path

from pipt.core.flowmap import MapSpec, StepMeta, render
from pipt.core.log import get_logger
from pipt.pipelines.recon.pipeline import PIPELINE

log = get_logger()

FLOWMETA: dict[str, StepMeta] = {
    # --- breadth (activity scope) ---
    "provision_wl": StepMeta(
        summary="Risolve i ruoli di wordlist globale (content/wordpress/…) per env/discovery/BYO.",
        commands=("# wordlists.provision() — symlink per ruolo",),
        outputs=("wl_global/<role>.txt",),
    ),
    "expand": StepMeta(
        summary="Split per tipo, harvest TLS/PTR, enum wildcard.",
        commands=(
            "mapcidr -silent",
            "naabu -top-ports 1000 -exclude-cdn -rate 1000",
            "tlsx -san -cn -resp-only     dnsx -ptr -resp-only",
            "assetfinder -subs-only       subfinder -silent",
        ),
        outputs=("scope_urls.txt", "scope_ip.txt", "tls_names.txt", "scope_dns.txt"),
    ),
    "resolve": StepMeta(
        summary="Risolve i candidati a subdomini live; consolida gli IP.",
        commands=(
            "shuffledns -mode resolve -r resolvers-trusted   # fallback dnsx",
            "dnsx -a -resp-only -silent     dnsx -a -resp -nc",
        ),
        outputs=("subdomains.txt", "unique_ips.txt", "domain_ip_map.txt"),
    ),
    "portscan": StepMeta(
        summary="Scan VELOCE su ~250 porte WEB curate (WEB_PORTS) → filtro honeypot → naabu_web.txt "
                "(il set che legge httpx). Il full-port è spanning (portscan_full), fuori dal percorso critico.",
        commands=("naabu -p <250 porte web> -exclude-cdn   # → honeypot_split + select_web_ports",),
        outputs=("honeypots.txt", "naabu_web.txt"),
    ),
    "portscan_full": StepMeta(
        summary="SPANNING — scan full 65535 porte sugli IP validi → naabu_full.txt (alimenta nerva). "
                "Gira ∥ cluster + loop, joinato al fan-in: il full-port non blocca più la breadth.",
        commands=("naabu -top-ports full -exclude-cdn",),
        outputs=("naabu_full.txt",),
    ),
    "httpx": StepMeta(
        summary="Fingerprint HTTP + segnali per il cluster (favicon, body-hash, header). "
                "Scope hygiene: scarta le probe by-IP di infra CDN/cloud/WAF (tiene gli hostname).",
        commands=("httpx -sc -cl -td -title -ip -hash sha256",
                  "      -favicon -location -fr -irh -j",
                  "split_cdn_ip_records → drop bare-IP CDN/cloud/WAF (excluded_cdn.jsonl)"),
        outputs=("httpx_full_metadata.jsonl", "unique_webapps.txt", "excluded_cdn.jsonl"),
    ),
    "nerva": StepMeta(
        summary="Fingerprint dei servizi non-HTTP (SPANNING, dopo portscan_full, ∥ cluster + loop).",
        commands=("nerva --json",),
        outputs=("nerva_full_metadata.jsonl",),
    ),
    # --- spanning ---
    "nuclei_scope": StepMeta(
        summary="Un processo full-template su tutto lo scope deduplicato, un solo rate-limit globale.",
        commands=("nuclei -ut   # update templates, poi:",
                  "nuclei -c 25 -bs 25 -rl 150 -timeout 10 -retries 2 -j -silent -duc"),
        outputs=("findings/nuclei_scope.jsonl",),
    ),
    # --- loop 1: enumeration ---
    "screenshot": StepMeta(
        summary="Post-cluster, UNA run su 1 candidato/gruppo → screenshot + fingerprint (status/title/"
                "server/tech/header, stile EyeWitness) → dashboard unica nativa (httpx ∥ EyeWitness).",
        commands=("httpx -ss -system-chrome -srd <activity>/screenshots -svrc   # screenshot.html",
                  "      -sc -cl -title -td -server -ip -favicon -irh -j        # fingerprint (-j)",
                  "eyewitness --web -f <tutti gli url> --no-prompt   # report.html (opzionale)"),
        outputs=("screenshots/screenshot/screenshot.html", "screenshots/screenshot/fingerprints.jsonl",
                 "scans/<app_id>/screenshot.png", "scans/<app_id>/screenshot.json", "default_creds.jsonl"),
        notes=("riconciliazione per URL (index_screenshot.txt / -j url / Requests.csv) → shot+fingerprint al suo gruppo",
               "fingerprint per-gruppo in screenshot.json (status/title/server/tech/header_signals)",
               "batch: 1 avvio EyeWitness invece di N (gira ∥ ai per-app loop)"),
    ),
    "passive_probe": StepMeta(
        summary="URL discovery passiva (OSINT).",
        commands=("gau --threads 5     urlfinder -silent",),
        outputs=("endpoints_passive.txt",),
    ),
    "crawl": StepMeta(
        summary="katana ∥ crawley (TIER 0). katana è il downloader (-srd) + classifica se l'app è JS-rendered.",
        commands=("katana -jc -jsl -kf all -fx -pc -fs fqdn -d 3 -srd responses/",
                  "crawley -depth 3 -all -js -robots crawl   # per host"),
        outputs=("endpoints.txt", "endpoints_crawley.txt", "crawl_class.json", "responses/"),
    ),
    "crawl_headless": StepMeta(
        summary="TIER 1 headless — solo sul bucket JS-rendered. RAM-capped da semaforo process-wide.",
        commands=("katana -hl -nos -jc -jsl -xhr -fx -iqp -ct 180 -srd responses/headless/",),
        outputs=("endpoints_headless.txt", "responses/headless/"),
    ),
    "subenum": StepMeta(
        summary="Enum passiva sugli apex scoperti del gruppo, filtrata live.",
        commands=("subfinder -silent     dnsx -silent",),
        outputs=("subs.txt",),
    ),
    "takeover": StepMeta(
        summary="Subdomain takeover su hosts + endpoint + subs.",
        commands=("subjack -w <candidates> -t 100 -timeout 30 -ssl",),
        outputs=("takeover.txt",),
    ),
    # --- loop 2: content discovery ---
    "wordlist": StepMeta(
        summary="Tokenizza endpoints (+ headless) in segmenti/basename/param — SOLO token app (custom).",
        commands=("# tokenize_urls → seed.txt (le liste tech/global le aggiunge content_discovery)",),
        outputs=("wl_custom/seed.txt",),
    ),
    "fetch_delta": StepMeta(
        summary="Scarica solo il delta (passive + crawley) non già nello store.",
        commands=("httpx -srd responses/osint/ -rl 50   # passive_delta",),
        outputs=("responses/osint/",),
    ),
    "mine_responses": StepMeta(
        summary="Estrae i body (idempotente) e mina SOLO endpoint col jsluice — alimenta il round 0.",
        commands=("jsluice urls <js>   # → raw/extracted/ esteso",),
        outputs=("endpoints_js.txt",),
        notes=("il fleet segreti NON gira più qui — spostato in coda al fixpoint",),
    ),
    "tech_enum": StepMeta(
        summary="Scanner per-stack: superficie (oggi shortscan IIS 8.3) + finding se dual-role.",
        commands=("shortutil wordlist <rainbow>",
                  "shortscan -o json -a auto -w <rainbow> @hosts"),
        outputs=("wl_custom/shortnames.txt", "findings/tilde_enum.jsonl"),
        notes=("shortscan è dual-role: superficie (shortnames) + finding IIS tilde → findings/tilde_enum.jsonl",),
    ),
    "content_discovery": StepMeta(
        summary="Forced browsing come FIXPOINT: fuzz → download → mine → fuzz il delta di token, poi il secret fleet una volta.",
        commands=(
            "# round 0:",
            "feroxbuster --smart -t 5 -L 2 --time-limit 20m -w round0.txt",
            "# feedback round (solo token nuovi):",
            "feroxbuster --smart --time-limit 5m -w round<r>.txt",
            "httpx -srd responses/discovered/round<r>/ -rl 50",
            "jsluice urls <new-js>   # → grow frontier",
            "# poi UNA volta, secret fleet:",
            "jsluice secrets ∥ gitleaks ∥ trufflehog --results=verified ∥ detect-secrets",
        ),
        outputs=("content_discovery.jsonl", "secrets.jsonl", "responses/discovered/round*/"),
        notes=(
            "wordlist = custom (seed+shortnames+js) + tradizionale (global+tech), per MODE",
            "mode auto: corpus ricco → targeted (cappa la tradizionale) · povero → broad · PIPT_WL_MODE",
            "round 0: --time-limit 20m · feedback: --time-limit 5m",
            "stop: wordlist-fixpoint · url-fixpoint · deadline 900s · diminishing <20 · round-cap 2",
            "mai rifuzzare un token (fuzzed) · mai riscaricare un URL (seen dagli index -srd)",
            "secret fleet UNA volta sul corpus completo → merge_secrets",
        ),
    ),
    # --- loop 3: param discovery ---
    "param_fuzz": StepMeta(
        summary="Scoperta parametri nascosti (arjun ∥ x8) sugli endpoint enumerati → alimenta la DAST.",
        commands=(
            "# set endpoint deduplicato per path-template + cappato (PARAM_MAX_ENDPOINTS):",
            "arjun -i targets.txt -oJ out.json -w <params> -t 5 --rate-limit 20 -q",
            "x8 -u targets.txt -w <params> -O json -o out.json -W2 -c2 --one-worker-per-host",
            "# cap di wall-clock per-tool (PARAM_TOOL_TIMEOUT) → partial best-effort",
        ),
        outputs=("params.jsonl",),
        notes=(
            "arjun ∥ x8 (best-effort) → merge per (url, param) → params.jsonl",
            "solo GET per ora · politeness: rate/worker bassi, --one-worker-per-host",
            "x8 saltato se manca la wordlist ruolo `params`",
        ),
    ),
}

_PIVOT = StepMeta(
    summary="Union-find su segnali di app-identity (redirect-final · body-hash · favicon/fingerprint "
            "apex-scoped), precision-first — un duplicato scansionato due volte è meglio di due app fuse.",
    outputs=("meta.json", "hosts.txt"),
)
_FANIN = StepMeta(
    summary="Fan-in terminale: oggi StubProvider deterministico; diventerà un consolidate.",
    outputs=("findings/hypotheses.jsonl",),
)

SPEC = MapSpec(
    title="pipt · pipeline recon",
    thesis="Ogni stage comunica solo via file su disco. La breadth mappa l'intero scope, il cluster "
           "fa da pivot fan-out, poi i loop per-app vanno in profondità con una barriera globale tra "
           "loro — fino al fixpoint di content discovery: fuzz → download → mine → fuzz, finché converge.",
    steps=FLOWMETA,
    phase_labels={1: "enumeration", 2: "content discovery", 3: "param discovery"},
    pivot=("scans/<app_id>/", _PIVOT),
    fanin=("agent", _FANIN),
)

# docs/pipeline-flow.html at the repo root (flowmeta.py is src/pipt/pipelines/recon/ → parents[4]).
_DEFAULT_OUT = Path(__file__).resolve().parents[4] / "docs" / "pipeline-flow.html"


def main(out: str | None = None) -> None:
    """Render the recon flow map to `out` (default docs/pipeline-flow.html). Deterministic."""
    dest = Path(out) if out else _DEFAULT_OUT
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render(PIPELINE.stages, SPEC), encoding="utf-8")
    log.info("flow map → %s (%d stages)", dest, len(PIPELINE.stages))


if __name__ == "__main__":
    main()
