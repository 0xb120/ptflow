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
from pipt.core.mermaidmap import render_html, render_markdown
from pipt.pipelines.recon.pipeline import PIPELINE

log = get_logger()

FLOWMETA: dict[str, StepMeta] = {
    # --- breadth (activity scope) ---
    "provision_wl": StepMeta(
        summary="Risolve i ruoli di wordlist globale (content/an_directories/an_php·aspx·jsp/an_txt·xml/"
                "mn_php·phpmillion·html/params/CMS) → wl_global/. Ordine: BYO (file già presente) > env "
                "PIPT_WL_<ROLE> > discovery in PIPT_WORDLISTS/SecLists.",
        commands=("# wordlists.provision() — un symlink wl_global/<role>.txt per ruolo risolto",),
        outputs=("wl_global/<role>.txt",),
        notes=("offline, gira ∥ a expand · ruolo non risolto ⇒ lo step a valle degrada su wl_custom",),
    ),
    "expand": StepMeta(
        summary="Espande lo scope: split per tipo, espande i CIDR, harvest TLS-SAN + PTR, enum wildcard.",
        commands=(
            "mapcidr -silent                                  # espande i CIDR",
            "naabu -top-ports 1000 -exclude-cdn -c 50 -rate 1000   # porte per harvest TLS (rate=profilo)",
            "tlsx -san -cn -resp-only  →  dnsx -silent        # nomi dai cert → risolti",
            "dnsx -ptr -resp-only                             # PTR sugli IP",
            "assetfinder -subs-only    subfinder -silent      # enum delle wildcard",
        ),
        outputs=("scope/scope_urls.txt", "scope/scope_ip.txt", "tls_names.txt", "scope/scope_dns.txt"),
    ),
    "resolve": StepMeta(
        summary="Risolve i candidati DNS a subdomini live e consolida gli IP (+ mappa dominio→IP).",
        commands=(
            "shuffledns -mode resolve -r resolvers-trusted    # fallback: dnsx -silent",
            "dnsx -a -resp-only -silent                       # → unique_ips",
            "dnsx -a -resp -nc -silent                        # → domain_ip_map",
        ),
        outputs=("subdomains.txt", "unique_ips.txt", "domain_ip_map.txt"),
    ),
    "portscan": StepMeta(
        summary="Scan VELOCE su ~250 porte WEB curate (WEB_PORTS) → filtro honeypot → naabu_web.txt "
                "(il set che legge httpx). Il full-port è spanning (portscan_full), fuori dal percorso critico.",
        commands=("naabu -p <~250 WEB_PORTS> -exclude-cdn -c 50 -rate 1000   # rate=profilo",
                  "# → honeypot_split (≥15 porte aperte = honeypot) + select_web_ports"),
        outputs=("honeypots.txt", "naabu_web.txt"),
    ),
    "portscan_full": StepMeta(
        summary="SPANNING — scan full 65535 porte sugli IP validi (non-honeypot) → naabu_full.txt "
                "(alimenta nerva). Gira ∥ cluster + loop, joinato al fan-in: il full-port non blocca la breadth.",
        commands=("naabu -top-ports full -exclude-cdn -c 50 -rate 1000   # rate=profilo",),
        outputs=("naabu_full.txt",),
    ),
    "httpx": StepMeta(
        summary="Fingerprint HTTP + segnali per il cluster (favicon, body-hash, redirect-final, header). "
                "Scope hygiene: scarta le probe by-IP di infra CDN/cloud/WAF (tiene gli hostname).",
        commands=("httpx -sc -cl -td -title -ip -hash sha256",
                  "      -favicon -location -fr -irh -j",
                  "split_cdn_ip_records → drop bare-IP CDN/cloud/WAF (→ excluded_cdn.jsonl)"),
        outputs=("httpx_full_metadata.jsonl", "unique_webapps.txt", "excluded_cdn.jsonl"),
        notes=("legge solo il set web veloce (naabu_web.txt) — il full-port è spanning",
               "httpx ignora lo scheme di input (default https): lo scheme esplicito di scope viene "
               "ri-applicato dal cluster (vedi pivot)"),
    ),
    "nerva": StepMeta(
        summary="Fingerprint dei servizi non-HTTP (SPANNING, dopo portscan_full, ∥ cluster + loop).",
        commands=("nerva --json",),
        outputs=("nerva_full_metadata.jsonl",),
    ),
    # --- spanning ---
    "nuclei_scope": StepMeta(
        summary="Un processo full-template su tutto lo scope deduplicato (subdomains + webapps), un "
                "solo rate-limit globale — più gentile del per-app sui backend condivisi.",
        commands=("nuclei -ut                              # aggiorna i template, poi:",
                  "nuclei -stats -nmhe -c 25 -bs 25 -rl 150 -timeout 10 -retries 2 -j -silent -duc"),
        outputs=("findings/nuclei_scope.jsonl",),
        notes=("-c / -rl = profilo (wide 25/150 · home 10/50) · subsume il vecchio scan takeover per-tag",),
    ),
    # --- post-cluster ∥ ---
    "screenshot": StepMeta(
        summary="Post-cluster, UNA run su 1 candidato/gruppo → screenshot + fingerprint (status/title/"
                "server/tech/header, stile EyeWitness) → dashboard unica nativa (httpx ∥ EyeWitness).",
        commands=("httpx -ss -system-chrome -no-screenshot-full-page -st 20 -srd <screenshots> -svrc",
                  "      -sc -cl -title -td -server -ip -favicon -location -irh -j   # fingerprint (-j)",
                  "eyewitness --web -f <1 url/gruppo> -d <out> --no-prompt --timeout 15   # opzionale"),
        outputs=("screenshots/screenshot/screenshot.html", "screenshots/screenshot/fingerprints.jsonl",
                 "scans/<app_id>/screenshot.png", "scans/<app_id>/screenshot.json", "default_creds.jsonl"),
        notes=("riconciliazione per URL (index_screenshot.txt / -j url / Requests.csv) → shot+fingerprint al suo gruppo",
               "fingerprint per-gruppo in screenshot.json (status/title/server/tech/header_signals)",
               "batch: 1 avvio EyeWitness invece di N (gira ∥ ai per-app loop) · default-cred = lead, non login verificato"),
    ),
    # --- PHASE 1: explorable surface (OSINT + crawl, NO guessing) ---
    "passive_probe": StepMeta(
        summary="URL discovery passiva/OSINT sui domini del gruppo (su TUTTI gli host).",
        commands=("gau --threads 5     urlfinder -silent",),
        outputs=("endpoints_passive.txt",),
    ),
    "crawl": StepMeta(
        summary="katana ∥ crawley (TIER 0, niente browser). katana è il downloader (-srd) + classifica "
                "se l'app è JS-rendered; crawley è un 2° motore di discovery. Host deduplicati per body.",
        commands=("katana -j -jc -jsl -kf all -fx -xhr -pc -fs fqdn -d 3 -c 2 -omit-body -srd responses/ [-H auth]",
                  "crawley -headless -depth 3 -workers 15 -all -js -robots crawl   # per host",
                  "# classify: <a href> raw + crawley vs fx-parsato (+ thin-shell) → crawl_class.json",
                  "# parse_katana_requests → requests_crawl.jsonl (method/body/form/xhr, non solo URL)"),
        outputs=("endpoints.txt", "endpoints_crawley.txt", "crawl_class.json", "responses/",
                 "requests_crawl.jsonl"),
        notes=("-headless di crawley = salta la HEAD pre-flight, NON è un browser",
               "crawley non scarica i body → le sue URL diventano candidate per fetch_delta",
               "-omit-raw OFF + -fx/-xhr: tiene metodo/body/form/xhr nel catalogo richieste (DAST POST/JSON)",
               "auth passthrough: PIPT_HTTP_HEADER → katana -H (raggiunge la superficie autenticata)"),
    ),
    "crawl_headless": StepMeta(
        summary="TIER 1 headless (katana -hl, chromium rod) — SOLO sul bucket JS-rendered (gate da "
                "crawl_class.json). Rende la SPA ed estrae rotte JS + XHR/fetch irraggiungibili dal link-crawl.",
        commands=("katana -hl -nos -jc -jsl -xhr -fx -iqp -fs fqdn -d 3 -c 5 -ct 180 -rl 50 -srd responses/headless/ [-H auth]",
                  "# parse_katana_requests → requests_headless.jsonl (XHR/fetch POST/JSON della SPA)"),
        outputs=("endpoints_headless.txt", "responses/headless/", "requests_headless.jsonl"),
        notes=("RAM 1-5 GB/host → max 2 processi headless concorrenti (semaforo process-wide) · -aff OFF",
               "le chiamate XHR/fetch (spesso POST/JSON) entrano nel catalogo richieste — il fuzzer GET-only le perde"),
    ),
    "subenum": StepMeta(
        summary="Enum passiva sugli apex scoperti del gruppo, filtrata live (su TUTTI gli host, alimenta takeover).",
        commands=("subfinder -silent     dnsx -silent",),
        outputs=("subs.txt",),
    ),
    "takeover": StepMeta(
        summary="Subdomain takeover su hosts + endpoint + subs (su TUTTI gli host).",
        commands=("subjack -w <candidates> -t 100 -timeout 30 -ssl",),
        outputs=("takeover.txt",),
    ),
    "fetch_delta": StepMeta(
        summary="Scarica nello store SOLO il delta (passive + crawley) non già preso da katana — 'fetch once'.",
        commands=("httpx -srd responses/osint/ -rl 50   # passive_delta = sorgenti - responses/index",),
        outputs=("responses/osint/",),
    ),
    "api_spec": StepMeta(
        summary="Scopre spec API (OpenAPI/Swagger JSON) + endpoint GraphQL e li espande in richieste "
                "COMPLETE (metodo+body+param) → requests_api.jsonl. È la superficie API che crawler e "
                "fuzzer GET non vedono; confluisce nel catalogo via request_catalog.",
        commands=(
            "httpx -srd store/ -mc 200   # sonda ~10 path spec noti (/openapi.json, /swagger.json, /v3/api-docs…)",
            "# expand_openapi: ogni operazione (path x metodo) → richiesta (path-param '1', query/header,",
            "#   requestBody/in:body → skeleton JSON|urlencoded), cap API_SPEC_MAX_OPS=300",
            "httpx -mc 200,400,405      # endpoint GraphQL → richiesta POST-json ({query:{__typename}})",
        ),
        outputs=("requests_api.jsonl",),
        notes=("best-effort: nessuna spec → file vuoto · gestisce OpenAPI v3 (servers/requestBody) e Swagger v2 (basePath/in:body)",
               "auth passthrough PIPT_HTTP_HEADER → httpx -H · ∥ al resto della FASE 1 (legge gli host, niente needs)"),
    ),
    "mine_responses": StepMeta(
        summary="Estrae i body dello store (idempotente) e mina SOLO endpoint col jsluice — semina il "
                "round 0 di content_discovery (FASE 3) e prepara il corpus per il catalogo di superficie.",
        commands=("jsluice urls <js dello store>   # raw/extracted/ esteso → endpoints_js.txt",),
        outputs=("endpoints_js.txt",),
        notes=("il fleet segreti NON gira qui — è in coda al fixpoint di content_discovery (vede anche i body fuzzati)",
               "l'estrazione raw/extracted/ serve a request_catalog per minare le shape POST/form/XHR del corpus"),
    ),
    "request_catalog": StepMeta(
        summary="FASE 1 (coda) — assembla il CATALOGO della SUPERFICIE ESPLORABILE (requests.jsonl): "
                "richieste COMPLETE (metodo/body/json/header, non solo URL). Merge di crawl/headless "
                "(form/xhr) + API spec + SHAPE minati dal corpus crawlato + sorgenti URL-only come GET. "
                "NIENTE superficie indovinata (content_discovery/recrawl girano in FASE 3).",
        commands=(
            "# 1) record richiesta: requests_crawl + requests_headless + requests_api",
            "# 2) SHAPE minati offline dal corpus crawl (fetch once — i body sono già su disco):",
            "#    jsluice_requests(JS) → metodo/contentType/bodyParams di fetch/XHR · html_form_requests(HTML)",
            "#    → form POST/GET; url relative risolte sull'URL sorgente del body (stem→url dagli index -srd)",
            "# 3) endpoint URL-only come GET di fallback · scheme raggiungibile (_working_schemes) · in-scope",
            "# dedup per shape (request_key = metodo + path-template) → merge_requests",
            "# 4) DROP delle shape GET il cui path il corpus ha visto SOLO come 404/410 (dead_url_keys)",
        ),
        outputs=("requests.jsonl",),
        notes=("offline (net=False) · needs crawl_headless/mine_responses/api_spec → record + corpus pronti",
               "raw HTTP/1.1 = path + Host (scheme-agnostic) → nuclei -im jsonl lo fuzza su ogni part",
               "dead-drop: URL passive/archive malformati + rotte JS fantasma che danno 404 NON entrano "
               "(GET-only/body-less: una shape POST/form/XHR scoperta resta sempre)",
               "input full-request del DAST di FASE 2 (frutti bassi) — sblocca POST/JSON/body"),
    ),
    # --- PHASE 2: DAST the explorable surface (low-hanging fruit) ---
    "dast": StepMeta(
        summary="FASE 2 — DAST della SUPERFICIE ESPLORABILE (frutti bassi): nuclei -dast sul catalogo "
                "superficie (requests.jsonl), fuzzando i parametri OSSERVATI (query/body/form/xhr che il "
                "crawl ha visto). Findings veloci ad alto segnale PRIMA del fuzzing pesante; niente "
                "scoperta di param nascosti (è guessing → FASE 4).",
        commands=(
            "# input: requests.jsonl (parametri osservati), dedup per shape, cap DAST_MAX_REQUESTS=1500",
            "#   → raw/dast/input.jsonl ({request:{endpoint,raw}})",
            "nuclei -dast -im jsonl -l input.jsonl -t <dast templates> -fa low -rl <profilo> -c <profilo>",
            "       -timeout 10 -retries 2 -j -silent -duc [-H auth]",
            "# dedup_dast_findings: 1 record per (template, host, path, fuzz position) — collassa i re-fire",
            "#   dello stesso punto di iniezione (varianti sintetizzate, http+https) su UN solo finding",
        ),
        outputs=("findings/dast.jsonl",),
        notes=(
            "nuclei costruisce la richiesta fuzzata dal campo `raw` → metodo/body/header arbitrari (POST/JSON)",
            "legge requests.jsonl oltre la barriera (FASE 1) · best-effort: salta se manca nuclei o i template dast",
            "-fa low = payload contenuti (politeness live) · il full-template whole-scope è nuclei_scope (breadth)",
            "dedup per punto-di-iniezione: niente conteggio gonfiato (lo stesso template su N varianti = 1)",
        ),
    ),
    "cve_lookup": StepMeta(
        summary="FASE 2 — CVE NOTE sui software ENUMERATI della superficie esplorabile (∥ dast). "
                "Correlazione OFFLINE (net=False, zero traffico): web server + tech wappalyzer + banner "
                "servizi non-HTTP (nerva) + librerie minate dal corpus crawl → DB locale search_vulns. "
                "Solo version-pinned.",
        commands=(
            "# software = collect_software(tech, Server header, banner nerva, lib del corpus) — solo con versione",
            "search_vulns -q '<Prodotto Versione>' -f json --ignore-general-product-vulns --use-created-product-ids",
            "# --use-created-product-ids: product ID alla versione ESATTA (no ladder) · cache memo process-wide · offline DB locale",
        ),
        outputs=("findings/cve.jsonl", "raw/cve/seen.txt"),
        notes=(
            "DB costruito FUORI dal run (search_vulns -u) · best-effort: salta se binario/DB assenti",
            "record: cve · cvss · epss · cisa_kev · exploits · cwe · hosts · sources — ordinati per triage (exploited/KEV first)",
            "seen.txt = coppie (prodotto,versione) coperte → la passata FASE 4 fa solo il delta",
            "override binario: PIPT_SEARCH_VULNS · normalizzazione versione (lezione 6.6.1p1) · search_vulns fa lui il check dei range",
        ),
    ),
    # --- PHASE 3: guessing / surface expansion ---
    "wordlist": StepMeta(
        summary="Estrattore di LESSICO offline (fuzzing-prep): mina sia i link crawlati sia i body "
                "scaricati (raw/extracted/) in prodotti per-app. Legge il corpus di FASE 1 oltre la "
                "barriera (raw/extracted/ già estratto da mine_responses — legge, non ri-estrae). Solo "
                "token app (le liste global/tech le aggiunge content_discovery).",
        commands=("tokenize_urls(endpoints + headless + js)            # → seed.txt",
                  "extract_param_names(query keys + jsluice q/bodyParams + form name= + JSON keys)  # → params.txt",
                  "extract_value_words(query values + app-name + tech/header + apex)                # → values.txt",
                  "extract_identities(email regex + mailto + local-part + campi user/owner/…)       # → identities.txt"),
        outputs=("wl_custom/seed.txt", "wl_custom/params.txt", "wl_custom/values.txt",
                 "wl_custom/identities.txt"),
        notes=("params.txt → consumato da param_fuzz (custom-first + ruolo `params`)",
               "values.txt / identities.txt = deliverable per la futura DAST (nessun consumer ora)",
               "filtri precision-first: drop numerici/opachi (hash/uuid/base64), denylist tracking, no PII fittizia"),
    ),
    "tech_enum": StepMeta(
        summary="Scanner per-stack (dispatch keyed su tech): superficie che alimenta l'enum + finding se "
                "dual-role. Oggi shortscan (IIS/ASP.NET 8.3 short-name).",
        commands=("shortutil wordlist <seed + global content> > rainbow.txt",
                  "shortscan -o json -a auto -w rainbow.txt -c 20 @hosts"),
        outputs=("wl_custom/shortnames.txt", "findings/tilde_enum.jsonl"),
        notes=("dispatch best-effort: gira solo se tech ∈ {iis, asp.net} E il binario c'è",
               "shortscan è dual-role: superficie (shortnames) + finding IIS tilde → findings/tilde_enum.jsonl"),
    ),
    "content_discovery": StepMeta(
        summary="Forced browsing come FIXPOINT: fuzz → download → mine → fuzz il delta di token, poi il "
                "secret fleet una volta. Host deduplicati per body. Chiude il loop che la ricorsione "
                "(link-only) di feroxbuster non copre.",
        commands=(
            "# Pass A round 0 (wordlist STAGED: build_content_wordlist):",
            "feroxbuster --smart -k -t 5 -L 2 -d 2 --timeout 15 --time-limit 20m -w round0.txt [-x exts]",
            "# feedback round (fuzza SOLO i token NUOVI):",
            "feroxbuster --smart … --time-limit 5m -w round<r>.txt",
            "httpx -srd responses/discovered/round<r>/ -rl 50   # scarica i nuovi hit 2xx/3xx",
            "jsluice urls <new-js>                              # mina → cresce la frontiera",
            "# stage 3 deep dive (OPT-IN PIPT_DEEP_DIVE, solo host high-value):",
            "feroxbuster --smart … -d 3 --time-limit 30m -w deepdive<i>.txt   # mn_php/mn_phpmillion/mn_html",
            "# poi UNA volta sul corpus completo, secret fleet ∥:",
            "jsluice secrets ∥ gitleaks ∥ trufflehog --results=verified ∥ detect-secrets",
        ),
        outputs=("content_discovery.jsonl", "secrets.jsonl", "responses/discovered/round*/"),
        notes=(
            "Pass A wordlist STAGED = custom(full) + 0:olfa_micro(full) + 1:an_directories(top 30k) + "
            "2:lista per-stack (top 30k, gated) + 2b:an_txt/an_xml(full)",
            "stage 2 per-stack (mai php su .NET): php→an_php · asp/.NET→an_aspx · java→an_jsp · "
            "node/next/python→an_apiroutes · client-side react/vue ignorati",
            "stage 3 DEEP DIVE: opt-in PIPT_DEEP_DIVE · per-stack manual full + recursion: php→mn_php(3M)+"
            "mn_phpmillion(1M) · asp→mn_aspx/asp/cfm · java→mn_jsp/do · sempre mn_html(4M) generico",
            "  gate deep: solo host con ≥50 hit Pass-A, max 2 host/app, budget 3600s, --time-limit 30m/host",
            "-t/-L = profilo (wide 5/2 · home 3/1) · round 0: --time-limit 20m · feedback: 5m",
            "fallback http: se feroxbuster non raggiunge nulla per TLS legacy (handshake rifiutato), ritenta su http",
            "stop fixpoint: wordlist-fixpoint · url-fixpoint · deadline 900s · diminishing <20 · round-cap 2",
            "mai rifuzzare un token (fuzzed) · mai riscaricare un URL (seen dagli index -srd)",
            "secret fleet UNA volta sul corpus completo → merge_secrets (sources + verified)",
        ),
    ),
    "recrawl": StepMeta(
        summary="Re-seed crawl LIMITATO: quando il fuzzing trova un entry point in territorio MAI "
                "crawlato (es. /debugging unlinked), ri-semina katana lì così la superficie linkata/"
                "renderizzata non si perde. PIPT_RECRAWL ∈ off|preview|on (default `on`; bound stretti).",
        commands=(
            "# select_recrawl_seeds: hit 2xx il cui PRIMO SEGMENTO di path nessun URL crawlato usa",
            "#   (covered = (host, primo-segmento) di endpoints.txt+headless+store) → 1 seed shallow/segmento nuovo",
            "# PIPT_RECRAWL: off | preview (scrive raw/recrawl/seeds.txt, NON crawla) | on (default: crawla)",
            "katana -jc -jsl -kf all -fx -xhr -fs fqdn -d 2 -c 2 -ct 120 -omit-body -srd responses/recrawl/ [-H auth]",
        ),
        outputs=("raw/recrawl/seeds.txt", "requests_recrawl.jsonl", "responses/recrawl/"),
        notes=("conservativo: solo regioni top-level nuove (un sotto-dir sotto una regione crawlata NON semina)",
               "bound anti-runaway: max RECRAWL_MAX_SEEDS=10 seed shallow, depth 2, -ct 120s, UN solo passaggio",
               "i body finiscono nel corpus → request_catalog ne mina gli shape (nessun codice di mining nuovo)",
               "preview per rivedere i seed senza crawlare; `on` (default) crawla"),
    ),
    # --- PHASE 4: DAST the guessed surface (detailed) ---
    "request_catalog_full": StepMeta(
        summary="FASE 4 (testa) — ricostruisce il catalogo INCLUDENDO la superficie indovinata → "
                "requests_full.jsonl. Stesso assembly di request_catalog ma aggiunge i record recrawl + "
                "gli hit 2xx di content_discovery + le SHAPE minate dal corpus ora esteso "
                "(responses/discovered/, responses/recrawl/ — ri-estratto idempotente).",
        commands=(
            "# _assemble_catalog(include_guessed=True): requests_crawl/headless/api + requests_recrawl",
            "#   + shape minati dal corpus completo + endpoint URL-only (incl. content_discovery 2xx) come GET",
            "# dedup per shape (request_key = metodo + path-template) → merge_requests · scheme raggiungibile · in-scope",
            "# DROP delle shape GET dead/404 (dead_url_keys, sul corpus ora esteso da content_discovery/recrawl)",
        ),
        outputs=("requests_full.jsonl",),
        notes=("offline (net=False) · legge FASE 1 + FASE 3 oltre le barriere → vede il corpus COMPLETO",
               "raw HTTP/1.1 = path + Host (scheme-agnostic) → nuclei -im jsonl lo fuzza su ogni part",
               "dead-drop GET-only/body-less come request_catalog (qui anche gli hit del corpus indovinato)",
               "alimenta param_fuzz + dast_full (la ricerca dettagliata)"),
    ),
    "param_fuzz": StepMeta(
        summary="FASE 4 — scoperta parametri nascosti su TUTTE le location (query · body · json · header), "
                "non solo GET. Legge il catalogo COMPLETO (requests_full.jsonl) → sonda anche gli endpoint "
                "trovati fuzzando; arjun (-m GET/POST/JSON) ∥ x8 (-X/--data-type/--headers).",
        commands=(
            "# query: ogni shape (dedup path-template, cap 50) · body+json: endpoint con body (form/xhr/POST,",
            "#   cap 25, + probe sui GET) · header: subset (cap 15, solo x8). wordlist params custom-first.",
            "arjun -i targets_<loc>.txt -oJ <loc>.json -m GET|POST|JSON -t 5 -T 15 --rate-limit 20 -q [--headers auth]",
            "x8 -u targets_<loc>.txt -w params -O json -o <loc>.json [-X POST] [-t json] [--headers] [-H auth]",
            "# matrice (tool, location) in un pool cappato (PARAM_FANOUT=3); cap wall-clock per-tool 600s",
            "# collapse_global_params: un param trovato su ≥75% degli endpoint testati (≥5) = riflesso",
            "#   SITE-WIDE → 1 record host-level {scope:site-wide}, non sprayato su ogni endpoint",
        ),
        outputs=("params.jsonl",),
        notes=(
            "merge per (url, param, LOCATION) → params.jsonl: query≠body sono punti d'iniezione distinti",
            "arjun -m: query→GET · body→POST · json→JSON (niente modo header → header solo x8)",
            "body/json mirati dove il crawl ha visto un body; + probe POST sui GET (param nascosti)",
            "collapse site-wide: param riflesso ovunque (es. ginandjuice echo `?category=` in Set-Cookie su "
            "ogni path) → x8 lo trova su tutti gli endpoint; collassato a 1 invece di gonfiare DAST",
            "url già allo scheme raggiungibile (lo fa request_catalog) · politeness: rate/worker bassi",
            "auth passthrough PIPT_HTTP_HEADER → arjun --headers (newline-join) · x8 -H (ripetuto)",
        ),
    ),
    "dast_full": StepMeta(
        summary="FASE 4 — DAST della SUPERFICIE INDOVINATA (ricerca dettagliata): per non ripetere la "
                "FASE 2, fuzza solo il DELTA (le shape in requests_full non già in requests, per "
                "request_key) + le richieste sintetizzate dai param nascosti (params.jsonl) — nuovi punti "
                "d'iniezione anche su un endpoint della superficie. nuclei -dast fuzza query/path/header/cookie/BODY.",
        commands=(
            "# delta = shape in requests_full.jsonl NON già in requests.jsonl (request_key) + build_fuzz_requests(params)",
            "#   dedup per shape, cap DAST_MAX_REQUESTS=1500 → raw/dast/input_full.jsonl ({request:{endpoint,raw}})",
            "nuclei -dast -im jsonl -l input_full.jsonl -t <dast templates> -fa low -rl <profilo> -c <profilo>",
            "       -timeout 10 -retries 2 -j -silent -duc [-H auth]",
            "# dedup_dast_findings: 1 record per (template, host, path, fuzz position), come in dast",
        ),
        outputs=("findings/dast_full.jsonl",),
        notes=(
            "nuclei costruisce la richiesta fuzzata dal campo `raw` → metodo/body/header arbitrari (POST/JSON)",
            "param scoperti iniettati in richieste concrete (build_fuzz_requests): query/body/json/header",
            "NON ri-DAST-a la superficie già coperta in FASE 2 · best-effort: salta se manca nuclei o i template dast",
            "dedup per punto-di-iniezione (il delta è path-disgiunto dalla superficie → niente dup cross-fase)",
            "il full-template whole-scope è nuclei_scope (breadth) · per-app findings → consolidate (pianificato)",
        ),
    ),
    "cve_lookup_full": StepMeta(
        summary="FASE 4 — CVE NOTE sull'enumerazione ESPANSA (∥ dast_full). Il crawl di FASE 3 "
                "(content_discovery/recrawl) fa crescere il corpus, quindi ri-mina le librerie e riporta "
                "solo il DELTA: software non già coperto dalla passata di FASE 2 (raw/cve/seen.txt).",
        commands=(
            "# stessa correlazione offline di cve_lookup, sul corpus ora esteso",
            "search_vulns -q '<Prodotto Versione>' -f json --ignore-general-product-vulns",
            "# delta = (prodotto,versione) NON in raw/cve/seen.txt · cache memo condivisa con la passata FASE 2",
        ),
        outputs=("findings/cve_full.jsonl",),
        notes=("offline (net=False) · best-effort: salta se search_vulns/DB assenti",
               "vede le librerie scaricate fuzzando (responses/discovered, recrawl) che la FASE 2 non aveva",
               "per-app findings → consolidate (fan-in terminale)"),
    ),
    "tech_vulnscan": StepMeta(
        summary="FASE 4 (findings) — scanner per-stack FINDINGS-only, gated sulla tech rilevata (il "
                "duale di tech_enum che invece alimenta l'enum). Oggi: wpprobe (plugin/theme WordPress "
                "→ CVE note via DB Wordfence locale) SOLO sui gruppi WordPress. ∥ al resto del loop 4.",
        commands=(
            "# gate: meta.tech contiene 'wordpress' (match a parola intera) · 1 scan stealthy per host (-body-dedup)",
            "wpprobe scan -u <host> -o raw/wpprobe/scanN.json --rate-limit 20 -t 5 [-H <auth>]",
            "# parse_wpprobe: un finding per (componente,versione,CVE) · ordinati per severità/CVSS",
        ),
        outputs=("findings/wpprobe.jsonl",),
        notes=("best-effort: salta se wpprobe assente o tech ≠ wordpress · DB out-of-band (wpprobe update-db)",
               "cap wall-clock per-host (WPPROBE_TIMEOUT) · auth passthrough (PIPT_HTTP_HEADER)",
               "per-app findings → consolidate (fan-in terminale)"),
    ),
}

_PIVOT = StepMeta(
    summary="Union-find su segnali di APP-IDENTITY (redirect-final · body-hash · favicon/fingerprint "
            "apex-scoped), MAI infrastruttura — precision-first: un duplicato scansionato due volte è "
            "meglio di due app fuse. app_id = <slug>-<hash8> stabile. Lo scheme esplicito di scope viene "
            "ri-applicato sugli host in output.",
    outputs=("meta.json", "hosts.txt"),
    notes=("meta.json registra body_by_host + headers_by_host + header_signals (cache/cdn/backend/stack/waf)",
           "gli scanner attivi deduplicano gli host per body (_scan_hosts); passive/subenum/takeover stanno su tutti"),
)
_FANIN = StepMeta(
    summary="Fan-in terminale DETERMINISTICO (consolidate): solleva i findings per-app in "
            "<activity>/findings/<tipo>.jsonl — un file per categoria, ogni record con app_id. cve e "
            "dast uniscono superficie (fase 2) + deep (fase 4); takeover.txt → record. nuclei_scope è "
            "già a livello activity. Il seam dell'agente (StubProvider) resta dormiente accanto.",
    outputs=("findings/cve.jsonl", "findings/dast.jsonl", "findings/tilde_enum.jsonl",
             "findings/wpprobe.jsonl", "findings/secrets.jsonl", "findings/takeover.jsonl",
             "findings/default_creds.jsonl", "findings/hypotheses.jsonl"),
)

SPEC = MapSpec(
    title="pipt · pipeline recon",
    thesis="Ogni stage comunica solo via file su disco. La breadth mappa l'intero scope, il cluster fa da "
           "pivot fan-out, poi i loop per-app vanno in profondità con una barriera globale tra loro: prima "
           "la SUPERFICIE ESPLORABILE (OSINT/crawl) e il suo DAST (frutti bassi), poi il guessing/fuzzing "
           "(fixpoint di content discovery: fuzz → download → mine → fuzz) e il DAST della superficie indovinata.",
    steps=FLOWMETA,
    phase_labels={1: "surface recon", 2: "DAST surface", 3: "fuzzing/guessing", 4: "DAST deep"},
    pivot=("scans/<app_id>/", _PIVOT),
    fanin=("consolidate", _FANIN),
)

# docs/pipeline-flow.html at the repo root (flowmeta.py is src/pipt/pipelines/recon/ → parents[4]).
_DEFAULT_OUT = Path(__file__).resolve().parents[4] / "docs" / "pipeline-flow.html"


def main(out: str | None = None) -> None:
    """Render the recon flow artifacts (all deterministic) into the docs dir of `out`:
    `pipeline-flow.html` (the detailed band spec sheet — `out` itself, default that path) plus the
    code-derived companions `pipeline-map.html` (pan/zoom flowchart) and `pipeline-map.md`."""
    dest = Path(out) if out else _DEFAULT_OUT
    docs = dest.parent
    docs.mkdir(parents=True, exist_ok=True)
    dest.write_text(render(PIPELINE.stages, SPEC), encoding="utf-8")
    (docs / "pipeline-map.html").write_text(render_html(PIPELINE.stages, SPEC), encoding="utf-8")
    (docs / "pipeline-map.md").write_text(render_markdown(PIPELINE.stages, SPEC), encoding="utf-8")
    log.info("flow map + concept map → %s (%d stages)", docs, len(PIPELINE.stages))


if __name__ == "__main__":
    main()
