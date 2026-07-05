"""Real asset_discovery (breadth) — faithful port of scope2surface.sh.

Each tool's output is written ONCE. Intermediate steps that only feed later
steps go to asset_discovery/raw/<tool>/ (top-level, not under scans/; provenance). A tool whose output
IS a final artifact is written straight to its canonical name — no duplicate raw
copy. Derived artifacts (unique IPs, honeypots, unique webapps) are computed in
memory. Pure transforms are module-level so they can be unit-tested.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urljoin, urlsplit, urlunsplit

from ptflow.core import scope, tools, workspace
from ptflow.core.log import get_logger, is_verbose
from ptflow.core.requirements import Requirement, check
from ptflow.pipelines.external import wordlists

if TYPE_CHECKING:
    from ptflow.core.paths import Activity, AppWorkspace
    from ptflow.core.scope import Target

log = get_logger()


# --- rate profiles (PTFLOW_PROFILE, resolved at import — set it BEFORE launching) ---
# The aggregate network load is roughly concurrency x per-tool rate. A `net` concurrency cap alone
# doesn't bound it (the heavy hitters — the full-port naabu flood, nuclei -rl — are single stages),
# so the per-tool RATES are the real lever. Two profiles: `wide` (today's values, for real
# bandwidth) and `home` (gentle on a domestic line/router — naabu especially, the full-port packet
# flood that exhausts a consumer NAT/conntrack table).
@dataclass(frozen=True)
class Profile:
    name: str
    naabu_rate: str   # naabu -rate (packets/s) — the prime "clogs my router" knob (full-port flood)
    naabu_conc: str   # naabu -c
    nuclei_rl: str    # nuclei -rl (req/s, global)
    nuclei_conc: str  # nuclei -c (templates in parallel)
    ferox_threads: str       # feroxbuster -t
    ferox_scan_limit: str    # feroxbuster -L (concurrent dir scans)


WIDE = Profile(name="wide", naabu_rate="1000", naabu_conc="50", nuclei_rl="150", nuclei_conc="25",
               ferox_threads="5", ferox_scan_limit="2")
HOME = Profile(name="home", naabu_rate="300", naabu_conc="20", nuclei_rl="50", nuclei_conc="10",
               ferox_threads="3", ferox_scan_limit="1")
_PROFILES = {p.name: p for p in (WIDE, HOME)}


def _resolve_profile() -> Profile:
    """Active profile from env PTFLOW_PROFILE (default `wide`; unknown → `wide`). Read each call so it's
    testable; the module constants below bind it once at import (set PTFLOW_PROFILE before launching)."""
    return _PROFILES.get(os.environ.get("PTFLOW_PROFILE", "wide").lower().strip(), WIDE)


PROFILE = _resolve_profile()

# --- tunables (mirror scope2surface.sh; conservative — live infra) ---
NAABU_TLS_TOP_PORTS = "1000"
NAABU_RATE = PROFILE.naabu_rate   # applied to every naabu run (TLS harvest + web + full portscan)
NAABU_CONC = PROFILE.naabu_conc
HONEYPOT_MIN_OPEN_PORTS = 15      # >= this many open ports => suspected honeypot
RESOLVERS = "/opt/resolvers/resolvers-trusted.txt"

# Curated WEB ports for the FAST portscan (feeds httpx -> cluster). 250 distinct HTTP(S)-bearing
# ports: union of aquatone-xlarge, hosting-panels, 8xxx alt-HTTP, app/dev servers, data/ops UIs,
# containers, IoT/devices, proxies. NOT nmap's generic top-1k - so httpx sees web apps on uncommon
# ports (5601/8161/9200/7001/...) that top-1k misses, while staying fast. Non-web ports (SSH/DB/SMB/
# RDP) are deliberately absent - portscan_full (full 65535, spanning) + nerva cover those.
WEB_PORTS = (
    "80,81,82,83,84,85,86,87,88,89,90,280,300,443,591,593,631,777,832,880,888,981,1010,"
    "1024,1080,1311,2052,2053,2080,2082,2083,2086,2087,2095,2096,2222,2375,2376,2379,2380,"
    "2480,3000,3001,3002,3003,3030,3127,3128,3129,3333,4000,4040,4080,4200,4243,4443,4444,"
    "4445,4567,4643,4646,4711,4712,4848,4993,5000,5001,5002,5050,5080,5104,5108,5555,5601,"
    "5800,5984,5985,5986,6080,6082,6346,6347,6379,6443,6488,6543,6588,6660,6661,6662,7000,"
    "7001,7002,7070,7071,7080,7100,7200,7396,7443,7474,7547,7574,7676,7777,7778,7990,8000,"
    "8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8020,"
    "8030,8040,8042,8050,8051,8055,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,"
    "8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8102,8110,8118,"
    "8123,8161,8172,8180,8181,8190,8200,8201,8222,8243,8280,8281,8300,8333,8377,8400,8443,"
    "8444,8480,8500,8501,8510,8530,8531,8554,8585,8649,8666,8686,8688,8765,8787,8800,8834,"
    "8843,8866,8880,8888,8889,8899,8983,8990,8991,8995,9000,9001,9002,9003,9009,9042,9043,"
    "9050,9060,9080,9081,9090,9091,9092,9100,9200,9300,9443,9800,9981,9990,9991,9999,10000,"
    "10001,10080,10250,10255,10443,11371,12443,15672,16080,18080,18091,18092,18443,19999,"
    "20000,20720,28017,34567,37777,49152,50000,55440,55443"
)

# whole-scope nuclei scan (spanning stage — ONE process, ONE global rate cap)
NUCLEI_CONC = PROFILE.nuclei_conc   # -c  templates in parallel (profile-driven)
NUCLEI_BULK = "25"      # -bs hosts per template
NUCLEI_RL = PROFILE.nuclei_rl       # -rl global requests/second (profile-driven)
NUCLEI_TIMEOUT = "10"   # -timeout seconds
NUCLEI_RETRIES = "2"    # -retries

# per-app enum (depth) — mirror run-passive-probe / run-crawler / run-takeover-discovered
GAU_THREADS = "5"
KATANA_DEPTH = "3"
KATANA_CONC = "2"
# crawley — a SECOND crawler run ∥ katana for coverage (see crawl()). Headless here means
# "skip the HEAD pre-flight", NOT browser rendering. Workers/delay mirror the manually-tuned
# combo; for wide fan-out across many apps consider dialing -workers down / -delay up.
CRAWLEY_DEPTH = "3"
CRAWLEY_WORKERS = "15"
CRAWLEY_DELAY = "0"         # per-request delay ("0" disables it; crawley's default is 150ms)
# headless crawl (TIER 1) — browser-backed, RAM-heavy; gated on the JS-render classification
# (is_js_rendered). Uses katana's bundled rod chromium (NOT -sc/system-chrome, which hangs here);
# -aff stays OFF (it would submit real forms). RAM (1-5 GB/host) is the dominant constraint at
# scale, so concurrent headless processes are capped PROCESS-WIDE by _HEADLESS_SLOTS (the
# ThreadPoolTaskRunner runs every stage as a thread in one process, so a module semaphore caps
# them across all app groups). -ct bounds runaway SPAs per host (footgun: per-host cap is a must).
HEADLESS_DEPTH = "3"
HEADLESS_CONC = "5"          # -c page concurrency within ONE headless process (RAM ∝ this)
HEADLESS_CT = "180"          # -ct crawl-duration cap per host (seconds)
HEADLESS_RL = "50"           # -rl requests/second
HEADLESS_PARALLELISM = 2     # max concurrent headless processes across ALL app groups
_HEADLESS_SLOTS = threading.BoundedSemaphore(HEADLESS_PARALLELISM)
# JS-render classification (NO browser) — calibrated on the crawler benchmark (handoff doc §6).
# Headless pays off only when the non-headless LINK surface is small yet JS-parse (fx) finds much
# more, or a thin-shell framework marker is present. A healthy link surface ⇒ traditional ⇒ skip.
JS_LINK_CEILING = 40   # link surface (max of raw <a href>, crawley) at/above this ⇒ traditional
JS_FX_MIN = 20         # require at least this many fx endpoints (avoid tiny-sample noise)
JS_FX_RATIO = 3        # ...and fx must dwarf the link surface by this factor
THIN_SHELL_MARKERS = ("__next_data__", "/_next/", "/_nuxt/", "__nuxt__", "ng-version", "data-reactroot")
SUBJACK_THREADS = "100"
SUBJACK_TIMEOUT = "30"
SCREENSHOT_TIMEOUT = "20"   # httpx -screenshot per-page timeout (seconds)
# EyeWitness (OPTIONAL) — adds signature-based default-credential detection on the SAME single
# best-host as the httpx screenshot (one URL per group, fed via a one-line -f file). Not a single
# binary (Selenium app); resolved best-effort by _eyewitness_cmd: PTFLOW_EYEWITNESS override, else
# `eyewitness` on PATH, else the known venv install at /opt/EyeWitness (_EYEWITNESS_DIR) — skipped if
# none resolve. Selenium ≥4.6 auto-provisions chromedriver (Selenium Manager); runs --headless=new.
EYEWITNESS_TIMEOUT = "15"   # --timeout per-URL seconds
NOISE_EXTENSIONS = frozenset({
    "jpg", "jpeg", "png", "gif", "svg", "bmp", "webp", "ico",
    "woff", "woff2", "ttf", "eot", "otf", "css",
    "mp3", "mp4", "wav", "avi", "mov", "webm",
})

# wordlist synthesis (PHASE 3 — active collection → custom per-app wordlist)
_TOKEN_MAX_LEN = 40                       # drop longer "segments" (hashes/junk)
OSINT_FETCH_RL = "50"  # httpx req/s when downloading the OSINT delta into responses/osint/
# wordlist STRATEGY (content_discovery) — a STAGED escalation, not one flat list. Pass A (every
# scanned host) fuzzes a combine of: custom (app-derived, full, first) + stage 0 `content`=olfa_micro
# (full, the grab-bag that ranks juicy/anomalous paths high) + stage 1 `an_directories` top-STAGE1_CAP
# (real web paths, frequency-ordered, ~97% additive over olfa) + stage 2 the ONE per-stack language
# list matched by detected tech, top-STAGE2_CAP + stage 2b the small `an_txt`/`an_xml` filetype lists
# (full). Stage 3 (the deep dive) is a SEPARATE gated pass — see DEEP_DIVE_* below. Lists resolve by
# ROLE (wordlists.py / wl_global/), never hardcoded; a missing role just drops its stage.
STAGE1_CAP = 30000  # an_directories_1m: top-N frequency head folded into Pass A (684k full would blow up)
STAGE2_CAP = 30000  # per-stack language list (an_php/an_aspx/an_jsp): top-N head

# content discovery (PHASE 3) — feroxbuster forced browsing. Global wordlists are
# resolved by ROLE (see wordlists.py / wl_global/), never hardcoded here.
# Gentle on live infra: --smart (auto-tune) adapts the rate down when the target errors/times
# out; low -t/-L keep concurrency bounded from the start. (--rate-limit is mutually exclusive
# with --smart, and is per-directory anyway, so it's the wrong tool here.)
FEROX_DEPTH = "2"        # -d recursion depth (feroxbuster default is 4)
FEROX_THREADS = PROFILE.ferox_threads        # -t threads per scan (profile-driven; default 50 is aggressive)
FEROX_SCAN_LIMIT = PROFILE.ferox_scan_limit  # -L concurrent directory scans (profile-driven)
FEROX_TIMEOUT = "15"     # --timeout per-request seconds (tolerate slow apps)
# --time-limit caps TOTAL scan wall-clock (--timeout is only per-request). Without it, a target that
# throttles under --smart can send feroxbuster's auto-tune into an unbounded backoff livelock that
# hangs the whole pipeline (no per-request timeout breaks it). --smart-compatible; exits gracefully,
# keeping partial results. See the scanme.nmap.org incident.
FEROX_TIME_LIMIT = "20m"  # --time-limit total scan duration (normal scans here finish in ~5m)
# content-discovery FIXPOINT (PHASE 3) — after round 0 (the classic forced-browse), feed the
# feroxbuster-discovered bodies back through download → mine → tokenize → fuzz the NEW token delta,
# until a fixpoint. Bounded by FOUR independent stops (no-new-words, no-new-urls, the per-app
# wall-clock deadline, diminishing-returns) under a hard round cap — see content_discovery().
CONTENT_FEEDBACK_ROUNDS = 2     # feedback rounds beyond round 0 (depth 3 total)
CONTENT_DEADLINE_S = 900        # per-app wall-clock budget across ALL rounds (incl. round 0)
DEEP_FEROX_TIME_LIMIT = "5m"    # --time-limit for feedback rounds (round 0 keeps FEROX_TIME_LIMIT)
MIN_NEW_TOKENS = 20             # a round contributing fewer new fuzz words ⇒ stop (diminishing returns)
DEEP_DOWNLOAD_CAP = 300         # max NEW urls downloaded+mined per round (logged when it bites)
# DEEP DIVE (PHASE 3, stage 3) — a SEPARATE forced-browse pass with the HUGE Assetnote manual lists
# (mn_php 3M, mn_phpmillion 1M, mn_html 4M — nearly disjoint from the an_* heads) at full depth, run
# ONLY on the few high-value hosts. OPT-IN (env PTFLOW_DEEP_DIVE truthy) because at these sizes it costs
# hours/host. Gated tight: a host qualifies only if Pass A already found ≥ DEEP_DIVE_MIN_HITS results
# on it (a real, content-bearing app), and at most the DEEP_DIVE_MAX_HOSTS richest qualify per app.
DEEP_DIVE_MIN_HITS = 50      # Pass A hits on a host below which the deep dive is not worth it
DEEP_DIVE_MAX_HOSTS = 2      # deep-dive at most the N richest scanned hosts per app
DEEP_DIVE_DEADLINE_S = 3600  # per-app wall-clock budget for the whole deep dive
DEEP_DIVE_TIME_LIMIT = "30m"  # feroxbuster --time-limit per deep-dive host run
DEEP_DIVE_DEPTH = "3"        # recursion depth for the deep dive (Pass A uses FEROX_DEPTH=2)

# parameter fuzzing (PHASE 4) — arjun ∥ x8 hidden-parameter discovery over the enumerated endpoints.
# Per-endpoint and request-heavy (a 6.5k-name wordlist over N endpoints, two tools), so the endpoint
# set is deduped by path-template and capped, and both tools run gently (low concurrency + rate cap).
PARAM_MAX_ENDPOINTS = 50   # cap distinct endpoint shapes fuzzed per app (logged when it bites)
# multi-location discovery (query · body · json · header) — body/json/header are heavier and
# lower-yield than query, so they get tighter caps. arjun -m GET/POST/JSON ∥ x8 -X/--data-type/--headers.
PARAM_MAX_BODY_ENDPOINTS = 25    # body + json discovery cap (POST/PUT/PATCH or body-bearing endpoints)
PARAM_MAX_HEADER_ENDPOINTS = 15  # header discovery cap (x8 only — arjun has no header-discovery mode)
PARAM_FANOUT = 3                 # concurrent (tool, location) param jobs per app
# a param reflection-discovered on ~EVERY tested endpoint for its location is a SITE-WIDE reflection
# artifact (e.g. a target that echoes any `?p=` into a Set-Cookie on every path), not N distinct hidden
# params — collapse it to one host-level record instead of spraying a fuzz request onto each endpoint.
PARAM_GLOBAL_RATIO = 0.75   # found on ≥ this fraction of the endpoints tested at a location → collapse
PARAM_GLOBAL_MIN_HITS = 5   # …but only above this many hits, so a tiny tested set can't trip the ratio

# per-app DAST (PHASE 2 surface + PHASE 4 deep) — nuclei -dast over the request catalog (full requests
# → fuzz query/path/header/cookie/body, not just GET query). Phase 2 hits the explorable surface
# (requests.jsonl); phase 4 hits the guessed delta + discovered params. Whole-scope full-template nuclei
# is nuclei_scope (breadth). Best-effort (skips if nuclei / dast templates absent).
DAST_MAX_REQUESTS = 1500   # cap requests fed to nuclei per app (reconftw DEEP_LIMIT2 analog); logged
DAST_AGGRESSION = "low"    # nuclei -fa (low|medium|high): payload count per fuzz point — low = polite

# API spec discovery (PHASE 1) — probe for OpenAPI/Swagger JSON specs + GraphQL endpoints, expand the
# spec into full request records (method/body/params) → requests_api.jsonl, folded into the catalog.
# The richest source of method+body+param info — the API surface a crawler / GET-fuzzer can't see.
API_SPEC_PATHS = ("/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
                  "/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json",
                  "/api/v1/openapi.json", "/swagger/doc.json")
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")
API_SPEC_MAX_OPS = 300     # cap operations expanded per app (logged when it bites)

# re-seed crawl (PHASE 3) — when fuzzing finds an entry point into UN-CRAWLED territory (e.g. a
# /debugging dir the link-crawler never reached), crawl it so its linked/rendered surface + request
# shapes aren't lost. PTFLOW_RECRAWL ∈ off|preview|on (default `on`); `preview` selects+logs the seeds
# without crawling (review raw/recrawl/seeds.txt). Bounded even when on: few shallow seeds, depth 2.
RECRAWL = os.environ.get("PTFLOW_RECRAWL", "on").lower().strip()
RECRAWL_MAX_SEEDS = 10     # cap new-territory entry points crawled per app (logged when it bites)
RECRAWL_DEPTH = "2"        # katana -d for the re-seed crawl (shallower than the phase-1 crawl)
RECRAWL_CT = "120"         # katana -ct crawl-duration cap per seed host (seconds)
ARJUN_THREADS = "5"        # arjun -t
ARJUN_RATE = "20"          # arjun --rate-limit (req/s)
ARJUN_TIMEOUT = "15"       # arjun -T (per-request seconds)
X8_WORKERS = "2"           # x8 -W (concurrent url checks)
X8_CONCURRENCY = "2"       # x8 -c (concurrent requests per url)
X8_TIMEOUT = "15"          # x8 --timeout (seconds, per-request)
X8_DELAY = "0"             # x8 -d (ms between requests)
# arjun/x8 have NO total wall-clock cap of their own (arjun none; x8 --timeout is per-request), so a
# slow/large target could run for hours — the feroxbuster-livelock lesson. PARAM_TOOL_TIMEOUT is the
# hard per-tool backstop: on hit we keep whatever partial output was written (best-effort).
PARAM_TOOL_TIMEOUT = 600   # seconds, per tool (arjun, x8) per app
TECH_EXTENSIONS = {  # detected-tech keyword → file extensions to fuzz
    "php": ["php"],
    "asp.net": ["asp", "aspx", "ashx"],
    "java": ["jsp", "do", "action"],
    "python": ["py"],
    "ruby": ["rb"],
    "coldfusion": ["cfm", "cfc"],
}
# detected-tech keyword → wordlist ROLE for the stage-2 per-stack language list (Pass A). Only the
# matching list rides along (never php on a .NET site); a tech that matches nothing skips stage 2. The
# API-driven stacks (server-side JS: node/express/next/nuxt; python frameworks) get `an_apiroutes` —
# their surface is API routes, not a server-page extension. NB: react/vue/angular are CLIENT-side and
# imply nothing about the backend, so they're deliberately NOT mapped. Python has no dedicated Assetnote
# list, so it leans on an_apiroutes + the .py extension + the generic stages (an_directories/olfa).
STAGE2_TECH_ROLES = {
    "php": "an_php",
    "asp.net": "an_aspx", "iis": "an_aspx", "microsoft-iis": "an_aspx", "coldfusion": "an_aspx",
    "java": "an_jsp", "jsp": "an_jsp", "tomcat": "an_jsp", "jboss": "an_jsp", "spring": "an_jsp",
    "node": "an_apiroutes", "express": "an_apiroutes", "next": "an_apiroutes", "nuxt": "an_apiroutes",
    "python": "an_apiroutes", "django": "an_apiroutes", "flask": "an_apiroutes", "fastapi": "an_apiroutes",
}
STAGE2B_ROLES = ("an_txt", "an_xml")  # small always-on filetype lists (robots/security.txt; sitemap/opensearch)
# detected-tech keyword → DEEP-DIVE (stage 3) roles, gated to a php/.NET/java stack (the huge MANUAL
# lists that exist). `mn_html` is GENERIC (every app serves html) so it always rides on a qualifying
# host; js/python have no dedicated manual list → they get only the generic mn_html.
DEEPDIVE_TECH_ROLES = {
    "php": ("mn_php", "mn_phpmillion"),
    "asp.net": ("mn_aspx", "mn_asp", "mn_cfm"), "iis": ("mn_aspx", "mn_asp", "mn_cfm"),
    "microsoft-iis": ("mn_aspx", "mn_asp", "mn_cfm"), "coldfusion": ("mn_cfm",),
    "java": ("mn_jsp", "mn_do"), "jsp": ("mn_jsp", "mn_do"), "tomcat": ("mn_jsp", "mn_do"),
    "jboss": ("mn_jsp", "mn_do"), "spring": ("mn_jsp", "mn_do"),
}
DEEPDIVE_GENERIC_ROLES = ("mn_html",)

# clustering (surfagr.sh port) — group webapps into application-groups by union-find over
# APP-IDENTITY signals only (see _cluster_signals/_CLUSTER_EDGES). Tuned PRECISION-FIRST: never
# merge logically-different apps (over-merge is a correctness bug); a duplicate scanned twice is
# acceptable waste. A GLOBAL signal value (body hash, final host) spanning more than
# GENERIC_MAX_APEXES distinct apexes is treated as generic (a default/error page, a parking
# redirect) and does NOT merge; the fuzzy signals (favicon, root fingerprint) are apex-scoped so
# they never merge across organizations regardless.
GENERIC_MAX_APEXES = 8   # global signal shared across more distinct apexes than this ⇒ generic, ignored
CLUSTER_MAX_HOSTS = 50   # a group larger than this ⇒ WARNING (likely residual collision)

# `httpx` on PATH is the pyenv shim; the ProjectDiscovery binary lives in ~/go/bin.
_HTTPX_BIN = Path.home() / "go" / "bin" / "httpx"
HTTPX = str(_HTTPX_BIN) if _HTTPX_BIN.exists() else "httpx"

# feroxbuster lives in ~/.local/bin (may not be on the subprocess PATH).
_FEROX_BIN = Path.home() / ".local" / "bin" / "feroxbuster"
FEROX = str(_FEROX_BIN) if _FEROX_BIN.exists() else "feroxbuster"

# shortscan + shortutil (IIS 8.3 short-name enum, tech_enum) live in ~/go/bin.
_SHORTSCAN_BIN = Path.home() / "go" / "bin" / "shortscan"
SHORTSCAN = str(_SHORTSCAN_BIN) if _SHORTSCAN_BIN.exists() else "shortscan"
_SHORTUTIL_BIN = Path.home() / "go" / "bin" / "shortutil"
SHORTUTIL = str(_SHORTUTIL_BIN) if _SHORTUTIL_BIN.exists() else "shortutil"
SHORTSCAN_CONC = "20"  # shortscan -c concurrency (its default)

# wpprobe (WordPress plugin/theme vuln scanner, tech_vulnscan) lives in ~/go/bin. Finding-only,
# best-effort — runs ONLY on app groups whose tech says WordPress. Maps detected plugins/themes +
# versions to known CVEs via its LOCAL Wordfence DB (provisioned out-of-band: `wpprobe update-db`).
_WPPROBE_BIN = Path.home() / "go" / "bin" / "wpprobe"
WPPROBE = str(_WPPROBE_BIN) if _WPPROBE_BIN.exists() else "wpprobe"
WPPROBE_RATE = "20"     # --rate-limit (req/s) — gentle on live infra (wpprobe default is 50)
WPPROBE_THREADS = "5"   # -t concurrent threads
WPPROBE_TIMEOUT = 300   # per-host wall-clock backstop (stealthy mode is fast; keep partial on hit)

# jsluice (offline JS endpoint/secret mining of the response store) lives in ~/go/bin.
_JSLUICE_BIN = Path.home() / "go" / "bin" / "jsluice"
JSLUICE = str(_JSLUICE_BIN) if _JSLUICE_BIN.exists() else "jsluice"

# secret-scanning fleet (mine_responses) — all best-effort, run ∥ over the extracted body corpus.
# gitleaks/trufflehog in ~/go/bin, detect-secrets (pip) in ~/.local/bin. trufflehog runs with
# --results=verified: it VALIDATES each hit against the credential's PROVIDER (network to AWS/GitHub/
# …, not the target) → near-zero false positives. gitleaks (regex/any-file) + detect-secrets
# (entropy, hashes only) are pure-offline recall layers; merge_secrets dedups across all sources.
_GITLEAKS_BIN = Path.home() / "go" / "bin" / "gitleaks"
GITLEAKS = str(_GITLEAKS_BIN) if _GITLEAKS_BIN.exists() else "gitleaks"
_TRUFFLEHOG_BIN = Path.home() / "go" / "bin" / "trufflehog"
TRUFFLEHOG = str(_TRUFFLEHOG_BIN) if _TRUFFLEHOG_BIN.exists() else "trufflehog"
_DETECT_SECRETS_BIN = Path.home() / ".local" / "bin" / "detect-secrets"
DETECT_SECRETS = str(_DETECT_SECRETS_BIN) if _DETECT_SECRETS_BIN.exists() else "detect-secrets"

# crawley (the second crawler, run ∥ katana) lives in ~/go/bin.
_CRAWLEY_BIN = Path.home() / "go" / "bin" / "crawley"
CRAWLEY = str(_CRAWLEY_BIN) if _CRAWLEY_BIN.exists() else "crawley"

# param_fuzz fleet (PHASE 4) — arjun (pip/uv, ~/.local/bin) ∥ x8 (cargo, ~/.cargo/bin). Best-effort.
_ARJUN_BIN = Path.home() / ".local" / "bin" / "arjun"
ARJUN = str(_ARJUN_BIN) if _ARJUN_BIN.exists() else "arjun"
_X8_BIN = Path.home() / ".cargo" / "bin" / "x8"
X8 = str(_X8_BIN) if _X8_BIN.exists() else "x8"

# nuclei DAST fuzzing templates (per-app `dast` step). Default to the standard nuclei-templates dast/
# dir; override with PTFLOW_NUCLEI_DAST_TEMPLATES. The step skips (best-effort) if the dir is absent.
_NUCLEI_DAST_TEMPLATES = Path.home() / "nuclei-templates" / "dast"
NUCLEI_DAST_TEMPLATES = os.environ.get("PTFLOW_NUCLEI_DAST_TEMPLATES") or str(_NUCLEI_DAST_TEMPLATES)

# dedicated vuln scanners (PHASE 2 surface + PHASE 4 deep) — dalfox (XSS) ∥ sqlmap (SQLi) over the
# request catalog's FULL requests (the `raw` field — Burp/ZAP format both tools ingest natively), ONE
# process per request so EVERY param location is tested (query/body/json/header/cookie), not GET-only.
# No candidate heuristic (gf-style param-NAME routing deliberately rejected): every parameterized
# request is a candidate and each tool's OWN engine decides — dalfox by reflection+context, sqlmap by
# its boolean/error/union/time tests. NOT --smart: its basic heuristic only fires on a reflected DBMS
# error, so a boolean/UNION SQLi that leaks NO error (e.g. ginandjuice `category`) is skipped untested
# — verified. We run the full per-param tests + --text-only (compare visible text only) so detection
# survives a content-DYNAMIC page, where the default page-comparison is "not stable" and misses the
# injection — verified: --smart→0, --text-only L1/R1→boolean+UNION in ~14s. Surface (phase 2) + delta
# (phase 4), mirroring dast/dast_full. Best-effort; per-request wall-clock cap (arjun/x8 livelock lesson).
_DALFOX_BIN = Path.home() / "go" / "bin" / "dalfox"
DALFOX = str(_DALFOX_BIN) if _DALFOX_BIN.exists() else "dalfox"
_SQLMAP_SCRIPT = os.environ.get("PTFLOW_SQLMAP") or "/opt/sqlmap-dev/sqlmap.py"
SQLMAP_CMD = [sys.executable, _SQLMAP_SCRIPT]   # sqlmap is a python script, not a PATH binary
VULN_MAX_REQUESTS = 40      # cap candidate (parameterized) requests per app per pass per tool
VULN_FANOUT = 3             # concurrent scanner processes per app (each is itself network-heavy)
VULN_TOOL_TIMEOUT = 180     # per-request wall-clock cap (s) — a slow target must not hang the loop
DALFOX_WORKERS = "30"       # dalfox -w (concurrent payloads per request)
DALFOX_HTTP_TIMEOUT = "10"  # dalfox --timeout (per HTTP request)
SQLMAP_LEVEL = "1"          # sqlmap --level (1 = query/cookie; polite on live infra)
SQLMAP_RISK = "1"           # sqlmap --risk (1 = safe payloads only)
SQLMAP_THREADS = "4"        # sqlmap --threads

# OAST / blind XSS (OPT-IN, best-effort) — dalfox -b fires blind payloads at an interactsh callback; the
# hit lands on the interactsh SERVER, not dalfox's output. So with PTFLOW_OAST on we run an interactsh-client
# for the dalfox pass, give EACH request a unique callback subdomain (<marker>.<domain> — the per-request
# runner gives per-request correlation), then drain the interactions and match each hit's full-id marker
# back to its request. Catches only SYNCHRONOUS callbacks (the scan's own request triggers the render); a
# truly-stored/delayed XSS fires after the run — out of scope (would need a persistent service, against
# files-as-only-state). interactsh-client >= 1.3 required (older can't decrypt the public servers' data).
_INTERACTSH_BIN = Path.home() / "go" / "bin" / "interactsh-client"
INTERACTSH = str(_INTERACTSH_BIN) if _INTERACTSH_BIN.exists() else "interactsh-client"
OAST_ENABLED = os.environ.get("PTFLOW_OAST", "").lower() in {"1", "on", "true", "yes"}
OAST_SERVER = os.environ.get("PTFLOW_INTERACTSH_SERVER", "")  # self-hosted server(s); else public default
OAST_TOKEN = os.environ.get("PTFLOW_INTERACTSH_TOKEN", "")    # auth token for a protected/self-hosted server
OAST_REG_TIMEOUT = 25   # s to wait for interactsh-client to register + print its callback domain
OAST_DRAIN_GRACE = 8    # s after the dalfox pool before draining (let synchronous callbacks land + poll)
OAST_POLL = "3"         # interactsh-client -pi (poll interval, seconds)

# CVE lookup (PHASE 2 surface + PHASE 4 deep) — search_vulns correlates the ENUMERATED software
# (web server + app tech + non-HTTP service banners + corpus-mined libs) against its LOCAL vuln DB
# (NVD+GHSA+ExploitDB+EPSS), fully OFFLINE (net=False — no target traffic). The DB is built/refreshed
# out-of-band (`search_vulns -u`); the stage skips best-effort if the binary or DB is absent. Override
# the binary path with PTFLOW_SEARCH_VULNS.
_SEARCH_VULNS_BIN = Path.home() / ".local" / "bin" / "search_vulns"
SEARCH_VULNS = os.environ.get("PTFLOW_SEARCH_VULNS") or (
    str(_SEARCH_VULNS_BIN) if _SEARCH_VULNS_BIN.exists() else "search_vulns")
CVE_TOOL_TIMEOUT = 90   # per-query wall-clock cap (offline, but a runaway query must not hang the loop)
CVE_FANOUT = 4          # concurrent search_vulns queries per app (offline → modest)

# EyeWitness (optional, screenshot step) — known venv install (own .venv + Python/EyeWitness.py);
# resolved by _eyewitness_cmd (overridable via PTFLOW_EYEWITNESS / `eyewitness` on PATH).
_EYEWITNESS_DIR = Path("/opt/EyeWitness")


# --- auth passthrough (env PTFLOW_HTTP_HEADER) — operator session headers/cookies so the crawl/fuzz/
# DAST reach the AUTHENTICATED surface (most POST/JSON lives behind a login). One or more
# "Name: value" headers, separated by newlines or ";;". Threaded into katana/httpx/arjun/x8/nuclei.
def _auth_headers() -> list[str]:
    """The operator's session headers/cookies (env PTFLOW_HTTP_HEADER), as a list of 'Name: value'
    strings. Read each call (testable); empty when unset or malformed (a part without ':' is dropped)."""
    raw = os.environ.get("PTFLOW_HTTP_HEADER", "")
    return [p.strip() for p in re.split(r";;|\n", raw) if p.strip() and ":" in p]


def _header_flags(flag: str = "-H") -> list[str]:
    """[flag, header, flag, header, …] for the operator's session headers — appended to a tool's argv
    so it reaches the authenticated surface. Empty when none set. katana/httpx/nuclei all take -H."""
    out: list[str] = []
    for h in _auth_headers():
        out += [flag, h]
    return out

# --- preflight tool inventory (logical name → command/path resolved with shutil.which) ---
# CORE: the pipeline genuinely relies on these — a missing one is a WARNING (its stage yields
# nothing). OPTIONAL: best-effort fleet whose absence is expected/fine (the stage simply skips).
_CORE_TOOLS = {
    "mapcidr": "mapcidr", "naabu": "naabu", "dnsx": "dnsx", "tlsx": "tlsx",
    "shuffledns": "shuffledns", "subfinder": "subfinder", "assetfinder": "assetfinder",
    "httpx": HTTPX, "katana": "katana", "gau": "gau", "urlfinder": "urlfinder",
    "nuclei": "nuclei", "nerva": "nerva", "subjack": "subjack", "feroxbuster": FEROX,
}
_OPTIONAL_TOOLS = {
    "crawley": CRAWLEY, "jsluice": JSLUICE, "shortscan": SHORTSCAN, "shortutil": SHORTUTIL,
    "gitleaks": GITLEAKS, "trufflehog": TRUFFLEHOG, "detect-secrets": DETECT_SECRETS,
    "arjun": ARJUN, "x8": X8, "search_vulns": SEARCH_VULNS, "wpprobe": WPPROBE, "dalfox": DALFOX,
    "interactsh-client": INTERACTSH,
}


def requirements() -> list[Requirement]:
    """The external pipeline's full host requirement manifest — the SINGLE source of truth that both
    `preflight` (run-time summary) and `ptflow doctor` render from, so the two can't drift. Tools come
    from the which-based `_CORE_TOOLS`/`_OPTIONAL_TOOLS` dicts; plus the non-PATH tools (sqlmap +
    EyeWitness — a python script / Selenium app, checked by their absolute path) and the on-disk
    datasets. Datasets are OPTIONAL: the pipeline degrades best-effort when one is absent (nuclei's dast
    step skips, resolvers falls back), so a missing dataset WARNS — only a missing CORE tool fails."""
    reqs = [Requirement(name, cmd, "core") for name, cmd in _CORE_TOOLS.items()]
    reqs += [
        Requirement(name, cmd, "optional")
        for name, cmd in _OPTIONAL_TOOLS.items()
        if name != "interactsh-client"
    ]
    reqs.append(Requirement(
        "interactsh-client", INTERACTSH, "optional", min_version="1.3", version_args=("-version",),
        note="OAST blind-XSS; >=1.3 required (older can't decrypt the public servers)"))
    # non-PATH tools (a python script / a Selenium app) — resolved by absolute path, not `which`
    reqs.append(Requirement(
        "sqlmap", _SQLMAP_SCRIPT, "optional",
        note="dedicated SQLi scanner: clone sqlmapproject/sqlmap → /opt/sqlmap-dev (or PTFLOW_SQLMAP)"))
    reqs.append(Requirement(
        "eyewitness", str(_EYEWITNESS_DIR / "Python" / "EyeWitness.py"), "optional",
        note="optional screenshot step: clone EyeWitness + its .venv (selenium), or PTFLOW_EYEWITNESS"))
    # on-disk datasets (path-existence; all best-effort → optional, they never fail the gate)
    reqs.append(Requirement(
        "nuclei dast templates", NUCLEI_DAST_TEMPLATES, "optional", category="dataset",
        note="fuzzing templates for the dast step: run `nuclei -ut` (updates ~/nuclei-templates)"))
    reqs.append(Requirement(
        "resolvers", RESOLVERS, "optional", category="dataset",
        note="trusted DNS resolvers: clone trickest/resolvers → /opt/resolvers"))
    return reqs


def preflight() -> None:
    """Log which external tools/datasets resolve at run start, so a missing dependency degrades a stage
    VISIBLY instead of yielding a silent empty result. Never aborts (best-effort): a missing CORE tool
    is a WARNING (that stage produces nothing); missing OPTIONAL tools/datasets just skip their
    best-effort stage. Renders from the same `requirements()` manifest as `ptflow doctor`."""
    log.info("  → profile: %s (naabu -rate %s -c %s · nuclei -rl %s · ferox -t %s -L %s)",
             PROFILE.name, NAABU_RATE, NAABU_CONC, NUCLEI_RL, FEROX_THREADS, FEROX_SCAN_LIMIT)
    report = check(requirements())
    core = [r for r in report.results if r.req.kind == "core"]
    opt = [r for r in report.results if r.req.kind == "optional"]
    log.info("  → preflight: core %d/%d · optional %d/%d",
             sum(1 for r in core if r.ok), len(core), sum(1 for r in opt if r.ok), len(opt))
    if report.core_missing:
        log.warning("  ⚠ preflight: missing CORE tool(s) — these stages will produce nothing: %s",
                    ", ".join(r.req.name for r in report.core_missing))
    opt_missing = [r.req.name for r in opt if not r.ok]
    if opt_missing:
        log.info("    optional deps absent (their stages skip): %s", ", ".join(opt_missing))


# --- pure transforms (unit-tested) ---
def split_scope(targets: list[Target]) -> tuple[list[str], list[str], list[str], list[str]]:
    """Return (urls, dns_names, wildcards, ips_cidr) from classified targets."""
    urls = [t.raw for t in targets if t.kind == "url"]
    dns = [t.normalized for t in targets if t.kind == "domain"]
    dns += [t.normalized for t in targets if t.kind == "url"]
    wildcards = [t.normalized for t in targets if t.kind == "wildcard"]
    ips_cidr = [t.raw for t in targets if t.kind in ("ip", "cidr")]
    return urls, dns, wildcards, ips_cidr


def honeypot_split(naabu_lines: list[str], threshold: int = HONEYPOT_MIN_OPEN_PORTS) -> tuple[list[str], list[str]]:
    """Split naabu 'ip:port' lines into (valid_ips, honeypot_ips) by open-port count."""
    counts: Counter[str] = Counter(ln.rsplit(":", 1)[0] for ln in naabu_lines if ":" in ln)
    valid = sorted(ip for ip, n in counts.items() if n < threshold)
    honeypots = sorted(ip for ip, n in counts.items() if n >= threshold)
    return valid, honeypots


def select_web_ports(naabu_lines: list[str], valid_ips: list[str]) -> list[str]:
    """Open `ip:port` lines on the VALID (non-honeypot) IPs — the FAST web target set httpx probes,
    so the full 65535-port scan can move off the breadth critical path (it becomes spanning). Pure."""
    valid = set(valid_ips)
    return [ln for ln in naabu_lines if ":" in ln and ln.rsplit(":", 1)[0] in valid]


def select_unique_webapps(httpx_records: list[dict]) -> list[str]:
    """Dedup httpx records by (Title, Content-Length, Webserver); return their URLs."""
    seen: set[tuple] = set()
    out: list[str] = []
    for r in httpx_records:
        key = (r.get("title"), r.get("content_length"), r.get("webserver"))
        if key not in seen:
            seen.add(key)
            if r.get("url"):
                out.append(r["url"])
    return out


def url_host(url: str) -> str:
    """Extract the bare host from a URL (drop scheme, path, port)."""
    host = url.split("://", 1)[-1].split("/", 1)[0]
    return host.split(":", 1)[0]


def is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)  # noqa: PLR2004


_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")  # dotted-quad literal anywhere in a line


def map_hosts_to_ips(lines: Iterable[str], hosts: set[str]) -> set[str]:
    """IPs belonging to `hosts` from a `dnsx -a -resp` map (domain_ip_map.txt). Each line is
    ``<host> [A] [<ip>] …`` — the record TYPE and the response IPs are SEPARATE, bracket-wrapped
    tokens, so positional column [1] is the type ('[A]'), not the IP. Take the host (first token)
    and extract every dotted-quad IPv4 literal from the REST of the line (bracket-agnostic, multiple
    A records supported). Pure — used to attribute nerva service banners to an app's hosts by IP."""
    out: set[str] = set()
    for line in lines:
        head, _, rest = line.strip().partition(" ")
        if head in hosts:
            out.update(_IPV4_RE.findall(rest))
    return out


def split_cdn_ip_records(records: list[dict], scope_ips: set[str]) -> tuple[list[dict], list[dict]]:
    """Partition httpx records into (kept, dropped) for SCOPE HYGIENE (pure).

    Drop a record ONLY when its host is a bare IP AND httpx flagged it CDN/cloud/WAF (cdncheck) —
    that's a raw-IP probe of shared PROVIDER infra (out of scope: the IP belongs to the provider,
    not the target; e.g. a Google frontend or an AWS ALB returning 421). KEEP:
      - CDN-fronted HOSTNAMES (the real target behind a CDN/LB — scanned by name),
      - self-hosted bare IPs (not CDN),
      - any IP explicitly in `scope_ips` (user listed it → in scope, never dropped).
    The dropped set is retained by the caller as an audit deliverable (excluded_cdn.jsonl). NB:
    IPv4-only (is_ip); CDN over a bare IPv6 literal would slip through — acceptable for now.
    """
    kept: list[dict] = []
    dropped: list[dict] = []
    for r in records:
        host = r.get("host") or url_host(r.get("url") or "")
        is_cdn = bool(r.get("cdn")) or bool(r.get("cdn_name"))
        if host and is_ip(host) and is_cdn and host not in scope_ips:
            dropped.append(r)
        else:
            kept.append(r)
    return kept, dropped


def apex(host: str) -> str:
    """Naive apex domain (last two labels). Good enough pre-PSL for common TLDs."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host  # noqa: PLR2004


def best_host(urls: list[str]) -> str | None:
    """Pick the single URL to screenshot for a cluster: prefer a non-IP host, then
    https, then the first. Returns None for an empty list."""
    pool = [u for u in (u.strip() for u in urls) if u]
    if not pool:
        return None
    non_ip = [u for u in pool if not is_ip(url_host(u))]
    pool = non_ip or pool
    https = [u for u in pool if u.startswith("https://")]
    return (https or pool)[0]


def dedup_by_body(hosts: list[str], body_by_host: dict[str, str | None]) -> list[str]:
    """Collapse hosts that serve an IDENTICAL response body to one representative (best_host per
    body) — same body = same backend/content, so scanning each is pure duplication (a domain and
    its IP, http+https). Hosts with a DIFFERENT body are distinct environments (staging vs test)
    and are all kept; hosts with an unknown body are kept individually (can't prove identity)."""
    buckets: dict[str, list[str]] = {}
    unknown: list[str] = []
    for h in hosts:
        body = body_by_host.get(h)
        if body:
            buckets.setdefault(body, []).append(h)
        else:
            unknown.append(h)
    reps = [best_host(group) for group in buckets.values()]
    return [*[r for r in reps if r], *unknown]


def https_to_http(url: str) -> str:
    """Rewrite the scheme of an https:// URL to http:// (scheme only — host/port/path kept); any
    other string is returned unchanged. Pure. Used to retry a scan over http when the https endpoint
    refuses a modern TLS handshake (see ferox_transport_failed)."""
    return "http://" + url[len("https://"):] if url.startswith("https://") else url


def force_scheme(url: str, by_host: dict[str, str]) -> str:
    """Rewrite `url`'s scheme to by_host[bare-host] when that host has an entry; else unchanged. Pure.
    The one primitive behind both scheme decisions: honoring an explicit scope scheme (cluster) and
    routing param_fuzz to the scheme the scanners actually reached. Keyed by port-stripped host."""
    if not by_host:
        return url
    scheme = by_host.get(url_host(url))
    if not scheme:
        return url
    return f"{scheme}://{url.split('://', 1)[1] if '://' in url else url}"


def denoise(urls: list[str]) -> list[str]:
    """Drop URLs to static assets (extensions in NOISE_EXTENSIONS)."""
    out: list[str] = []
    for u in urls:
        last = u.split("?", 1)[0].rsplit("/", 1)[-1]
        ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
        if ext not in NOISE_EXTENSIONS:
            out.append(u)
    return out


def _add_token(out: set[str], seg: str) -> None:
    """Add a path/param token (and a filename's basename) if it's wordlist-worthy."""
    seg = seg.strip()
    if not seg or seg.isdigit() or len(seg) > _TOKEN_MAX_LEN:
        return
    out.add(seg)
    if "." in seg:  # filename → also offer the basename (login.php → login)
        base = seg.rsplit(".", 1)[0]
        if base and not base.isdigit():
            out.add(base)


def tokenize_urls(urls: Iterable[str]) -> list[str]:
    """Mine wordlist candidates from a URL/endpoint corpus.

    Extracts path segments, filename basenames and query-parameter names. Drops
    the scheme+host, pure-numeric segments (IDs), and junk longer than
    _TOKEN_MAX_LEN. Accepts full URLs, scheme-less host/path, and bare ``/path``
    forms (as emitted by jsluice). Case is preserved; the result is sorted+deduped.
    """
    out: set[str] = set()
    for raw in urls:
        u = raw.strip()
        if not u:
            continue
        if "://" in u:
            u = u.split("://", 1)[1]
            u = u.split("/", 1)[1] if "/" in u else ""           # drop scheme + host
        elif u.startswith("/"):
            u = u[1:]                                            # bare /path
        elif "/" in u and "." in u.split("/", 1)[0]:
            u = u.split("/", 1)[1]                               # host/path (first label has a dot)
        path, _, query = u.partition("?")
        for seg in path.split("/"):
            _add_token(out, seg)
        for pair in query.split("&"):
            _add_token(out, pair.split("=", 1)[0])
    return sorted(out)


# --- lexicon extraction (build_wordlist) — pure, unit-testable corpus miners ---
# These turn the crawled link surface AND the downloaded response bodies into per-app wordlist
# products beyond the endpoint seed: parameter-name candidates, high-semantic value words, and
# identities (users/emails). values/identities have no consumer yet (deliverables for the planned
# DAST), so the filters lean PRECISION-FIRST — a smaller clean list beats a noisy one.
_VALUE_MIN_LEN = 3
_JSON_MAX_BYTES = 2_000_000        # skip JSON-parsing a body larger than this (memory bound)
_JSON_MAX_DEPTH = 6
_JSON_MAX_ITEMS = 200              # per-list fan-out bound while walking a parsed body
# query keys whose VALUES are noise (session/tracking/nonce) — skipped when mining value words
_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid",
    "ref", "sid", "token", "csrf", "nonce", "sig", "signature", "hash", "t", "ts", "_", "v", "cb",
})
# boilerplate dropped from app-name / apex value words
_BOILERPLATE_WORDS = frozenset({
    "login", "logout", "home", "welcome", "error", "404", "403", "500", "index", "untitled",
    "page", "sign", "register", "search", "www", "com", "net", "org",
})
# JSON/form field names whose VALUES are likely identities (usernames)
_IDENTITY_FIELDS = ("username", "user", "login", "email", "owner", "author")
_EMAIL_DENY_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "domain.com", "email.com", "localhost",
    "sentry.io", "w3.org", "schema.org",
})
# asset extensions that masquerade as an email TLD (logo@2x.png, sprite@3x.svg, …)
_EMAIL_DENY_TLDS = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "jsx", "ts", "json",
    "html", "htm", "php", "map", "woff", "woff2", "ttf",
})
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")
_MAILTO_RE = re.compile(r"mailto:([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})",
                        re.IGNORECASE)
_FIELD_TAG_RE = re.compile(r"<(?:input|select|textarea|button)\b[^>]{0,400}?>", re.IGNORECASE)
_NAME_ID_RE = re.compile(r"""\b(?:name|id)\s*=\s*["']([^"']{1,40})["']""", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE)
_META_NAME_RE = re.compile(
    r"""<meta\b[^>]*?(?:property\s*=\s*["']og:site_name["']|name\s*=\s*["']application-name["'])"""
    r"""[^>]*?content\s*=\s*["']([^"']{1,200})["']""",
    re.IGNORECASE,
)


def _query_of(url: str) -> str:
    """The raw query string of a URL/endpoint (between '?' and '#'), or '' if none. Pure."""
    return url.partition("?")[2].split("#", 1)[0]


def _looks_opaque(s: str) -> bool:
    """True for hash/token/uuid/base64-ish blobs that pollute a value/identity lexicon. Pure."""
    if any(c in s for c in "+/="):                       # base64 charset/padding
        return True
    if _UUID_RE.fullmatch(s):
        return True
    low = s.lower()
    if len(low) >= 16 and all(c in "0123456789abcdef" for c in low):  # long hex hash  # noqa: PLR2004
        return True
    return sum(c.isalpha() for c in s) / len(s) < 0.4    # mostly digits/symbols  # noqa: PLR2004


def _add_value(out: set[str], raw: str) -> None:
    """Add a value word if it survives the precision filters (length, numeric, opaqueness). Pure."""
    v = raw.strip()
    if _VALUE_MIN_LEN <= len(v) <= _TOKEN_MAX_LEN and not v.isdigit() and not _looks_opaque(v):
        out.add(v)


def _split_words(text: str) -> list[str]:
    """Split a human string into lowercase alphanumeric word tokens (titles, apex labels). Pure."""
    return [w for w in re.split(r"[^A-Za-z0-9]+", text.lower()) if w]


def query_param_names(urls: Iterable[str]) -> list[str]:
    """Parameter-NAME candidates from query strings in the link corpus. Pure."""
    out: set[str] = set()
    for u in urls:
        for pair in _query_of(u).split("&"):
            _add_token(out, pair.partition("=")[0])
    return sorted(out)


def query_param_values(urls: Iterable[str]) -> list[str]:
    """High-signal VALUE words from query strings (URL-decoded), skipping tracking/opaque values. Pure."""
    out: set[str] = set()
    for u in urls:
        for pair in _query_of(u).split("&"):
            key, sep, val = pair.partition("=")
            if sep and key.lower() not in _TRACKING_PARAMS:
                _add_value(out, unquote_plus(val))
    return sorted(out)


def jsluice_param_names(records: Iterable[dict]) -> list[str]:
    """Parameter names from jsluice `urls` records (queryParams + bodyParams). Pure over parsed dicts."""
    out: set[str] = set()
    for r in records:
        for p in (r.get("queryParams") or []):
            _add_token(out, str(p))
        for p in (r.get("bodyParams") or []):
            _add_token(out, str(p))
    return sorted(out)


def html_field_names(html: str) -> list[str]:
    """name=/id= of form fields (input/select/textarea/button) in an HTML body. Pure."""
    out: set[str] = set()
    for tag in _FIELD_TAG_RE.finditer(html):
        for m in _NAME_ID_RE.finditer(tag.group(0)):
            _add_token(out, m.group(1))
    return sorted(out)


def _walk_json(obj: object, visit: Callable[[str, object], None]) -> None:
    """Depth/fan-out-bounded walk of a parsed JSON value; call visit(key, value) per dict item. Pure."""
    def walk(o: object, depth: int) -> None:
        if depth > _JSON_MAX_DEPTH:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                visit(str(k), v)
                walk(v, depth + 1)
        elif isinstance(o, list):
            for it in o[:_JSON_MAX_ITEMS]:
                walk(it, depth + 1)

    walk(obj, 0)


def json_keys(obj: object) -> list[str]:
    """Object keys from a parsed JSON value (depth/fan-out bounded). Pure."""
    out: set[str] = set()
    _walk_json(obj, lambda k, _v: _add_token(out, k))
    return sorted(out)


def html_app_name(html: str) -> list[str]:
    """App-name value words from <title> / og:site_name / application-name, boilerplate dropped. Pure."""
    out: set[str] = set()
    for raw in [*_TITLE_RE.findall(html), *_META_NAME_RE.findall(html)]:
        for tok in _split_words(raw):
            if len(tok) >= _VALUE_MIN_LEN and tok not in _BOILERPLATE_WORDS and not tok.isdigit():
                out.add(tok)
    return sorted(out)


def stack_terms(tech: Iterable[str], header_signals: Iterable[str]) -> list[str]:
    """Bare value words from detected tech + header signals (cdn:cloudflare → cloudflare). Pure."""
    out: set[str] = set()
    for t in tech:
        out.update(tok for tok in _split_words(str(t)) if len(tok) >= _VALUE_MIN_LEN)
    for s in header_signals:
        term = str(s).split(":", 1)[-1].strip().lower()
        if len(term) >= _VALUE_MIN_LEN:
            out.add(term)
    return sorted(out)


def extract_param_names(*, links: list[str], jsluice_recs: list[dict],
                        html_bodies: list[str], json_objs: list[object]) -> list[str]:
    """Aggregate parameter-name candidates from links + JS (jsluice) + HTML forms + JSON keys. Pure."""
    out = {*query_param_names(links), *jsluice_param_names(jsluice_recs)}
    for h in html_bodies:
        out.update(html_field_names(h))
    for o in json_objs:
        out.update(json_keys(o))
    return sorted(out)


def extract_value_words(*, links: list[str], html_bodies: list[str], tech: Iterable[str],
                        header_signals: Iterable[str], group_apex: str | None) -> list[str]:
    """Aggregate high-semantic value words: query values + app name + stack terms + apex label. Pure."""
    out = {*query_param_values(links), *stack_terms(tech, header_signals)}
    for h in html_bodies:
        out.update(html_app_name(h))
    if group_apex:
        for label in group_apex.lower().split(".")[:-1]:   # drop the TLD label
            out.update(tok for tok in _split_words(label)
                       if len(tok) >= _VALUE_MIN_LEN and tok not in _BOILERPLATE_WORDS)
    return sorted(out)


def extract_emails(text: str) -> list[str]:
    """Emails in a body (bounded regex), dropping example/asset-TLD false positives. Pure."""
    out: set[str] = set()
    for m in _EMAIL_RE.finditer(text):
        addr = m.group(0).lower()
        domain = addr.rsplit("@", 1)[1]
        if domain in _EMAIL_DENY_DOMAINS or domain.rsplit(".", 1)[-1] in _EMAIL_DENY_TLDS:
            continue
        out.add(addr)
    return sorted(out)


def mailto_links(urls: Iterable[str]) -> list[str]:
    """Email addresses from mailto: links in the corpus. Pure."""
    out: set[str] = set()
    for u in urls:
        m = _MAILTO_RE.search(u)
        if m:
            out.add(m.group(1).lower())
    return sorted(out)


def _add_identity(out: set[str], raw: str) -> None:
    """Add a username-ish value if it survives the precision filters (no spaces/@/opaque). Pure."""
    v = raw.strip()
    if (_VALUE_MIN_LEN <= len(v) <= _TOKEN_MAX_LEN and not v.isdigit()
            and " " not in v and "@" not in v and not _looks_opaque(v)):
        out.add(v.lower())


def identity_field_values(json_objs: Iterable[object]) -> list[str]:
    """Username-ish VALUES of identity-named keys (user/login/owner/…) in parsed JSON bodies. Pure."""
    out: set[str] = set()

    def visit(k: str, v: object) -> None:
        if isinstance(v, str) and any(f in k.lower() for f in _IDENTITY_FIELDS):
            _add_identity(out, v)

    for o in json_objs:
        _walk_json(o, visit)
    return sorted(out)


def extract_identities(*, links: list[str], html_bodies: list[str],
                       json_objs: list[object]) -> dict[str, list[str]]:
    """Aggregate identities: emails (mailto + bodies) and usernames (email local-parts + JSON fields). Pure."""
    emails = set(mailto_links(links))
    for h in html_bodies:
        emails.update(extract_emails(h))
    usernames = {*identity_field_values(json_objs), *(e.split("@", 1)[0] for e in emails)}
    return {"emails": sorted(emails), "usernames": sorted(usernames)}


def passive_delta(passive: list[str], crawled: list[str]) -> list[str]:
    """OSINT URLs (gau/urlfinder) whose bodies the crawl never fetched.

    `denoise(passive)` minus what the crawler already requested — the only URLs a
    separate downloader needs (the crawler is the downloader for everything it
    reached). Static assets are dropped; order is preserved.
    """
    already = set(crawled)
    return [u for u in denoise(tools.dedupe(passive)) if u not in already]


def _tech_match(key: str, tags: list[str]) -> bool:
    """True if `key` occurs as a WHOLE WORD in any tag (word-boundary, case-insensitive). Avoids the
    substring false positives of a bare `in`: 'java' matches 'Apache Tomcat (Java)' but NOT
    'JavaScript', and 'next' matches 'Next.js' but NOT 'Nextcloud' — so a client-side-JS app is never
    mis-gated onto the Java/JSP wordlist + .jsp/.do extensions. `key`/`tags` are lowercase by the
    callers; re.escape keeps dotted/hyphenated keys (asp.net, microsoft-iis) literal. Pure."""
    pat = re.compile(rf"\b{re.escape(key)}\b")
    return any(pat.search(tag) for tag in tags)


def tech_extensions(tech: list[str], mapping: dict[str, list[str]]) -> list[str]:
    """File extensions to fuzz, derived from detected tech (case-insensitive, whole-word match)."""
    tags = [t.lower() for t in tech]
    out: list[str] = []
    for key, exts in mapping.items():
        if _tech_match(key, tags):
            out += exts
    return tools.dedupe(out)


def roles_for_tech(tech: list[str], mapping: Mapping[str, str | tuple[str, ...]]) -> list[str]:
    """Wordlist ROLE names selected by detected tech (case-insensitive, whole-word match), deduped in
    mapping order. A mapping value is one role (str) or several (tuple). Pure."""
    tags = [t.lower() for t in tech]
    out: list[str] = []
    for key, roles in mapping.items():
        if _tech_match(key, tags):
            out += [roles] if isinstance(roles, str) else list(roles)
    return tools.dedupe(out)


def assemble_wordlist(custom: list[str], layers: list[tuple[list[str], int | None]]) -> list[str]:
    """Assemble a content-discovery wordlist in priority order: the CUSTOM layer (app-derived) in FULL
    and FIRST, then each (lines, cap) layer truncated to its top-`cap` (None = full). Assetnote/OLFA
    lists are ~frequency-ordered, so a top-N cap keeps the high-signal head and drops the blow-up tail.
    Deduped, first-occurrence order preserved. Pure."""
    out = list(custom)
    for lines, cap in layers:
        out += lines if cap is None else lines[:cap]
    return tools.dedupe(out)


# response-header NAME present ⇒ signal (httpx normalizes header keys to snake_case lowercase)
_HEADER_PRESENT = {
    "x_cache": "cache", "cf_cache_status": "cache", "x_varnish": "cache",
    "x_proxy_cache": "cache", "x_drupal_cache": "cache", "age": "cache",
    "cf_ray": "cdn:cloudflare", "x_amz_cf_id": "cdn:cloudfront",
    "x_fastly_request_id": "cdn:fastly", "x_akamai_transformed": "cdn:akamai",
    "x_sucuri_id": "waf:sucuri", "x_amzn_waf_action": "waf:aws",
    "strict_transport_security": "hsts", "content_security_policy": "csp",
}
_SERVER_FAMILIES = ("nginx", "apache", "iis", "envoy", "openresty", "caddy", "litespeed")
_POWERED_BY = {"php": "stack:php", "asp.net": "stack:aspnet", "express": "stack:express", "next.js": "stack:nextjs"}
_COOKIE_STACK = {"jsessionid": "stack:java", "phpsessid": "stack:php", "asp.net_sessionid": "stack:aspnet",
                 "laravel_session": "stack:laravel", "_rails": "stack:rails", "csrftoken": "stack:django"}


def header_signals(headers: dict) -> list[str]:
    """Actionable signals from a response-header dict (httpx's `header`) — a small controlled
    vocabulary downstream stages can gate tools on, like `tech`. Encodes PRESENCE/family
    (cache · cdn:* · backend:* · stack:* · waf:* · hsts/csp), never volatile values (Date,
    Set-Cookie value, request ids). Returns a sorted list (JSON-friendly)."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    sig = {s for name, s in _HEADER_PRESENT.items() if name in h}
    server = h.get("server", "")
    sig |= {f"backend:{fam}" for fam in _SERVER_FAMILIES if fam in server}
    powered = h.get("x_powered_by", "")
    sig |= {s for key, s in _POWERED_BY.items() if key in powered}
    cookies = h.get("set_cookie", "")
    sig |= {s for name, s in _COOKIE_STACK.items() if name in cookies}
    return sorted(sig)


def parse_ferox(out: str) -> list[dict]:
    """Keep feroxbuster --json 'response' records (drop stats/garbage); normalize."""
    records: list[dict] = []
    for ln in out.splitlines():
        text = ln.strip()
        if not text:
            continue
        try:
            r = json.loads(text)
        except json.JSONDecodeError:
            continue
        if r.get("type") != "response":
            continue
        records.append({
            "url": r.get("url"),
            "status": r.get("status"),
            "length": r.get("content_length"),
            "words": r.get("word_count"),
            "lines": r.get("line_count"),
        })
    return records


def ferox_transport_failed(out: str) -> bool:
    """True iff feroxbuster's statistics record proves it reached NOTHING — every request failed at
    the transport layer (successes 0, errors > 0). That's the signature of an https endpoint a modern
    TLS client refuses to handshake (legacy renegotiation / weak DH — e.g. zero.webappsecurity.com:
    `-k` only skips cert *verification*, not these). Pure.

    Deliberately narrow so the http fallback never fires spuriously: it returns False for a scan that
    'connected but found nothing' (successes > 0), and for a healthy scan killed by --time-limit
    (feroxbuster emits NO statistics record when interrupted, only `response` lines)."""
    for ln in out.splitlines():
        text = ln.strip()
        if not text:
            continue
        try:
            r = json.loads(text)
        except json.JSONDecodeError:
            continue
        if r.get("type") == "statistics":
            return (r.get("successes") or 0) == 0 and (r.get("errors") or 0) > 0
    return False


def select_new_urls(records: list[dict], seen: set[str], *, cap: int) -> list[str]:
    """feroxbuster hits worth downloading+mining: 2xx/3xx URLs not already in the response store.

    Dedups (order-preserving), drops anything in `seen` (already fetched) and non-2xx/3xx, and caps
    the count to `cap` to bound a round's download fan-out — logging a WARNING when the cap actually
    bites (no silent truncation). The frontier the content-discovery fixpoint feeds back. Pure."""
    out: list[str] = []
    picked: set[str] = set()
    for r in records:
        url, status = r.get("url"), r.get("status") or 0
        if not url or url in seen or url in picked or not (200 <= status < 400):  # noqa: PLR2004
            continue
        picked.add(url)
        out.append(url)
    if len(out) > cap:
        log.warning("⚠ content fixpoint: capping round delta %d→%d new url(s)", len(out), cap)
        return out[:cap]
    return out


def merge_ferox_by_url(acc: list[dict], new: list[dict]) -> list[dict]:
    """Accumulate feroxbuster `response` records across fixpoint rounds, deduped by url (first
    wins), order preserved — the per-round merge that yields the single content_discovery.jsonl. Pure."""
    seen = {r.get("url") for r in acc}
    out = list(acc)
    for r in new:
        u = r.get("url")
        if u and u not in seen:
            seen.add(u)
            out.append(r)
    return out


def parse_shortscan(out: str) -> list[str]:
    """Fuzz words from shortscan --output json 'result' records (schema: v0.9.2).

    Per confirmed hit: the resolved full name + its basename when `fullmatch`
    (autocomplete/rainbow recovered the real filename), else the 8.3 `shortfile`
    prefix. All lowercased and deduped — surface words for content_discovery, not
    URLs. 'status'/'statistics' records and unparseable lines are dropped.
    """
    words: list[str] = []
    for ln in out.splitlines():
        text = ln.strip()
        if not text:
            continue
        try:
            r = json.loads(text)
        except json.JSONDecodeError:
            continue
        if r.get("type") != "result":
            continue
        full = (r.get("fullname") or "").strip()
        if full:
            words.append(full)
            words.append(full.rsplit(".", 1)[0])
        short = (r.get("shortfile") or "").strip()
        if short:
            words.append(short)
    return tools.dedupe(w.lower() for w in words if w.strip())


def parse_shortscan_findings(out: str) -> list[dict]:
    """Findings from shortscan `status` records with `vulnerable: true` — the IIS 8.3 short-name
    (tilde) enumeration is itself an information-disclosure finding (one per vulnerable host). Pure.
    (Surface words come from `parse_shortscan`; this is the dual-role's findings half.)"""
    findings: list[dict] = []
    for ln in out.splitlines():
        text = ln.strip()
        if not text:
            continue
        try:
            r = json.loads(text)
        except json.JSONDecodeError:
            continue
        if r.get("type") == "status" and r.get("vulnerable"):
            findings.append({
                "type": "iis-tilde-enumeration",
                "title": "IIS 8.3 short-name (tilde) enumeration",
                "severity": "low",
                "target": r.get("url"),
                "server": r.get("server"),
                "evidence": "shortscan: vulnerable",
                "source": "shortscan",
            })
    return findings


# wpprobe `scan -o json` schema (Chocapikk/wpprobe): per site
#   {url, plugins:{<slug>:[{version, severities:[{<severity>:[{auth_type, vulnerabilities:[
#       {cve, cve_link, title, cvss_score, cvss_vector}]}]}]}]}, themes:{…same…}}
# A detected component with NO known vuln has no `severities` (just a version) → no finding emitted.
_WPPROBE_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _wpprobe_sort_key(f: dict) -> tuple:
    """Triage order for wpprobe findings: by severity (critical first), then CVSS desc, then CVE. Pure."""
    try:
        cvss = float(f.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    return (_WPPROBE_SEV_RANK.get((f.get("severity") or "").lower(), 9), -cvss, f.get("cve") or "")


def _wpprobe_component_vulns(versions: Any) -> Iterable[tuple]:
    """Yield (version, severity, auth_type, vuln) for one component's version groups. Guards the outer
    list; trusts wpprobe's well-formed inner schema (severities → {<sev>:[{auth_type,vulnerabilities}]}).
    Pure generator."""
    if not isinstance(versions, list):
        return
    for vg in versions:
        version = vg.get("version")
        for sev_entry in vg.get("severities") or ():
            for severity, groups in sev_entry.items():
                for ag in groups:
                    for v in ag.get("vulnerabilities") or ():
                        yield version, severity, ag.get("auth_type"), v


def parse_wpprobe(text: str) -> list[dict]:
    """wpprobe `scan -o json` → one finding record per (component, version, CVE). Handles plugins AND
    themes, a single-site object (`-u`) or a list (`-f`); guards the outer shapes (no crash on garbage).
    version-only entries (a detected component with no known vuln) yield nothing — findings-only. Pure."""
    try:
        data = json.loads(text) if text.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return []
    out: list[dict] = []
    for site in data if isinstance(data, list) else [data]:
        if not isinstance(site, dict):
            continue
        url = site.get("url", "")
        for kind in ("plugin", "theme"):
            coll = site.get(f"{kind}s")
            for slug, versions in (coll.items() if isinstance(coll, dict) else []):
                for version, severity, auth, v in _wpprobe_component_vulns(versions):
                    if isinstance(v, dict):
                        out.append({
                            "type": f"wordpress-{kind}-vuln", "kind": kind,
                            "component": str(slug), "version": version, "severity": severity,
                            "auth": auth, "cve": v.get("cve"), "cvss": v.get("cvss_score"),
                            "title": v.get("title"), "cve_link": v.get("cve_link"),
                            "target": url, "source": "wpprobe",
                        })
    out.sort(key=_wpprobe_sort_key)
    return out


def parse_eyewitness_csv(text: str) -> list[dict]:
    """Default-credential leads from an EyeWitness `Requests.csv` (pure).

    Columns: Protocol,Port,Domain,URL,Resolved,Request Status,Title,Category,Default Creds,
    Screenshot Path, Source Path. EyeWitness matches the page source against its signatures.txt
    and writes the known default creds (or 'None') into the "Default Creds" column. Keeps only
    rows with a real match → {url, title, category, creds}. NB: these are signature-based LEADS
    (a page that ships with known defaults), not verified logins.
    """
    findings: list[dict] = []
    for row in csv.DictReader(io.StringIO(text)):
        creds = (row.get("Default Creds") or "").strip()
        if creds and creds.lower() != "none":
            findings.append({
                "url": (row.get("URL") or "").strip(),
                "title": (row.get("Title") or "").strip(),
                "category": (row.get("Category") or "").strip(),
                "creds": creds,
            })
    return findings


def parse_katana(out: str) -> list[str]:
    """URLs from katana -j JSONL output: the `endpoint` nested under each `request`.

    katana emits one JSON object per crawled request ({"request":{"endpoint":...}}).
    Unparseable lines and records without an endpoint are skipped; order is preserved
    (dedup happens at the merge in crawl())."""
    urls: list[str] = []
    for rec in _jsonl_str(out):
        endpoint = (rec.get("request") or {}).get("endpoint")
        if endpoint:
            urls.append(endpoint)
    return urls


# --- request catalog (requests.jsonl) — full HTTP requests, not bare URLs ----------------------
# A bare URL can only describe a GET query (reconftw's limit); to fuzz POST/JSON/body/header the DAST
# needs the METHOD + CONTENT-TYPE + BODY. katana already discovers this (-fx forms, -xhr, request
# bodies) — parse_katana (URL-only) just discards it. These pure helpers build per-request records
# {method,url,headers,body,params[loc],raw,sources}; `raw` is the full HTTP request nuclei `-im jsonl`
# fuzzes (proven against nuclei -dast -dfp — see the nuclei-dast-jsonl note). For a request katana
# captured we reuse its own `raw`; for synthesized ones (forms, param discovery, API specs) we build
# the raw ourselves with build_raw_request. Param locations: query (URL), body (urlencoded), json keys.
def build_raw_request(method: str, url: str, headers: Mapping[str, str] | None = None,
                      body: str = "") -> str:
    """A raw HTTP/1.1 request string (CRLF) for nuclei `-im jsonl`: request line + Host + caller
    headers + blank line + body. Host is derived from the URL (never duplicated from caller headers);
    with a body and no caller Content-Type one is guessed from the body shape (JSON vs urlencoded) and
    Content-Length added. Pure; the format validated to drive DAST fuzzing of every request part."""
    method = (method or "GET").upper()
    parts = urlsplit(url if "://" in url else f"http://{url}")
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    hdrs: dict[str, str] = {str(k): str(v) for k, v in (headers or {}).items()
                            if k and str(k).lower() != "host"}
    if body and not any(k.lower() == "content-type" for k in hdrs):
        hdrs["Content-Type"] = ("application/json" if body.lstrip()[:1] in "{["
                                else "application/x-www-form-urlencoded")
    if body and not any(k.lower() == "content-length" for k in hdrs):
        hdrs["Content-Length"] = str(len(body.encode("utf-8")))
    lines = [f"{method} {target} HTTP/1.1", f"Host: {parts.netloc}",
             *(f"{k}: {v}" for k, v in hdrs.items())]
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _qs_pairs(qs: str) -> list[tuple[str, str]]:
    """(name, value) pairs of a query/urlencoded string, first value per name kept, blanks kept
    ('a=1&b=&a=2' → [('a','1'),('b','')]). Pure — the param surface WITH the observed values."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for k, v in parse_qsl(qs, keep_blank_values=True):
        if k and k not in seen:
            seen.add(k)
            out.append((k, v))
    return out


def _qs_names(qs: str) -> list[str]:
    """Parameter names of a query/urlencoded-body string ('a=1&b=2' → ['a','b']), deduped. Pure."""
    return [k for k, _ in _qs_pairs(qs)]


def request_params(url: str, body: str = "", content_type: str = "") -> list[dict]:
    """Known parameters of a request with their LOCATION and observed VALUE: query (URL), body
    (urlencoded) or json (JSON object keys; content-type or body shape decides). The value (blank when
    none was seen) is kept so normalize_request can re-seed a request with a realistic token instead of
    an empty `name=`. Pure — the param surface the DAST/param steps reason about."""
    out: list[dict] = [{"name": n, "loc": "query", "value": v}
                       for n, v in _qs_pairs(urlsplit(url if "://" in url else f"http://{url}").query)]
    b = body.strip()
    if b:
        if "json" in content_type.lower() or b[:1] in "{[":
            obj = _try_json(b)
            if isinstance(obj, dict):
                out += [{"name": str(k), "loc": "json", "value": v} for k, v in obj.items()]
        else:
            out += [{"name": n, "loc": "body", "value": v} for n, v in _qs_pairs(b)]
    return out


# Placeholder value for a known param with no observed value: a non-empty token fuzzes better than a
# bare `name=` (sqlmap's heuristic/boolean tests and dalfox's reflection probes need something in the
# slot; nuclei -dast fuzzes regardless). Observed values are reused when present (see normalize_request).
PARAM_SEED_VALUE = "1"


def _seeded(value: object, fallback: str = PARAM_SEED_VALUE) -> str:
    """An observed value as a string, or the seed when it's blank/None. Pure."""
    s = "" if value is None else str(value)
    return s or fallback


def normalize_request(rec: dict) -> dict:
    """Realign a catalog request's url/body/raw so EVERY known param (rec['params']) is actually present
    in the request the scanners fuzz. This closes the gap where merge_requests unions params across
    duplicate shapes but keeps a param-LESS variant's url/raw (first-wins): the merged record then
    advertised params nuclei/dalfox/sqlmap never saw — a bare `GET /catalog` fed to sqlmap exits with
    'no testable parameter', and the real injection point (ginandjuice's `category`) was never tested.

    Query params are folded into the URL query, body params into a urlencoded body, json params into a
    JSON body; each gets its observed value when known, else PARAM_SEED_VALUE. A request with no
    query/body/json params is returned UNCHANGED, preserving an authoritative `raw` (e.g. katana's own).
    Pure."""
    params = rec.get("params") or []
    q = [p for p in params if p.get("loc") == "query"]
    b = [p for p in params if p.get("loc") == "body"]
    j = [p for p in params if p.get("loc") == "json"]
    if not (q or b or j):
        return rec
    method = (rec.get("method") or "GET").upper()
    url = rec.get("url") or ""
    parts = urlsplit(url if "://" in url else f"http://{url}")
    # query: keep existing pairs (re-seeding blanks), then append known query params not already present
    qval = {p["name"]: p.get("value") for p in q}
    pairs = [(k, v or _seeded(qval.get(k))) for k, v in _qs_pairs(parts.query)]
    have = {k for k, _ in pairs}
    pairs += [(p["name"], _seeded(p.get("value"))) for p in q if p["name"] not in have]
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(pairs), parts.fragment))
    headers = dict(rec.get("headers") or {})
    body = rec.get("body") or ""
    if j:                                              # json body wins when json params are present
        obj = _try_json(body) if body.strip()[:1] in "{[" else None
        obj = dict(obj) if isinstance(obj, dict) else {}
        for p in j:
            if not obj.get(p["name"]):
                obj[p["name"]] = p.get("value") if p.get("value") not in (None, "") else PARAM_SEED_VALUE
        body = json.dumps(obj)
        headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        headers["Content-Type"] = "application/json"
    elif b:
        bval = {p["name"]: p.get("value") for p in b}
        bpairs = [(k, v or _seeded(bval.get(k))) for k, v in _qs_pairs(body)]
        bhave = {k for k, _ in bpairs}
        bpairs += [(p["name"], _seeded(p.get("value"))) for p in b if p["name"] not in bhave]
        body = urlencode(bpairs)
        headers = {k: v for k, v in headers.items() if k.lower() not in ("content-type", "content-length")}
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return {**rec, "url": new_url, "body": body, "raw": build_raw_request(method, new_url, headers, body)}


def _form_field_names(form: dict) -> list[str]:
    """Input/field names of a katana -fx form record, tolerant of its schema (a list under
    parameters/fields/inputs, each a name string or a {name|key:…} dict). Pure."""
    raw = form.get("parameters") or form.get("fields") or form.get("inputs") or []
    names: list[str] = []
    for it in raw if isinstance(raw, list) else []:
        if isinstance(it, str):
            names.append(it)
        elif isinstance(it, dict) and (n := it.get("name") or it.get("key")):
            names.append(str(n))
    return tools.dedupe([n for n in names if n])


def _katana_forms(rec: dict, base_url: str) -> list[dict]:
    """Synthesize catalog requests from a record's -fx forms: GET → field names as query params,
    POST/other → urlencoded body. action resolved against the page URL. Skips shapes we can't read
    (no crash). Pure."""
    out: list[dict] = []
    for form in rec.get("forms") or []:
        if not isinstance(form, dict):
            continue
        action = form.get("action") or base_url
        url = urljoin(base_url, str(action)) if base_url else str(action)
        method = (form.get("method") or "GET").upper()
        names = _form_field_names(form)
        if not (url and names):
            continue
        if method == "GET":
            full = url + ("&" if "?" in url else "?") + "&".join(f"{n}=" for n in names)
            out.append({"method": "GET", "url": full, "headers": {}, "body": "",
                        "params": [{"name": n, "loc": "query"} for n in names],
                        "raw": build_raw_request("GET", full), "sources": ["katana-form"]})
        else:
            ct = {"Content-Type": "application/x-www-form-urlencoded"}
            body = "&".join(f"{n}=" for n in names)
            out.append({"method": method, "url": url, "headers": ct, "body": body,
                        "params": [{"name": n, "loc": "body"} for n in names],
                        "raw": build_raw_request(method, url, ct, body), "sources": ["katana-form"]})
    return out


def parse_katana_requests(out: str, *, source: str = "katana") -> list[dict]:
    """Catalog records from katana -j JSONL — preserves the METHOD/BODY/headers/forms that
    parse_katana (URL-only) drops. Each crawled request → one record (its own `raw` reused when present
    — authoritative for nuclei — else built); each -fx form → a synthesized request. Order preserved
    (dedup at merge_requests). Pure."""
    records: list[dict] = []
    for rec in _jsonl_str(out):
        req = rec.get("request") or {}
        endpoint = req.get("endpoint")
        if endpoint:
            method = (req.get("method") or "GET").upper()
            headers = req.get("headers") or req.get("header") or {}
            headers = headers if isinstance(headers, dict) else {}
            body = req.get("body") or ""
            ct = next((str(v) for k, v in headers.items() if str(k).lower() == "content-type"), "")
            records.append({
                "method": method, "url": endpoint, "headers": headers, "body": body,
                "params": request_params(endpoint, body, ct),
                "raw": req.get("raw") or build_raw_request(method, endpoint, headers, body),
                "sources": [source],
            })
        records += _katana_forms(rec, endpoint or "")
    return records


def request_key(rec: dict) -> tuple:
    """Dedup key for a catalog request: (method, path-template). Collapses /user/123 vs /user/456 and
    ignores query/values but keeps GET≠POST distinct — one representative per request SHAPE;
    merge_requests unions the params discovered across the collapsed shapes. Pure."""
    return (rec.get("method") or "GET").upper(), path_template(rec.get("url") or "")


def merge_requests(records: Iterable[dict]) -> list[dict]:
    """Dedup catalog requests by request_key (first wins for url/headers/body): union `sources`, union
    `params` by (name,loc) preferring a NON-BLANK observed value, then realign each merged record's
    url/body/raw to its unioned params via normalize_request — otherwise first-wins keeps a param-less
    variant's raw and the unioned params would never reach the fuzzers. Deterministic order. Pure — the
    catalog merge across crawl/headless/specs/params."""
    by_key: dict[tuple, dict] = {}
    for r in records:
        key = request_key(r)
        if key not in by_key:
            by_key[key] = {**r, "sources": sorted(set(r.get("sources") or [])),
                           "params": [dict(p) for p in (r.get("params") or [])]}
            continue
        cur = by_key[key]
        cur["sources"] = sorted(set(cur["sources"]) | set(r.get("sources") or []))
        idx = {(p.get("name"), p.get("loc")): p for p in cur["params"]}
        for p in r.get("params") or []:
            k = (p.get("name"), p.get("loc"))
            if k not in idx:
                np = dict(p)
                cur["params"].append(np)
                idx[k] = np
            elif not idx[k].get("value") and p.get("value"):
                idx[k]["value"] = p.get("value")        # upgrade a blank value with an observed one
    return [normalize_request(r) for r in
            sorted(by_key.values(), key=lambda r: (r.get("url") or "", r.get("method") or ""))]


def _url_to_get_request(url: str, source: str) -> dict:
    """A URL-only discovery (passive/crawley/feroxbuster/jsluice) as a GET catalog request — its query
    string becomes its known params. Pure."""
    return {"method": "GET", "url": url, "headers": {}, "body": "",
            "params": request_params(url), "raw": build_raw_request("GET", url), "sources": [source]}


def catalog_records(request_recs: Iterable[dict], get_urls: Iterable[str], in_scope: set[str],
                    schemes: dict[str, str], *, get_source: str = "url") -> list[dict]:
    """Assemble the per-app request catalog: the full request records (crawl/headless/API spec) plus
    the URL-only sources folded in as GET requests — every url scheme-normalized to the reachable
    scheme (force_scheme: the http fallback a strict-TLS scanner needs) and in-scope-filtered, then
    deduped by request shape (merge_requests). Only the `url` field is re-schemed; `raw` is HTTP/1.1
    (path + Host, scheme-agnostic) so it's unaffected. Pure."""
    def keep(url: str) -> bool:
        return bool(url) and (not in_scope or url_host(url) in in_scope)
    recs: list[dict] = []
    for r in request_recs:
        u = force_scheme(r.get("url") or "", schemes)
        if keep(u):
            recs.append({**r, "url": u})
    for raw_url in get_urls:
        u = force_scheme(raw_url, schemes)
        if keep(u):
            recs.append(_url_to_get_request(u, get_source))
    return merge_requests(recs)


def jsluice_requests(records: Iterable[dict], source_urls: dict[str, str]) -> list[dict]:
    """Catalog requests from jsluice `urls` records — recovers the METHOD / contentType / body params
    jsluice already extracts from fetch/XHR/ajax calls (mine_responses keeps only the URL). Relative
    urls are resolved against the JS file's SOURCE url (source_urls keyed by the extracted file stem);
    a url that stays relative (no source) is skipped — it can't be fuzzed without a host. bodyParams →
    a JSON or urlencoded body skeleton for body-bearing methods. Pure."""
    out: list[dict] = []
    for r in records:
        raw_url = (r.get("url") or "").strip()
        if not raw_url or raw_url[:1] in "#?" or raw_url.startswith(("data:", "javascript:", "mailto:")):
            continue
        base = source_urls.get(Path(r.get("filename") or "").stem, "")
        url = urljoin(base, raw_url) if base else raw_url
        if "://" not in url:                          # unresolved relative → no host → can't fuzz
            continue
        method = (r.get("method") or "GET").upper()
        ct = str(r.get("contentType") or "")
        hdrs = r.get("headers")
        headers = {str(k): str(v) for k, v in hdrs.items()} if isinstance(hdrs, dict) else {}
        body_names = [str(p) for p in (r.get("bodyParams") or []) if p]
        if body_names and method in {"POST", "PUT", "PATCH", "DELETE"}:
            if "json" in ct.lower():
                headers.setdefault("Content-Type", "application/json")
                body = json.dumps(dict.fromkeys(body_names, ""))
            else:
                headers.setdefault("Content-Type", ct or "application/x-www-form-urlencoded")
                body = "&".join(f"{n}=" for n in tools.dedupe(body_names))
        else:
            body = ""
        out.append(_synth_request(method, url, headers, body, "jsluice"))
    return out


class _FormParser(HTMLParser):
    """Collect <form> elements (method, action, field names) from an HTML body. stdlib-only."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "form":
            self._cur = {"method": (a.get("method") or "GET"), "action": a.get("action") or "",
                         "fields": []}
        elif tag in ("input", "select", "textarea", "button") and self._cur is not None and a.get("name"):
            self._cur["fields"].append(a["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def close(self) -> None:
        super().close()
        if self._cur is not None:                     # flush an unclosed trailing <form>
            self.forms.append(self._cur)
            self._cur = None


def parse_forms(html: str) -> list[dict]:
    """`<form>` elements of an HTML body → [{method, action, fields:[name]}]. Pure (best-effort: a
    malformed body yields whatever parsed)."""
    parser = _FormParser()
    try:
        parser.feed(html)
        parser.close()
    except (ValueError, AssertionError):
        pass
    return parser.forms


def html_form_requests(bodies_dir: Path, source_urls: dict[str, str]) -> list[dict]:
    """Catalog requests from the <form> elements in the downloaded HTML corpus — recovers POST/GET form
    endpoints, INCLUDING on the unlinked pages feroxbuster discovered (their bodies are stored, but
    katana -fx only saw the pages katana itself crawled). action resolved against the page's source url
    (source_urls by file stem). GET → fields as query, others → urlencoded body. Pure (reads files)."""
    out: list[dict] = []
    if not bodies_dir.exists():
        return out
    for path in sorted(bodies_dir.glob("*.html")):
        base = source_urls.get(path.stem, "")
        if not base:                                  # no source url → can't resolve a relative action
            continue
        for form in parse_forms(path.read_text(encoding="utf-8", errors="replace")):
            names = tools.dedupe([str(n) for n in form["fields"] if n])
            action = urljoin(base, form["action"]) if form["action"] else base
            if not names or "://" not in action:
                continue
            if form["method"].upper() == "GET":
                full = action + ("&" if "?" in action else "?") + "&".join(f"{n}=" for n in names)
                out.append(_synth_request("GET", full, {}, "", "html-form"))
            else:
                out.append(_synth_request(form["method"], action,
                                          {"Content-Type": "application/x-www-form-urlencoded"},
                                          "&".join(f"{n}=" for n in names), "html-form"))
    return out


def count_hrefs(html: str) -> int:
    """Number of <a href=...> links in raw HTML — the 'traditional' link-surface baseline.

    Counts only anchor links (not <link href>, <area>, etc.); used by the JS-render
    classification to compare the raw HTML surface against the JS-parsed one."""
    return len(re.findall(r"<a\b[^>]*\bhref\s*=", html, flags=re.IGNORECASE))


def has_thin_shell_marker(html: str) -> bool:
    """Whether the HTML carries a JS-framework thin-shell marker (Next/Nuxt/Angular/React)."""
    blob = html.lower()
    return any(m in blob for m in THIN_SHELL_MARKERS)


def is_js_rendered(raw_href: int, fx: int, crawley: int, *, marker: bool) -> bool:
    """Classify (NO browser) whether an app's surface lives in JS ⇒ a headless crawl pays off.

    Validated signal from the crawler benchmark (handoff §6): headless wins only when the
    non-headless LINK surface (raw <a href> and crawley) is small yet JS-parse (katana -fx /
    jsluice) finds far more — or a thin-shell framework marker is present. A healthy link
    surface means ordinary crawling already saw the site (traditional, or a React/finto-SPA that
    behaves traditionally), so a browser launch would be pure cost. Thresholds are tunable.
    """
    link = max(raw_href, crawley)
    if link >= JS_LINK_CEILING:
        return False                              # link-crawl already found a healthy surface
    if marker:
        return True                               # thin shell + framework marker ⇒ JS-rendered
    return fx >= JS_FX_MIN and fx >= JS_FX_RATIO * max(link, 1)


def is_js_url(url: str) -> bool:
    """True if the URL points at a JavaScript file (path ends .js, ignoring the query)."""
    last = url.split("?", 1)[0].rsplit("/", 1)[-1]
    return last.lower().endswith(".js")


def http_body(text: str) -> str:
    """Body of a katana/httpx -srd stored response (URL + request + response headers +
    body). Returns the text after the response headers — the lines after the first blank
    line that follows the 'HTTP/...' status line. '' if no response line is found."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("HTTP/")), None)
    if start is None:
        return ""
    for j in range(start + 1, len(lines)):
        if not lines[j].strip():
            return "\n".join(lines[j + 1:]).strip("\n")
    return ""


# --- helpers ---
def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _slug(text: str, *, maxlen: int = 24) -> str:
    """Filesystem-safe, readable slug from a host/apex: lowercase, keep [a-z0-9.-], everything else
    collapses to '-'; trimmed; '' → 'app'. Cosmetic prefix for app_id (the hash carries identity)."""
    s = re.sub(r"[^a-z0-9.-]+", "-", text.lower())
    s = re.sub(r"-{2,}", "-", s).strip("-.")[:maxlen].strip("-.")
    return s or "app"


def _app_id(anchor_key: str, anchor_value: str) -> str:
    """Stable, collision-free, PSEUDO-READABLE app id: ``<slug>-<hash8>``. The slug is the group's
    apex (favicon-anchored) or host (host-anchored) for at-a-glance recognition; the 8-hex hash of
    the full anchor preserves identity — two groups can't share an anchor, so the dir name is stable
    across runs and never collides (even when the slug repeats, e.g. two ``appspot.com`` apps).
    Filesystem-safe. NOT derived from a mutable host/title string — only the stable cluster anchor."""
    readable = anchor_value.split("@", 1)[-1] if anchor_key == "favicon" else anchor_value
    digest = hashlib.sha1(f"{anchor_key}:{anchor_value}".encode()).hexdigest()[:8]  # noqa: S324
    return f"{_slug(readable)}-{digest}"


def _run(tool: str, cmd: list[str], *, stdin: str, dest: Path, label: str) -> str:
    """Run a tool over `stdin`, write its stdout to `dest` exactly once, return stdout.

    `dest` is either a raw path (intermediate provenance) or a canonical artifact
    name. No-op on empty input. Logs one INFO line per invocation; in verbose mode
    logs the exact command, streams the tool's stderr live, and dumps its stdout.
    """
    if not stdin.strip():
        log.debug("  · skip %s/%s (no input)", tool, label)
        return ""
    log.info("  → %s (%s) — %d input(s)", tool, label, len(_lines(stdin)))
    verbose = is_verbose()
    out = tools.run(cmd, stdin=stdin, stream_stderr=verbose)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(out, encoding="utf-8")
    log.info("    %s (%s) → %d line(s) → %s", tool, label, len(_lines(out)), dest.name)
    if verbose and out.strip():
        log.debug("    stdout:\n%s", out.rstrip())
    return out


# --- breadth sub-phases (each reads/writes via disk → independently rerunnable) ---
def provision_wl(activity: Activity) -> None:
    """BREADTH — resolve global wordlist ROLES into wl_global/<role>.txt (env/discovery/BYO).

    Environment- and provider-agnostic: roles map to candidate filenames across collections,
    found under PTFLOW_WORDLISTS / common locations, or supplied per-role (PTFLOW_WL_<ROLE>) / by
    dropping a file in wl_global/. Best-effort — unresolved roles just leave the dependent
    steps to run on the generated wl_custom (the pipeline never fails for missing wordlists).
    """
    resolved = wordlists.provision(activity)
    log.info("  → wordlists: %d role(s) provisioned%s", len(resolved),
             f" ({', '.join(sorted(resolved))})" if resolved else " — none found, degrading")


def _raw(activity: Activity, tool: str, label: str) -> Path:
    return activity.asset_discovery_raw(tool) / f"{label}.txt"


def expand(activity: Activity) -> None:
    """Phase 1 — expand the scope: split by kind, TLS/PTR harvest, wildcard enum.

    Reads scope/scope_init.txt; writes scope/scope_urls.txt, scope/scope_ip.txt
    (mapcidr-expanded), tls_names.txt, and scope/scope_dns.txt (the full candidate
    name set that `resolve` consumes).
    """
    targets = scope.parse_scope(activity.scope_init.read_text(encoding="utf-8", errors="replace"))
    urls, dns, wildcards, ips_cidr = split_scope(targets)
    tools.write_lines(activity.scope_urls, urls)

    scope_ips = _lines(
        _run("mapcidr", ["mapcidr", "-silent"],
             stdin="\n".join(ips_cidr), dest=_raw(activity, "mapcidr", "expand"), label="expand")
    ) or ips_cidr
    tools.write_lines(activity.scope_ip, scope_ips)

    dns_names = list(dns)
    naabu_tls = _lines(
        _run("naabu",
             ["naabu", "-silent", "-top-ports", NAABU_TLS_TOP_PORTS, "-exclude-cdn",
              "-c", NAABU_CONC, "-rate", NAABU_RATE],
             stdin="\n".join(scope_ips), dest=_raw(activity, "naabu", "tls_ports"), label="tls_ports")
    )
    tls_names = _lines(
        _run("tlsx", ["tlsx", "-san", "-cn", "-silent", "-resp-only"],
             stdin="\n".join(naabu_tls),
             dest=activity.asset_discovery_canonical("tls_names.txt"), label="from_ports")
    )
    dns_names += _lines(
        _run("dnsx", ["dnsx", "-silent"],
             stdin="\n".join(tls_names), dest=_raw(activity, "dnsx", "tls_resolve"), label="tls_resolve")
    )
    dns_names += _lines(
        _run("dnsx", ["dnsx", "-ptr", "-resp-only", "-silent"],
             stdin="\n".join(scope_ips), dest=_raw(activity, "dnsx", "ptr"), label="ptr")
    )
    for wc in wildcards:
        dns_names += _lines(
            _run("assetfinder", ["assetfinder", "-subs-only"],
                 stdin=wc, dest=_raw(activity, "assetfinder", wc), label=wc)
        )
    if wildcards:
        dns_names += _lines(
            _run("subfinder", ["subfinder", "-silent"],
                 stdin="\n".join(wildcards), dest=_raw(activity, "subfinder", "wildcards"),
                 label="wildcards")
        )

    tools.write_lines(activity.scope_dns, [*dns_names, *wildcards])


def resolve(activity: Activity) -> None:
    """Phase 2 — resolve candidate names to live subdomains; consolidate IPs.

    Reads scope/scope_dns.txt, scope/scope_ip.txt, tls_names.txt; writes
    subdomains.txt, unique_ips.txt, domain_ip_map.txt.
    """
    canon = activity.asset_discovery_canonical
    all_dns = "\n".join(tools.read_lines(activity.scope_dns))
    subdomains = _lines(
        _run("shuffledns", ["shuffledns", "-mode", "resolve", "-r", RESOLVERS, "-silent"],
             stdin=all_dns, dest=canon("subdomains.txt"), label="resolve")
    )
    if not subdomains:
        subdomains = _lines(
            _run("dnsx", ["dnsx", "-silent"],
                 stdin=all_dns, dest=canon("subdomains.txt"), label="resolve_fallback")
        )

    tls_names = tools.read_lines(canon("tls_names.txt"))
    a_input = "\n".join([*subdomains, *tls_names])
    resolved_ips = _lines(
        _run("dnsx", ["dnsx", "-a", "-resp-only", "-silent"],
             stdin=a_input, dest=_raw(activity, "dnsx", "a_responly"), label="a_responly")
    )
    tools.write_lines(canon("unique_ips.txt"), [*resolved_ips, *tools.read_lines(activity.scope_ip)])
    _run("dnsx", ["dnsx", "-a", "-resp", "-nc", "-silent"],
         stdin=a_input, dest=canon("domain_ip_map.txt"), label="a_resp")


def portscan(activity: Activity) -> None:
    """Phase 3 — FAST web-port scan: WEB_PORTS → honeypot filter → naabu_web.txt (the web target set
    httpx probes). Reads unique_ips.txt; writes honeypots.txt + naabu_web.txt (canonical).

    Scans the curated ~250 HTTP(S)-bearing ports (WEB_PORTS), NOT nmap's generic top-1k — so httpx
    sees web apps on uncommon ports (5601/8161/9200/7001/…) that top-1k would miss, while staying
    fast. The expensive full 65535-port scan is split into the SPANNING `portscan_full` stage so it
    no longer serializes in front of httpx→cluster→loops (the observed ~15-min breadth block);
    non-web ports are picked up there ∥ in the background (→ nerva). The naabu stdout is provenance
    (raw/naabu/), consumed in memory by honeypot_split/select_web_ports."""
    canon = activity.asset_discovery_canonical
    unique_ips = tools.read_lines(canon("unique_ips.txt"))
    scanned = _lines(
        _run("naabu", ["naabu", "-silent", "-p", WEB_PORTS, "-exclude-cdn",
                       "-c", NAABU_CONC, "-rate", NAABU_RATE],
             stdin="\n".join(unique_ips), dest=_raw(activity, "naabu", "web"), label="web")
    )
    valid_ips, honeypots = honeypot_split(scanned)
    tools.write_lines(canon("honeypots.txt"), honeypots)
    tools.write_lines(canon("naabu_web.txt"), select_web_ports(scanned, valid_ips))


def portscan_full(activity: Activity) -> None:
    """SPANNING — full 65535-port scan on the valid (non-honeypot) IPs → naabu_full.txt, which feeds
    nerva (non-HTTP service fingerprint). Launched after `portscan`, runs ∥ clustering + the per-app
    loops, joined at the fan-in — off the critical path, since breadth→cluster→loops only needs the
    fast top-1k web set (naabu_web.txt). Recomputes the valid set from disk (unique_ips minus
    honeypots) — only strings cross the stage boundary."""
    canon = activity.asset_discovery_canonical
    honeypots = set(tools.read_lines(canon("honeypots.txt")))
    valid = [ip for ip in tools.read_lines(canon("unique_ips.txt")) if ip not in honeypots]
    _run("naabu", ["naabu", "-silent", "-top-ports", "full", "-exclude-cdn",
                   "-c", NAABU_CONC, "-rate", NAABU_RATE],
         stdin="\n".join(valid), dest=canon("naabu_full.txt"), label="full")


def httpx_fingerprint(activity: Activity) -> None:
    """Phase 4a — HTTP fingerprinting (httpx) → httpx_full_metadata.jsonl + unique_webapps.txt.

    Independent of nerva, so the two fingerprint stages run in parallel. SCOPE HYGIENE: httpx flags
    CDN/cloud/WAF hosts (cdncheck), and split_cdn_ip_records drops the raw-IP probes of that shared
    PROVIDER infra (out of scope — the IP is the provider's, not the target's) while KEEPING the
    CDN-fronted hostnames and any explicitly-in-scope IP. So the raw httpx dump (everything probed)
    is provenance under raw/httpx/; the FILTERED records are the canonical metadata downstream reads
    (cluster/nuclei/screenshot never see the dropped IPs); the dropped set is kept as the audit
    deliverable excluded_cdn.jsonl (RoE evidence of what we deliberately skipped).
    """
    canon = activity.asset_discovery_canonical
    httpx_input = "\n".join(tools.dedupe([
        *tools.read_lines(canon("tls_names.txt")),
        *tools.read_lines(canon("subdomains.txt")),
        *tools.read_lines(canon("naabu_web.txt")),  # fast top-1k web set (full scan is now spanning)
        *tools.read_lines(canon("honeypots.txt")),
    ]))
    out = _run(
        "httpx",
        [HTTPX, "-silent", "-sc", "-cl", "-td", "-title", "-ip", "-hash", "sha256",
         "-favicon", "-location", "-fr", "-irh", "-j"],
        stdin=httpx_input, dest=activity.asset_discovery_raw("httpx") / "fingerprint.jsonl",
        label="fingerprint",
    )
    records = _jsonl_str(out)  # tolerant: a stray non-JSON line from httpx must not crash this CORE stage
    kept, dropped = split_cdn_ip_records(records, set(tools.read_lines(activity.scope_ip)))
    tools.write_jsonl(canon("httpx_full_metadata.jsonl"), kept)
    tools.write_jsonl(canon("excluded_cdn.jsonl"), dropped)
    if dropped:
        log.info("  → scope: excluded %d raw-IP CDN/cloud target(s) (hostnames kept) → excluded_cdn.jsonl",
                 len(dropped))
    tools.write_lines(canon("unique_webapps.txt"), select_unique_webapps(kept))


def ingest_httpx(activity: Activity) -> None:
    """WEB-MODE breadth entry (the `webscan` pipeline) — fingerprint a PRE-AGGREGATED web target list,
    skipping ALL scope expansion (subdomain/DNS/TLS OSINT) and active network scan (portscan/nerva/
    whole-scope nuclei). Reads the scope URLs verbatim (scheme://host[:port]) and probes them with httpx
    honouring the input scheme via ``-nfs`` — so an explicit http/https + port from the hand-off is
    respected (unlike the discovery fingerprint, which defaults to https). Produces the SAME
    httpx_full_metadata.jsonl + unique_webapps.txt that ``cluster()`` and the per-app depth loops consume,
    so the rest of the external pipeline runs unchanged on top of it. Every in-scope host is treated as
    in-scope for the CDN filter (these ARE the chosen targets), so nothing is dropped."""
    canon = activity.asset_discovery_canonical
    targets = scope.parse_scope(activity.scope_init.read_text(encoding="utf-8", errors="replace"))
    tools.write_lines(activity.scope_urls, [t.raw for t in targets if t.kind == "url"])
    out = _run(
        "httpx",
        [HTTPX, "-silent", "-nfs", "-sc", "-cl", "-td", "-title", "-ip", "-hash", "sha256",
         "-favicon", "-location", "-fr", "-irh", "-j"],
        stdin="\n".join(t.raw for t in targets),
        dest=activity.asset_discovery_raw("httpx") / "ingest.jsonl", label="ingest",
    )
    records = _jsonl_str(out)
    kept, _ = split_cdn_ip_records(records, {t.normalized for t in targets})  # all targets are in-scope
    tools.write_jsonl(canon("httpx_full_metadata.jsonl"), kept)
    tools.write_lines(canon("unique_webapps.txt"), select_unique_webapps(kept))
    log.info("  → ingest — %d target(s) → %d live web app(s)", len(targets), len(kept))


def nerva_fingerprint(activity: Activity) -> None:
    """Phase 4b — non-HTTP service fingerprinting (nerva) → nerva_full_metadata.jsonl."""
    canon = activity.asset_discovery_canonical
    _run("nerva", ["nerva", "--json"],
         stdin="\n".join(tools.read_lines(canon("naabu_full.txt"))),
         dest=canon("nerva_full_metadata.jsonl"), label="json")


def nuclei_scope(activity: Activity) -> None:
    """SPANNING (whole-scope) — full-template nuclei over the entire discovered surface.

    ONE process over the deduped scope (subdomains + webapps) with a single global rate
    cap (-rl) — gentler and more efficient than per-app, which would multiply traffic on
    shared backends and reload templates per process. Runs ∥ clustering + the per-app
    loops, joined at the fan-in. Subsumes the old per-tag takeover scan. Updates the
    nuclei-templates first (`-ut`), then scans with -duc (no redundant check mid-run).
    """
    canon = activity.asset_discovery_canonical
    targets = tools.dedupe([*tools.read_lines(canon("subdomains.txt")),
                            *tools.read_lines(canon("unique_webapps.txt"))])
    if not targets:
        log.debug("  · skip nuclei_scope (no targets)")
        return
    log.info("  → nuclei -ut (update templates)")
    tools.run(["nuclei", "-ut"], stream_stderr=is_verbose())
    _run("nuclei",
         ["nuclei", "-stats", "-nmhe", "-c", NUCLEI_CONC, "-bs", NUCLEI_BULK, "-rl", NUCLEI_RL,
          "-timeout", NUCLEI_TIMEOUT, "-retries", NUCLEI_RETRIES, "-j", "-silent", "-duc"],
         stdin="\n".join(targets), dest=activity.findings / "nuclei_scope.jsonl", label="scope")


# --- clustering (surfagr.sh port) ---
def _cluster_signals(record: dict) -> dict:
    """Clustering signals for one httpx record (pure), tuned PRECISION-FIRST.

    Goal: never merge logically-different apps (over-merge is a correctness bug here — merged
    apps share one endpoints.txt and get cross-fuzzed); over-split (a duplicate scanned twice)
    is only wasted work. So we cluster on APP-IDENTITY signals, NOT infrastructure (cert/IP,
    which routinely span distinct apps under one company). Each value is a bucket key; None =
    no edge. The fuzzy app-fingerprint signals (fav, sig) are APEX-SCOPED — keyed by (value,
    apex) — so they can never merge across organizations, only sibling subdomains of one apex.
    """
    host = url_host(record.get("url") or "")
    apex_of = apex(host)
    digests = record.get("hash") or {}
    favicon = record.get("favicon")
    favicon = favicon if favicon not in (None, "", "0") else None
    status = record.get("status_code") or 0
    body = digests.get("body_sha256") if 200 <= status < 400 else None  # noqa: PLR2004
    title, server = record.get("title") or "", record.get("webserver") or ""
    signature = f"{title}|{record.get('content_length')}|{server}"
    return {
        "host": host, "apex": apex_of,
        "final": host or None,                              # GLOBAL, safe: redirect-converged final host
        "body": body or None,                               # GLOBAL, safe: identical 2xx/3xx bytes (demoted)
        "fav": (favicon, apex_of) if favicon else None,     # apex-scoped app fingerprint
        "sig": (signature, apex_of) if (title or server) else None,  # apex-scoped, non-blank only
    }


# Only APP-IDENTITY edges. Dropped vs the first v2: `cert` and `iht` (ip+header+tech) — those are
# INFRASTRUCTURE (one cert / one box routinely fronts distinct apps) and over-merge. `final`+`body`
# are cross-apex safe; `fav`+`sig` are apex-scoped so they never merge across organizations.
_CLUSTER_EDGES = ("final", "body", "fav", "sig")


def _connected_components(n: int, to_union: list[list[int]]) -> list[list[int]]:
    """Union-find: merge each index-list in `to_union`, return components as sorted index
    lists ordered by smallest index (deterministic)."""
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path halving
            x = parent[x]
        return x

    for idxs in to_union:
        for j in idxs[1:]:
            parent[find(j)] = find(idxs[0])
    comps: dict[int, list[int]] = {}
    for i in range(n):
        comps.setdefault(find(i), []).append(i)
    return sorted((sorted(c) for c in comps.values()), key=lambda c: c[0])


def cluster_partition(records: list[dict]) -> list[list[int]]:
    """Partition httpx records into application-groups (pure, deterministic).

    For each signal, records sharing a value are unioned — UNLESS the value spans more than
    GENERIC_MAX_APEXES distinct apexes (a generic default/error page or parking redirect →
    demoted, no merge). The apex-scoped signals (fav, sig) sit in one apex by construction, so
    demotion only ever bites the global `body` edge. Components are the groups, sorted.
    """
    sigs = [_cluster_signals(r) for r in records]
    to_union: list[list[int]] = []
    for edge in _CLUSTER_EDGES:
        buckets: dict[object, list[int]] = {}
        for i, s in enumerate(sigs):
            if s[edge] is not None:
                buckets.setdefault(s[edge], []).append(i)
        for value, idxs in buckets.items():
            if len({sigs[i]["apex"] for i in idxs}) > GENERIC_MAX_APEXES:
                log.debug("  · demote generic %s value (%r) across many apexes", edge, value)
            else:
                to_union.append(idxs)
    return _connected_components(len(records), to_union)


def _cluster_anchor(members: list[dict]) -> tuple[str, str]:
    """Stable, collision-free id anchor for a group: plurality (favicon, apex), else host.

    A (favicon, apex) pair is unique across groups — two groups sharing it would have merged via
    the apex-scoped favicon edge — and intrinsic, so it stays stable when a minority member joins
    or leaves. Failing that, a host is in exactly one group, so plurality host is also unique.
    Ties broken deterministically (highest count, then value).
    """
    sigs = [_cluster_signals(r) for r in members]
    favs = Counter(s["fav"] for s in sigs if s["fav"])  # keys are (favicon, apex)
    if favs:
        favicon, apex_of = max(favs, key=lambda k: (favs[k], k))
        return "favicon", f"{favicon}@{apex_of}"
    hosts = Counter(s["host"] for s in sigs)
    return "host", max(hosts, key=lambda v: (hosts[v], v))


def _scheme_pins(activity: Activity) -> dict[str, str]:
    """Bare host → explicit scheme for every scope entry the operator wrote WITH a scheme
    (http://h / https://h). httpx defaults to https and ignores the input scheme, so an explicit
    `http://` is lost by the time cluster builds hosts.txt; this re-applies it on the scan hosts."""
    if not activity.scope.exists():
        return {}
    pins: dict[str, str] = {}
    for t in scope.parse_scope(activity.scope.read_text(encoding="utf-8", errors="replace")):
        if t.kind == "url":
            pins[url_host(t.raw)] = t.raw.split("://", 1)[0].lower()
    return pins


def cluster(activity: Activity) -> list[str]:
    """Group httpx vhosts into scans/<app_id>/ via union-find over APP-IDENTITY signals.

    Port of surfagr.sh, precision-first. Connected-components partition (cluster_partition) over
    redirect-final host, exact body hash, and apex-scoped favicon / root-fingerprint — chosen so
    logically-different apps are NEVER merged (infra signals like cert/IP are deliberately not
    used). When in doubt it does NOT merge: a duplicate scanned twice is cheaper than two apps
    fused into one workspace. Each group becomes one application-group workspace with meta.json +
    hosts.txt. Returns the sorted app_ids.
    """
    canon = activity.asset_discovery_canonical
    records = [r for r in tools.read_jsonl(canon("httpx_full_metadata.jsonl")) if r.get("url")]
    pins = _scheme_pins(activity)  # honor an explicit scope scheme on the scan hosts (see _scheme_pins)

    app_ids: list[str] = []
    for idxs in cluster_partition(records):
        members = [records[i] for i in idxs]
        key, value = _cluster_anchor(members)
        app_id = _app_id(key, value)
        rep = min(members, key=lambda r: r["url"])
        # scheme is honored at OUTPUT only — clustering keys on scheme-independent signals
        # (favicon/body/redirect) and the id anchor on url_host, so pinning never shifts a group/id.
        urls = tools.dedupe(force_scheme(r["url"], pins) for r in members)
        # per-host response-body hash → lets per-app stages dedup same-backend hosts (domain+IP,
        # http+https) while keeping distinct environments (staging vs test). See dedup_by_body.
        body_by_host = {force_scheme(r["url"], pins): (r.get("hash") or {}).get("body_sha256") for r in members}
        # raw response headers (httpx -irh) kept per host for later reasoning; header_signals is the
        # curated, gate-on-able view (cache/cdn/backend/stack/waf), unioned over the group's hosts.
        headers_by_host = {force_scheme(r["url"], pins): (r.get("header") or {}) for r in members}
        signals = sorted({s for hdrs in headers_by_host.values() for s in header_signals(hdrs)})
        if len(urls) > CLUSTER_MAX_HOSTS:
            log.warning("⚠ cluster %s has %d hosts — possible residual collision (id_anchor=%s)",
                        app_id, len(urls), key)
        ws = activity.app(app_id).ensure()
        workspace.write_meta(
            ws.meta,
            {
                "app_id": app_id,
                "id_anchor": key,  # signal the STABLE id is derived from (not necessarily the merge reason)
                "signature": f"{rep.get('title') or ''}|{rep.get('content_length')}|{rep.get('webserver') or ''}",
                "title": rep.get("title"),
                "webserver": rep.get("webserver"),
                "content_length": rep.get("content_length"),
                "status_code": rep.get("status_code"),
                "tech": rep.get("tech") or [],
                "hosts": urls,
                "body_by_host": body_by_host,
                "headers_by_host": headers_by_host,
                "header_signals": signals,
            },
        )
        tools.write_lines(ws.hosts, urls)
        log.info("  → app %s [id:%s] — %d host(s)", app_id, key, len(urls))
        app_ids.append(app_id)
    return sorted(app_ids)


# --- depth sub-phases (per app group; chain via the app workspace on disk) ---
def _eyewitness_cmd() -> list[str] | None:
    """How to invoke EyeWitness, or None if unavailable (best-effort, like shortscan/wpprobe).

    Not a single binary (Selenium app): PTFLOW_EYEWITNESS — a full launch command, e.g.
    "python3 /opt/EyeWitness/Python/EyeWitness.py" or a venv wrapper — takes precedence; else a
    pip-installed `eyewitness` on PATH. The operator owns the Python/deps/chromedriver behind it.
    """
    explicit = os.environ.get("PTFLOW_EYEWITNESS")
    if explicit:
        return shlex.split(explicit)
    found = shutil.which("eyewitness")
    if found:
        return [found]
    # known install: a dedicated venv python + EyeWitness.py (PATH-independent)
    venv_py = _EYEWITNESS_DIR / ".venv" / "bin" / "python"
    script = _EYEWITNESS_DIR / "Python" / "EyeWitness.py"
    return [str(venv_py), str(script)] if venv_py.exists() and script.exists() else None


def reconcile_by_url(index_entries: list[tuple[str, str]], url_to_app: dict[str, str]) -> dict[str, str]:
    """Map app_id → file by crossing a `-srd` index ([(file, url)]) with our url→app_id candidate map.
    URLs are matched trailing-slash-insensitively; first file per app wins (one candidate/group). Pure."""
    norm = {u.rstrip("/"): a for u, a in url_to_app.items()}
    out: dict[str, str] = {}
    for file, url in index_entries:
        app_id = norm.get(url.rstrip("/"))
        if app_id and app_id not in out:
            out[app_id] = file
    return out


def _eyewitness_batch(activity: Activity, url_to_app: dict[str, str]) -> None:
    """OPTIONAL — ONE EyeWitness run over every candidate URL (one per group): a unified report.html
    + Requests.csv. The signature-based default-cred leads are split back per group (url→app_id) →
    scans/<app_id>/default_creds.jsonl. Best-effort (no-op if EyeWitness isn't resolvable); batching a
    single run avoids the per-group Selenium startup cost."""
    cmd = _eyewitness_cmd()
    if cmd is None:
        log.debug("  · skip eyewitness (not installed)")
        return
    out_dir = activity.screenshots / "eyewitness"
    if out_dir.exists():
        shutil.rmtree(out_dir)  # EyeWitness wants a fresh -d (else it prompts / appends)
    target_file = activity.tmp / "eyewitness_targets.txt"
    tools.write_lines(target_file, list(url_to_app))
    log.info("  → eyewitness — %d url(s), batched", len(url_to_app))
    tools.run([*cmd, "--web", "-f", str(target_file), "-d", str(out_dir), "--no-prompt",
               "--timeout", EYEWITNESS_TIMEOUT], stream_stderr=is_verbose(), reap_group=True)
    csv_path = out_dir / "Requests.csv"
    rows = (parse_eyewitness_csv(csv_path.read_text(encoding="utf-8", errors="replace"))
            if csv_path.exists() else [])
    norm = {u.rstrip("/"): a for u, a in url_to_app.items()}
    by_app: dict[str, list[dict]] = {}
    for row in rows:
        app_id = norm.get((row.get("url") or "").rstrip("/"))
        if app_id:
            by_app.setdefault(app_id, []).append(row)
    n = sum(tools.write_jsonl(activity.app(a).canonical("default_creds.jsonl"), leads)
            for a, leads in by_app.items())
    if n:
        log.info("    eyewitness → report.html · %d default-cred lead(s) across %d group(s)", n, len(by_app))


def _screenshot_fingerprint(record: dict) -> dict:
    """Slim an httpx `-ss -j` record to the EyeWitness-style fingerprint shown beside a screenshot:
    status, title, web server, tech, content-length, IP, favicon + curated header signals. Pure."""
    return {
        "url": record.get("url"),
        "status": record.get("status_code"),
        "title": record.get("title"),
        "webserver": record.get("webserver"),
        "tech": record.get("tech") or [],
        "content_length": record.get("content_length"),
        "ip": record.get("host_ip"),
        "favicon": record.get("favicon"),
        "header_signals": header_signals(record.get("header") or {}),
    }


def screenshot_all(activity: Activity) -> None:
    """SPANNING post-cluster — ONE batched screenshot run over a single best-host candidate per app
    group, so the tools' NATIVE aggregate reports give a UNIFIED gallery (no hand-built HTML).

    httpx `-ss … -j` over all candidates screenshots each best host AND fingerprints it (status,
    title, web server, tech, content-length, IP, favicon, headers — like EyeWitness shows beside each
    shot). The gallery (screenshot.html) + per-host PNGs + index land under screenshots/screenshot/;
    the `-j` fingerprint is captured, reconciled by URL, and written per group to
    scans/<app_id>/screenshot.json (+ a consolidated fingerprints.jsonl). EyeWitness (optional) adds
    its own report.html + default-cred leads. Each PNG is reconciled to scans/<app_id>/screenshot.png
    by URL (via the index). Runs ∥ the per-app loops (cluster_scope): reads only meta/hosts, writes
    distinct filenames — no race.
    """
    apps = activity.list_apps()
    url_to_app = {t: ws.root.name for ws in apps if (t := best_host(tools.read_lines(ws.hosts)))}
    if not url_to_app:
        log.debug("  · skip screenshot (no candidates)")
        return
    store = activity.screenshots
    store.mkdir(parents=True, exist_ok=True)
    log.info("▶ screenshot — %d candidate(s) (one per group), batched", len(url_to_app))
    out = tools.run(
        [HTTPX, "-ss", "-system-chrome", "-no-screenshot-full-page", "-st", SCREENSHOT_TIMEOUT,
         "-silent", "-srd", str(store), "-svrc",
         # fingerprint each candidate too (EyeWitness-style), captured from the -j stream:
         "-sc", "-cl", "-title", "-td", "-server", "-ip", "-favicon", "-location", "-irh", "-j"],
        stdin="\n".join(url_to_app), stream_stderr=is_verbose(),
        reap_group=True,  # sweep any system-chrome the screenshot left behind, even on clean exit
    )
    norm = {u.rstrip("/"): a for u, a in url_to_app.items()}
    fp_by_app = {app: _screenshot_fingerprint(rec)
                 for rec in _jsonl_str(out)
                 if (app := norm.get((rec.get("url") or "").rstrip("/")))}
    shot_dir = store / "screenshot"
    by_app = reconcile_by_url(_store_index(shot_dir / "index_screenshot.txt"), url_to_app)
    n_shot = 0
    for ws in apps:
        rel = by_app.get(ws.root.name)
        if rel:  # COPY (the gallery keeps its own pngs) → per-group reconciled artifact
            shutil.copy(shot_dir / rel, ws.canonical("screenshot.png"))
            n_shot += 1
        else:
            ws.canonical("screenshot.failed").write_text("", encoding="utf-8")
        if (fp := fp_by_app.get(ws.root.name)):
            workspace.write_meta(ws.canonical("screenshot.json"), fp)  # per-group fingerprint
    tools.write_jsonl(shot_dir / "fingerprints.jsonl", list(fp_by_app.values()))
    log.info("    screenshot → %s · %d/%d shot · %d fingerprint(s)",
             shot_dir / "screenshot.html", n_shot, len(url_to_app), len(fp_by_app))
    _eyewitness_batch(activity, url_to_app)


def passive_probe(activity: Activity, app_id: str) -> None:
    """DEPTH 1 — passive URL discovery (gau + urlfinder) → endpoints_passive.txt."""
    ws = activity.app(app_id)
    domains = tools.dedupe([url_host(u) for u in tools.read_lines(ws.hosts)])
    gau = _lines(_run("gau", ["gau", "--threads", GAU_THREADS],
                      stdin="\n".join(domains), dest=ws.raw("gau") / "out.txt", label=app_id))
    urls = _lines(_run("urlfinder", ["urlfinder", "-silent"],
                       stdin="\n".join(domains), dest=ws.raw("urlfinder") / "out.txt", label=app_id))
    tools.write_lines(ws.canonical("endpoints_passive.txt"), [*gau, *urls])


def _scan_hosts(ws: AppWorkspace) -> list[str]:
    """The group's hosts deduped to one representative per distinct response body (see
    dedup_by_body) — one scan per backend/environment, not per hostname alias. Used by the
    active scanners (crawl, crawl_headless, content_discovery)."""
    body_by_host = workspace.read_meta(ws.meta).get("body_by_host") or {}
    return dedup_by_body(tools.read_lines(ws.hosts), body_by_host)


def _run_katana(ws: AppWorkspace, hosts: list[str], app_id: str) -> str:
    """katana — the DOWNLOADER crawler: parses JS endpoints (-jc/-jsl), known files
    (-kf all), forms (-fx), XHR/fetch url+method (-xhr), climbs parent paths (-pc),
    scoped to each host's fqdn (-fs fqdn), stores every response under responses/ (-srd)
    for offline mining. Returns katana's raw JSONL stdout — the caller derives BOTH the
    crawled URLs (parse_katana) and the request catalog (parse_katana_requests).

    -omit-raw is OFF (was on) so request.method/body/raw survive in the JSONL — the catalog
    needs them to fuzz POST/JSON, not just GET; -omit-body still trims the heavy response
    body (already on disk via -srd). Auth headers (PTFLOW_HTTP_HEADER) reach the logged-in surface."""
    cmd = ["katana", "-silent", "-j", "-jc", "-jsl", "-kf", "all", "-fx", "-xhr", "-pc",
           "-fs", "fqdn", "-d", KATANA_DEPTH, "-c", KATANA_CONC,
           "-omit-body", "-srd", str(ws.responses), *_header_flags("-H")]
    return _run("katana", cmd, stdin="\n".join(hosts),
                dest=ws.raw("katana") / "crawl" / "out.jsonl", label=app_id)


def _run_crawley(hosts: list[str], app_id: str) -> list[str]:
    """crawley — the second DISCOVERY crawler, run ∥ katana to widen the corpus.

    Takes a single positional URL (not stdin), so it runs once per host; bypasses
    _run like subjack/feroxbuster. Static URL discovery only (-all/-js scan css/js
    for endpoints) — it does NOT download bodies, so its URLs flow into fetch_delta
    as candidates (like the passive sources). -headless skips the HEAD pre-flight."""
    if not hosts:
        return []
    log.info("  → crawley (%s) — %d host(s)", app_id, len(hosts))
    urls: list[str] = []
    for host in hosts:
        out = tools.run(
            [CRAWLEY, "-headless", "-depth", CRAWLEY_DEPTH, "-workers", CRAWLEY_WORKERS,
             "-all", "-js", "-robots", "crawl", "-delay", CRAWLEY_DELAY, "-silent", host],
            stream_stderr=is_verbose(),
        )
        urls += _lines(out)
    log.info("    crawley (%s) → %d url(s)", app_id, len(urls))
    return urls


def _stored_root_html(ws: AppWorkspace, hosts: list[str]) -> str:
    """Root-page HTML from katana's response store (fetch once) — for JS classification.

    Returns the body of the stored response whose URL is one of the app's host roots,
    or '' if none was stored. Reused instead of a fresh curl (the cheap crawl already
    fetched the root)."""
    roots = {h.rstrip("/") for h in hosts}
    for stored, url in _store_index(ws.responses / "index.txt"):
        # the -srd index can reference a body the store never wrote (empty/redirect response,
        # partial store) — skip a missing file instead of crashing, keep looking for a root
        if url.rstrip("/") in roots and Path(stored).is_file():
            return http_body(Path(stored).read_text(encoding="utf-8", errors="replace"))
    return ""


def crawl(activity: Activity, app_id: str) -> None:
    """DEPTH 2 — TWO crawlers in PARALLEL (TIER 0 cheap layer) + JS-render classification.

    katana (downloader) and crawley (second discovery engine) run concurrently against the
    group's hosts deduped by response body (_scan_hosts: one per backend, but distinct
    environments like staging vs test are still all crawled — their linked content differs).
    katana stores every response under responses/ (-srd) as the per-app
    corpus offline steps mine WITHOUT re-fetching; its URL output is JS-/form-enriched.
    crawley adds the URLs katana didn't reach. Their union plus the passive sources,
    denoised, is endpoints.txt; crawley's discovery is also persisted (endpoints_crawley.txt)
    so fetch_delta downloads the bodies only it found.

    Then it CLASSIFIES (no browser) whether the app's surface lives in JS — comparing the
    raw <a href> count + crawley against the JS-parsed (fx) count, plus thin-shell markers —
    and records the verdict in crawl_class.json. The gated headless pass (crawl_headless)
    reads it and only renders the apps that actually benefit.
    """
    ws = activity.app(app_id)
    hosts = _scan_hosts(ws)
    if hosts:
        ws.responses.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        katana_fut = pool.submit(_run_katana, ws, hosts, app_id)
        crawley_fut = pool.submit(_run_crawley, hosts, app_id)
        katana_out, crawley_urls = katana_fut.result(), crawley_fut.result()
    katana_urls = parse_katana(katana_out)
    tools.write_lines(ws.canonical("endpoints_crawley.txt"), crawley_urls)
    passive = tools.read_lines(ws.canonical("endpoints_passive.txt"))
    tools.write_lines(ws.canonical("endpoints.txt"),
                      denoise(tools.dedupe([*passive, *katana_urls, *crawley_urls])))
    # the request catalog: katana's method/body/forms/xhr (a GET-only URL list can't drive DAST of
    # POST/JSON). crawley/passive are URL-only → folded in later as GET requests by the catalog merge.
    n_req = tools.write_jsonl(ws.canonical("requests_crawl.jsonl"),
                              merge_requests(parse_katana_requests(katana_out)))
    log.debug("    catalog (%s) — %d request shape(s) from katana → requests_crawl.jsonl", app_id, n_req)

    root_html = _stored_root_html(ws, hosts)
    raw_href, marker = count_hrefs(root_html), has_thin_shell_marker(root_html)
    fx_n, cr_n = len(tools.dedupe(katana_urls)), len(tools.dedupe(crawley_urls))
    js_render = is_js_rendered(raw_href, fx_n, cr_n, marker=marker)
    workspace.write_meta(ws.canonical("crawl_class.json"), {
        "js_render": js_render, "raw_href": raw_href, "fx": fx_n, "crawley": cr_n,
        "thin_shell_marker": marker,
    })
    log.info("    classify (%s) — raw_href=%d fx=%d crawley=%d marker=%s → js_render=%s",
             app_id, raw_href, fx_n, cr_n, marker, js_render)


def crawl_headless(activity: Activity, app_id: str) -> None:
    """DEPTH 2b — headless katana, run ONLY on the JS-rendered bucket (TIER 1, gated).

    crawl classified each app (crawl_class.json). Traditional apps skip this entirely —
    headless is browser-backed and RAM-heavy (1-5 GB/host), so concurrent launches are
    capped process-wide (_HEADLESS_SLOTS). On a JS-rendered app it renders the SPA (-hl)
    and extracts what link-crawling can't reach — JS-built routes and XHR/fetch URLs
    (-jsl/-xhr) — storing bodies under responses/headless/ for offline mining. -iqp folds
    query-param variants; -ct bounds runaway SPAs per host; -aff is OFF (never submit forms).
    Output endpoints_headless.txt is folded into the phase-3 wordlist (like endpoints_js.txt).
    """
    ws = activity.app(app_id)
    cls_path = ws.canonical("crawl_class.json")
    if not (cls_path.exists() and workspace.read_meta(cls_path).get("js_render")):
        log.debug("  · skip headless (not JS-rendered) for %s", app_id)
        return
    hosts = _scan_hosts(ws)  # one render per backend (headless is RAM-heavy); keeps distinct envs
    if not hosts:
        return
    store = ws.responses / "headless"
    store.mkdir(parents=True, exist_ok=True)
    cmd = ["katana", "-silent", "-j", "-hl", "-nos", "-jc", "-jsl", "-xhr", "-fx", "-iqp",
           "-fs", "fqdn", "-d", HEADLESS_DEPTH, "-c", HEADLESS_CONC, "-ct", HEADLESS_CT,
           "-rl", HEADLESS_RL, "-omit-body", "-srd", str(store), *_header_flags("-H")]
    log.info("  → headless (%s) — JS-rendered, %d host(s) (capped at %d concurrent)",
             app_id, len(hosts), HEADLESS_PARALLELISM)
    with _HEADLESS_SLOTS:
        out = _run("katana-headless", cmd, stdin="\n".join(hosts),
                   dest=ws.raw("katana") / "headless" / "out.jsonl", label=app_id)
    tools.write_lines(ws.canonical("endpoints_headless.txt"), denoise(parse_katana(out)))
    # headless catches the SPA's XHR/fetch API calls (often POST/JSON) link-crawling can't —
    # exactly the surface a GET-only fuzzer misses. Preserve their method/body in the catalog.
    n_req = tools.write_jsonl(ws.canonical("requests_headless.jsonl"),
                              merge_requests(parse_katana_requests(out, source="katana-headless")))
    log.debug("    catalog (%s) — %d request shape(s) from headless → requests_headless.jsonl",
              app_id, n_req)


def subenum(activity: Activity, app_id: str) -> None:
    """DEPTH 3 — passive subdomain enum (subfinder + dnsx live filter) → subs.txt.

    NOTE — overlaps with breadth on purpose, by different trigger: breadth `expand`
    enumerates subs of the input SCOPE WILDCARDS (feeds httpx); this enumerates subs
    of the clustered app's discovered APEXES (feeds `takeover`). Non-redundant when an
    apex was discovered (TLS SAN / PTR) or the scope had no wildcard — breadth never
    covered it. Redundant only when a scope wildcard == the app apex; no dedup against
    breadth's subdomains.txt today (a cheap future win; ties into a `recluster` step).
    """
    ws = activity.app(app_id)
    hosts = [url_host(u) for u in tools.read_lines(ws.hosts)]
    apexes = sorted({apex(h) for h in hosts if not is_ip(h)})
    subs = _lines(_run("subfinder", ["subfinder", "-silent"],
                       stdin="\n".join(apexes), dest=ws.raw("subfinder") / "out.txt", label=app_id))
    live = _lines(_run("dnsx", ["dnsx", "-silent"],
                       stdin="\n".join(subs), dest=ws.raw("dnsx") / "live.txt", label=app_id))
    tools.write_lines(ws.canonical("subs.txt"), live)


def takeover(activity: Activity, app_id: str) -> None:
    """DEPTH 4 — subdomain takeover check (subjack) over endpoints + subs → takeover.txt.

    subjack reads a host file (-w), not stdin, so it bypasses the _run helper.
    """
    ws = activity.app(app_id)
    candidates = tools.dedupe([
        *[url_host(u) for u in tools.read_lines(ws.hosts)],  # every group hostname (crawl may dedup)
        *[url_host(u) for u in tools.read_lines(ws.canonical("endpoints.txt"))],
        *tools.read_lines(ws.canonical("subs.txt")),
    ])
    if not candidates:
        log.debug("  · skip subjack (no candidates) for %s", app_id)
        return
    cand_file = ws.raw("subjack") / "candidates.txt"  # subjack -w input (provenance, not canonical)
    tools.write_lines(cand_file, candidates)
    log.info("  → subjack (%s) — %d candidate(s)", app_id, len(candidates))
    out = tools.run(
        ["subjack", "-w", str(cand_file), "-t", SUBJACK_THREADS, "-timeout", SUBJACK_TIMEOUT, "-ssl"],
        stream_stderr=is_verbose(),
    )
    raw_out = ws.raw("subjack") / "out.txt"
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    raw_out.write_text(out, encoding="utf-8")
    findings = [ln for ln in _lines(out) if "Not Vulnerable" not in ln]
    tools.write_lines(ws.canonical("takeover.txt"), findings)


# --- per-app depth (PHASE 1 corpus mining + PHASE 3 content discovery) — run after their barriers ---
def _try_json(text: str) -> object | None:
    """Parse a stored body as JSON when it plausibly is one (cheap guard + size cap), else None.

    _extract_bodies saves every non-JS body as .html (no .json), so a JSON API response is on disk
    as .html; this lets build_wordlist mine its keys/values without a separate store."""
    s = text.strip()
    if not s or s[0] not in "{[" or len(s) > _JSON_MAX_BYTES:
        return None
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None


def _group_apex(hosts: list[str]) -> str | None:
    """The group's representative apex (first non-IP host) — seeds app-name value words. Pure."""
    for h in hosts:
        host = url_host(h)
        if host and not is_ip(host):
            return apex(host)
    return None


def build_wordlist(activity: Activity, app_id: str) -> None:
    """PHASE 3 — OFFLINE lexicon extractor (fuzzing-prep): mine the crawled LINKS *and* the downloaded
    response BODIES into per-app wl_custom products.

    Reads the PHASE-1 corpus across the barrier — mine_responses already extracted it to raw/extracted/
    (read, never re-extract) and wrote endpoints_js.txt. Its only consumers are content_discovery /
    tech_enum / param_fuzz (all phase 3+), so it lives with the guessing. Emits four app-derived products
    (the traditional global/tech lists are layered in later by content_discovery):
      - seed.txt        endpoint candidates (tokenize_urls over the whole link surface)
      - params.txt      parameter-NAME candidates (query keys + jsluice query/body params + HTML form
                        fields + JSON object keys) → merged into param_fuzz custom-first
      - values.txt      high-semantic VALUE words (query values + app name + stack terms + apex label)
      - identities.txt  users/emails (emails + mailto + email local-parts + identity-field values)
    values.txt / identities.txt have no consumer yet — deliverables for the planned DAST; the filters
    lean precision-first. Reads phase-1 artifacts directly — the barrier guarantees they exist.
    """
    ws = activity.app(app_id)
    links = [*tools.read_lines(ws.canonical("endpoints.txt")),
             *tools.read_lines(ws.canonical("endpoints_headless.txt")),
             *tools.read_lines(ws.canonical("endpoints_js.txt"))]

    bodies = ws.raw("extracted")  # mine_responses already extracted the corpus here — read, don't re-extract
    js_files: list[str] = []
    html_bodies: list[str] = []
    json_objs: list[object] = []
    if bodies.exists():
        js_files = sorted(str(p) for p in bodies.glob("*.js"))
        for p in sorted(bodies.glob("*.html")):
            text = p.read_text(encoding="utf-8", errors="replace")
            obj = _try_json(text)
            (json_objs.append(obj) if obj is not None else html_bodies.append(text))
    recs = _jsluice_records(js_files)

    meta = workspace.read_meta(ws.meta)
    n_seed = tools.write_lines(ws.wl_custom / "seed.txt", tokenize_urls(links))
    n_par = tools.write_lines(ws.wl_custom / "params.txt", extract_param_names(
        links=links, jsluice_recs=recs, html_bodies=html_bodies, json_objs=json_objs))
    n_val = tools.write_lines(ws.wl_custom / "values.txt", extract_value_words(
        links=links, html_bodies=html_bodies, tech=meta.get("tech") or [],
        header_signals=meta.get("header_signals") or [], group_apex=_group_apex(meta.get("hosts") or [])))
    ids = extract_identities(links=links, html_bodies=html_bodies, json_objs=json_objs)
    n_id = tools.write_lines(ws.wl_custom / "identities.txt", sorted({*ids["emails"], *ids["usernames"]}))
    log.info("  → wordlist (%s) offline — seed %d · params %d · values %d · identities %d",
             app_id, n_seed, n_par, n_val, n_id)


# --- JS sourcemap extraction (point 5b) — recover original sources the crawlers can't see ---------
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def sourcemap_ref(js_text: str) -> str | None:
    """The `//# sourceMappingURL=<ref>` value in a JS body (LAST occurrence wins), or None. Pure."""
    matches = _SOURCEMAP_RE.findall(js_text)
    return matches[-1].strip() if matches else None


def decode_inline_sourcemap(ref: str) -> str | None:
    """An inline `data:` sourcemap ref → the decoded map JSON text (base64 or url-encoded), else None
    (a non-data ref is a URL fetched by fetch_delta). Pure."""
    if not ref.startswith("data:"):
        return None
    header, _, payload = ref.partition(",")
    if "base64" in header:
        try:
            return base64.b64decode(payload).decode("utf-8", "replace")
        except ValueError:               # binascii.Error subclasses ValueError
            return None
    return unquote(payload)


def parse_sourcemap(map_text: str) -> list[tuple[str, str]]:
    """A sourcemap's `sources`/`sourcesContent` → [(source_path, original_content)] for the entries
    that actually carry content (the reconstructable ones). Pure ([] on non-JSON / no content)."""
    try:
        data = json.loads(map_text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out: list[tuple[str, str]] = []
    for i, content in enumerate(contents):
        if isinstance(content, str) and content.strip():
            src = sources[i] if i < len(sources) and isinstance(sources[i], str) else f"source{i}"
            out.append((src, content))
    return out


def _stored_js(ws: AppWorkspace) -> list[tuple[str, str]]:
    """(url, body) for every stored JS response in the -srd corpus — offline. Skips missing files."""
    out: list[tuple[str, str]] = []
    for index in _all_store_indices(ws):
        for stored, url in _store_index(index):
            if not is_js_url(url):
                continue
            src = Path(stored)
            if src.is_file():
                out.append((url, http_body(src.read_text(encoding="utf-8", errors="replace"))))
    return out


def _sourcemap_fetch_targets(ws: AppWorkspace, have: set[str]) -> list[str]:
    """Absolute .map URLs referenced (non-inline) by the stored JS and NOT yet in the store — added to
    fetch_delta's download set so the maps land in the corpus (fetch-once). Pure-ish (reads disk)."""
    targets = [urljoin(url, ref) for url, body in _stored_js(ws)
               if (ref := sourcemap_ref(body)) and not ref.startswith("data:")]
    return [t for t in tools.dedupe(targets) if t not in have]


def _reconstruct_sourcemaps(ws: AppWorkspace) -> tuple[list[str], list[str]]:
    """OFFLINE — reconstruct original sources from every sourcemap in the corpus (fetched `.map`
    responses + inline `data:` maps in JS) into raw/extracted/sourcemap/*.js, so jsluice + the secret
    fleet mine the un-bundled source. Idempotent (skips existing). Returns (new source files, exposed
    map URLs)."""
    smdir = ws.raw("extracted") / "sourcemap"
    new_files: list[str] = []
    exposed: list[str] = []
    for index in _all_store_indices(ws):
        for stored, url in _store_index(index):
            src = Path(stored)
            if not src.is_file():
                continue
            body = http_body(src.read_text(encoding="utf-8", errors="replace"))
            if url.split("?", 1)[0].endswith(".map"):
                map_text: str | None = body
            elif is_js_url(url) and (ref := sourcemap_ref(body)) and ref.startswith("data:"):
                map_text = decode_inline_sourcemap(ref)
            else:
                continue
            sources = parse_sourcemap(map_text or "")
            if not sources:
                continue
            exposed.append(url)
            for path, content in sources:
                stem = re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_")[-60:] or "src"
                dst = smdir / f"{stem}-{hashlib.sha256(content.encode()).hexdigest()[:8]}.js"
                if dst.exists():
                    continue
                smdir.mkdir(parents=True, exist_ok=True)
                dst.write_text(content, encoding="utf-8")
                new_files.append(str(dst))
    return new_files, tools.dedupe(exposed)


def fetch_delta(activity: Activity, app_id: str) -> None:
    """PHASE 1 — download the discovery delta into the response store.

    The discovery sources whose bodies katana never downloaded — passive_probe
    (gau/urlfinder) and crawley (endpoints_crawley.txt) — are the only URLs a separate
    downloader needs; katana already stored everything IT fetched (responses/index.txt
    is that record). httpx fetches the delta's live URLs (dropping dead hosts) and
    stores their bodies under responses/osint/, so offline body-mining covers the
    archived/OSINT/crawley-only surface too. Needs crawl_headless so the crawl + headless
    stores are complete (so 'have' is right and we don't re-download what katana stored).
    """
    ws = activity.app(app_id)
    have = [url for idx in _all_store_indices(ws) for _, url in _store_index(idx)]  # already stored
    delta = passive_delta(
        [*tools.read_lines(ws.canonical("endpoints_passive.txt")),
         *tools.read_lines(ws.canonical("endpoints_crawley.txt"))],
        have,
    )
    # + the .map files referenced by the stored JS (point 5b) — fetch once so mine_responses can
    # reconstruct the original sources offline.
    delta = tools.dedupe([*delta, *_sourcemap_fetch_targets(ws, set(have))])
    if not delta:
        log.debug("  · skip osint fetch (empty delta) for %s", app_id)
        return
    store = ws.responses / "osint"
    store.mkdir(parents=True, exist_ok=True)
    _run("httpx", [HTTPX, "-silent", "-srd", str(store), "-rl", OSINT_FETCH_RL, *_header_flags("-H")],
         stdin="\n".join(delta), dest=ws.raw("httpx") / "osint" / "out.txt", label=app_id)


# --- API spec discovery (OpenAPI/Swagger/GraphQL) — the API surface a crawler/GET-fuzzer misses ----
def _schema_prop_names(schema: object) -> list[str]:
    """Top-level property names of an OpenAPI/JSON-schema object ({properties:{name:…}}). Pure."""
    props = schema.get("properties") if isinstance(schema, dict) else None
    return [str(k) for k in props] if isinstance(props, dict) else []


def _openapi_base(spec: dict, spec_url: str) -> str:
    """Base URL for a spec's operations: an absolute v3 server, else origin(spec_url) + (v3 relative
    server path | v2 basePath). Pure."""
    parts = urlsplit(spec_url if "://" in spec_url else f"https://{spec_url}")
    origin = f"{parts.scheme}://{parts.netloc}"
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        srv = str(servers[0].get("url") or "")
        if srv.startswith("http"):
            return srv.rstrip("/")
        if srv.startswith("/"):
            return origin + srv.rstrip("/")
    base_path = spec.get("basePath")
    if isinstance(base_path, str) and base_path.startswith("/"):
        return origin + base_path.rstrip("/")
    return origin


def _openapi_params(params: list) -> tuple[list[str], dict[str, str], list[str], list[str]]:
    """Classify an operation's parameters by location → (query names, header map, json body names,
    urlencoded body names). Path params are handled by the {..}→1 substitution, not here. Pure."""
    query: list[str] = []
    headers: dict[str, str] = {}
    json_names: list[str] = []
    form_names: list[str] = []
    for p in params:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        name, loc = str(p["name"]), p.get("in")
        if loc == "query":
            query.append(name)
        elif loc == "header":
            headers[name] = "x"
        elif loc == "body":                       # swagger v2 body parameter
            json_names += _schema_prop_names(p.get("schema"))
        elif loc == "formData":                   # swagger v2 form parameter
            form_names.append(name)
    return query, headers, json_names, form_names


def _openapi_request(base: str, path: str, method: str, params: list, op: dict) -> dict:
    """One catalog request from an OpenAPI/Swagger operation: path params → '1', query/header recorded,
    requestBody / in:body → a JSON or urlencoded body skeleton (keys, empty values). Pure."""
    query, headers, json_names, form_names = _openapi_params(params)
    body_def = op.get("requestBody")
    content = body_def.get("content") if isinstance(body_def, dict) else None
    if isinstance(content, dict):                 # openapi v3 requestBody
        json_names += _schema_prop_names((content.get("application/json") or {}).get("schema"))
        form_names += _schema_prop_names((content.get("application/x-www-form-urlencoded") or {}).get("schema"))
    url = base + re.sub(r"\{[^}]+\}", "1", path)   # any {path param} → placeholder
    if query:
        url += ("&" if "?" in url else "?") + "&".join(f"{n}=" for n in tools.dedupe(query))
    if json_names:
        headers.setdefault("Content-Type", "application/json")
        body = json.dumps(dict.fromkeys(tools.dedupe(json_names), ""))
    elif form_names:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        body = "&".join(f"{n}=" for n in tools.dedupe(form_names))
    else:
        body = ""
    return _synth_request(method, url, headers, body, "openapi")


def is_openapi(obj: object) -> bool:
    """Whether a parsed JSON body looks like an OpenAPI/Swagger spec (has openapi|swagger + paths)."""
    return (isinstance(obj, dict) and bool(obj.get("openapi") or obj.get("swagger"))
            and isinstance(obj.get("paths"), dict))


def expand_openapi(spec: object, spec_url: str, *, cap: int) -> list[dict]:
    """Expand an OpenAPI v3 / Swagger v2 JSON spec into catalog request records — one per operation
    (method x path), capped. Handles shared path-item params + per-operation params. Pure."""
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _openapi_base(spec, spec_url)
    out: list[dict] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters")
        shared = shared if isinstance(shared, list) else []
        for method in ("get", "post", "put", "patch", "delete"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            op_params = op.get("parameters")
            op_params = op_params if isinstance(op_params, list) else []
            out.append(_openapi_request(base, str(path), method, [*shared, *op_params], op))
            if len(out) >= cap:
                return out
    return out


def api_spec(activity: Activity, app_id: str) -> None:
    """PHASE 1 — discover API specs (OpenAPI/Swagger JSON) + GraphQL endpoints and expand them into the
    request catalog (requests_api.jsonl).

    The richest source of method+body+param surface — exactly the API endpoints a link-crawler and a
    GET-only fuzzer miss. Probes a fixed set of well-known spec paths on the group's hosts (httpx, 200
    only, bodies stored), parses each JSON spec and expands EVERY operation into a full request record;
    GraphQL endpoints that respond are recorded as a POST-json request the DAST can fuzz. Best-effort
    (no spec → empty file). request_catalog folds requests_api.jsonl in across the barrier.
    """
    ws = activity.app(app_id)
    roots = [h.rstrip("/") for h in _scan_hosts(ws)]
    if not roots:
        return
    store = ws.raw("api_spec")
    _run("httpx", [HTTPX, "-silent", "-srd", str(store / "store"), "-mc", "200", *_header_flags("-H")],
         stdin="\n".join(r + p for r in roots for p in API_SPEC_PATHS),
         dest=store / "probe.txt", label=app_id)
    records: list[dict] = []
    for stored, url in _store_index(store / "store" / "index.txt"):
        if not Path(stored).is_file():
            continue
        obj = _try_json(http_body(Path(stored).read_text(encoding="utf-8", errors="replace")))
        if is_openapi(obj):
            records += expand_openapi(obj, url, cap=API_SPEC_MAX_OPS)
    # GraphQL: any endpoint that responds (200/400/405 to the GET probe) → a POST-json request to fuzz
    gql = _run("httpx", [HTTPX, "-silent", "-mc", "200,400,405", *_header_flags("-H")],
               stdin="\n".join(r + p for r in roots for p in GRAPHQL_PATHS),
               dest=store / "graphql.txt", label=app_id)
    records += [_synth_request("POST", u, {"Content-Type": "application/json"},
                               '{"query":"{__typename}"}', "graphql") for u in _lines(gql)]
    n = tools.write_jsonl(ws.canonical("requests_api.jsonl"), merge_requests(records))
    log.info("  → api_spec (%s) — %d API request(s) from specs/graphql → requests_api.jsonl", app_id, n)


def _store_index(index: Path) -> list[tuple[str, str]]:
    """Parse a katana/httpx -srd index.txt → [(stored_file, url)]; lines are
    '<filepath> <url> (<status>)'."""
    out: list[tuple[str, str]] = []
    for ln in tools.read_lines(index):
        parts = ln.split()
        if len(parts) >= 2:  # noqa: PLR2004
            out.append((parts[0], parts[1]))
    return out


def _all_store_indices(ws: AppWorkspace) -> list[Path]:
    """Every -srd store index under responses/ — katana cheap (responses/index.txt) + headless +
    httpx osint + the content-discovery fixpoint's discovered/round*/ stores. Globbed so the corpus
    is SELF-DESCRIBING: a new store is picked up automatically by fetch_delta's `have` set,
    _extract_bodies and the fixpoint's `seen` set, with no hardcoded path list to keep in sync.
    Returns [] before responses/ exists. Sorted for determinism."""
    if not ws.responses.exists():
        return []
    return sorted(ws.responses.rglob("index.txt"))


_DEAD_STATUS = frozenset({404, 410})           # Not Found / Gone → confirmed-dead endpoint
_STORE_STATUS_RE = re.compile(r"\((\d{3})\b")  # the '(<code> <reason>)' suffix of a -srd index line


def _url_pathkey(url: str) -> str:
    """host + path, scheme/port/query/fragment stripped and percent-encoding NORMALIZED (unquote) — the
    key for per-endpoint status lookup (404-ness is a property of the path, not of the scheme, the query
    values, or whether the path was written `/about</a>` or `/about%3C/a%3E`). Normalizing matters
    because the -srd index stores the decoded form while the catalog often carries the encoded one."""
    rest = url.split("://", 1)[-1].split("#", 1)[0].split("?", 1)[0]
    host, _, path = rest.partition("/")
    return f"{host.split(':', 1)[0]}/{unquote(path)}"


def dead_url_keys(index_lines: Iterable[str]) -> set[str]:
    """Host+path keys (`_url_pathkey`) seen in the -srd store indices ONLY as 404/410 — confirmed-dead
    endpoints. Index lines are '<file> <url> (<status> <reason>)'. A path with ANY non-dead observation
    (2xx/3xx, or 401/403/405 = exists-but-protected) is alive and kept; only paths whose every recorded
    fetch was 404/410 are returned. Pure — feeds the catalog's dead-endpoint drop so DAST/param-fuzz
    don't waste payloads on URLs that 404 (malformed passive/archive URLs, phantom JS routes)."""
    alive: dict[str, bool] = {}
    for ln in index_lines:
        parts = ln.split()
        if len(parts) < 3:                                  # need file, url, (status …)  # noqa: PLR2004
            continue
        m = _STORE_STATUS_RE.search(" ".join(parts[2:]))
        if not m:
            continue
        key = _url_pathkey(parts[1])
        alive[key] = alive.get(key, False) or int(m.group(1)) not in _DEAD_STATUS
    return {k for k, ok in alive.items() if not ok}


def _jsonl_str(out: str) -> list[dict]:
    """Parse NDJSON from a command's stdout (jsluice), skipping unparseable lines."""
    recs: list[dict] = []
    for ln in out.splitlines():
        text = ln.strip()
        if text:
            try:
                recs.append(json.loads(text))
            except json.JSONDecodeError:
                continue
    return recs


# --- secret-finding normalizers/parsers (pure; one shape: sources·type·secret·hash·file·line·verified) ---
def _norm_jsluice_secret(rec: dict) -> dict:
    """jsluice `secrets` record ({kind,data,filename,severity}) → the common secret shape."""
    data = rec.get("data")
    secret = data if isinstance(data, str) else (json.dumps(data, sort_keys=True) if data else None)
    return {"sources": ["jsluice"], "type": rec.get("kind") or "secret", "secret": secret,
            "file": Path(rec.get("filename") or "").name or None, "line": None,
            "verified": False, "severity": rec.get("severity")}


def parse_gitleaks(text: str) -> list[dict]:
    """gitleaks `-f json` report (array of {RuleID,Secret,File,StartLine}) → common shape."""
    try:
        rows = json.loads(text) if text.strip() else []
    except json.JSONDecodeError:
        return []
    return [{"sources": ["gitleaks"], "type": r.get("RuleID") or "secret",
             "secret": r.get("Secret") or None, "file": Path(r.get("File") or "").name or None,
             "line": r.get("StartLine"), "verified": False} for r in rows]


def parse_trufflehog(text: str) -> list[dict]:
    """trufflehog filesystem --json NDJSON → common shape (Verified carried through)."""
    out: list[dict] = []
    for r in _jsonl_str(text):
        fs = ((r.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        out.append({"sources": ["trufflehog"], "type": r.get("DetectorName") or "secret",
                    "secret": r.get("Raw") or r.get("Redacted") or None,
                    "file": Path(fs.get("file") or "").name or None, "line": fs.get("line"),
                    "verified": bool(r.get("Verified"))})
    return out


def parse_detect_secrets(text: str) -> list[dict]:
    """detect-secrets `scan` JSON ({results:{file:[{type,hashed_secret,line_number}]}}) → common
    shape. detect-secrets emits only the HASH (no raw value) — kept as a typed lead."""
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for fname, hits in (data.get("results") or {}).items():
        out += [{"sources": ["detect-secrets"], "type": h.get("type") or "secret", "secret": None,
                 "hash": h.get("hashed_secret"), "file": Path(fname).name or None,
                 "line": h.get("line_number"), "verified": bool(h.get("is_verified"))} for h in hits]
    return out


def merge_secrets(records: list[dict]) -> list[dict]:
    """Dedup secret findings across tools by (file, raw-secret | #hash | #type); union `sources`
    and OR `verified`. Deterministic order (sorted), so the same corpus always yields the same file."""
    ordered = sorted(records, key=lambda r: (r.get("file") or "", r.get("type") or "",
                                             str(r.get("secret") or r.get("hash") or "")))
    by_key: dict[tuple, dict] = {}
    for r in ordered:
        ident = r.get("secret") or (f"#{r['hash']}" if r.get("hash") else f"#{r.get('type')}")
        key = (r.get("file"), ident)
        if key in by_key:
            cur = by_key[key]
            cur["sources"] = sorted(set(cur["sources"]) | set(r.get("sources", [])))
            cur["verified"] = bool(cur.get("verified") or r.get("verified"))
        else:
            by_key[key] = {**r, "sources": sorted(set(r.get("sources", [])))}
    return list(by_key.values())


# --- offline corpus prep + the parallel secret-scanning fleet ---
def _extract_bodies(ws: AppWorkspace) -> tuple[Path | None, list[str]]:
    """Write every NOT-YET-EXTRACTED stored response BODY to raw/extracted/ — JS as .js (the new ones
    returned, for jsluice), everything else as .html. IDEMPOTENT: a dst that already exists is
    skipped, so the content-discovery fixpoint can call this once per round and get back only THAT
    round's new JS to mine (no re-extraction, no re-mining). Reads every -srd store via
    _all_store_indices (auto-covers the discovered/ rounds). Returns (bodies_dir, new_js_files), or
    (None, []) when the corpus is still empty."""
    bodies = ws.raw("extracted")
    new_js: list[str] = []
    for index in _all_store_indices(ws):
        for stored, url in _store_index(index):
            is_js = is_js_url(url)
            dst = bodies / f"{Path(stored).stem}.{'js' if is_js else 'html'}"
            if dst.exists():
                continue  # already extracted in an earlier call/round — idempotent
            src = Path(stored)
            if not src.is_file():  # index references a body the -srd store never wrote → skip, not crash
                continue
            body = http_body(src.read_text(encoding="utf-8", errors="replace"))
            if not body.strip():
                continue
            bodies.mkdir(parents=True, exist_ok=True)
            dst.write_text(body, encoding="utf-8")
            if is_js:
                new_js.append(str(dst))
    has_corpus = bodies.exists() and any(bodies.iterdir())
    return (bodies, new_js) if has_corpus else (None, [])


def _run_jsluice_secrets(js_files: list[str]) -> list[dict]:
    if not js_files or shutil.which(JSLUICE) is None:
        return []
    return [_norm_jsluice_secret(r) for r in _jsonl_str(tools.run([JSLUICE, "secrets", *js_files]))]


def _jsluice_records(js_files: list[str]) -> list[dict]:
    """Parsed `jsluice urls` records over JS files (best-effort; [] if none, or jsluice is absent).
    Each record: {url, queryParams[], bodyParams[], method, type, filename}. Shared by mine_responses
    (urls), build_wordlist (params), and the content_discovery fixpoint (each feedback round)."""
    if not js_files or shutil.which(JSLUICE) is None:
        return []
    return _jsonl_str(tools.run([JSLUICE, "urls", *js_files]))


def _jsluice_urls(js_files: list[str]) -> list[str]:
    """jsluice endpoint URLs over JS files — a projection of _jsluice_records (best-effort)."""
    return [r["url"] for r in _jsluice_records(js_files) if r.get("url")]


def _run_gitleaks(ws: AppWorkspace, bodies: Path, app_id: str) -> list[dict]:
    if shutil.which(GITLEAKS) is None:
        log.debug("  · skip gitleaks (not installed) for %s", app_id)
        return []
    report = ws.raw("gitleaks") / "report.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    tools.run([GITLEAKS, "detect", "--no-git", "-s", str(bodies), "-f", "json", "-r", str(report)],
              stream_stderr=is_verbose())
    return parse_gitleaks(report.read_text(encoding="utf-8", errors="replace") if report.exists() else "")


def _run_trufflehog(bodies: Path, app_id: str) -> list[dict]:
    if shutil.which(TRUFFLEHOG) is None:
        log.debug("  · skip trufflehog (not installed) for %s", app_id)
        return []
    # --results=verified VALIDATES each hit against its provider (network to AWS/GitHub/…)
    out = tools.run([TRUFFLEHOG, "filesystem", str(bodies), "--json", "--results=verified"],
                    stream_stderr=is_verbose())
    return parse_trufflehog(out)


def _run_detect_secrets(bodies: Path, app_id: str) -> list[dict]:
    if shutil.which(DETECT_SECRETS) is None:
        log.debug("  · skip detect-secrets (not installed) for %s", app_id)
        return []
    # --all-files scans recursively (default = only git-tracked files → nothing here); it honors the
    # CWD ('.'), not an absolute path arg — so run from inside the bodies dir.
    return parse_detect_secrets(tools.run([DETECT_SECRETS, "scan", "--all-files", "."],
                                          cwd=bodies, stream_stderr=is_verbose()))


def _secret_fleet(ws: AppWorkspace, bodies: Path, js_files: list[str], app_id: str) -> list[dict]:
    """Run the secret scanners CONCURRENTLY (independent, I/O-/network-bound) over the body corpus
    and return their flattened findings — jsluice (JS AST) ∥ gitleaks (regex/any-file) ∥ trufflehog
    (verified) ∥ detect-secrets (entropy/hashes). Each is best-effort (skipped if its binary is absent)."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(_run_jsluice_secrets, js_files),
            pool.submit(_run_gitleaks, ws, bodies, app_id),
            pool.submit(_run_trufflehog, bodies, app_id),
            pool.submit(_run_detect_secrets, bodies, app_id),
        ]
        return [rec for f in futures for rec in f.result()]


def mine_responses(activity: Activity, app_id: str) -> None:
    """PHASE 1 — mine the per-app response store OFFLINE for ENDPOINTS (cashes in 'fetch once').

    Extracts every stored response body (cheap crawl + headless + fetch_delta) to raw/extracted/
    WITHOUT re-fetching, then runs jsluice over the JS for endpoints (→ endpoints_js.txt), folded
    into the round-0 content_discovery wordlist. Needs fetch_delta so the OSINT bodies are present;
    the crawl bodies are guaranteed by the loop barrier.

    Secret scanning is NOT here: the fleet runs ONCE at the tail of content_discovery, over the
    corpus the fixpoint's downloads complete — so it also covers feroxbuster-discovered files, which
    mine_responses (running before the fuzzing) never sees. raw/extracted/ is extended incrementally
    (idempotent _extract_bodies), so the final fleet sees everything this step already wrote.
    """
    ws = activity.app(app_id)
    bodies, js_files = _extract_bodies(ws)
    if bodies is None:
        log.debug("  · skip mine_responses (empty response store) for %s", app_id)
        return
    # point 5b: reconstruct original sources from sourcemaps → mine them for endpoints too (and the
    # secret fleet picks up raw/extracted/sourcemap/ automatically at content_discovery's tail).
    sm_files, exposed = _reconstruct_sourcemaps(ws)
    n_ep = tools.write_lines(ws.canonical("endpoints_js.txt"), _jsluice_urls([*js_files, *sm_files]))
    if exposed:
        tools.write_jsonl(ws.findings / "sourcemap.jsonl",
                          [{"type": "sourcemap-exposed", "severity": "info", "url": u} for u in exposed])
    log.info("  → mine_responses (%s) — %d JS (+%d sourcemap src) → %d endpoint(s) · %d map(s) exposed",
             app_id, len(js_files), len(sm_files), n_ep, len(exposed))


def _shortscan_surface(activity: Activity, ws: AppWorkspace, app_id: str) -> tuple[list[str], list[dict]]:
    """IIS 8.3 short-name enumeration — DUAL-ROLE, one run: returns (surface words, findings).

    Builds a shortutil rainbow table from the per-app seed + global list so shortscan resolves the
    leaked 8.3 names to real filenames (on top of its HTTP autocomplete oracles), then harvests those
    names as SURFACE (parse_shortscan) AND the IIS-tilde-enumeration FINDING per vulnerable host
    (parse_shortscan_findings) from the same JSON. Best-effort: ([], []) if binaries missing / no hosts.
    """
    if shutil.which(SHORTSCAN) is None or shutil.which(SHORTUTIL) is None:
        log.debug("  · skip shortscan (not installed) for %s", app_id)
        return [], []
    hosts = tools.read_lines(ws.hosts)
    if not hosts:
        return [], []
    content_wl = wordlists.role_path(activity, "content")
    rainbow_src = ws.raw("shortscan") / "rainbow_src.txt"  # shortutil scratch (not a wl product)
    tools.write_lines(rainbow_src, [
        *tools.read_lines(ws.wl_custom / "seed.txt"),
        *(tools.read_lines(content_wl) if content_wl else []),
    ])
    rainbow = ws.raw("shortscan") / "rainbow.txt"
    rainbow.write_text(tools.run([SHORTUTIL, "wordlist", str(rainbow_src)]), encoding="utf-8")
    hosts_file = ws.raw("shortscan") / "hosts.txt"
    tools.write_lines(hosts_file, hosts)
    log.info("  → shortscan (%s) — %d host(s)", app_id, len(hosts))
    out = tools.run(
        [SHORTSCAN, "-o", "json", "-a", "auto", "-w", str(rainbow), "-c", SHORTSCAN_CONC,
         f"@{hosts_file}"],
        stream_stderr=is_verbose(),
    )
    (ws.raw("shortscan") / "out.json").write_text(out, encoding="utf-8")
    return parse_shortscan(out), parse_shortscan_findings(out)


def tech_enum(activity: Activity, app_id: str) -> None:
    """PHASE 3 (surface) — specialized per-stack scanners whose output FEEDS enum.

    Best-effort dispatch keyed on the cluster's detected tech: a scanner runs only if
    its tech matched AND its binary is installed. Primary output is SURFACE (fuzz words) →
    wl_custom/shortnames.txt, which content_discovery merges into its wordlist. A scanner may also be
    DUAL-ROLE and emit findings: shortscan's IIS 8.3 short-name enumeration is itself an
    information-disclosure finding → tilde_enum.jsonl (a dedicated artifact; `consolidate` lifts it to
    <activity>/findings/). Findings-only scanners (wpprobe, nuclei, …) belong to tech_vulnscan / phase 4.

    Today: shortscan (IIS/ASP.NET 8.3 short-name enumeration). Reads phase-1 hosts
    across the barrier; needs the wordlist seed for the shortutil rainbow table.
    """
    ws = activity.app(app_id)
    tech = " ".join(workspace.read_meta(ws.meta).get("tech") or []).lower()
    surface: list[str] = []
    findings: list[dict] = []
    if any(k in tech for k in ("iis", "asp.net", "microsoft-iis")):
        surface, findings = _shortscan_surface(activity, ws, app_id)
    n = tools.write_lines(ws.wl_custom / "shortnames.txt", surface)
    if findings:  # per-app findings/ folder — consolidate lifts these to <activity>/findings/
        tools.write_jsonl(ws.findings / "tilde_enum.jsonl", findings)
    log.info("  → tech_enum (%s) — %d surface term(s) → shortnames.txt%s", app_id, n,
             f" · {len(findings)} finding(s) → findings/tilde_enum.jsonl" if findings else "")


def _wpprobe(ws: AppWorkspace, app_id: str) -> list[dict]:
    """Run wpprobe over the group's scan hosts (one stealthy scan per distinct-body host) → vuln
    findings. Best-effort: [] if the binary is absent or there are no hosts. Writes JSON to -o (csv/
    json by extension), so it bypasses _run; auth headers (PTFLOW_HTTP_HEADER) reach the logged-in site.
    Each scan is capped by WPPROBE_TIMEOUT (a runaway must not hang the loop — keep partial on hit)."""
    if shutil.which(WPPROBE) is None:
        log.debug("  · skip wpprobe (not installed) for %s", app_id)
        return []
    hosts = _scan_hosts(ws)
    if not hosts:
        return []
    log.info("  → wpprobe (%s) — %d host(s)", app_id, len(hosts))
    findings: list[dict] = []
    for i, host in enumerate(hosts):
        out_file = ws.raw("wpprobe") / f"scan{i}.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        cmd = [WPPROBE, "scan", "-u", host, "-o", str(out_file), "--rate-limit", WPPROBE_RATE,
               "-t", WPPROBE_THREADS, *_header_flags("-H")]
        try:
            tools.run(cmd, timeout=WPPROBE_TIMEOUT, stream_stderr=is_verbose())
        except subprocess.TimeoutExpired:
            log.warning("⚠ wpprobe hit the %ds cap for %s (%s) — keeping partial results",
                        WPPROBE_TIMEOUT, app_id, host)
        if out_file.exists():
            findings += parse_wpprobe(out_file.read_text(encoding="utf-8", errors="replace"))
    return findings


def tech_vulnscan(activity: Activity, app_id: str) -> None:
    """PHASE 4 (findings) — specialized per-stack scanners whose output is FINDINGS-only (the dual of
    tech_enum, whose output feeds enum). Best-effort dispatch keyed on the cluster's detected tech: a
    scanner runs only if its tech matched (whole-word, _tech_match) AND its binary is installed.

    Today: wpprobe (WordPress plugin/theme → known-CVE), run ONLY on WordPress app groups → the per-app
    findings/wpprobe.jsonl (consolidate lifts it to <activity>/findings/). Reads meta tech + hosts; no
    needs (runs ∥ the other phase-4 stages). Future finding-only scanners (nuclei tech-tags, nikto, …)
    dispatch here too."""
    ws = activity.app(app_id)
    tags = [t.lower() for t in (workspace.read_meta(ws.meta).get("tech") or [])]
    findings: list[dict] = []
    if _tech_match("wordpress", tags):
        findings += _wpprobe(ws, app_id)
    if findings:
        tools.write_jsonl(ws.findings / "wpprobe.jsonl", findings)
    hot = sum(1 for f in findings if (f.get("severity") or "").lower() in ("critical", "high"))
    log.info("  → tech_vulnscan (%s) — %d finding(s)%s%s", app_id, len(findings),
             f" ({hot} critical/high)" if hot else "",
             " → findings/wpprobe.jsonl" if findings else "")


def _dur_seconds(spec: str) -> int:
    """Parse a feroxbuster-style duration ('20m', '300s', '1h') to seconds. Pure."""
    s = spec.strip().lower()
    unit = {"s": 1, "m": 60, "h": 3600}.get(s[-1:], 1)
    return int(s[:-1] if s[-1:] in "smh" else s) * unit


def _ferox_time_limit(round_idx: int, remaining_s: float) -> str:
    """feroxbuster --time-limit for a fixpoint round: round 0 keeps the full FEROX_TIME_LIMIT (the
    essential baseline pass); a feedback round gets min(DEEP_FEROX_TIME_LIMIT, remaining budget)."""
    if round_idx == 0:
        return FEROX_TIME_LIMIT
    return f"{max(1, int(min(_dur_seconds(DEEP_FEROX_TIME_LIMIT), remaining_s)))}s"


def _run_ferox(ws: AppWorkspace, hosts: list[str], words: list[str], round_idx: int,  # noqa: PLR0913
               *, remaining: float, depth: str = FEROX_DEPTH, time_limit: str | None = None,
               tag: str | None = None) -> list[dict]:
    """One feroxbuster forced-browse pass over `hosts` with `words` → parsed `response` records.

    `tag` names the wordlist/JSON files (default `round<idx>`); `depth`/`time_limit` override the
    recursion depth / total cap (default FEROX_DEPTH and the fixpoint's _ferox_time_limit) — the deep
    dive uses both. Writes the wordlist + raw JSON under wl_custom/ and raw/feroxbuster/ (feroxbuster
    writes JSON to -o, not stdout, so it bypasses _run). --smart brings auto-tune soft-404 calibration
    + collect-words/backups + link extraction/recursion. --time-limit is the hard cap that breaks
    --smart's backoff livelock (the scanme.nmap.org incident). Returns [] for an empty wordlist."""
    app_id = ws.root.name
    label = tag or f"round{round_idx}"
    wordlist = ws.wl_custom / f"{label}.txt"
    n_wl = tools.write_lines(wordlist, words)
    if not n_wl:
        return []
    exts = tech_extensions(workspace.read_meta(ws.meta).get("tech") or [], TECH_EXTENSIONS)
    ext_args = ["-x", *exts] if exts else []
    out_file = ws.raw("feroxbuster") / f"{label}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    tl = time_limit or _ferox_time_limit(round_idx, remaining)
    log.info("  → feroxbuster (%s) %s — %d host(s), %d term(s), -d %s, --time-limit %s",
             app_id, label, len(hosts), n_wl, depth, tl)
    cmd = [FEROX, "--stdin", "--silent", "--json", "-o", str(out_file), "--no-state", "-k",
           "--smart", "-t", FEROX_THREADS, "-L", FEROX_SCAN_LIMIT, "--timeout", FEROX_TIMEOUT,
           "--time-limit", tl, "-d", depth, "-w", str(wordlist), *ext_args]
    tools.run(cmd, stdin="\n".join(hosts), stream_stderr=is_verbose())
    raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
    recs = parse_ferox(raw)
    # An https endpoint a modern TLS client can't handshake (legacy renegotiation / weak DH) makes
    # feroxbuster reach nothing — `-k` doesn't help (cert-only). httpx/katana (Go TLS) connect, so
    # the host looks live; only the rustls scanner fails. Retry the same round over http (the same
    # app on the other scheme) instead of leaving the group's content discovery empty.
    if not recs and ferox_transport_failed(raw) and any(h.startswith("https://") for h in hosts):
        http_hosts = tools.dedupe([https_to_http(h) for h in hosts])
        log.warning("  ⚠ feroxbuster (%s) %s — https unreachable (legacy-TLS handshake refused); "
                    "retrying over http", app_id, label)
        tools.run(cmd, stdin="\n".join(http_hosts), stream_stderr=is_verbose())
        raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
        recs = parse_ferox(raw)
    return recs


def _download_and_mine(ws: AppWorkspace, urls: list[str], round_idx: int) -> list[str]:
    """Download `urls` into responses/discovered/round<r>/ (httpx -srd), extract+mine their NEW
    bodies, and return the grown fuzz tokens (jsluice endpoints + the urls' own paths/params),
    tokenized — the next round's frontier. The downloaded bodies also join the corpus the final
    secret fleet scans."""
    app_id = ws.root.name
    store = ws.responses / "discovered" / f"round{round_idx}"
    store.mkdir(parents=True, exist_ok=True)
    _run("httpx", [HTTPX, "-silent", "-srd", str(store), "-rl", OSINT_FETCH_RL],
         stdin="\n".join(urls), dest=ws.raw("httpx") / "discovered" / f"round{round_idx}.txt",
         label=f"{app_id} r{round_idx}")
    _, new_js = _extract_bodies(ws)
    return tokenize_urls([*_jsluice_urls(new_js), *urls])


def _content_rounds(ws: AppWorkspace, hosts: list[str], frontier: list[str]) -> tuple[list[dict], int, str]:
    """Drive the bounded content-discovery FIXPOINT and return (merged hits, rounds run, stop reason).

    Round 0 fuzzes the combined wordlist; each feedback round fuzzes ONLY the NEW token delta, then
    downloads+mines its hits to grow the frontier. Four independent stops keep it convergent:
    wordlist-fixpoint (no new words), deadline (per-app wall-clock), round-cap (CONTENT_FEEDBACK_
    ROUNDS), url-fixpoint (no new urls), diminishing-returns (< MIN_NEW_TOKENS). A token is never
    re-fuzzed (`fuzzed`); a URL never re-downloaded (`seen`, from the -srd store indices)."""
    app_id = ws.root.name
    fuzzed: set[str] = set()
    seen = {url for idx in _all_store_indices(ws) for _, url in _store_index(idx)}
    hits: list[dict] = []
    deadline = time.monotonic() + CONTENT_DEADLINE_S
    rounds, stop = 0, "round-cap"
    for r in range(CONTENT_FEEDBACK_ROUNDS + 1):
        new_words = [w for w in tools.dedupe(frontier) if w not in fuzzed]
        if not new_words:
            stop = "wordlist-fixpoint"
            break
        remaining = deadline - time.monotonic()
        if r > 0 and remaining <= 0:
            stop = "deadline"
            break
        recs = _run_ferox(ws, hosts, new_words, r, remaining=remaining)
        fuzzed |= set(new_words)
        hits = merge_ferox_by_url(hits, recs)
        rounds += 1
        if r == CONTENT_FEEDBACK_ROUNDS:
            break  # round cap reached — no feedback round left to consume new findings
        new_urls = select_new_urls(recs, seen, cap=DEEP_DOWNLOAD_CAP)
        if not new_urls:
            stop = "url-fixpoint"
            break
        seen |= set(new_urls)
        frontier = _download_and_mine(ws, new_urls, r)
        n_new = len([w for w in frontier if w not in fuzzed])
        log.info("    fixpoint (%s) r%d → %d new url(s) · %d new token(s)",
                 app_id, r, len(new_urls), n_new)
        if n_new < MIN_NEW_TOKENS:
            stop = "diminishing-returns"
            break
    return hits, rounds, stop


def _scan_secrets(ws: AppWorkspace, app_id: str) -> None:
    """Secret-scanning fleet, run ONCE over the COMPLETE corpus (incl. the fuzz-discovered bodies —
    mine_responses, running before the fuzzing, never sees them): jsluice ∥ gitleaks ∥ trufflehog
    (--results=verified) ∥ detect-secrets, merged + deduped (merge_secrets) → secrets.jsonl.
    Best-effort; no-op when the corpus is empty."""
    bodies, _ = _extract_bodies(ws)
    if bodies is None:
        log.debug("  · no corpus to secret-scan for %s", app_id)
        return
    js_files = sorted(str(p) for p in bodies.glob("*.js"))
    secrets = merge_secrets(_secret_fleet(ws, bodies, js_files, app_id))
    n_sec = tools.write_jsonl(ws.canonical("secrets.jsonl"), secrets)
    n_verified = sum(1 for s in secrets if s.get("verified"))
    log.info("  → secrets (%s) — %d JS · %d secret(s) (%d verified) → secrets.jsonl",
             app_id, len(js_files), n_sec, n_verified)


def content_discovery(activity: Activity, app_id: str) -> None:
    """PHASE 3 — forced browsing to a FIXPOINT: fuzz → download → mine → fuzz the new token delta.

    Discovers UNLINKED paths/files — the one thing reusing downloaded bodies can't do, so it must
    make new requests. Round 0 is the classic feroxbuster --smart pass (auto-tune soft-404 +
    collect-words/backups + link extraction/recursion built in) over the combined wordlist. Then,
    instead of dead-ending there, each feedback round feeds feroxbuster's NEW 2xx/3xx hits back
    through the same machinery (_content_rounds): download their bodies into
    responses/discovered/round<r>/, mine them (jsluice endpoints + tokenized paths/params), and fuzz
    ONLY the resulting new tokens. This closes the cross-tool loop feroxbuster's own (link-only)
    recursion can't — a fuzz-found JS file's API routes become the next round's wordlist.

    Targets the group's hosts deduped by response body (_scan_hosts): one host per backend —
    same-backend aliases (domain+IP, http+https) collapsed (no re-fuzz; the scanme.nmap.org incident)
    but distinct environments (staging vs test) each fuzzed. The Pass-A wordlist is the STAGED combine
    (build_content_wordlist): custom + olfa_micro + an_directories head + per-stack language head + the
    small filetype lists, plus tech-derived extensions. BOUNDED by four convergence/budget stops under
    a hard round cap (see _content_rounds), so it never loops forever and never re-fuzzes/re-downloads.

    Stage 3 (the deep dive, _deep_dive) is an OPT-IN extra pass with the huge Assetnote manual lists on
    the few high-value hosts; its hits merge into the same artifact. Finally the secret-scanning fleet
    runs ONCE over the now-complete corpus (_scan_secrets) → secrets.jsonl. Output:
    scans/<app_id>/content_discovery.jsonl (merge of all rounds + the deep dive, deduped).
    """
    ws = activity.app(app_id)
    hosts = _scan_hosts(ws)
    if not hosts:
        log.debug("  · skip content_discovery (no host) for %s", app_id)
        return

    tech = workspace.read_meta(ws.meta).get("tech") or []
    wordlist = build_content_wordlist(activity, ws, tech)

    hits, rounds, stop = _content_rounds(ws, hosts, wordlist)
    hits = _deep_dive(activity, ws, hosts, tech, hits)  # stage 3 — opt-in, gated; merges into hits
    n = tools.write_jsonl(ws.canonical("content_discovery.jsonl"), hits)
    log.info("    content_discovery (%s) → %d result(s) over %d round(s) [stop: %s]",
             app_id, n, rounds, stop)
    _scan_secrets(ws, app_id)


def build_content_wordlist(activity: Activity, ws: AppWorkspace, tech: list[str]) -> list[str]:
    """Pass-A staged wordlist (stages 0+1+2+2b) for content_discovery. Reads roles by name and hands
    (lines, cap) layers to the pure assemble_wordlist. A missing role just drops its stage."""
    app_id = ws.root.name
    # stage 0 custom (app-derived, high signal) — always full, first
    custom = [*tools.read_lines(ws.wl_custom / "seed.txt"),                 # build_wordlist app tokens
              *tools.read_lines(ws.wl_custom / "ai_seed.txt"),              # ai_wordlist contextual tokens (--ai)
              *tools.read_lines(ws.wl_custom / "shortnames.txt"),           # tech_enum surface (8.3 names)
              *tokenize_urls(tools.read_lines(ws.canonical("endpoints_js.txt")))]  # mine_responses

    def _read(role: str) -> list[str]:
        p = wordlists.role_path(activity, role)
        return tools.read_lines(p) if p else []

    layers: list[tuple[list[str], int | None]] = [
        (_read("content"), None),                                  # stage 0: olfa_micro grab-bag (full)
        (_read("an_directories"), STAGE1_CAP),                     # stage 1: real paths head
    ]
    layers += [(_read(role), STAGE2_CAP)                           # stage 2: ONE per-stack language head
               for role in roles_for_tech(tech, STAGE2_TECH_ROLES)]
    layers += [(_read(role), None) for role in STAGE2B_ROLES]      # stage 2b: small filetype lists (full)
    wordlist = assemble_wordlist(custom, layers)
    log.info("    wordlist (%s) — %d custom + stages[%s] → %d combined", app_id,
             len(tools.dedupe(custom)),
             " ".join(str(min(len(ls), cap) if cap else len(ls)) for ls, cap in layers), len(wordlist))
    return wordlist


def _richest_hosts(hits: list[dict], hosts: list[str], *, cap: int) -> list[str]:
    """The `cap` scanned hosts with the most Pass-A hits (a content-richness proxy), in-scope only.
    Used to pick deep-dive targets — the few high-value hosts worth the huge lists. Pure."""
    scanned = {url_host(h): h for h in hosts}
    counts: dict[str, int] = {}
    for r in hits:
        host = url_host(r.get("url") or "")
        if host in scanned:
            counts[host] = counts.get(host, 0) + 1
    ranked = sorted(counts, key=lambda h: counts[h], reverse=True)
    return [scanned[h] for h in ranked[:cap]]


def _deep_dive(activity: Activity, ws: AppWorkspace, hosts: list[str], tech: list[str],
               hits: list[dict]) -> list[dict]:
    """Stage 3 — OPT-IN (PTFLOW_DEEP_DIVE) deep forced-browse with the huge Assetnote manual lists at
    full recursion, on the few high-value hosts only. Gated: per-host Pass-A hits ≥ DEEP_DIVE_MIN_HITS
    and at most DEEP_DIVE_MAX_HOSTS hosts. Merges its hits into `hits` (no body download — the secret
    fleet already scans the Pass-A corpus). Returns the (possibly extended) hits."""
    app_id = ws.root.name
    if not os.environ.get("PTFLOW_DEEP_DIVE"):
        return hits
    roles = [*roles_for_tech(tech, DEEPDIVE_TECH_ROLES), *DEEPDIVE_GENERIC_ROLES]
    words: list[str] = []
    for role in roles:
        p = wordlists.role_path(activity, role)
        if p:
            words += tools.read_lines(p)
    words = tools.dedupe(words)
    if not words:
        log.debug("  · skip deep-dive (%s) — no deep list resolved", app_id)
        return hits
    per_host = _richest_hosts(hits, hosts, cap=DEEP_DIVE_MAX_HOSTS)
    targets = [h for h in per_host if sum(url_host(r.get("url") or "") == url_host(h) for r in hits)
               >= DEEP_DIVE_MIN_HITS]
    if not targets:
        log.info("  · skip deep-dive (%s) — no host ≥ %d Pass-A hits", app_id, DEEP_DIVE_MIN_HITS)
        return hits
    log.info("  → deep-dive (%s) — %d host(s), %d term(s), -d %s, --time-limit %s",
             app_id, len(targets), len(words), DEEP_DIVE_DEPTH, DEEP_DIVE_TIME_LIMIT)
    deadline = time.monotonic() + DEEP_DIVE_DEADLINE_S
    for i, host in enumerate(targets):
        if time.monotonic() >= deadline:
            log.warning("  ⚠ deep-dive (%s) — deadline hit, %d host(s) skipped", app_id, len(targets) - i)
            break
        recs = _run_ferox(ws, [host], words, 0, remaining=deadline - time.monotonic(),
                          depth=DEEP_DIVE_DEPTH, time_limit=DEEP_DIVE_TIME_LIMIT, tag=f"deepdive{i}")
        hits = merge_ferox_by_url(hits, recs)
    return hits


# --- PHASE 4 (param discovery) — arjun ∥ x8 hidden-parameter fuzzing ---
def _is_id_segment(seg: str) -> bool:
    """A path segment that's an id/hash → collapsed to '*' in a path template (pure)."""
    if seg.isdigit():
        return True
    return len(seg) >= 8 and all(c in "0123456789abcdef" for c in seg.lower())  # noqa: PLR2004


def path_template(url: str) -> str:
    """Dedup key for an endpoint: scheme://host/path with query/fragment dropped and numeric/long-hex
    segments collapsed to '*', so /user/123/edit and /user/456/edit share ONE template — we fuzz one
    representative per endpoint SHAPE, not per id. Pure."""
    clean = url.split("#", 1)[0].split("?", 1)[0]
    scheme, sep, rest = clean.partition("://")
    if not sep:
        scheme, rest = "", clean
    host, _, path = rest.partition("/")
    norm = "/".join("*" if _is_id_segment(s) else s for s in path.split("/"))
    base = f"{scheme}://{host}" if scheme else host
    return f"{base}/{norm}"


def select_param_endpoints(urls: Iterable[str], in_scope_hosts: set[str], *, cap: int) -> list[str]:
    """The endpoints to param-fuzz: in-scope host, deduped by path_template (one shape, first wins,
    query stripped), capped to `cap` (logged when it bites). Pure (logging only)."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in urls:
        u = raw.strip()
        if not u:
            continue
        if in_scope_hosts and url_host(u) not in in_scope_hosts:
            continue
        clean = u.split("#", 1)[0].split("?", 1)[0]
        tpl = path_template(clean)
        if tpl in seen:
            continue
        seen.add(tpl)
        out.append(clean)
    if len(out) > cap:
        log.warning("⚠ param_fuzz: capping endpoint set %d→%d", len(out), cap)
        return out[:cap]
    return out


def select_body_targets(catalog: Iterable[dict], in_scope: set[str], *, cap: int) -> tuple[list[str], list[str]]:
    """From the request catalog, the endpoints to test for BODY/JSON params, split by content type:
    the records the crawl saw with a body or a body-bearing method (POST/PUT/PATCH) — that's where
    hidden body params actually live. Deduped by (method, path-template), each side capped. Returns
    (urlencoded_urls, json_urls). Pure."""
    body: list[str] = []
    js: list[str] = []
    seen: set[tuple] = set()
    for r in catalog:
        method = (r.get("method") or "GET").upper()
        has_body = bool((r.get("body") or "").strip()) or method in {"POST", "PUT", "PATCH"}
        url = r.get("url") or ""
        if not (has_body and url) or (in_scope and url_host(url) not in in_scope):
            continue
        key = (method, path_template(url))
        if key in seen:
            continue
        seen.add(key)
        ct = next((str(v) for k, v in (r.get("headers") or {}).items()
                   if str(k).lower() == "content-type"), "")
        is_json = "json" in ct.lower() or any(p.get("loc") == "json" for p in r.get("params") or [])
        (js if is_json else body).append(url)
    return body[:cap], js[:cap]


def _first_segment(path: str) -> str:
    """The first non-empty path segment of a URL path ('/a/b/c'→'a', '/'→'', '/x'→'x'). Pure — the
    top-level 'region' a recrawl seed must open to count as new (un-crawled) territory."""
    for seg in path.split("/"):
        if seg:
            return seg
    return ""


def select_recrawl_seeds(discovered: Iterable[str], crawled: Iterable[str], in_scope: set[str],
                         *, cap: int) -> list[str]:
    """The fuzzing-discovered entry points that open UN-CRAWLED territory — a discovered URL whose
    TOP-LEVEL path segment no crawled URL uses (conservative: only genuinely-new top-level regions, so
    a new sub-dir UNDER an already-crawled region does NOT seed). One shallowest seed per new region,
    static assets / JS files / out-of-scope dropped, capped. Pure (logging only).

    `covered` = the (host, first-segment) of every crawled URL; a discovered /debugging/x whose segment
    'debugging' isn't covered → the crawler never went there → seed (one per new segment)."""
    covered = {(urlsplit(c).netloc, _first_segment(urlsplit(c).path or "/")) for c in crawled if c}
    seeds: list[str] = []
    seen: set[tuple] = set()
    for raw in discovered:
        u = (raw or "").strip()
        # skip empties, out-of-scope, static assets (denoise) and JS files (not navigable pages)
        if (not u or "://" not in u or (in_scope and url_host(u) not in in_scope)
                or not denoise([u]) or is_js_url(u)):
            continue
        p = urlsplit(u)
        key = (p.netloc, _first_segment(p.path or "/"))
        if key in covered or key in seen:
            continue
        seen.add(key)
        seeds.append(u)
    seeds.sort(key=lambda s: (s.count("/"), s))   # shallowest entry points first, deterministic
    if len(seeds) > cap:
        log.warning("⚠ recrawl: capping new-territory seeds %d→%d", len(seeds), cap)
        return seeds[:cap]
    return seeds


def parse_arjun(text: str, *, loc: str = "query") -> list[dict]:
    """arjun -oJ ({<url>: {method, params:[names], headers}}) → common shape per discovered param,
    stamped with its LOCATION (query/body/json — arjun's -m method determines which)."""
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for url, rec in (data.items() if isinstance(data, dict) else []):
        if not isinstance(rec, dict):
            continue
        method = rec.get("method") or "GET"
        out += [{"url": url, "param": str(p), "method": method, "loc": loc,
                 "sources": ["arjun"], "reason": None}
                for p in (rec.get("params") or []) if p]
    return out


def parse_x8(text: str, *, loc: str = "query") -> list[dict]:
    """x8 -O json ([{url, method, found_params:[{name, reason_kind, …}]}]) → common shape per param,
    stamped with its LOCATION (query/body/json/header — x8's mode determines which)."""
    try:
        data = json.loads(text) if text.strip() else []
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for rec in (data if isinstance(data, list) else []):
        if not isinstance(rec, dict):
            continue
        url, method = rec.get("url"), rec.get("method") or "GET"
        for p in rec.get("found_params") or []:
            name = p.get("name") if isinstance(p, dict) else p
            if url and name:
                out.append({"url": url, "param": str(name), "method": method, "loc": loc,
                            "sources": ["x8"],
                            "reason": p.get("reason_kind") if isinstance(p, dict) else None})
    return out


def merge_params(records: list[dict]) -> list[dict]:
    """Dedup discovered params across arjun/x8 by (url, param, LOCATION): union `sources`, keep first
    method + first non-null reason. A param found in the query AND the body of the same url is two
    distinct findings (different injection points). Deterministic order. Pure."""
    ordered = sorted(records, key=lambda r: (r.get("url") or "", r.get("param") or "", r.get("loc") or ""))
    by_key: dict[tuple, dict] = {}
    for r in ordered:
        key = (r.get("url"), r.get("param"), r.get("loc"))
        if key in by_key:
            cur = by_key[key]
            cur["sources"] = sorted(set(cur["sources"]) | set(r.get("sources", [])))
            cur["reason"] = cur.get("reason") or r.get("reason")
        else:
            by_key[key] = {**r, "sources": sorted(set(r.get("sources", [])))}
    return list(by_key.values())


def collapse_global_params(records: list[dict], tested: Mapping[str, int], *,
                           ratio: float = PARAM_GLOBAL_RATIO,
                           min_hits: int = PARAM_GLOBAL_MIN_HITS) -> list[dict]:
    """Collapse a param that x8/arjun report on ~EVERY tested endpoint for its location into ONE
    host-level record — a site-wide reflection artifact, not N distinct injection points. A target that
    reflects an arbitrary param into a response element present everywhere (verified: ginandjuice echoes
    `?category=` into a `Set-Cookie` on every path) makes reflection-based discovery flag that param on
    all `tested[loc]` endpoints; build_fuzz_requests would then spray a fuzz request onto each and DAST
    would re-fire the same low-value finding per endpoint. When a (param, loc) is found on ≥ `ratio` of
    the endpoints TESTED at that location AND on ≥ `min_hits` of them (so a tiny tested set can't trip
    the ratio), its records collapse to the FIRST one, marked {"scope": "site-wide", "endpoints": N}.
    Endpoint-specific params (the real hidden ones) are untouched. Order-preserving, pure.

    Operates on merge_params' output (already deduped by (url, param, loc)), so the per-(param, loc)
    record count IS the distinct-endpoint hit count."""
    hits: Counter[tuple] = Counter((r.get("param"), r.get("loc")) for r in records)
    glob_keys = {k for k, c in hits.items()
                 if (d := tested.get(k[1] or "query", 0)) and c >= min_hits and c / d >= ratio}
    out: list[dict] = []
    emitted: set[tuple] = set()
    for r in records:
        k = (r.get("param"), r.get("loc"))
        if k not in glob_keys:
            out.append(r)
        elif k not in emitted:
            emitted.add(k)
            out.append({**r, "scope": "site-wide", "endpoints": hits[k]})
    return out


def merge_params_wordlist(custom: list[str], glob: list[str]) -> list[str]:
    """The arjun/x8 wordlist: per-app custom param candidates FIRST, then the global params role,
    deduped (custom-first preserved). Pure."""
    return tools.dedupe([*custom, *glob])


def _effective_params_wl(ws: AppWorkspace, glob: Path | None) -> Path | None:
    """Resolve the params wordlist for arjun/x8: wl_custom/params.txt (build_wordlist) merged
    custom-first with the global `params` role into raw/param_fuzz/params.txt (tool scratch). Falls
    back to the global path unchanged when there are no custom params, or None when neither resolves
    (preserving the 'no params wl → x8 skipped' semantics)."""
    custom = tools.read_lines(ws.wl_custom / "params.txt")
    if not custom:
        return glob
    merged = merge_params_wordlist(custom, tools.read_lines(glob) if glob else [])
    dest = ws.raw("param_fuzz") / "params.txt"
    tools.write_lines(dest, merged)
    return dest


# location → the arjun request method (-m) that injects params there. arjun has no header-discovery
# mode, so "header" is x8-only (absent here).
_ARJUN_METHOD = {"query": "GET", "body": "POST", "json": "JSON"}


def _arjun_header_flags() -> list[str]:
    """arjun takes session headers as ONE --headers arg (newline-separated), unlike the repeated -H of
    katana/httpx/x8."""
    hs = _auth_headers()
    return ["--headers", "\n".join(hs)] if hs else []


def _run_arjun(targets_file: Path, out_file: Path, params_wl: Path | None, app_id: str,
               *, loc: str = "query") -> list[dict]:
    """arjun over the targets file for ONE location (best-effort). -m picks the request method that
    puts params in `loc` (query→GET, body→POST, json→JSON). Writes JSON to -oJ (bypasses _run);
    falls back to arjun's builtin wordlist when the params role is unresolved. loc='header' is x8-only."""
    method = _ARJUN_METHOD.get(loc)
    if method is None:
        return []
    if shutil.which(ARJUN) is None:
        log.debug("  · skip arjun (not installed) for %s", app_id)
        return []
    out_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = [ARJUN, "-i", str(targets_file), "-oJ", str(out_file), "-m", method, "-t", ARJUN_THREADS,
           "-T", ARJUN_TIMEOUT, "--rate-limit", ARJUN_RATE, "-q", *_arjun_header_flags()]
    if params_wl is not None:
        cmd += ["-w", str(params_wl)]
    try:
        tools.run(cmd, timeout=PARAM_TOOL_TIMEOUT, stream_stderr=is_verbose())
    except subprocess.TimeoutExpired:
        log.warning("⚠ arjun(%s) hit the %ds cap for %s — keeping partial results",
                    loc, PARAM_TOOL_TIMEOUT, app_id)
    text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
    return parse_arjun(text, loc=loc)


def _run_x8(targets_file: Path, out_file: Path, params_wl: Path | None, app_id: str,
            *, mode: str = "query") -> list[dict]:
    """x8 over the targets file for ONE location (best-effort). mode picks where x8 injects: query
    (default), body (-X POST), json (-X POST -t json), header (--headers). Writes JSON to -o (bypasses
    _run). Needs a params wordlist (skipped if the role is unresolved). --one-worker-per-host is the
    politeness lever."""
    if shutil.which(X8) is None:
        log.debug("  · skip x8 (not installed) for %s", app_id)
        return []
    if params_wl is None:
        log.debug("  · skip x8 (no params wordlist) for %s", app_id)
        return []
    out_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = [X8, "-u", str(targets_file), "-w", str(params_wl), "-O", "json", "-o", str(out_file),
           "-W", X8_WORKERS, "-c", X8_CONCURRENCY, "--timeout", X8_TIMEOUT, "-d", X8_DELAY,
           "--one-worker-per-host", "--disable-progress-bar"]
    if mode == "body":
        cmd += ["-X", "POST"]
    elif mode == "json":
        cmd += ["-X", "POST", "-t", "json"]
    elif mode == "header":
        cmd += ["--headers"]
    cmd += ["-H", *_auth_headers()] if _auth_headers() else []
    try:
        tools.run(cmd, timeout=PARAM_TOOL_TIMEOUT, stream_stderr=is_verbose())
    except subprocess.TimeoutExpired:
        log.warning("⚠ x8(%s) hit the %ds cap for %s — keeping partial results",
                    mode, PARAM_TOOL_TIMEOUT, app_id)
    text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
    return parse_x8(text, loc=mode)


def _working_schemes(ws: AppWorkspace) -> dict[str, str]:
    """Bare host → the scheme the scanners actually reached this app on: the cluster hosts.txt scheme
    (which already honors an explicit scope scheme), overridden by the scheme of content_discovery's
    hit URLs — empirical proof of the reachable scheme, including feroxbuster's http fallback for an
    https endpoint a strict-TLS client refuses (legacy renegotiation / weak DH). Lets param_fuzz route
    arjun/x8 to that scheme instead of httpx's https guess: both fail the same handshake SILENTLY (no
    error, no params — indistinguishable from a clean 0-param result), so there's no signal to retry
    on reactively the way feroxbuster's statistics record allows."""
    schemes: dict[str, str] = {}
    for h in tools.read_lines(ws.hosts):
        if "://" in h:
            schemes.setdefault(url_host(h), h.split("://", 1)[0])
    for r in tools.read_jsonl(ws.canonical("content_discovery.jsonl")):
        u = r.get("url")
        if u and "://" in u:
            schemes[url_host(u)] = u.split("://", 1)[0]
    return schemes


def recrawl(activity: Activity, app_id: str) -> None:
    """PHASE 3 — bounded re-seed crawl of fuzzing-discovered entry points into UN-CRAWLED territory.

    When content_discovery's forced-browse finds a directory the link-crawler never reached (e.g. an
    unlinked /debugging that opens a whole sub-app), forced-browse + body-mining recover the downloaded
    surface but NOT what needs a real crawl (JS-rendered nav, deeper link-following). This re-seeds
    katana on those entry points (select_recrawl_seeds: a discovered URL whose directory no crawled URL
    touched), storing bodies into the corpus so request_catalog mines them — no new mining code.

    Mode via env PTFLOW_RECRAWL (default `on`): `off` skip; `preview` select + write + LOG the seeds but
    DON'T crawl (review raw/recrawl/seeds.txt); `on` also crawl. Bounded even when on: at most
    RECRAWL_MAX_SEEDS shallow seeds, depth RECRAWL_DEPTH, -ct per-host cap, ONE pass (no crawl⇄fuzz loop).
    Reads content_discovery across the barrier (no needs)."""
    if RECRAWL == "off":
        return
    ws = activity.app(app_id)
    crawled = [*tools.read_lines(ws.canonical("endpoints.txt")),
               *tools.read_lines(ws.canonical("endpoints_headless.txt")),
               *[u for idx in _all_store_indices(ws) for _, u in _store_index(idx)]]
    discovered = [r["url"] for r in tools.read_jsonl(ws.canonical("content_discovery.jsonl"))
                  if r.get("url") and 200 <= (r.get("status") or 0) < 300]  # 2xx entry points only  # noqa: PLR2004
    in_scope = {url_host(h) for h in tools.read_lines(ws.hosts)}
    seeds = select_recrawl_seeds(discovered, crawled, in_scope, cap=RECRAWL_MAX_SEEDS)
    seeds_file = ws.raw("recrawl") / "seeds.txt"
    tools.write_lines(seeds_file, seeds)
    if not seeds:
        log.debug("  · recrawl (%s) — no new-territory seeds", app_id)
        return
    if RECRAWL != "on":   # preview (default): surface the seeds for review, do NOT crawl
        log.info("  → recrawl (%s) — PREVIEW: %d new-territory seed(s) → %s "
                 "(set PTFLOW_RECRAWL=on to crawl them)", app_id, len(seeds), seeds_file)
        return
    store = ws.responses / "recrawl"
    store.mkdir(parents=True, exist_ok=True)
    cmd = ["katana", "-silent", "-j", "-jc", "-jsl", "-kf", "all", "-fx", "-xhr", "-fs", "fqdn",
           "-d", RECRAWL_DEPTH, "-c", KATANA_CONC, "-ct", RECRAWL_CT,
           "-omit-body", "-srd", str(store), *_header_flags("-H")]
    out = _run("katana-recrawl", cmd, stdin="\n".join(seeds),
               dest=ws.raw("katana") / "recrawl" / "out.jsonl", label=app_id)
    n = tools.write_jsonl(ws.canonical("requests_recrawl.jsonl"),
                          merge_requests(parse_katana_requests(out, source="katana-recrawl")))
    log.info("  → recrawl (%s) — crawled %d new-territory seed(s) → %d request(s) (bodies → responses/recrawl/)",
             app_id, len(seeds), n)


# Cross-group endpoint routing: discovery artifacts (JS/XHR/crawl-derived) that can carry a reference to
# a DIFFERENT in-scope group's host — e.g. attack.com's frontend calling api.company.com's API.
_XREF_REQUEST_FILES = ("requests_crawl.jsonl", "requests_headless.jsonl", "requests_api.jsonl")
_XREF_ENDPOINT_FILES = ("endpoints.txt", "endpoints_js.txt", "endpoints_headless.txt")


def _cross_group_surface(activity: Activity, ws: AppWorkspace) -> list[dict]:
    """Request records discovered in OTHER app groups whose host belongs to `ws` — cross-group routing
    that carries an API host's surface (only discoverable from another group's frontend JS) into that
    host's OWN group. Returns request records (bare endpoints converted to GET via _url_to_get_request),
    each with `xref:<origin app_id>` appended to `sources`. Reads only other groups' DERIVED discovery
    artifacts (no re-mining, no network). RoE-safe: only hosts owned by `ws` are kept, so a host that is
    no group's host is never routed. Pure-ish (reads disk only)."""
    mine = {url_host(h) for h in tools.read_lines(ws.hosts)}
    if not mine:
        return []
    out: list[dict] = []
    for other in activity.list_apps():
        origin = other.root.name
        if origin == ws.root.name:
            continue
        tag = f"xref:{origin}"
        for fname in _XREF_REQUEST_FILES:
            out.extend({**rec, "sources": [*(rec.get("sources") or []), tag]}
                       for rec in tools.read_jsonl(other.canonical(fname))
                       if url_host(rec.get("url") or "") in mine)
        for fname in _XREF_ENDPOINT_FILES:
            out.extend(_url_to_get_request(u, tag)
                       for u in tools.read_lines(other.canonical(fname))
                       if url_host(u) in mine)
    return out


def _finalize_catalog(ws: AppWorkspace, request_recs: list[dict], get_urls: list[str]) -> tuple[list[dict], int]:
    """Turn assembled request records + URL-only GETs into the final per-app catalog: scheme-normalize
    to the empirically-reachable scheme (_working_schemes), in-scope-filter to ws.hosts, dedup by shape
    (catalog_records), then DROP GET shapes whose path the corpus only ever saw as 404/410 (dead_url_keys
    — a discovered POST/form/XHR/JSON shape, status never recorded, is always kept). Returns (kept catalog,
    count dropped as dead). Pure-ish (reads disk only)."""
    in_scope = {url_host(h) for h in tools.read_lines(ws.hosts)}
    schemes = _working_schemes(ws)
    catalog = catalog_records(request_recs, get_urls, in_scope, schemes)
    dead = dead_url_keys(ln for idx in _all_store_indices(ws) for ln in tools.read_lines(idx))
    kept = [r for r in catalog
            if not (r.get("method", "GET").upper() == "GET" and not r.get("body")
                    and _url_pathkey(r.get("url") or "") in dead)]
    return kept, len(catalog) - len(kept)


def _assemble_catalog(activity: Activity, ws: AppWorkspace, *, include_guessed: bool) -> tuple[list[dict], int, int]:
    """Assemble a per-app request catalog → (catalog records, count mined from corpus, count dropped as
    dead/404). Pure-ish (reads disk only). Three contributions, all deduped by request shape
    (`merge_requests`):
    1. the crawl/headless/API-spec request records (method/body/forms/xhr/spec);
    2. SHAPES MINED from the downloaded corpus — `jsluice_requests` (fetch/XHR method+body, the JS API
       surface) + `html_form_requests` (POST/GET forms, incl. the UNLINKED pages feroxbuster found —
       their bodies are stored, but katana -fx only saw what katana crawled). "fetch once, mine offline":
       no re-crawl — the bodies are already on disk; relative urls resolve against each body's source url;
    3. the URL-only discovery sources (passive/crawley/feroxbuster/jsluice endpoints) as GET fallbacks.
    Every url is scheme-normalized to the empirically-reachable scheme (_working_schemes — the http
    fallback a strict-TLS scanner needs) and in-scope-filtered.

    `include_guessed` gates the GUESSED-surface inputs (recrawl requests + content_discovery 2xx hits +
    the fuzz-downloaded corpus, which only exists once content_discovery/recrawl have run): False builds
    the EXPLORABLE-surface catalog (phase 1, requests.jsonl), True the full catalog (phase 4,
    requests_full.jsonl). The corpus mining scales with what's on disk — the gate just keeps the surface
    catalog stable even on a --resume rerun after the guessed artifacts already exist.

    Finally, GET shapes whose endpoint the corpus only ever saw as 404/410 are dropped (`dead_url_keys`)
    — malformed passive/archive URLs and phantom JS routes that would just burn DAST/param-fuzz payloads.
    GET-only + body-less: a discovered POST/form/XHR/JSON shape (status never recorded) is always kept."""
    # mine request SHAPES from the already-downloaded corpus (idempotent extract → ensure it's present)
    bodies, _ = _extract_bodies(ws)
    source_urls = {Path(s).stem: u for idx in _all_store_indices(ws) for s, u in _store_index(idx)}
    js_files = sorted(str(p) for p in bodies.glob("*.js")) if bodies else []
    mined = jsluice_requests(_jsluice_records(js_files), source_urls)
    mined += html_form_requests(bodies, source_urls) if bodies else []
    request_recs = [*tools.read_jsonl(ws.canonical("requests_crawl.jsonl")),
                    *tools.read_jsonl(ws.canonical("requests_headless.jsonl")),
                    *tools.read_jsonl(ws.canonical("requests_api.jsonl")),
                    *mined]
    get_urls = [*tools.read_lines(ws.canonical("endpoints.txt")),
                *tools.read_lines(ws.canonical("endpoints_js.txt")),
                *tools.read_lines(ws.canonical("endpoints_headless.txt"))]
    if include_guessed:
        request_recs += tools.read_jsonl(ws.canonical("requests_recrawl.jsonl"))  # re-seed crawl (if on)
        request_recs += _cross_group_surface(activity, ws)  # endpoints discovered in OTHER in-scope groups
        get_urls += [r["url"] for r in tools.read_jsonl(ws.canonical("content_discovery.jsonl"))
                     if r.get("url") and 200 <= (r.get("status") or 0) < 300]  # noqa: PLR2004
    kept, n_dead = _finalize_catalog(ws, request_recs, get_urls)
    return kept, len(mined), n_dead


def request_catalog(activity: Activity, app_id: str) -> None:
    """PHASE 1 (tail) — assemble the EXPLORABLE-SURFACE request catalog (requests.jsonl), the
    full-request DAST input for phase 2.

    Crawl/headless/API-spec records + shapes mined from the crawl corpus + the URL-only discovery
    sources as GET fallbacks — NO guessed surface (content_discovery/recrawl run later, in phase 3).
    Offline (net=False); needs crawl_headless/mine_responses/api_spec so the records + extracted corpus
    are present. A bare URL list can only fuzz GET query — this catalog is what unlocks POST/JSON/body."""
    ws = activity.app(app_id)
    catalog, n_mined, n_dead = _assemble_catalog(activity, ws, include_guessed=False)
    n = tools.write_jsonl(ws.canonical("requests.jsonl"), catalog)
    methods = ",".join(sorted({m for r in catalog if (m := r.get("method"))}))
    log.info("  → request_catalog (%s) — %d surface request shape(s) [%s] (mined %d from corpus,"
             " dropped %d dead/404) → requests.jsonl", app_id, n, methods, n_mined, n_dead)


def request_catalog_full(activity: Activity, app_id: str) -> None:
    """PHASE 4 (head) — rebuild the catalog INCLUDING the guessed surface → requests_full.jsonl.

    Same assembly as request_catalog but folds in the fuzzing-discovered surface: recrawl requests +
    content_discovery 2xx hits + the shapes mined from the now-extended corpus (responses/discovered/,
    responses/recrawl/ — re-extracted idempotently). Offline (net=False); reads phase-1 + phase-3
    artifacts across the barriers, so it sees the COMPLETE corpus. Feeds param_fuzz + dast_full."""
    ws = activity.app(app_id)
    catalog, n_mined, n_dead = _assemble_catalog(activity, ws, include_guessed=True)
    n = tools.write_jsonl(ws.canonical("requests_full.jsonl"), catalog)
    methods = ",".join(sorted({m for r in catalog if (m := r.get("method"))}))
    log.info("  → request_catalog_full (%s) — %d request shape(s) [%s] (mined %d from corpus,"
             " dropped %d dead/404) → requests_full.jsonl", app_id, n, methods, n_mined, n_dead)


def xref_catalog(activity: Activity, app_id: str) -> None:
    """PHASE 2 (head) — assemble the CROSS-GROUP surface catalog (requests_xref.jsonl): requests/endpoints
    discovered in OTHER in-scope groups whose host belongs to THIS group, so the phase-2 dast/xss/sqli
    pass tests the cross-group surface on the FAST pass, not only in phase 4 (request_catalog_full).

    Safe by the loop barrier: the global 1→2 barrier guarantees every group finished phase 1, so reading
    peers' discovery artifacts is race-free (same guarantee request_catalog_full relies on at phase 4).
    Offline (net=False). A lone group has no peers → an empty sidecar (tolerant reads make it a no-op)."""
    ws = activity.app(app_id)
    catalog, n_dead = _finalize_catalog(ws, _cross_group_surface(activity, ws), [])
    n = tools.write_jsonl(ws.canonical("requests_xref.jsonl"), catalog)
    log.info("  → xref_catalog (%s) — %d cross-group request shape(s) (dropped %d dead/404)"
             " → requests_xref.jsonl", app_id, n, n_dead)


def param_fuzz(activity: Activity, app_id: str) -> None:
    """PHASE 4 — hidden-parameter discovery across ALL locations (query · body · json · header), not
    just GET, over the FULL request catalog (requests_full.jsonl) — so it probes the fuzzing-discovered
    endpoints for hidden params too, not only the crawl surface.

    reconftw and the old param_fuzz tested only the GET query string. Here:
    - QUERY discovery runs over every endpoint shape (select_param_endpoints: deduped by path-template,
      capped PARAM_MAX_ENDPOINTS);
    - BODY + JSON discovery targets the endpoints the crawl saw with a body (forms/xhr/POST —
      select_body_targets), topped up from the query set to PARAM_MAX_BODY_ENDPOINTS so hidden POST
      params on a GET-looking endpoint are probed too;
    - HEADER discovery (x8 only — arjun has no header mode) over a small subset.
    arjun (-m GET/POST/JSON) ∥ x8 (-X / --data-type json / --headers), best-effort, capped per-tool
    wall-clock; merged by (url, param, loc) → params.jsonl (a deliverable + the DAST input). The
    catalog urls are already scheme-normalized (request_catalog), so no re-scheme here.
    """
    ws = activity.app(app_id)
    catalog = tools.read_jsonl(ws.canonical("requests_full.jsonl"))
    in_scope = {url_host(h) for h in tools.read_lines(ws.hosts)}
    query_targets = select_param_endpoints((r.get("url") or "" for r in catalog), in_scope,
                                           cap=PARAM_MAX_ENDPOINTS)
    if not query_targets:
        log.debug("  · skip param_fuzz (no endpoints) for %s", app_id)
        return
    body_targets, json_targets = select_body_targets(catalog, in_scope, cap=PARAM_MAX_BODY_ENDPOINTS)
    # probe hidden POST params on GET-looking endpoints too (top up urlencoded body, still capped)
    body_targets = tools.dedupe([*body_targets, *query_targets])[:PARAM_MAX_BODY_ENDPOINTS]
    header_targets = query_targets[:PARAM_MAX_HEADER_ENDPOINTS]
    params_wl = _effective_params_wl(ws, wordlists.role_path(activity, "params"))
    jobs = [(loc, t) for loc, t in
            (("query", query_targets), ("body", body_targets),
             ("json", json_targets), ("header", header_targets)) if t]
    log.info("  → param_fuzz (%s) — %s, arjun ∥ x8%s", app_id,
             " ".join(f"{loc}:{len(t)}" for loc, t in jobs),
             "" if params_wl else " (no params wl → x8 skipped)")
    # one bounded pool over the flat (tool, location) matrix — arjun only where it has a mode
    records: list[dict] = []
    with ThreadPoolExecutor(max_workers=PARAM_FANOUT) as pool:
        futs = []
        for loc, targets in jobs:
            tf = ws.raw("param_fuzz") / f"targets_{loc}.txt"
            tools.write_lines(tf, targets)
            if loc in _ARJUN_METHOD:
                futs.append(pool.submit(_run_arjun, tf, ws.raw("arjun") / f"{loc}.json",
                                        params_wl, app_id, loc=loc))
            futs.append(pool.submit(_run_x8, tf, ws.raw("x8") / f"{loc}.json", params_wl, app_id, mode=loc))
        for fut in futs:
            records += fut.result()
    merged = merge_params(records)
    params = collapse_global_params(merged, {loc: len(t) for loc, t in jobs})
    n = tools.write_jsonl(ws.canonical("params.jsonl"), params)
    by_loc = " ".join(f"{loc}:{c}" for loc, c in sorted(Counter(p.get("loc") for p in params).items()))
    n_global = sum(1 for p in params if p.get("scope") == "site-wide")
    collapsed = f", {n_global} site-wide collapsed" if n_global else ""
    log.info("    param_fuzz (%s) → %d param(s) on %d endpoint(s) [%s]%s → params.jsonl",
             app_id, n, len({p["url"] for p in params}), by_loc, collapsed)


# --- DAST (PHASE 2 surface + PHASE 4 deep) — nuclei -dast over the request catalog --------------
def _synth_request(method: str, url: str, headers: dict[str, str], body: str, source: str) -> dict:
    """A catalog request synthesized from scratch (its raw built by build_raw_request) — used to turn
    discovered hidden params into a concrete fuzzable request. Pure."""
    ct = next((str(v) for k, v in headers.items() if str(k).lower() == "content-type"), "")
    return {"method": method.upper(), "url": url, "headers": headers, "body": body,
            "params": request_params(url, body, ct),
            "raw": build_raw_request(method, url, headers, body), "sources": [source]}


def build_fuzz_requests(params: Iterable[dict]) -> list[dict]:
    """Synthesize fuzzable requests from the discovered params (params.jsonl), grouped by (url,
    location): query→GET ?p=, body→POST urlencoded, json→POST JSON {p:""}, header→GET with the headers
    present. nuclei fuzzes params that EXIST in the request, so a hidden param param_fuzz found is only
    reachable once injected into a concrete request here. Pure."""
    groups: dict[tuple, list[str]] = {}
    for p in params:
        url, name, loc = p.get("url"), p.get("param"), p.get("loc") or "query"
        if url and name:
            groups.setdefault((url, loc), []).append(str(name))
    out: list[dict] = []
    for (url, loc), raw_names in groups.items():
        names = tools.dedupe(raw_names)
        if loc == "header":
            out.append(_synth_request("GET", url, dict.fromkeys(names, "x"), "", "param_fuzz"))
        elif loc == "json":
            out.append(_synth_request("POST", url, {"Content-Type": "application/json"},
                                      json.dumps(dict.fromkeys(names, "")), "param_fuzz"))
        elif loc == "body":
            out.append(_synth_request("POST", url, {"Content-Type": "application/x-www-form-urlencoded"},
                                      "&".join(f"{n}=" for n in names), "param_fuzz"))
        else:  # query
            full = url + ("&" if "?" in url else "?") + "&".join(f"{n}=" for n in names)
            out.append(_synth_request("GET", full, {}, "", "param_fuzz"))
    return out


def dast_requests(catalog: Iterable[dict], params: Iterable[dict], *, cap: int) -> list[dict]:
    """The full request set to fuzz: the catalog + the synthesized requests for discovered hidden
    params, deduped by shape (merge_requests) and capped (logged when it bites). Pure (logging only)."""
    merged = merge_requests([*catalog, *build_fuzz_requests(params)])
    if len(merged) > cap:
        log.warning("⚠ dast: capping request set %d→%d (set PTFLOW_* / raise DAST_MAX_REQUESTS)",
                    len(merged), cap)
        return merged[:cap]
    return merged


def dedup_dast_findings(records: Iterable[dict]) -> list[dict]:
    """Collapse nuclei -dast findings to one record per distinct INJECTION POINT. nuclei emits one hit
    per fuzzed request, so a template that fires on many synthesized variants of the same endpoint (the
    param-sprayed catalog, http+https of one host, …) yields a pile of records for ONE issue — that's
    what inflated the count. A fuzzing hit is keyed by (template, host, path, fuzz position, method): the
    payload lives in the query/body so the path is taken WITHOUT it. Non-fuzzing hits key on
    (template, matched-at) so unrelated findings are never merged. First full record per key wins
    (its matched-at keeps a concrete example); order-preserving, pure."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for r in records:
        tid = r.get("template-id") or r.get("template_id") or ""
        at = r.get("matched-at") or r.get("matched_at") or r.get("url") or ""
        if r.get("is_fuzzing_result"):
            sp = urlsplit(at)
            key: tuple = (tid, sp.netloc, sp.path, r.get("fuzzing_position") or "",
                          r.get("fuzzing_method") or "")
        else:
            key = (tid, at)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _run_dast(ws: AppWorkspace, requests_: list[dict], *, input_name: str, out_name: str,
              label: str) -> None:
    """Run nuclei -dast over a prepared request set → findings/<out_name>. Shared by dast (phase-2
    surface) + dast_full (phase-4 guessed). nuclei -im jsonl builds each fuzzed request from `raw`, so
    it fuzzes query · path · header · cookie · BODY — not just the GET query a bare URL list allows.
    Best-effort: skips if the nuclei binary or the dast templates (PTFLOW_NUCLEI_DAST_TEMPLATES) are
    absent, or the request set is empty. Provenance input → raw/dast/<input_name>."""
    stage = out_name.removesuffix(".jsonl")
    if shutil.which("nuclei") is None:
        log.debug("  · skip %s (nuclei not installed) for %s", stage, label)
        return
    if not Path(NUCLEI_DAST_TEMPLATES).is_dir():
        log.info("  · skip %s (no dast templates at %s) for %s", stage, NUCLEI_DAST_TEMPLATES, label)
        return
    if not requests_:
        log.debug("  · skip %s (no requests) for %s", stage, label)
        return
    input_file = ws.raw("dast") / input_name   # nuclei -l input (provenance, tool's own input)
    tools.write_jsonl(input_file, [{"request": {"endpoint": r["url"], "raw": r["raw"]}}
                                   for r in requests_])
    log.info("  → %s (%s) — nuclei -dast over %d request(s) [-fa %s]", stage, label, len(requests_),
             DAST_AGGRESSION)
    cmd = ["nuclei", "-dast", "-im", "jsonl", "-l", str(input_file), "-t", NUCLEI_DAST_TEMPLATES,
           "-fa", DAST_AGGRESSION, "-rl", NUCLEI_RL, "-c", NUCLEI_CONC, "-timeout", NUCLEI_TIMEOUT,
           "-retries", NUCLEI_RETRIES, "-j", "-silent", "-duc", *_header_flags("-H")]
    out = tools.run(cmd, stream_stderr=is_verbose())
    findings = _jsonl_str(out)
    deduped = dedup_dast_findings(findings)
    n = tools.write_jsonl(ws.findings / out_name, deduped)
    extra = f" (deduped from {len(findings)})" if len(findings) != n else ""
    log.info("    %s (%s) → %d finding(s)%s → findings/%s", stage, label, n, extra, out_name)


def _surface_request_set(ws: AppWorkspace, *, cap: int) -> list[dict]:
    """The EXPLORABLE-surface request set (phase 2): the surface catalog (requests.jsonl), deduped by
    shape and capped. Shared by `dast` and the surface vuln scanners (xss/sqli)."""
    return dast_requests(tools.read_jsonl(ws.canonical("requests.jsonl")), [], cap=cap)


def _delta_request_set(ws: AppWorkspace, *, cap: int) -> list[dict]:
    """The GUESSED-surface DELTA request set (phase 4): full-catalog shapes NOT already in the surface
    catalog (by request_key) + the synthesized requests for the discovered hidden params (params.jsonl),
    deduped and capped. Shared by `dast_full` and the deep vuln scanners (xss_full/sqli_full) so the
    "delta, not the whole catalog" rule lives in ONE place."""
    surface_keys = {request_key(r) for r in tools.read_jsonl(ws.canonical("requests.jsonl"))}
    delta = [r for r in tools.read_jsonl(ws.canonical("requests_full.jsonl"))
             if request_key(r) not in surface_keys]
    return dast_requests(delta, tools.read_jsonl(ws.canonical("params.jsonl")), cap=cap)


def dast(activity: Activity, app_id: str) -> None:
    """PHASE 2 — DAST the EXPLORABLE SURFACE (low-hanging fruit): nuclei -dast over the surface catalog
    (requests.jsonl), fuzzing the OBSERVED params (query/body/form/xhr the crawl actually saw). Fast,
    high-signal findings on the real attack surface BEFORE the heavy fuzzing — no hidden-param discovery
    yet (that's guessing → phase 4). Output → findings/dast.jsonl. Reads requests.jsonl across the
    barrier (phase 1)."""
    ws = activity.app(app_id)
    _run_dast(ws, _surface_request_set(ws, cap=DAST_MAX_REQUESTS),
              input_name="input.jsonl", out_name="dast.jsonl", label=app_id)


def dast_full(activity: Activity, app_id: str) -> None:
    """PHASE 4 — DAST the GUESSED surface (detailed). To avoid re-DASTing what phase-2 already covered,
    it fuzzes only the DELTA: the request shapes in the full catalog (requests_full.jsonl) NOT already
    in the surface catalog (requests.jsonl, keyed by request_key) PLUS the synthesized requests for the
    hidden params param_fuzz discovered (params.jsonl) — those are NEW injection points even on a
    crawl-surface endpoint. Output → findings/dast_full.jsonl. Needs request_catalog_full + param_fuzz.
    """
    ws = activity.app(app_id)
    _run_dast(ws, _delta_request_set(ws, cap=DAST_MAX_REQUESTS),
              input_name="input_full.jsonl", out_name="dast_full.jsonl", label=app_id)


# --- dedicated vuln scanners (PHASE 2 surface + PHASE 4 deep) — dalfox (XSS) ∥ sqlmap (SQLi) ----------
# Both consume the catalog's `raw` (one request per process, Burp/ZAP raw), so EVERY param location is
# tested, not GET-only. NO gf-style name routing: every parameterized request is a candidate, each tool's
# own engine decides (dalfox reflection+context · sqlmap --smart heuristic). Best-effort, capped, with a
# per-request wall-clock cap (TimeoutExpired → that request yields nothing, the stage keeps the rest).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")  # strip terminal control sequences from tool stdout


def _has_params(r: dict) -> bool:
    """A request worth handing to dalfox/sqlmap — it has something to fuzz: enumerated params, a query
    string, or a body. A bare param-less GET is useless to either tool."""
    return bool(r.get("params")) or "?" in (r.get("url") or "") or bool(r.get("body"))


def _vuln_candidates(requests_: Iterable[dict], *, cap: int) -> list[dict]:
    """The parameterized subset of a request set, capped — the scanner candidate list (no name-based
    routing: presence of a fuzzable param is the ONLY filter)."""
    return [r for r in requests_ if _has_params(r)][:cap]


def parse_dalfox(out: str) -> list[dict]:
    """dalfox --format jsonl stdout → XSS findings. Each PoC record:
    {type:R|V|G, inject_type, poc_type, method, data:<PoC url>, param, payload, evidence, cwe, severity,
    message_str}. Normalized to a finding stamped type:'xss'. Pure (skips non-json/banner lines)."""
    out_recs: list[dict] = []
    for j in _jsonl_str(out):
        if not isinstance(j, dict) or not j.get("data"):
            continue
        out_recs.append({"type": "xss", "poc_kind": j.get("type"), "inject_type": j.get("inject_type"),
                         "severity": str(j.get("severity") or "").lower(), "param": j.get("param"),
                         "method": j.get("method"), "payload": j.get("payload"),
                         "evidence": j.get("evidence"), "cwe": j.get("cwe"),
                         "matched-at": j.get("data"), "sources": ["dalfox"]})
    return out_recs


def parse_sqlmap(out: str, *, url: str | None = None) -> list[dict]:
    """sqlmap stdout → SQLi findings. Parses the stable 'Parameter: <p> (<loc>)' result block(s), one
    finding per (param, technique) from each Type/Title/Payload triple, stamped with the back-end DBMS.
    Pure; tolerant of empty/garbled output (returns [] when no injection block is present)."""
    text = _ANSI_RE.sub("", out or "")
    dm = re.search(r"back-end DBMS(?:\s+is)?:?\s*([^\n]+)", text)
    dbms = dm.group(1).strip() if dm else None
    findings: list[dict] = []
    for pm in re.finditer(r"^Parameter:\s*(?P<param>.+?)\s*\((?P<loc>[^)]+)\)\s*$(?P<body>.*?)"
                          r"(?=^Parameter:|\Z)", text, re.DOTALL | re.MULTILINE):
        param, loc = pm.group("param").strip(), pm.group("loc").strip()
        findings.extend(
            {"type": "sqli", "param": param, "location": loc,
             "technique": tm.group("t").strip(), "title": tm.group("title").strip(),
             "payload": tm.group("p").strip(), "dbms": dbms,
             "matched-at": url, "sources": ["sqlmap"]}
            for tm in re.finditer(r"Type:\s*(?P<t>[^\n]+)\n\s*Title:\s*(?P<title>[^\n]+)\n\s*"
                                  r"Payload:\s*(?P<p>[^\n]+)", pm.group("body")))
    return findings


_OAST_DOMAIN_RE = re.compile(r"[a-z0-9]{20,}\.oast\.\w+")  # interactsh-client's registered callback host


def correlate_oast(interactions: Iterable[dict], marker_map: Mapping[str, dict],
                   *, unique_id: str) -> list[dict]:
    """Match interactsh interactions back to the dalfox request that fired them → blind-XSS findings.
    Each interaction's `full-id` is `<marker>.<unique-id>` (the per-request callback subdomain we set as
    dalfox's -b); strip the trailing `.<unique-id>` to recover the marker → marker_map[marker] is the
    request. Bare-domain hits (full-id == unique-id) are interactsh background noise → ignored. Deduped
    by (marker, protocol) so repeated DNS polls of one callback are one finding. Pure."""
    out: list[dict] = []
    seen: set[tuple] = set()
    suffix = "." + unique_id
    for it in interactions:
        fid = str(it.get("full-id") or "")
        if not fid.endswith(suffix):           # bare domain (no marker) or unrelated → noise
            continue
        marker = fid[: -len(suffix)]
        r = marker_map.get(marker)
        if r is None:
            continue
        key = (marker, it.get("protocol"))
        if key in seen:                        # repeated polls of the same callback → one finding
            continue
        seen.add(key)
        out.append({"type": "xss", "poc_kind": "blind", "severity": "high",
                    "method": r.get("method"), "matched-at": r.get("url"), "params": r.get("params"),
                    "oast_protocol": it.get("protocol"), "remote_address": it.get("remote-address"),
                    "timestamp": it.get("timestamp"), "sources": ["dalfox", "interactsh"]})
    return out


def _oast_start(ws: AppWorkspace, stage: str) -> tuple[subprocess.Popen, str, Path] | None:
    """Start an interactsh-client OAST daemon for a dalfox pass (best-effort). Returns
    (proc, callback_domain, interactions_jsonl) or None if OAST is off / the client is absent / it never
    registered within OAST_REG_TIMEOUT. The callback domain is parsed from the client's stderr log."""
    if not OAST_ENABLED or shutil.which(INTERACTSH) is None:
        return None
    oast_dir = ws.raw("dalfox")
    oast_dir.mkdir(parents=True, exist_ok=True)
    jsonl = oast_dir / f"{stage}_oast.jsonl"
    errlog = oast_dir / f"{stage}_oast.log"
    jsonl.write_text("", encoding="utf-8")
    cmd = [INTERACTSH, "-json", "-o", str(jsonl), "-pi", OAST_POLL,
           *(["-s", OAST_SERVER] if OAST_SERVER else []), *(["-t", OAST_TOKEN] if OAST_TOKEN else [])]
    proc = tools.spawn(cmd, stderr_path=errlog)
    for _ in range(OAST_REG_TIMEOUT):
        time.sleep(1)
        m = _OAST_DOMAIN_RE.search(errlog.read_text(encoding="utf-8", errors="replace"))
        if m:
            log.info("  → OAST (%s) — interactsh callback %s", stage, m.group(0))
            return proc, m.group(0), jsonl
        if proc.poll() is not None:            # client exited → couldn't register
            break
    log.warning("⚠ OAST (%s): interactsh-client did not register in %ds — blind XSS off this pass",
                stage, OAST_REG_TIMEOUT)
    tools.stop(proc)
    return None


def _oast_drain(oast: tuple[subprocess.Popen, str, Path], marker_map: dict[str, dict]) -> list[dict]:
    """Stop the interactsh-client and correlate the interactions it captured → blind-XSS findings."""
    proc, domain, jsonl = oast
    time.sleep(OAST_DRAIN_GRACE)               # let synchronous callbacks land + one more poll cycle
    tools.stop(proc)
    return correlate_oast(tools.read_jsonl(jsonl), marker_map, unique_id=domain.split(".", 1)[0])


def _run_dalfox(ws: AppWorkspace, requests_: list[dict], *, out_name: str, label: str) -> None:
    """Run dalfox over each candidate request's `raw` (file --rawdata), one process per request so body/
    json/header params are tested too. JSONL PoCs parsed from stdout → findings/<out_name>. With PTFLOW_OAST
    on, an interactsh-client runs alongside and each request gets a unique callback subdomain (dalfox -b)
    so a SYNCHRONOUS blind-XSS callback correlates back to its request. Best-effort: skips if dalfox is
    absent or there are no parameterized requests."""
    stage = out_name.removesuffix(".jsonl")
    if shutil.which(DALFOX) is None:
        log.debug("  · skip %s (dalfox not installed) for %s", stage, label)
        return
    if not requests_:
        log.debug("  · skip %s (no parameterized requests) for %s", stage, label)
        return
    reqdir = ws.raw("dalfox")
    reqdir.mkdir(parents=True, exist_ok=True)
    auth = _header_flags("-H")
    oast = _oast_start(ws, stage)                       # None unless PTFLOW_OAST on + client present
    domain = oast[1] if oast else None
    marker_map: dict[str, dict] = {}                    # callback marker → request (per-request blind XSS)
    log.info("  → %s (%s) — dalfox over %d parameterized request(s)%s", stage, label, len(requests_),
             " [+OAST]" if domain else "")

    def one(i_r: tuple[int, dict]) -> list[dict]:
        i, r = i_r
        reqfile = reqdir / f"{stage}_{i}.txt"
        reqfile.write_text(r.get("raw") or "", encoding="utf-8")
        cmd = [DALFOX, "file", str(reqfile), "--rawdata", "--format", "jsonl", "--no-color",
               "--skip-bav", "-w", DALFOX_WORKERS, "--timeout", DALFOX_HTTP_TIMEOUT, *auth]
        if domain:
            marker = f"b{i}"                             # unique per-request callback subdomain
            marker_map[marker] = r
            cmd += ["-b", f"https://{marker}.{domain}"]
        if (r.get("url") or "").startswith("http://"):
            cmd.append("--http")          # raw mode defaults to https; force http where that's the scheme
        try:
            return parse_dalfox(tools.run(cmd, stdin="", timeout=VULN_TOOL_TIMEOUT,
                                          stream_stderr=is_verbose()))
        except subprocess.TimeoutExpired:
            log.warning("⚠ %s: dalfox hit the %ds cap on %s", stage, VULN_TOOL_TIMEOUT, r.get("url"))
            return []

    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=VULN_FANOUT) as pool:
        for res in pool.map(one, enumerate(requests_)):
            findings += res
    blind = _oast_drain(oast, marker_map) if oast else []
    findings += blind
    n = tools.write_jsonl(ws.findings / out_name, findings)
    log.info("    %s (%s) → %d finding(s)%s → findings/%s", stage, label, n,
             f" ({len(blind)} blind via OAST)" if blind else "", out_name)


def _run_sqlmap(ws: AppWorkspace, requests_: list[dict], *, out_name: str, label: str) -> None:
    """Run sqlmap over each candidate request's `raw` (-r), one process per request. --text-only (NOT
    --smart): --smart's basic heuristic only fires on a reflected DBMS error, so it skips a boolean/UNION
    SQLi that leaks none (ginandjuice `category`); --text-only compares visible text so detection holds on
    a content-dynamic ("not stable") page. Injection block parsed from stdout → findings/<out_name>.
    Best-effort: skips if the sqlmap script or parameterized requests are absent. On the per-request
    timeout that request yields nothing (sqlmap prints its result block at the end)."""
    stage = out_name.removesuffix(".jsonl")
    if not Path(_SQLMAP_SCRIPT).exists():
        log.debug("  · skip %s (sqlmap not found at %s) for %s", stage, _SQLMAP_SCRIPT, label)
        return
    if not requests_:
        log.debug("  · skip %s (no parameterized requests) for %s", stage, label)
        return
    reqdir = ws.raw("sqlmap")
    reqdir.mkdir(parents=True, exist_ok=True)
    auth = _auth_headers()
    log.info("  → %s (%s) — sqlmap over %d parameterized request(s)", stage, label, len(requests_))

    def one(i_r: tuple[int, dict]) -> list[dict]:
        i, r = i_r
        reqfile = reqdir / f"{stage}_{i}.txt"
        reqfile.write_text(r.get("raw") or "", encoding="utf-8")
        cmd = [*SQLMAP_CMD, "-r", str(reqfile), "--batch", "--text-only", "--level", SQLMAP_LEVEL,
               "--risk", SQLMAP_RISK, "--threads", SQLMAP_THREADS, "--disable-coloring",
               "--output-dir", str(reqdir / f"out_{i}")]
        # The `raw` request carries only `Host:` (no scheme), so sqlmap defaults to http — on an
        # https-only target that means a 302→https round-trip on EVERY probe (minutes/request) and
        # tests the wrong endpoint. Force https from the catalog url's scheme; http needs no flag.
        if str(r.get("url") or "").lower().startswith("https"):
            cmd.append("--force-ssl")
        if auth:
            cmd += ["--headers", "\n".join(auth)]
        try:
            # stdin_tty: sqlmap gates on os.isatty(0) — given a plain pipe it silently reads targets
            # from STDIN and IGNORES `-r` (tests nothing). A pty slave keeps -r honoured; --batch means
            # it never blocks reading it. Default verbosity (NOT -v 0, which suppresses the injection
            # block parse_sqlmap keys on).
            return parse_sqlmap(tools.run(cmd, stdin_tty=True, timeout=VULN_TOOL_TIMEOUT,
                                          stream_stderr=is_verbose()), url=r.get("url"))
        except subprocess.TimeoutExpired:
            log.warning("⚠ %s: sqlmap hit the %ds cap on %s", stage, VULN_TOOL_TIMEOUT, r.get("url"))
            return []

    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=VULN_FANOUT) as pool:
        for res in pool.map(one, enumerate(requests_)):
            findings += res
    n = tools.write_jsonl(ws.findings / out_name, findings)
    log.info("    %s (%s) → %d finding(s) → findings/%s", stage, label, n, out_name)


def xss(activity: Activity, app_id: str) -> None:
    """PHASE 2 — dalfox over the EXPLORABLE-surface parameterized requests → findings/xss.jsonl."""
    ws = activity.app(app_id)
    _run_dalfox(ws, _vuln_candidates(_surface_request_set(ws, cap=DAST_MAX_REQUESTS), cap=VULN_MAX_REQUESTS),
                out_name="xss.jsonl", label=app_id)


def xss_full(activity: Activity, app_id: str) -> None:
    """PHASE 4 — dalfox over the GUESSED-surface DELTA + discovered-param requests → findings/xss_full.jsonl."""
    ws = activity.app(app_id)
    _run_dalfox(ws, _vuln_candidates(_delta_request_set(ws, cap=DAST_MAX_REQUESTS), cap=VULN_MAX_REQUESTS),
                out_name="xss_full.jsonl", label=app_id)


def sqli(activity: Activity, app_id: str) -> None:
    """PHASE 2 — sqlmap over the EXPLORABLE-surface parameterized requests → findings/sqli.jsonl."""
    ws = activity.app(app_id)
    _run_sqlmap(ws, _vuln_candidates(_surface_request_set(ws, cap=DAST_MAX_REQUESTS), cap=VULN_MAX_REQUESTS),
                out_name="sqli.jsonl", label=app_id)


def sqli_full(activity: Activity, app_id: str) -> None:
    """PHASE 4 — sqlmap over the GUESSED-surface DELTA + discovered-param requests → findings/sqli_full.jsonl."""
    ws = activity.app(app_id)
    _run_sqlmap(ws, _vuln_candidates(_delta_request_set(ws, cap=DAST_MAX_REQUESTS), cap=VULN_MAX_REQUESTS),
                out_name="sqli_full.jsonl", label=app_id)


# --- CVE lookup (PHASE 2 surface + PHASE 4 deep) — search_vulns over the ENUMERATED software --------
# OFFLINE correlation (net=False): no target traffic, just the enumerated software (web server + app
# tech + non-HTTP service banners + libs mined from the crawl corpus) against search_vulns' local DB.
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")          # dotted version, ≥ X.Y (single major is too vague)
_CVE_BODY_HEAD = 4096                               # bytes/body to scan — lib banners live at the head
_CVE_DESC_MAX = 500                                 # trim CVE descriptions in the finding record
# service banners (nerva metadata.banner) → (product, version). Precision-first: only known patterns.
_BANNER_PATTERNS = (
    (re.compile(r"OpenSSH[_/ ]?([\w.]+)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"vsFTPd[_/ ]?([\w.]+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"ProFTPD[_/ ]?([\w.]+)", re.IGNORECASE), "ProFTPD"),
    (re.compile(r"Exim[_/ ]?([\w.]+)", re.IGNORECASE), "Exim"),
    (re.compile(r"Sendmail[_/ ]?([\w.]+)", re.IGNORECASE), "Sendmail"),
    (re.compile(r"MariaDB[_/ -]?([\w.]+)", re.IGNORECASE), "MariaDB"),
    (re.compile(r"MySQL[_/ ]?([\w.]+)", re.IGNORECASE), "MySQL"),
    (re.compile(r"PostgreSQL[_/ ]?([\w.]+)", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"Redis(?:[_/ ]?server)?[_/ ]?v?([\w.]+)", re.IGNORECASE), "Redis"),
)
# crawl-corpus library banners (JS file heads / HTML) → (product, version). Precision-first.
_CORPUS_PATTERNS = (
    (re.compile(r"jQuery(?: JavaScript Library)? v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "jQuery"),
    (re.compile(r"jQuery UI[ -]?(?:v)?(\d+\.\d+[\d.]*)", re.IGNORECASE), "jQuery UI"),
    (re.compile(r"jQuery Migrate[ -]?(?:v)?(\d+\.\d+[\d.]*)", re.IGNORECASE), "jQuery Migrate"),
    (re.compile(r"Bootstrap v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Bootstrap"),
    (re.compile(r"AngularJS v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "AngularJS"),
    (re.compile(r"Vue(?:\.js)? v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Vue.js"),
    (re.compile(r"Lodash v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Lodash"),
    (re.compile(r"Moment\.js v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Moment.js"),
    (re.compile(r"\bReact v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "React"),
    (re.compile(r"\bD3(?:\.js)? v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "D3"),
    (re.compile(r"Underscore(?:\.js)? v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Underscore.js"),
    (re.compile(r"Backbone(?:\.js)? v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Backbone.js"),
    (re.compile(r"Handlebars(?:\.js)? v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Handlebars.js"),
    (re.compile(r"Modernizr v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Modernizr"),
    (re.compile(r"Swiper v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Swiper"),
    (re.compile(r"Select2 v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "Select2"),
    (re.compile(r"DataTables v?(\d+\.\d+[\d.]*)", re.IGNORECASE), "DataTables"),
)
_GENERATOR_RE = re.compile(r'name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', re.IGNORECASE)

# Versioned ASSET references (filenames / CDN paths / `<script src>`) — the lib version is often ONLY
# in the URL (jquery-3.6.0.min.js · /npm/vue@2.6.14/ · ajax/libs/angularjs/1.8.2/), not in a banner
# comment (minifiers strip those). Map a KNOWN library token → canonical product (precision-first: an
# unknown 'foo-1.2.3.js' never fabricates a product). The token is word-bounded and must be IMMEDIATELY
# followed by a separator + dotted version — which also stops a prefix token from matching a longer lib
# (jquery-ui-1.13.2 → after 'jquery' comes '-ui', not a digit → no jQuery match; 'jquery-ui' → jQuery
# UI). Names match the banner convention above so dedup collapses the two sources.
_ASSET_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("jquery-migrate", "jQuery Migrate"), ("jquery-ui", "jQuery UI"), ("jquery.ui", "jQuery UI"),
    ("jquery", "jQuery"), ("angularjs", "AngularJS"), ("angular", "AngularJS"),
    ("bootstrap", "Bootstrap"), ("vue-router", "Vue Router"), ("vue", "Vue.js"),
    ("react-dom", "React"), ("react", "React"), ("lodash", "Lodash"),
    ("underscore", "Underscore.js"), ("backbone", "Backbone.js"), ("moment", "Moment.js"),
    ("d3", "D3"), ("axios", "Axios"), ("ember", "Ember.js"), ("handlebars", "Handlebars.js"),
    ("modernizr", "Modernizr"), ("tinymce", "TinyMCE"), ("ckeditor", "CKEditor"),
    ("datatables", "DataTables"), ("highcharts", "Highcharts"), ("leaflet", "Leaflet"),
    ("swiper", "Swiper"), ("popper", "Popper"), ("select2", "Select2"),
)
_ASSET_RE = tuple(
    (re.compile(rf"\b{re.escape(tok)}[-@/._]v?(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE), product)
    for tok, product in _ASSET_PRODUCTS
)

_CVE_CACHE: dict[tuple[str, str], list[dict]] = {}   # (product.lower, version) → CVE records
_CVE_CACHE_LOCK = threading.Lock()                   # the fan-out runs in one process → dedup across apps


def _norm_version(raw: object) -> str | None:
    """First dotted version (≥ X.Y) in `raw`, patch/build suffix dropped: '6.6.1p1'→'6.6.1',
    'Apache/2.4.7 (Ubuntu)'→'2.4.7'. None if no usable version (precision-first: version-pinned only).
    Pure."""
    m = _VERSION_RE.search(str(raw or ""))
    return m.group(0) if m else None


def _split_name_version(s: str) -> tuple[str, str] | None:
    """A 'Name X.Y.Z' / 'Name:X.Y.Z' string → (name, normalized version). None if no version. Pure."""
    name, _, rest = s.partition(":")
    ver = _norm_version(rest) if rest else None
    if ver:
        return name.strip(), ver
    m = _VERSION_RE.search(s)                        # fall back to a trailing 'Name 1.2.3' form
    if m:
        name = s[:m.start()].strip(" /_-:")
        if name:
            return name, m.group(0)
    return None


def _tech_software(tech: Iterable[str]) -> list[tuple[str, str]]:
    """wappalyzer tech entries ('Apache HTTP Server:2.4.7', 'jQuery:1.11.0') → version-pinned
    (product, version) pairs (version-less entries dropped). Pure."""
    return [pv for raw in tech if (pv := _split_name_version(str(raw).strip()))]


def _header_software(server: object) -> tuple[str, str] | None:
    """A Server header ('Apache/2.4.7 (Ubuntu)', 'nginx/1.18.0', 'Microsoft-IIS/10.0') →
    (product, version). None if no version. Pure."""
    s = str(server or "").strip()
    if not s:
        return None
    name, sep, rest = s.partition("/")
    ver = _norm_version(rest) if sep else _norm_version(s)
    name = name.strip()
    return (name, ver) if (name and ver) else None


def _banner_software(banner: object) -> tuple[str, str] | None:
    """A non-HTTP service banner (nerva metadata.banner, e.g. 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu…') →
    (product, version) via the known _BANNER_PATTERNS. None if unrecognized / no version. Pure."""
    text = str(banner or "")
    for rx, product in _BANNER_PATTERNS:
        m = rx.search(text)
        if m and m.groups() and (ver := _norm_version(m.group(1))):
            return product, ver
    return None


def mine_asset_versions(text: str) -> list[tuple[str, str]]:
    """(product, version) pairs from VERSIONED ASSET references in a corpus text OR a fetched URL —
    jquery-3.6.0.min.js · /npm/vue@2.6.14/ · ajax/libs/angularjs/1.8.2/ · bootstrap-5.1.3.min.css.
    Curated product map only (precision-first: an unknown 'foo-1.2.3.js' never fabricates a product),
    word-bounded + version-adjacent. version-pinned (≥ X.Y), deduped. Pure."""
    out: set[tuple[str, str]] = set()
    for rx, product in _ASSET_RE:
        for m in rx.finditer(text):
            if (ver := _norm_version(m.group(1))):
                out.add((product, ver))
    return sorted(out)


def _corpus_software(texts: Iterable[str]) -> list[tuple[str, str]]:
    """Library/CMS versions mined from crawl-corpus body heads — JS lib banners (_CORPUS_PATTERNS) +
    the HTML <meta generator> tag + versioned asset refs in the body (`<script src=…>`,
    mine_asset_versions). version-pinned, deduped. Pure (offline mining)."""
    out: set[tuple[str, str]] = set()
    for text in texts:
        for rx, product in _CORPUS_PATTERNS:
            m = rx.search(text)
            if m and (ver := _norm_version(m.group(1))):
                out.add((product, ver))
        gm = _GENERATOR_RE.search(text)
        if gm and (pv := _split_name_version(gm.group(1))):
            out.add(pv)
        out.update(mine_asset_versions(text))
    return sorted(out)


def collect_software(*, tech: Iterable[str], server: object,  # noqa: PLR0913
                     services: Iterable[tuple[str, str]],
                     corpus_texts: Iterable[str], app_hosts: Iterable[str],
                     corpus_urls: Iterable[str] = ()) -> list[dict]:
    """Deduped ENUMERATED software → [{product, version, sources, where}], version-pinned. Sources:
    web server (Server header), app tech (wappalyzer), non-HTTP service banners ((host:port, banner)),
    libs mined from the crawl corpus — body banners/generator/asset-refs (corpus_texts) AND the
    versioned filenames of the fetched URLs (corpus_urls, e.g. .../jquery-3.6.0.min.js). tech/server/
    corpus are attributed to the app's hosts; a service banner to its own host:port. Pure — the
    query/attribution set for search_vulns."""
    grp = sorted(set(app_hosts))
    by_pv: dict[tuple[str, str], dict[str, set]] = {}

    def add(product: str, version: str, source: str, where: Iterable[str]) -> None:
        e = by_pv.setdefault((product, version), {"sources": set(), "where": set()})
        e["sources"].add(source)
        e["where"].update(where)

    for product, version in _tech_software(tech):
        add(product, version, "tech", grp)
    if (hh := _header_software(server)):
        add(hh[0], hh[1], "server", grp)
    for hostport, banner in services:
        if (sw := _banner_software(banner)):
            add(sw[0], sw[1], "service", [hostport])
    for product, version in _corpus_software(corpus_texts):
        add(product, version, "corpus", grp)
    for url in corpus_urls:                                  # versioned asset filenames in fetched URLs
        for product, version in mine_asset_versions(url):
            add(product, version, "corpus", grp)
    return [{"product": p, "version": v, "sources": sorted(e["sources"]), "where": sorted(e["where"])}
            for (p, v), e in sorted(by_pv.items())]


def parse_search_vulns(out: str, product: str, version: str) -> list[dict] | None:
    """Parse `search_vulns -f json` for ONE query into CVE finding records, or None when the query
    matched NO product (so the caller can retry a coarser version). A match with zero vulns → []. Pure."""
    try:
        data = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    entry = next(iter(data.values()))
    if not isinstance(entry, dict):          # "Warning: Could not find matching software for query"
        return None
    product_ids = entry.get("product_ids")
    cpes = product_ids.get("cpe") if isinstance(product_ids, dict) else None
    cpes = cpes if isinstance(cpes, list) else []
    vulns = entry.get("vulns")
    if not isinstance(vulns, dict):          # matched a product but no vulns → empty (not a no-match)
        return []
    recs: list[dict] = []
    for cve_id, v in vulns.items():
        if not isinstance(v, dict):
            continue
        sev = v.get("severity")
        sev = sev if isinstance(sev, dict) else {}
        cvss = sev.get("CVSS")
        cvss = cvss if isinstance(cvss, dict) else {}
        epss = sev.get("EPSS")
        epss = epss if isinstance(epss, dict) else {}
        exploits = v.get("exploits") or []
        kev = bool(v.get("cisa_kev"))
        desc = v.get("description")
        recs.append({
            "cve": cve_id, "product": product, "version": version,
            "cvss": cvss.get("score"), "cvss_version": cvss.get("version"),
            "epss": epss.get("score"), "kev": kev, "exploited": bool(exploits) or kev,
            "exploits": exploits, "cwe": v.get("cwe_ids") or [], "match_reason": v.get("match_reason"),
            "published": v.get("published"), "cpe": cpes[0] if cpes else None,
            "description": (desc if isinstance(desc, str) else "")[:_CVE_DESC_MAX],
        })
    return recs


def _search_vulns_query(product: str, version: str) -> list[dict]:
    """Query search_vulns for the EXACT (product, version), version-pinned, memoized process-wide.

    `--use-created-product-ids`: when cpe_search can't find a product ID for the exact version (e.g.
    'OpenSSH 6.6.1', whose CPE isn't indexed under that string), search_vulns SYNTHESIZES one at that
    exact version and still does the CPE version-range ('between') check correctly — so we never query a
    DIFFERENT version (a coarser one would falsely add/drop the exact-version-pinned CVEs). It's a no-op
    for products that already match, and never fabricates a match for an unknown product (→ 0 CVEs).
    Best-effort: [] on timeout/error/no-match. Offline (reads the local DB; no target traffic)."""
    key = (product.lower(), version)
    with _CVE_CACHE_LOCK:
        if key in _CVE_CACHE:
            return _CVE_CACHE[key]
    result: list[dict] = []
    try:
        out = tools.run([SEARCH_VULNS, "-q", f"{product} {version}", "-f", "json",
                         "--ignore-general-product-vulns", "--use-created-product-ids"],
                        timeout=CVE_TOOL_TIMEOUT)
        result = parse_search_vulns(out, product, version) or []   # None (no match) / [] (no vulns) → []
    except subprocess.TimeoutExpired:
        log.warning("⚠ search_vulns hit the %ds cap for '%s %s'", CVE_TOOL_TIMEOUT, product, version)
    except OSError:
        pass
    with _CVE_CACHE_LOCK:
        _CVE_CACHE[key] = result
    return result


def _corpus_texts(ws: AppWorkspace) -> list[str]:
    """Head of each extracted body (JS lib / HTML generator banners live at the top) for offline
    version mining. Reuses the corpus _extract_bodies already wrote (idempotent), reading at most
    _CVE_BODY_HEAD bytes/file."""
    bodies, _ = _extract_bodies(ws)
    if bodies is None:
        return []
    texts: list[str] = []
    for p in sorted([*bodies.glob("*.js"), *bodies.glob("*.html")]):
        try:
            texts.append(p.read_text(encoding="utf-8", errors="replace")[:_CVE_BODY_HEAD])
        except OSError:
            continue
    return texts


def _corpus_urls(ws: AppWorkspace) -> list[str]:
    """Every fetched URL in the response store (-srd indices) — the lib version is often only in the
    FILENAME (.../jquery-3.6.0.min.js), which mine_asset_versions recovers. Deduped, offline."""
    return tools.dedupe(u for idx in _all_store_indices(ws) for _, u in _store_index(idx))


def _app_service_banners(activity: Activity, meta: dict) -> list[tuple[str, str]]:
    """Non-HTTP service banners (nerva) on THIS app's hosts → [(host:port, banner)]. Maps a nerva record
    to the app by hostname, or by IP via domain_ip_map.txt. Best-effort: [] if nerva output is absent."""
    canon = activity.asset_discovery_canonical
    nerva = canon("nerva_full_metadata.jsonl")
    recs = tools.read_jsonl(nerva) if nerva.exists() else []
    if not recs:
        return []
    app_hosts = {url_host(h) for h in (meta.get("hosts") or [])}
    dim = canon("domain_ip_map.txt")
    app_ips = map_hosts_to_ips(tools.read_lines(dim), app_hosts) if dim.exists() else set()
    out: list[tuple[str, str]] = []
    for r in recs:
        host, ip, port = r.get("host"), r.get("ip"), r.get("port")
        banner = (r.get("metadata") or {}).get("banner") or ""
        if banner and (host in app_hosts or (ip and ip in app_ips)):
            out.append((f"{host or ip}:{port}", banner))
    return out


def _app_software(activity: Activity, ws: AppWorkspace) -> list[dict]:
    """Gather the app's ENUMERATED software (web server + tech + service banners + corpus libs) →
    collect_software records. Reads meta.json + breadth nerva + the extracted corpus (current state)."""
    meta = workspace.read_meta(ws.meta)
    servers = [h.get("Server") or h.get("server") for h in (meta.get("headers_by_host") or {}).values()]
    server = next((s for s in servers if s), None) or meta.get("webserver")
    return collect_software(
        tech=meta.get("tech") or [], server=server,
        services=_app_service_banners(activity, meta), corpus_texts=_corpus_texts(ws),
        corpus_urls=_corpus_urls(ws),
        app_hosts=[url_host(h) for h in (meta.get("hosts") or [])])


def _cve_sort_key(f: dict) -> tuple:
    """Triage order: known-exploited/KEV first, then by CVSS desc, then CVE id. Pure."""
    try:
        cvss = float(f.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    return (not f.get("exploited"), not f.get("kev"), -cvss, f.get("cve") or "")


def _run_cve(ws: AppWorkspace, software: list[dict], *, out_name: str,
             seen_path: Path | None, label: str) -> None:
    """Query search_vulns for each enumerated (product, version) in a bounded pool (memoized), attach
    sources/hosts, sort for triage → findings/<out_name>. Best-effort: skips if search_vulns/its DB is
    absent. When seen_path is set (phase-2 pass), records the covered (product, version) set so the
    phase-4 pass reports only the delta."""
    stage = out_name.removesuffix(".jsonl")
    if shutil.which(SEARCH_VULNS) is None:
        log.debug("  · skip %s (search_vulns not installed) for %s", stage, label)
        return
    if seen_path is not None:   # record what this pass covers (read by the phase-4 delta), even if empty
        tools.write_lines(seen_path, [f"{s['product']}\t{s['version']}" for s in software])
    findings: list[dict] = []
    if software:
        with ThreadPoolExecutor(max_workers=CVE_FANOUT) as pool:
            futs = [(s, pool.submit(_search_vulns_query, s["product"], s["version"])) for s in software]
            for s, fut in futs:
                findings += [{**cve, "sources": s["sources"], "hosts": s["where"]} for cve in fut.result()]
    findings.sort(key=_cve_sort_key)
    n = tools.write_jsonl(ws.findings / out_name, findings)
    hot = sum(1 for f in findings if f.get("exploited"))
    log.info("  → %s (%s) — %d software → %d CVE(s)%s → findings/%s", stage, label, len(software), n,
             f" ({hot} known-exploited/KEV)" if hot else "", out_name)


def cve_lookup(activity: Activity, app_id: str) -> None:
    """PHASE 2 — known-CVE lookup over the EXPLORABLE-surface enumerated software, ∥ the surface DAST.
    OFFLINE correlation (net=False, no target traffic): web server + app tech + non-HTTP service banners
    + libs mined from the phase-1 crawl corpus → search_vulns' local DB, version-pinned. Output
    findings/cve.jsonl + the covered (product,version) set (raw/cve/seen.txt) so the phase-4 pass reports
    only the delta. Best-effort: skips if search_vulns / its DB is absent."""
    ws = activity.app(app_id)
    _run_cve(ws, _app_software(activity, ws), out_name="cve.jsonl",
             seen_path=ws.raw("cve") / "seen.txt", label=app_id)


def cve_lookup_full(activity: Activity, app_id: str) -> None:
    """PHASE 4 — CVE lookup over the EXPANDED enumeration, ∥ the deep DAST. The phase-3 content_discovery
    /recrawl downloads grow the corpus, so this re-mines it and reports only the DELTA: software not
    already covered by the phase-2 pass (raw/cve/seen.txt). Output findings/cve_full.jsonl."""
    ws = activity.app(app_id)
    seen = {tuple(line.split("\t", 1)) for line in tools.read_lines(ws.raw("cve") / "seen.txt")
            if "\t" in line}
    delta = [s for s in _app_software(activity, ws) if (s["product"], s["version"]) not in seen]
    _run_cve(ws, delta, out_name="cve_full.jsonl", seen_path=None, label=app_id)


# --- consolidate (TERMINAL fan-in) — lift per-app findings → <activity>/findings/<type>.jsonl ------
# Deterministic terminal step (replaces the dormant agent seam, which stays in place). Each entry maps
# an activity-level finding TYPE → the per-app JSONL source files (paths relative to the app workspace
# root) lifted into it, every record stamped with its app_id. A scanner's surface (phase 2) and deep
# (phase 4) passes FOLD INTO ONE type file (cve+cve_full → cve · dast+dast_full → dast), so the
# activity findings/ is organized by finding TYPE, not by pipeline phase.
# --- cloud bucket enumeration (point 5a) — S3/GCS/Azure exposure from corpus + apex candidates -----
_S3_VHOST = re.compile(r"https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][\w.\-]*amazonaws\.com", re.IGNORECASE)
_S3_PATH = re.compile(r"https?://s3[.\-][\w.\-]*amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])", re.IGNORECASE)
_GCS_PATH = re.compile(r"https?://storage\.googleapis\.com/([a-z0-9][\w.\-]{1,61}[a-z0-9])", re.IGNORECASE)
_GCS_VHOST = re.compile(r"https?://([a-z0-9][\w.\-]{1,61}[a-z0-9])\.storage\.googleapis\.com", re.IGNORECASE)
_AZURE = re.compile(r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9\-]{3,63})", re.IGNORECASE)
_BUCKET_SUFFIXES = ("", "-assets", "-static", "-media", "-dev", "-prod", "-staging", "-backup",
                    "-backups", "-uploads", "-data", "-public", "-files")
_BUCKET_LISTING_RE = "ListBucketResult|EnumerationResults|<Contents>|storage#objects"
_BUCKET_CACHE: dict[str, str] = {}   # url → public|exists|none (process-wide: one probe per bucket URL)
_BUCKET_LOCK = threading.Lock()


def parse_cloud_refs(text: str) -> list[dict]:
    """Cloud-storage bucket references in a text corpus → [{provider, bucket, url}] (pure, deduped).
    Covers S3 (vhost + path style), GCS (path + vhost) and Azure blob (account/container)."""
    out: dict[tuple[str, str], dict] = {}
    for provider, rx in (("s3", _S3_VHOST), ("s3", _S3_PATH), ("gcs", _GCS_PATH), ("gcs", _GCS_VHOST)):
        for m in rx.finditer(text):
            out[provider, m.group(1)] = {"provider": provider, "bucket": m.group(1), "url": m.group(0)}
    for m in _AZURE.finditer(text):
        bucket = f"{m.group(1)}/{m.group(2)}"
        out["azure", bucket] = {"provider": "azure", "bucket": bucket, "url": m.group(0)}
    return list(out.values())


def bucket_candidates(apex_domain: str) -> list[str]:
    """Modest, precision-first candidate bucket names from an apex label (base + common suffixes, both
    `<label>-x` and `x-<label>`). Pure ([] for a blank apex)."""
    label = apex_domain.split(".", maxsplit=1)[0].strip()
    if not label:
        return []
    names = {f"{label}{sfx}" for sfx in _BUCKET_SUFFIXES}
    names |= {f"{sfx.lstrip('-')}-{label}" for sfx in _BUCKET_SUFFIXES if sfx}
    return sorted(names)


def cloud_findings(public: set[str], exists: set[str], url_meta: dict[str, dict]) -> list[dict]:
    """Merge probe results into findings (pure): a public-listable bucket is HIGH, a present-but-403
    one is info. Public wins over exists for the same URL."""
    findings = [{"type": "cloud-bucket-public", "severity": "high", "url": u, **url_meta.get(u, {})}
                for u in sorted(public)]
    findings += [{"type": "cloud-bucket-exists", "severity": "info", "url": u, **url_meta.get(u, {})}
                 for u in sorted(set(exists) - set(public))]
    return findings


def _httpx_match(urls: list[str], flags: list[str], dest: Path) -> set[str]:
    """URLs whose httpx probe matches `flags` (best-effort; empty if httpx absent). `-silent` prints
    the matching URLs one per line."""
    if not urls or shutil.which(HTTPX) is None:
        return set()
    out = _run("httpx", [HTTPX, "-silent", "-timeout", "10", "-rl", OSINT_FETCH_RL, *flags],
               stdin="\n".join(urls), dest=dest, label="cloud")
    return {ln.strip().rstrip("/") for ln in out.splitlines() if ln.strip()}


def _probe_buckets(ws: AppWorkspace, urls: list[str]) -> dict[str, str]:
    """Classify each bucket URL public|exists|none via httpx (`-mr` listing regex, `-mc 403`),
    memoized process-wide so a bucket shared across apps is probed once."""
    with _BUCKET_LOCK:
        todo = [u for u in urls if u not in _BUCKET_CACHE]
    if todo and shutil.which(HTTPX):
        raw = ws.raw("httpx") / "cloud"
        raw.mkdir(parents=True, exist_ok=True)
        public = _httpx_match(todo, ["-mr", _BUCKET_LISTING_RE], raw / "public.txt")
        exists = _httpx_match(todo, ["-mc", "403"], raw / "exists.txt")
        with _BUCKET_LOCK:
            for u in todo:
                _BUCKET_CACHE[u] = "public" if u in public else ("exists" if u in exists else "none")
    with _BUCKET_LOCK:
        return {u: _BUCKET_CACHE.get(u, "none") for u in urls}


def cloud_assets(activity: Activity, app_id: str) -> None:
    """PHASE 3 — cloud storage exposure. Passively mines the corpus for S3/GCS/Azure bucket references,
    adds modest apex-derived candidate names, and probes each for public listability with httpx (public
    = high, present-but-private/403 = info) → findings/cloud_assets.jsonl. Best-effort; per-bucket
    probe memoized across apps."""
    ws = activity.app(app_id)
    meta = workspace.read_meta(ws.meta)
    hosts = [url_host(h) for h in (meta.get("hosts") or [])]
    apex_domain = apex(hosts[0]) if hosts else ""
    refs = parse_cloud_refs("\n".join([*_corpus_texts(ws), *_corpus_urls(ws)]))
    url_meta: dict[str, dict] = {
        r["url"].rstrip("/"): {"provider": r["provider"], "bucket": r["bucket"], "source": "passive"}
        for r in refs}
    for name in bucket_candidates(apex_domain):
        for url in (f"https://{name}.s3.amazonaws.com", f"https://storage.googleapis.com/{name}"):
            url_meta.setdefault(url, {"provider": "s3" if ".s3." in url else "gcs",
                                      "bucket": name, "source": "candidate"})
    if not url_meta:
        log.debug("  · skip cloud_assets (no refs/candidates) for %s", app_id)
        return
    classified = _probe_buckets(ws, sorted(url_meta))
    public = {u for u, c in classified.items() if c == "public"}
    exists = {u for u, c in classified.items() if c == "exists"}
    tools.write_jsonl(ws.findings / "cloud_assets.jsonl", cloud_findings(public, exists, url_meta))
    log.info("  → cloud_assets (%s) — %d bucket URL(s) → %d public · %d exists",
             app_id, len(url_meta), len(public), len(exists))


_CONSOLIDATE_SOURCES: dict[str, tuple[str, ...]] = {
    "cve.jsonl": ("findings/cve.jsonl", "findings/cve_full.jsonl"),
    "dast.jsonl": ("findings/dast.jsonl", "findings/dast_full.jsonl"),
    "xss.jsonl": ("findings/xss.jsonl", "findings/xss_full.jsonl"),
    "sqli.jsonl": ("findings/sqli.jsonl", "findings/sqli_full.jsonl"),
    "tilde_enum.jsonl": ("findings/tilde_enum.jsonl",),
    "wpprobe.jsonl": ("findings/wpprobe.jsonl",),
    "cloud_assets.jsonl": ("findings/cloud_assets.jsonl",),
    "sourcemap.jsonl": ("findings/sourcemap.jsonl",),
    "secrets.jsonl": ("secrets.jsonl",),
    "secrets_triage.jsonl": ("findings/secrets_triage.jsonl",),
    "default_creds.jsonl": ("default_creds.jsonl",),
}


def consolidate(activity: Activity) -> dict[str, int]:
    """TERMINAL fan-in (deterministic, OFFLINE) — lift every app group's per-app findings into the
    activity level: one <activity>/findings/<type>.jsonl per finding TYPE, each record stamped with its
    app_id for traceability. A scanner's surface+deep passes fold into one file (cve, dast); the
    subjack takeover lines become records too. Reads only on-disk artifacts; tolerant of a malformed
    line (read_jsonl skips it). Whole-scope nuclei_scope.jsonl is already an activity finding and is
    left untouched; the agent seam (hypotheses.jsonl) runs separately — dormant by default, Claude-backed
    under --ai. Returns {type: count} for the NON-EMPTY categories (empty types write no file — no
    clutter). Idempotent: overwrites on every run / --resume."""
    apps = activity.list_apps()
    counts: dict[str, int] = {}
    for out_name, sources in _CONSOLIDATE_SOURCES.items():
        records = [{"app_id": ws.root.name, **rec}
                   for ws in apps for src in sources
                   for rec in tools.read_jsonl(ws.root / src)]
        if records:
            counts[out_name.removesuffix(".jsonl")] = tools.write_jsonl(
                activity.findings / out_name, records)
    takeovers = [{"app_id": ws.root.name, "type": "subdomain-takeover", "evidence": ln,
                  "source": "subjack"}
                 for ws in apps for ln in tools.read_lines(ws.canonical("takeover.txt"))]
    if takeovers:
        counts["takeover"] = tools.write_jsonl(activity.findings / "takeover.jsonl", takeovers)
    log.info("  → consolidate — %s",
             ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no per-app findings")
    return counts
