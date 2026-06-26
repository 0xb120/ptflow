"""Real asset_discovery (breadth) — faithful port of scope2surface.sh.

Each tool's output is written ONCE. Intermediate steps that only feed later
steps go to asset_discovery/raw/<tool>/ (top-level, not under scans/; provenance). A tool whose output
IS a final artifact is written straight to its canonical name — no duplicate raw
copy. Derived artifacts (unique IPs, honeypots, unique webapps) are computed in
memory. Pure transforms are module-level so they can be unit-tested.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pipt.core import scope, tools, workspace
from pipt.core.log import get_logger, is_verbose
from pipt.pipelines.recon import wordlists

if TYPE_CHECKING:
    from pipt.core.paths import Activity, AppWorkspace
    from pipt.core.scope import Target

log = get_logger()


# --- rate profiles (PIPT_PROFILE, resolved at import — set it BEFORE launching) ---
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
    """Active profile from env PIPT_PROFILE (default `wide`; unknown → `wide`). Read each call so it's
    testable; the module constants below bind it once at import (set PIPT_PROFILE before launching)."""
    return _PROFILES.get(os.environ.get("PIPT_PROFILE", "wide").lower().strip(), WIDE)


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
# binary (Selenium app); resolved best-effort by _eyewitness_cmd: PIPT_EYEWITNESS override, else
# `eyewitness` on PATH, else the known venv install at /opt/EyeWitness (_EYEWITNESS_DIR) — skipped if
# none resolve. Selenium ≥4.6 auto-provisions chromedriver (Selenium Manager); runs --headless=new.
EYEWITNESS_TIMEOUT = "15"   # --timeout per-URL seconds
NOISE_EXTENSIONS = frozenset({
    "jpg", "jpeg", "png", "gif", "svg", "bmp", "webp", "ico",
    "woff", "woff2", "ttf", "eot", "otf", "css",
    "mp3", "mp4", "wav", "avi", "mov", "webm",
})

# wordlist synthesis (LOOP 2 — active collection → custom per-app wordlist)
_TOKEN_MAX_LEN = 40                       # drop longer "segments" (hashes/junk)
OSINT_FETCH_RL = "50"  # httpx req/s when downloading the OSINT delta into responses/osint/
# wordlist STRATEGY (content_discovery combine): the CUSTOM layer (app-derived tokens) always goes in
# full; how much of the TRADITIONAL layer (global content + tech CMS lists) rides along depends on the
# mode. `auto` (override via env PIPT_WL_MODE ∈ auto|targeted|broad) → `targeted` when the app gave a
# rich custom corpus (lean on it, cap the traditional lists), else `broad` (opaque app → full lists).
WL_RICH_TOKENS = 200   # custom-token count at/above which `auto` picks `targeted`
WL_TARGETED_CAP = 2000  # in `targeted`, keep only the top-N of each traditional list (freq-ordered)

# content discovery (LOOP 2) — feroxbuster forced browsing. Global wordlists are
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
# content-discovery FIXPOINT (LOOP 2) — after round 0 (the classic forced-browse), feed the
# feroxbuster-discovered bodies back through download → mine → tokenize → fuzz the NEW token delta,
# until a fixpoint. Bounded by FOUR independent stops (no-new-words, no-new-urls, the per-app
# wall-clock deadline, diminishing-returns) under a hard round cap — see content_discovery().
CONTENT_FEEDBACK_ROUNDS = 2     # feedback rounds beyond round 0 (depth 3 total)
CONTENT_DEADLINE_S = 900        # per-app wall-clock budget across ALL rounds (incl. round 0)
DEEP_FEROX_TIME_LIMIT = "5m"    # --time-limit for feedback rounds (round 0 keeps FEROX_TIME_LIMIT)
MIN_NEW_TOKENS = 20             # a round contributing fewer new fuzz words ⇒ stop (diminishing returns)
DEEP_DOWNLOAD_CAP = 300         # max NEW urls downloaded+mined per round (logged when it bites)

# parameter fuzzing (LOOP 3) — arjun ∥ x8 hidden-parameter discovery over the enumerated endpoints.
# Per-endpoint and request-heavy (a 6.5k-name wordlist over N endpoints, two tools), so the endpoint
# set is deduped by path-template and capped, and both tools run gently (low concurrency + rate cap).
PARAM_MAX_ENDPOINTS = 50   # cap distinct endpoint shapes fuzzed per app (logged when it bites)
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

# param_fuzz fleet (LOOP 3) — arjun (pip/uv, ~/.local/bin) ∥ x8 (cargo, ~/.cargo/bin). Best-effort.
_ARJUN_BIN = Path.home() / ".local" / "bin" / "arjun"
ARJUN = str(_ARJUN_BIN) if _ARJUN_BIN.exists() else "arjun"
_X8_BIN = Path.home() / ".cargo" / "bin" / "x8"
X8 = str(_X8_BIN) if _X8_BIN.exists() else "x8"

# EyeWitness (optional, screenshot step) — known venv install (own .venv + Python/EyeWitness.py);
# resolved by _eyewitness_cmd (overridable via PIPT_EYEWITNESS / `eyewitness` on PATH).
_EYEWITNESS_DIR = Path("/opt/EyeWitness")

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
    "arjun": ARJUN, "x8": X8,
}


def preflight() -> None:
    """Log which external tools resolve at run start, so a missing binary degrades a stage VISIBLY
    instead of yielding a silent empty result. Never aborts (best-effort): a missing CORE tool is a
    WARNING (that stage produces nothing); missing OPTIONAL tools just skip their best-effort stage."""
    log.info("  → profile: %s (naabu -rate %s -c %s · nuclei -rl %s · ferox -t %s -L %s)",
             PROFILE.name, NAABU_RATE, NAABU_CONC, NUCLEI_RL, FEROX_THREADS, FEROX_SCAN_LIMIT)
    core_missing = sorted(n for n, cmd in _CORE_TOOLS.items() if shutil.which(cmd) is None)
    opt_missing = sorted(n for n, cmd in _OPTIONAL_TOOLS.items() if shutil.which(cmd) is None)
    ew = _eyewitness_cmd() is not None
    log.info("  → preflight: core %d/%d · optional %d/%d · eyewitness %s",
             len(_CORE_TOOLS) - len(core_missing), len(_CORE_TOOLS),
             len(_OPTIONAL_TOOLS) - len(opt_missing), len(_OPTIONAL_TOOLS),
             "present" if ew else "absent")
    if core_missing:
        log.warning("  ⚠ preflight: missing CORE tool(s) — these stages will produce nothing: %s",
                    ", ".join(core_missing))
    if opt_missing:
        log.info("    optional tools absent (their stages skip): %s", ", ".join(opt_missing))


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


def passive_delta(passive: list[str], crawled: list[str]) -> list[str]:
    """OSINT URLs (gau/urlfinder) whose bodies the crawl never fetched.

    `denoise(passive)` minus what the crawler already requested — the only URLs a
    separate downloader needs (the crawler is the downloader for everything it
    reached). Static assets are dropped; order is preserved.
    """
    already = set(crawled)
    return [u for u in denoise(tools.dedupe(passive)) if u not in already]


def tech_extensions(tech: list[str], mapping: dict[str, list[str]]) -> list[str]:
    """File extensions to fuzz, derived from detected tech (case-insensitive substring)."""
    tags = [t.lower() for t in tech]
    out: list[str] = []
    for key, exts in mapping.items():
        if any(key in tag for tag in tags):
            out += exts
    return tools.dedupe(out)


def resolve_wl_mode(mode: str, custom_count: int, *, rich_threshold: int) -> str:
    """Pick the wordlist strategy. An explicit 'targeted'/'broad' passes through; 'auto' (or anything
    else) resolves by corpus richness: a rich custom corpus (>= rich_threshold app tokens) ⇒ 'targeted'
    (lean on the app-specific list, cap the traditional ones), else 'broad' (opaque app ⇒ full lists)."""
    if mode in ("targeted", "broad"):
        return mode
    return "targeted" if custom_count >= rich_threshold else "broad"


def combine_wordlist(custom: list[str], traditional: list[list[str]], *, mode: str, cap: int) -> list[str]:
    """Assemble the content-discovery wordlist. The custom layer (app-derived) always goes in FULL and
    FIRST; the traditional layer (global content + tech CMS lists) rides along whole in 'broad', or
    with each list capped to its top-`cap` in 'targeted' (SecLists are ~frequency-ordered, so top-N is
    the high-value head). Deduped, custom-first preserved. Pure."""
    trad = [w for lst in traditional for w in (lst if mode == "broad" else lst[:cap])]
    return tools.dedupe([*custom, *trad])


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
    found under PIPT_WORDLISTS / common locations, or supplied per-role (PIPT_WL_<ROLE>) / by
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
    records = [json.loads(ln) for ln in out.splitlines() if ln.strip()]
    kept, dropped = split_cdn_ip_records(records, set(tools.read_lines(activity.scope_ip)))
    tools.write_jsonl(canon("httpx_full_metadata.jsonl"), kept)
    tools.write_jsonl(canon("excluded_cdn.jsonl"), dropped)
    if dropped:
        log.info("  → scope: excluded %d raw-IP CDN/cloud target(s) (hostnames kept) → excluded_cdn.jsonl",
                 len(dropped))
    tools.write_lines(canon("unique_webapps.txt"), select_unique_webapps(kept))


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

    Not a single binary (Selenium app): PIPT_EYEWITNESS — a full launch command, e.g.
    "python3 /opt/EyeWitness/Python/EyeWitness.py" or a venv wrapper — takes precedence; else a
    pip-installed `eyewitness` on PATH. The operator owns the Python/deps/chromedriver behind it.
    """
    explicit = os.environ.get("PIPT_EYEWITNESS")
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


def _run_katana(ws: AppWorkspace, hosts: list[str], app_id: str) -> list[str]:
    """katana — the DOWNLOADER crawler: parses JS endpoints (-jc/-jsl), known files
    (-kf all), forms (-fx), climbs parent paths (-pc), scoped to each host's fqdn
    (-fs fqdn), and stores every response under responses/ (-srd) for offline mining.
    JSONL output (-j, bodies/raw omitted from stdout — the bodies still land on disk
    via -srd). Returns the crawled URLs (request.endpoint per record)."""
    cmd = ["katana", "-silent", "-j", "-jc", "-jsl", "-kf", "all", "-fx", "-pc",
           "-fs", "fqdn", "-d", KATANA_DEPTH, "-c", KATANA_CONC,
           "-omit-raw", "-omit-body", "-srd", str(ws.responses)]
    out = _run("katana", cmd, stdin="\n".join(hosts),
               dest=ws.raw("katana") / "crawl" / "out.jsonl", label=app_id)
    return parse_katana(out)


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
        katana_urls, crawley_urls = katana_fut.result(), crawley_fut.result()
    tools.write_lines(ws.canonical("endpoints_crawley.txt"), crawley_urls)
    passive = tools.read_lines(ws.canonical("endpoints_passive.txt"))
    tools.write_lines(ws.canonical("endpoints.txt"),
                      denoise(tools.dedupe([*passive, *katana_urls, *crawley_urls])))

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
    Output endpoints_headless.txt is folded into the loop-2 wordlist (like endpoints_js.txt).
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
           "-rl", HEADLESS_RL, "-omit-raw", "-omit-body", "-srd", str(store)]
    log.info("  → headless (%s) — JS-rendered, %d host(s) (capped at %d concurrent)",
             app_id, len(hosts), HEADLESS_PARALLELISM)
    with _HEADLESS_SLOTS:
        out = _run("katana-headless", cmd, stdin="\n".join(hosts),
                   dest=ws.raw("katana") / "headless" / "out.jsonl", label=app_id)
    tools.write_lines(ws.canonical("endpoints_headless.txt"), denoise(parse_katana(out)))


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


# --- LOOP 2 (content discovery) — runs after the loop-1 barrier ---
def build_wordlist(activity: Activity, app_id: str) -> None:
    """LOOP 2.1 — synthesize the per-app CUSTOM wordlist (wl_custom/seed.txt) OFFLINE.

    No fetching: the crawl (loop 1) already downloaded and JS-parsed the linked surface — its
    JS-discovered endpoints and robots/sitemap paths are already in endpoints.txt. This step
    tokenizes endpoints.txt (plus the gated headless crawl's endpoints_headless.txt, when present)
    into path segments, filename basenames and parameter names (tokenize_urls). Output is
    **app-derived tokens only** — the traditional layer (global content + tech CMS lists) is added
    later by content_discovery's combine, so 'custom' stays genuinely custom (see resolve_wl_mode /
    combine_wordlist). Reads loop-1 artifacts directly — the cross-loop barrier guarantees they exist.
    """
    ws = activity.app(app_id)
    words = tokenize_urls([*tools.read_lines(ws.canonical("endpoints.txt")),
                           *tools.read_lines(ws.canonical("endpoints_headless.txt"))])
    n = tools.write_lines(ws.wl_custom / "seed.txt", words)
    log.info("  → wordlist (%s) — %d app token(s), offline → wl_custom/seed.txt", app_id, n)


def fetch_delta(activity: Activity, app_id: str) -> None:
    """LOOP 2.2 — download the discovery delta into the response store (∥ wordlist).

    The discovery sources whose bodies katana never downloaded — passive_probe
    (gau/urlfinder) and crawley (endpoints_crawley.txt) — are the only URLs a separate
    downloader needs; katana already stored everything IT fetched (responses/index.txt
    is that record). httpx fetches the delta's live URLs (dropping dead hosts) and
    stores their bodies under responses/osint/, so offline body-mining covers the
    archived/OSINT/crawley-only surface too. Reads loop-1 artifacts directly — the
    barrier guarantees they exist.
    """
    ws = activity.app(app_id)
    have = [url for idx in _all_store_indices(ws) for _, url in _store_index(idx)]  # already stored
    delta = passive_delta(
        [*tools.read_lines(ws.canonical("endpoints_passive.txt")),
         *tools.read_lines(ws.canonical("endpoints_crawley.txt"))],
        have,
    )
    if not delta:
        log.debug("  · skip osint fetch (empty delta) for %s", app_id)
        return
    store = ws.responses / "osint"
    store.mkdir(parents=True, exist_ok=True)
    _run("httpx", [HTTPX, "-silent", "-srd", str(store), "-rl", OSINT_FETCH_RL],
         stdin="\n".join(delta), dest=ws.raw("httpx") / "osint" / "out.txt", label=app_id)


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


def _jsluice_urls(js_files: list[str]) -> list[str]:
    """jsluice endpoint extraction over JS files (best-effort; [] if none, or jsluice is absent).
    Reused by mine_responses (round 0) and the content_discovery fixpoint (each feedback round)."""
    if not js_files or shutil.which(JSLUICE) is None:
        return []
    return [r["url"] for r in _jsonl_str(tools.run([JSLUICE, "urls", *js_files])) if r.get("url")]


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
    """LOOP 2 — mine the per-app response store OFFLINE for ENDPOINTS (cashes in 'fetch once').

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
    n_ep = tools.write_lines(ws.canonical("endpoints_js.txt"), _jsluice_urls(js_files))
    log.info("  → mine_responses (%s) — %d JS → %d endpoint(s) → endpoints_js.txt",
             app_id, len(js_files), n_ep)


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
    """LOOP 2 (surface) — specialized per-stack scanners whose output FEEDS enum.

    Best-effort dispatch keyed on the cluster's detected tech: a scanner runs only if
    its tech matched AND its binary is installed. Primary output is SURFACE (fuzz words) →
    wl_custom/shortnames.txt, which content_discovery merges into its wordlist. A scanner may also be
    DUAL-ROLE and emit findings: shortscan's IIS 8.3 short-name enumeration is itself an
    information-disclosure finding → tilde_enum.jsonl (a dedicated artifact; the general findings
    model/consolidate is backlog #4). Findings-only scanners (wpprobe, nuclei, …) belong to
    tech_vulnscan / loop 3.

    Today: shortscan (IIS/ASP.NET 8.3 short-name enumeration). Reads loop-1 hosts
    across the barrier; needs the wordlist seed for the shortutil rainbow table.
    """
    ws = activity.app(app_id)
    tech = " ".join(workspace.read_meta(ws.meta).get("tech") or []).lower()
    surface: list[str] = []
    findings: list[dict] = []
    if any(k in tech for k in ("iis", "asp.net", "microsoft-iis")):
        surface, findings = _shortscan_surface(activity, ws, app_id)
    n = tools.write_lines(ws.wl_custom / "shortnames.txt", surface)
    if findings:  # per-app findings/ folder (#4 consolidate will lift these to <activity>/findings/)
        tools.write_jsonl(ws.findings / "tilde_enum.jsonl", findings)
    log.info("  → tech_enum (%s) — %d surface term(s) → shortnames.txt%s", app_id, n,
             f" · {len(findings)} finding(s) → findings/tilde_enum.jsonl" if findings else "")


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


def _run_ferox(ws: AppWorkspace, hosts: list[str], words: list[str], round_idx: int,
               *, remaining: float) -> list[dict]:
    """One feroxbuster forced-browse pass over `hosts` with `words` → parsed `response` records.

    Writes the round wordlist + raw JSON under wl_custom/ and raw/feroxbuster/ (feroxbuster writes
    JSON to -o, not stdout, so it bypasses _run). --smart brings auto-tune soft-404 calibration +
    collect-words/backups + link extraction/recursion. --time-limit is the hard cap that breaks
    --smart's backoff livelock (the scanme.nmap.org incident). Returns [] for an empty wordlist."""
    app_id = ws.root.name
    wordlist = ws.wl_custom / f"round{round_idx}.txt"
    n_wl = tools.write_lines(wordlist, words)
    if not n_wl:
        return []
    exts = tech_extensions(workspace.read_meta(ws.meta).get("tech") or [], TECH_EXTENSIONS)
    ext_args = ["-x", *exts] if exts else []
    out_file = ws.raw("feroxbuster") / f"round{round_idx}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    tl = _ferox_time_limit(round_idx, remaining)
    log.info("  → feroxbuster (%s) r%d — %d host(s), %d term(s), --time-limit %s",
             app_id, round_idx, len(hosts), n_wl, tl)
    cmd = [FEROX, "--stdin", "--silent", "--json", "-o", str(out_file), "--no-state", "-k",
           "--smart", "-t", FEROX_THREADS, "-L", FEROX_SCAN_LIMIT, "--timeout", FEROX_TIMEOUT,
           "--time-limit", tl, "-d", FEROX_DEPTH, "-w", str(wordlist), *ext_args]
    tools.run(cmd, stdin="\n".join(hosts), stream_stderr=is_verbose())
    raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
    recs = parse_ferox(raw)
    # An https endpoint a modern TLS client can't handshake (legacy renegotiation / weak DH) makes
    # feroxbuster reach nothing — `-k` doesn't help (cert-only). httpx/katana (Go TLS) connect, so
    # the host looks live; only the rustls scanner fails. Retry the same round over http (the same
    # app on the other scheme) instead of leaving the group's content discovery empty.
    if not recs and ferox_transport_failed(raw) and any(h.startswith("https://") for h in hosts):
        http_hosts = tools.dedupe([https_to_http(h) for h in hosts])
        log.warning("  ⚠ feroxbuster (%s) r%d — https unreachable (legacy-TLS handshake refused); "
                    "retrying over http", app_id, round_idx)
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
    """LOOP 2.3 — forced browsing to a FIXPOINT: fuzz → download → mine → fuzz the new token delta.

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
    but distinct environments (staging vs test) each fuzzed. Combined wordlist (per-app seed +
    tech_enum surface + JS-mined paths, then a global SecLists list) + tech-derived extensions.
    BOUNDED by four convergence/budget stops under a hard round cap (see _content_rounds), so it
    never loops forever and never re-fuzzes/re-downloads.

    Finally the secret-scanning fleet runs ONCE over the now-complete corpus (_scan_secrets) →
    secrets.jsonl. Output: scans/<app_id>/content_discovery.jsonl (merge of all rounds, deduped).
    """
    ws = activity.app(app_id)
    hosts = _scan_hosts(ws)
    if not hosts:
        log.debug("  · skip content_discovery (no host) for %s", app_id)
        return

    # CUSTOM layer (app-derived, high signal) — always in full, first
    seed = tools.read_lines(ws.wl_custom / "seed.txt")              # build_wordlist app tokens
    shortnames = tools.read_lines(ws.wl_custom / "shortnames.txt")  # tech_enum surface (8.3 names)
    js_tokens = tokenize_urls(tools.read_lines(ws.canonical("endpoints_js.txt")))  # mine_responses
    custom = [*seed, *shortnames, *js_tokens]
    # TRADITIONAL layer (global content + tech CMS lists), resolved by role; sized by the mode
    tech = workspace.read_meta(ws.meta).get("tech") or []
    content_wl = wordlists.role_path(activity, "content")
    traditional = [tools.read_lines(content_wl) if content_wl else [],
                   *(tools.read_lines(p) for p in wordlists.tech_role_paths(tech, activity.wl_global))]
    mode = resolve_wl_mode(os.environ.get("PIPT_WL_MODE", "auto"),
                           len(tools.dedupe(custom)), rich_threshold=WL_RICH_TOKENS)
    wordlist = combine_wordlist(custom, traditional, mode=mode, cap=WL_TARGETED_CAP)
    log.info("    wordlist (%s) — mode=%s · %d custom + %d traditional → %d combined", app_id, mode,
             len(tools.dedupe(custom)), sum(len(t) for t in traditional), len(wordlist))

    hits, rounds, stop = _content_rounds(ws, hosts, wordlist)
    n = tools.write_jsonl(ws.canonical("content_discovery.jsonl"), hits)
    log.info("    content_discovery (%s) → %d result(s) over %d round(s) [stop: %s]",
             app_id, n, rounds, stop)
    _scan_secrets(ws, app_id)


# --- LOOP 3 (param discovery) — arjun ∥ x8 hidden-parameter fuzzing ---
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


def parse_arjun(text: str) -> list[dict]:
    """arjun -oJ ({<url>: {method, params:[names], headers}}) → common shape per discovered param."""
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for url, rec in (data.items() if isinstance(data, dict) else []):
        if not isinstance(rec, dict):
            continue
        method = rec.get("method") or "GET"
        out += [{"url": url, "param": str(p), "method": method, "sources": ["arjun"], "reason": None}
                for p in (rec.get("params") or []) if p]
    return out


def parse_x8(text: str) -> list[dict]:
    """x8 -O json ([{url, method, found_params:[{name, reason_kind, …}]}]) → common shape per param."""
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
                out.append({"url": url, "param": str(name), "method": method, "sources": ["x8"],
                            "reason": p.get("reason_kind") if isinstance(p, dict) else None})
    return out


def merge_params(records: list[dict]) -> list[dict]:
    """Dedup discovered params across arjun/x8 by (url, param): union `sources`, keep first method +
    first non-null reason. Deterministic order (sorted), so the same input yields the same file. Pure."""
    ordered = sorted(records, key=lambda r: (r.get("url") or "", r.get("param") or ""))
    by_key: dict[tuple, dict] = {}
    for r in ordered:
        key = (r.get("url"), r.get("param"))
        if key in by_key:
            cur = by_key[key]
            cur["sources"] = sorted(set(cur["sources"]) | set(r.get("sources", [])))
            cur["reason"] = cur.get("reason") or r.get("reason")
        else:
            by_key[key] = {**r, "sources": sorted(set(r.get("sources", [])))}
    return list(by_key.values())


def _run_arjun(targets_file: Path, out_file: Path, params_wl: Path | None, app_id: str) -> list[dict]:
    """arjun over the targets file (best-effort). Writes JSON to -oJ (bypasses _run). Falls back to
    arjun's builtin wordlist when the params role is unresolved."""
    if shutil.which(ARJUN) is None:
        log.debug("  · skip arjun (not installed) for %s", app_id)
        return []
    out_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = [ARJUN, "-i", str(targets_file), "-oJ", str(out_file), "-t", ARJUN_THREADS,
           "-T", ARJUN_TIMEOUT, "--rate-limit", ARJUN_RATE, "-q"]
    if params_wl is not None:
        cmd += ["-w", str(params_wl)]
    try:
        tools.run(cmd, timeout=PARAM_TOOL_TIMEOUT, stream_stderr=is_verbose())
    except subprocess.TimeoutExpired:
        log.warning("⚠ arjun hit the %ds cap for %s — keeping partial results", PARAM_TOOL_TIMEOUT, app_id)
    return parse_arjun(out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else "")


def _run_x8(targets_file: Path, out_file: Path, params_wl: Path | None, app_id: str) -> list[dict]:
    """x8 over the targets file (best-effort). Writes JSON to -o (bypasses _run). Needs a params
    wordlist (skipped if the role is unresolved). --one-worker-per-host is the politeness lever."""
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
    try:
        tools.run(cmd, timeout=PARAM_TOOL_TIMEOUT, stream_stderr=is_verbose())
    except subprocess.TimeoutExpired:
        log.warning("⚠ x8 hit the %ds cap for %s — keeping partial results", PARAM_TOOL_TIMEOUT, app_id)
    return parse_x8(out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else "")


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


def param_fuzz(activity: Activity, app_id: str) -> None:
    """LOOP 3 — hidden-parameter discovery (arjun ∥ x8) over the app's enumerated endpoints.

    Selects the endpoints to test (`select_param_endpoints`): the loop-1/2 endpoint artifacts
    (endpoints.txt + endpoints_js/headless + 2xx content_discovery hits), scoped to the group's hosts,
    deduped by path-template and capped (PARAM_MAX_ENDPOINTS) — one representative per endpoint shape,
    since arjun/x8 are request-heavy. Target schemes are normalized to the reachable scheme first
    (`_working_schemes`) so the cap isn't spent on https URLs a strict-TLS client can't handshake.
    Runs arjun ∥ x8 (best-effort, like the secret fleet) with the `params` role wordlist, merges their
    finds by (url, param) → params.jsonl (a deliverable + the input the future DAST consumes). Reads
    loop-2 artifacts across the barrier — no `needs`.
    """
    ws = activity.app(app_id)
    in_scope = {url_host(h) for h in tools.read_lines(ws.hosts)}
    schemes = _working_schemes(ws)  # route arjun/x8 to the scheme the scanners reached (http fallback)
    urls = [force_scheme(u, schemes) for u in [
        *tools.read_lines(ws.canonical("endpoints.txt")),
        *tools.read_lines(ws.canonical("endpoints_js.txt")),
        *tools.read_lines(ws.canonical("endpoints_headless.txt")),
        *[r["url"] for r in tools.read_jsonl(ws.canonical("content_discovery.jsonl"))
          if r.get("url") and 200 <= (r.get("status") or 0) < 300],  # noqa: PLR2004
    ]]
    targets = select_param_endpoints(urls, in_scope, cap=PARAM_MAX_ENDPOINTS)
    if not targets:
        log.debug("  · skip param_fuzz (no endpoints) for %s", app_id)
        return
    targets_file = ws.raw("param_fuzz") / "targets.txt"
    tools.write_lines(targets_file, targets)
    params_wl = wordlists.role_path(activity, "params")
    log.info("  → param_fuzz (%s) — %d endpoint(s), arjun ∥ x8%s", app_id, len(targets),
             "" if params_wl else " (no params wl → x8 skipped)")
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(_run_arjun, targets_file, ws.raw("arjun") / "out.json", params_wl, app_id)
        x = pool.submit(_run_x8, targets_file, ws.raw("x8") / "out.json", params_wl, app_id)
        records = [*a.result(), *x.result()]
    params = merge_params(records)
    n = tools.write_jsonl(ws.canonical("params.jsonl"), params)
    log.info("    param_fuzz (%s) → %d param(s) on %d endpoint(s) → params.jsonl",
             app_id, n, len({p["url"] for p in params}))
