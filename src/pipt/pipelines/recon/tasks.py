"""Real asset_discovery (breadth) — faithful port of scope2surface.sh.

Each tool's output is written ONCE. Intermediate steps that only feed later
steps go to scans/asset_discovery/raw/<tool>/ (provenance). A tool whose output
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
import threading
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

from pipt.core import scope, tools, workspace
from pipt.core.log import get_logger, is_verbose
from pipt.pipelines.recon import wordlists

if TYPE_CHECKING:
    from pipt.core.paths import Activity, AppWorkspace
    from pipt.core.scope import Target

log = get_logger()

# --- tunables (mirror scope2surface.sh; conservative — live infra) ---
NAABU_TLS_TOP_PORTS = "1000"
NAABU_TLS_RATE = "1000"
NAABU_TLS_CONC = "50"
HONEYPOT_MIN_OPEN_PORTS = 15      # >= this many open ports => suspected honeypot
RESOLVERS = "/opt/resolvers/resolvers-trusted.txt"

# whole-scope nuclei scan (spanning stage — ONE process, ONE global rate cap)
NUCLEI_CONC = "25"      # -c  templates in parallel
NUCLEI_BULK = "25"      # -bs hosts per template
NUCLEI_RL = "150"       # -rl global requests/second
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

# content discovery (LOOP 2) — feroxbuster forced browsing. Global wordlists are
# resolved by ROLE (see wordlists.py / wl_global/), never hardcoded here.
# Gentle on live infra: --smart (auto-tune) adapts the rate down when the target errors/times
# out; low -t/-L keep concurrency bounded from the start. (--rate-limit is mutually exclusive
# with --smart, and is per-directory anyway, so it's the wrong tool here.)
FEROX_DEPTH = "2"        # -d recursion depth (feroxbuster default is 4)
FEROX_THREADS = "5"      # -t threads per scan (default 50 is aggressive for fragile apps)
FEROX_SCAN_LIMIT = "2"   # -L concurrent directory scans (caps recursion fan-out)
FEROX_TIMEOUT = "15"     # --timeout per-request seconds (tolerate slow apps)
# --time-limit caps TOTAL scan wall-clock (--timeout is only per-request). Without it, a target that
# throttles under --smart can send feroxbuster's auto-tune into an unbounded backoff livelock that
# hangs the whole pipeline (no per-request timeout breaks it). --smart-compatible; exits gracefully,
# keeping partial results. See the scanme.nmap.org incident.
FEROX_TIME_LIMIT = "20m"  # --time-limit total scan duration (normal scans here finish in ~5m)
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

# crawley (the second crawler, run ∥ katana) lives in ~/go/bin.
_CRAWLEY_BIN = Path.home() / "go" / "bin" / "crawley"
CRAWLEY = str(_CRAWLEY_BIN) if _CRAWLEY_BIN.exists() else "crawley"

# EyeWitness (optional, screenshot step) — known venv install (own .venv + Python/EyeWitness.py);
# resolved by _eyewitness_cmd (overridable via PIPT_EYEWITNESS / `eyewitness` on PATH).
_EYEWITNESS_DIR = Path("/opt/EyeWitness")


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


def _app_id(signature: str) -> str:
    """Stable app id from the cluster identity (NOT a mutable host/title string)."""
    return hashlib.sha1(signature.encode()).hexdigest()[:12]  # noqa: S324


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
    (mapcidr-expanded), tlsx_raw.txt, and scope/scope_dns.txt (the full candidate
    name set that `resolve` consumes).
    """
    targets = scope.parse_scope(activity.scope_init.read_text(encoding="utf-8"))
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
              "-c", NAABU_TLS_CONC, "-rate", NAABU_TLS_RATE],
             stdin="\n".join(scope_ips), dest=_raw(activity, "naabu", "tls_ports"), label="tls_ports")
    )
    tls_names = _lines(
        _run("tlsx", ["tlsx", "-san", "-cn", "-silent", "-resp-only"],
             stdin="\n".join(naabu_tls),
             dest=activity.asset_discovery_canonical("tlsx_raw.txt"), label="from_ports")
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

    Reads scope/scope_dns.txt, scope/scope_ip.txt, tlsx_raw.txt; writes
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

    tls_names = tools.read_lines(canon("tlsx_raw.txt"))
    a_input = "\n".join([*subdomains, *tls_names])
    resolved_ips = _lines(
        _run("dnsx", ["dnsx", "-a", "-resp-only", "-silent"],
             stdin=a_input, dest=_raw(activity, "dnsx", "a_responly"), label="a_responly")
    )
    tools.write_lines(canon("unique_ips.txt"), [*resolved_ips, *tools.read_lines(activity.scope_ip)])
    _run("dnsx", ["dnsx", "-a", "-resp", "-nc", "-silent"],
         stdin=a_input, dest=canon("domain_ip_map.txt"), label="a_resp")


def portscan(activity: Activity) -> None:
    """Phase 3 — tiered port scan (1k → honeypot filter → full) on unique IPs.

    Reads unique_ips.txt; writes naabu_1k.txt, honeypots.txt, naabu_full.txt.
    """
    canon = activity.asset_discovery_canonical
    unique_ips = tools.read_lines(canon("unique_ips.txt"))
    naabu_1k = _lines(
        _run("naabu", ["naabu", "-silent", "-top-ports", "1000", "-exclude-cdn"],
             stdin="\n".join(unique_ips), dest=canon("naabu_1k.txt"), label="top1k")
    )
    valid_ips, honeypots = honeypot_split(naabu_1k)
    tools.write_lines(canon("honeypots.txt"), honeypots)
    _run("naabu", ["naabu", "-silent", "-top-ports", "full", "-exclude-cdn"],
         stdin="\n".join(valid_ips), dest=canon("naabu_full.txt"), label="full")


def httpx_fingerprint(activity: Activity) -> None:
    """Phase 4a — HTTP fingerprinting (httpx) → httpx_full_metadata.jsonl + unique_webapps.txt.

    Independent of nerva, so the two fingerprint stages run in parallel.
    """
    canon = activity.asset_discovery_canonical
    httpx_input = "\n".join(tools.dedupe([
        *tools.read_lines(canon("tlsx_raw.txt")),
        *tools.read_lines(canon("subdomains.txt")),
        *tools.read_lines(canon("naabu_full.txt")),
        *tools.read_lines(canon("honeypots.txt")),
    ]))
    out = _run(
        "httpx",
        [HTTPX, "-silent", "-sc", "-cl", "-td", "-title", "-ip", "-hash", "sha256",
         "-favicon", "-location", "-fr", "-irr", "-j"],
        stdin=httpx_input, dest=canon("httpx_full_metadata.jsonl"), label="fingerprint",
    )
    records = [json.loads(ln) for ln in out.splitlines() if ln.strip()]
    tools.write_lines(canon("unique_webapps.txt"), select_unique_webapps(records))


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

    app_ids: list[str] = []
    for idxs in cluster_partition(records):
        members = [records[i] for i in idxs]
        key, value = _cluster_anchor(members)
        app_id = _app_id(f"{key}:{value}")
        rep = min(members, key=lambda r: r["url"])
        urls = tools.dedupe(r["url"] for r in members)
        # per-host response-body hash → lets per-app stages dedup same-backend hosts (domain+IP,
        # http+https) while keeping distinct environments (staging vs test). See dedup_by_body.
        body_by_host = {r["url"]: (r.get("hash") or {}).get("body_sha256") for r in members}
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


def _eyewitness(activity: Activity, ws: AppWorkspace, target: str, app_id: str) -> None:
    """OPTIONAL — EyeWitness on the SINGLE best-host `target` (like httpx, one URL per group):
    screenshot + signature-based default-cred detection. Fed via a one-line -f file — the -f report
    path is the one that writes Requests.csv (--single skips it). Parses Requests.csv →
    default_creds.jsonl (the leads); the HTML report stays under raw/eyewitness/. No-op when
    EyeWitness isn't resolvable (best-effort)."""
    cmd = _eyewitness_cmd()
    if cmd is None:
        log.debug("  · skip eyewitness (not installed) for %s", app_id)
        return
    out_dir = ws.raw("eyewitness")
    if out_dir.exists():
        shutil.rmtree(out_dir)  # EyeWitness wants a fresh -d (else it prompts / appends)
    target_file = activity.tmp / f"eyewitness_{app_id}.txt"
    tools.write_lines(target_file, [target])
    log.info("  → eyewitness (%s) — %s", app_id, target)
    tools.run(
        [*cmd, "--web", "-f", str(target_file), "-d", str(out_dir), "--no-prompt",
         "--timeout", EYEWITNESS_TIMEOUT],
        stream_stderr=is_verbose(),
    )
    csv_path = out_dir / "Requests.csv"
    findings = (parse_eyewitness_csv(csv_path.read_text(encoding="utf-8", errors="replace"))
                if csv_path.exists() else [])
    n = tools.write_jsonl(ws.canonical("default_creds.jsonl"), findings)
    if n:
        log.info("    eyewitness (%s) → %d default-cred lead(s) → default_creds.jsonl", app_id, n)


def screenshot(activity: Activity, app_id: str) -> None:
    """LOOP 1 (first step) — root-page screenshot + (optional) EyeWitness default-cred detection.

    Captures the cluster's best host (non-IP preferred; see best_host) via httpx -screenshot →
    the canonical scans/<app_id>/screenshot.png (or a screenshot.failed marker). Then, best-effort,
    runs EyeWitness on the SAME single best host for its signature-based default-credential leads
    (→ default_creds.jsonl) plus an HTML report — skipped cleanly if EyeWitness isn't installed,
    so httpx stays the reliable screenshot baseline. No needs — runs right after cluster fan-out.
    """
    ws = activity.app(app_id)
    target = best_host(tools.read_lines(ws.hosts))
    if not target:
        log.debug("  · skip screenshot (no host) for %s", app_id)
        return
    store = ws.raw("httpx_screenshot")
    store.mkdir(parents=True, exist_ok=True)
    log.info("  → screenshot (%s) — %s", app_id, target)
    out = tools.run(
        [HTTPX, "-screenshot", "-system-chrome", "-no-screenshot-full-page", "-esb",
         "-st", SCREENSHOT_TIMEOUT, "-silent", "-j", "-srd", str(store)],
        stdin=target, stream_stderr=is_verbose(),
    )
    (store / "out.json").write_text(out, encoding="utf-8")
    pngs = sorted(store.rglob("*.png"))
    if pngs:
        shutil.copy(pngs[0], ws.canonical("screenshot.png"))
        log.info("    screenshot (%s) → screenshot.png", app_id)
    else:
        ws.canonical("screenshot.failed").write_text("", encoding="utf-8")
        log.info("    screenshot (%s) → screenshot.failed", app_id)
    _eyewitness(activity, ws, target, app_id)


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
               dest=ws.raw("katana") / "out.jsonl", label=app_id)
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
        if url.rstrip("/") in roots:
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
                   dest=ws.raw("katana_headless") / "out.jsonl", label=app_id)
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
    cand_file = ws.canonical("takeover_candidates.txt")
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
    """LOOP 2.1 — synthesize a custom per-app wordlist (wl_custom/seed.txt) OFFLINE.

    No fetching: the crawl (loop 1) already downloaded and JS-parsed the linked
    surface — its JS-discovered endpoints and robots/sitemap paths are already in
    endpoints.txt, and the bodies are under responses/. This step tokenizes
    endpoints.txt (plus the gated headless crawl's endpoints_headless.txt, when present)
    into path segments, filename basenames and parameter names (tokenize_urls) and
    merges any tech-specific static lists keyed on the cluster's detected tech. Output:
    scans/<app_id>/wl_custom/seed.txt (the activity wl_global/ holds shared/global lists
    instead). Reads loop-1 artifacts directly — the cross-loop barrier guarantees they exist.
    """
    ws = activity.app(app_id)
    words = tokenize_urls([*tools.read_lines(ws.canonical("endpoints.txt")),
                           *tools.read_lines(ws.canonical("endpoints_headless.txt"))])

    tech = workspace.read_meta(ws.meta).get("tech") or []
    static: list[str] = []
    for wl_file in wordlists.tech_role_paths(tech, activity.wl_global):
        static += tools.read_lines(wl_file)

    n = tools.write_lines(ws.wl_custom / "seed.txt", [*words, *static])
    log.info("  → wordlist (%s) — %d term(s) (+%d tech), offline → wl_custom/seed.txt", app_id, n, len(static))


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
    have = [url for idx in (ws.responses / "index.txt", ws.responses / "headless" / "index.txt")
            for _, url in _store_index(idx)]  # bodies katana stored (cheap + headless crawl)
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
         stdin="\n".join(delta), dest=ws.raw("httpx_osint") / "out.txt", label=app_id)


def _store_index(index: Path) -> list[tuple[str, str]]:
    """Parse a katana/httpx -srd index.txt → [(stored_file, url)]; lines are
    '<filepath> <url> (<status>)'."""
    out: list[tuple[str, str]] = []
    for ln in tools.read_lines(index):
        parts = ln.split()
        if len(parts) >= 2:  # noqa: PLR2004
            out.append((parts[0], parts[1]))
    return out


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


def mine_responses(activity: Activity, app_id: str) -> None:
    """LOOP 2 — mine the per-app response store OFFLINE (cashes in 'fetch once').

    Reads the stored HTTP responses (cheap crawl + headless crawl + fetch_delta -srd)
    WITHOUT re-fetching: extracts each JS body (http_body) and runs jsluice for endpoints
    (→ endpoints_js.txt, folded into the content_discovery wordlist) and secrets
    (→ secrets.jsonl). Needs fetch_delta so the OSINT bodies are present; the crawl bodies
    are guaranteed by the loop barrier. Port of run-web-sast.sh, but AST-based via jsluice.
    """
    ws = activity.app(app_id)
    js_dir = ws.raw("js")
    js_files: list[str] = []
    for index in (ws.responses / "index.txt", ws.responses / "headless" / "index.txt",
                  ws.responses / "osint" / "response" / "index.txt"):
        for stored, url in _store_index(index):
            if not is_js_url(url):
                continue
            body = http_body(Path(stored).read_text(encoding="utf-8", errors="replace"))
            if not body.strip():
                continue
            js_dir.mkdir(parents=True, exist_ok=True)
            dst = js_dir / f"{Path(stored).stem}.js"
            dst.write_text(body, encoding="utf-8")
            js_files.append(str(dst))
    if not js_files:
        log.debug("  · skip mine_responses (no JS in store) for %s", app_id)
        return
    endpoints = [r["url"] for r in _jsonl_str(tools.run([JSLUICE, "urls", *js_files])) if r.get("url")]
    secrets = _jsonl_str(tools.run([JSLUICE, "secrets", *js_files]))
    n_ep = tools.write_lines(ws.canonical("endpoints_js.txt"), endpoints)
    n_sec = tools.write_jsonl(ws.canonical("secrets.jsonl"), secrets)
    log.info("  → mine_responses (%s) — %d JS · %d endpoint(s) · %d secret(s)",
             app_id, len(js_files), n_ep, n_sec)


def _shortscan_surface(activity: Activity, ws: AppWorkspace, app_id: str) -> list[str]:
    """IIS 8.3 short-name enumeration → fuzz words (shortscan + shortutil rainbow).

    Builds a shortutil rainbow table from the per-app seed + global list so shortscan
    resolves the leaked 8.3 names to real filenames (on top of its HTTP autocomplete
    oracles), then harvests those names as surface. Best-effort: no-op if the binaries
    are missing or the app has no hosts.
    """
    if shutil.which(SHORTSCAN) is None or shutil.which(SHORTUTIL) is None:
        log.debug("  · skip shortscan (not installed) for %s", app_id)
        return []
    hosts = tools.read_lines(ws.hosts)
    if not hosts:
        return []
    content_wl = wordlists.role_path(activity, "content")
    rainbow_src = ws.wl_custom / "rainbow_src.txt"
    tools.write_lines(rainbow_src, [
        *tools.read_lines(ws.wl_custom / "seed.txt"),
        *(tools.read_lines(content_wl) if content_wl else []),
    ])
    rainbow = ws.wl_custom / "rainbow.txt"
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
    return parse_shortscan(out)


def tech_enum(activity: Activity, app_id: str) -> None:
    """LOOP 2 (surface) — specialized per-stack scanners whose output FEEDS enum.

    Best-effort dispatch keyed on the cluster's detected tech: a scanner runs only if
    its tech matched AND its binary is installed. Output is SURFACE (fuzz words) →
    wl_custom/shortnames.txt, which content_discovery merges into its wordlist. Scanners whose
    output is findings-only (wpprobe, nuclei, …) belong to tech_vulnscan / loop 3.

    Today: shortscan (IIS/ASP.NET 8.3 short-name enumeration). Reads loop-1 hosts
    across the barrier; needs the wordlist seed for the shortutil rainbow table.
    """
    ws = activity.app(app_id)
    tech = " ".join(workspace.read_meta(ws.meta).get("tech") or []).lower()
    surface: list[str] = []
    if any(k in tech for k in ("iis", "asp.net", "microsoft-iis")):
        surface += _shortscan_surface(activity, ws, app_id)
    n = tools.write_lines(ws.wl_custom / "shortnames.txt", surface)
    log.info("  → tech_enum (%s) — %d surface term(s) → wl_custom/shortnames.txt", app_id, n)


def content_discovery(activity: Activity, app_id: str) -> None:
    """LOOP 2.3 — forced browsing (feroxbuster) seeded by the custom wordlist.

    Discovers UNLINKED paths/files — the one thing reusing downloaded bodies can't
    do, so it must make new requests. feroxbuster --smart brings auto-tune (soft-404
    calibration), collect-words/backups and link extraction/recursion for free, so
    the wordlist-feedback loop is built in. Targets the group's hosts deduped by response body
    (_scan_hosts): one host per backend — same-backend aliases (domain+IP, http+https) are
    collapsed (no re-fuzz; the scanme.nmap.org incident) but distinct environments (staging vs
    test) are each fuzzed, since env-specific files differ. Combined wordlist (per-app
    wl_custom/seed.txt first, then a global SecLists list) + tech-derived extensions. Output:
    scans/<app_id>/content_discovery.jsonl.

    feroxbuster writes JSON to -o (not stdout), so it bypasses _run.
    """
    ws = activity.app(app_id)
    hosts = _scan_hosts(ws)
    if not hosts:
        log.debug("  · skip content_discovery (no host) for %s", app_id)
        return

    # combined wordlist = per-app seed + tech_enum surface + JS-mined paths, then global SecLists
    seed = tools.read_lines(ws.wl_custom / "seed.txt")
    shortnames = tools.read_lines(ws.wl_custom / "shortnames.txt")  # tech_enum surface (8.3 names)
    js_tokens = tokenize_urls(tools.read_lines(ws.canonical("endpoints_js.txt")))  # mine_responses
    content_wl = wordlists.role_path(activity, "content")  # global list, resolved by role
    global_wl = tools.read_lines(content_wl) if content_wl else []
    wordlist = ws.wl_custom / "combined.txt"
    n_wl = tools.write_lines(wordlist, [*seed, *shortnames, *js_tokens, *global_wl])
    if not n_wl:
        log.debug("  · skip content_discovery (empty wordlist) for %s", app_id)
        return

    exts = tech_extensions(workspace.read_meta(ws.meta).get("tech") or [], TECH_EXTENSIONS)
    ext_args = ["-x", *exts] if exts else []
    out_file = ws.raw("feroxbuster") / "out.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    log.info("  → feroxbuster (%s) — %d host(s), %d term(s)%s", app_id, len(hosts), n_wl,
             f", -x {','.join(exts)}" if exts else "")
    cmd = [FEROX, "--stdin", "--silent", "--json", "-o", str(out_file), "--no-state", "-k",
           "--smart", "-t", FEROX_THREADS, "-L", FEROX_SCAN_LIMIT, "--timeout", FEROX_TIMEOUT,
           "--time-limit", FEROX_TIME_LIMIT, "-d", FEROX_DEPTH, "-w", str(wordlist), *ext_args]
    tools.run(cmd, stdin="\n".join(hosts), stream_stderr=is_verbose())
    records = parse_ferox(out_file.read_text(encoding="utf-8") if out_file.exists() else "")
    n = tools.write_jsonl(ws.canonical("content_discovery.jsonl"), records)
    log.info("    feroxbuster (%s) → %d result(s) → content_discovery.jsonl", app_id, n)
