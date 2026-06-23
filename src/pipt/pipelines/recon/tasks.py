"""Real asset_discovery (breadth) — faithful port of scope2surface.sh.

Each tool's output is written ONCE. Intermediate steps that only feed later
steps go to scans/asset_discovery/raw/<tool>/ (provenance). A tool whose output
IS a final artifact is written straight to its canonical name — no duplicate raw
copy. Derived artifacts (unique IPs, honeypots, unique webapps) are computed in
memory. Pure transforms are module-level so they can be unit-tested.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from pipt.core import scope, tools, workspace
from pipt.core.log import get_logger, is_verbose

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
SUBJACK_THREADS = "100"
SUBJACK_TIMEOUT = "30"
SCREENSHOT_TIMEOUT = "20"   # httpx -screenshot per-page timeout (seconds)
SPA_FRAMEWORKS = frozenset({"react", "vue", "angular", "svelte", "next", "nuxt", "gatsby", "ember"})
NOISE_EXTENSIONS = frozenset({
    "jpg", "jpeg", "png", "gif", "svg", "bmp", "webp", "ico",
    "woff", "woff2", "ttf", "eot", "otf", "css",
    "mp3", "mp4", "wav", "avi", "mov", "webm",
})

# wordlist synthesis (LOOP 2 — active collection → custom per-app wordlist)
_TOKEN_MAX_LEN = 40                       # drop longer "segments" (hashes/junk)
WORDLIST_DIR = Path("/opt/wordlists")     # shared static lists (seclists-style); optional
TECH_WORDLISTS = {                        # detected-tech keyword → list relative to WORDLIST_DIR
    "wordpress": "cms/wordpress.txt",
    "drupal": "cms/drupal.txt",
    "joomla": "cms/joomla.txt",
    "tomcat": "servers/tomcat.txt",
    "jboss": "servers/jboss.txt",
    "jenkins": "apps/jenkins.txt",
    "gitlab": "apps/gitlab.txt",
    "php": "languages/php.txt",
    "asp.net": "languages/aspnet.txt",
    "java": "languages/java.txt",
}
OSINT_FETCH_RL = "50"  # httpx req/s when downloading the OSINT delta into responses/osint/

# content discovery (LOOP 2) — feroxbuster forced browsing
SECLISTS_DIR = Path("/opt/wordlist/SecLists")
CONTENT_WORDLIST = SECLISTS_DIR / "Discovery" / "Web-Content" / "raft-medium-directories.txt"  # global; optional
# Gentle on live infra: --smart (auto-tune) adapts the rate down when the target errors/times
# out; low -t/-L keep concurrency bounded from the start. (--rate-limit is mutually exclusive
# with --smart, and is per-directory anyway, so it's the wrong tool here.)
FEROX_DEPTH = "2"        # -d recursion depth (feroxbuster default is 4)
FEROX_THREADS = "5"      # -t threads per scan (default 50 is aggressive for fragile apps)
FEROX_SCAN_LIMIT = "2"   # -L concurrent directory scans (caps recursion fan-out)
FEROX_TIMEOUT = "15"     # --timeout per-request seconds (tolerate slow apps)
TECH_EXTENSIONS = {  # detected-tech keyword → file extensions to fuzz
    "php": ["php"],
    "asp.net": ["asp", "aspx", "ashx"],
    "java": ["jsp", "do", "action"],
    "python": ["py"],
    "ruby": ["rb"],
    "coldfusion": ["cfm", "cfc"],
}

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


def select_tech_wordlists(tech: list[str], mapping: dict[str, str], base: Path) -> list[Path]:
    """Map detected-tech tags to existing static wordlist files under ``base``.

    Matching is case-insensitive substring (httpx tags like 'WordPress 6.4' still
    hit the 'wordpress' key). Returns only files that exist — absent files or an
    absent ``base`` make this a no-op, so the step needs no external data to run.
    """
    tags = [t.lower() for t in tech]
    out: list[Path] = []
    for key, rel in mapping.items():
        if any(key in tag for tag in tags):
            path = base / rel
            if path.is_file():
                out.append(path)
    return out


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


def is_spa(tech: list[str]) -> bool:
    """Whether the cluster's detected tech (meta.json) suggests a JS SPA → headless crawl."""
    blob = " ".join(tech).lower()
    return any(fw in blob for fw in SPA_FRAMEWORKS)


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
         "-location", "-fr", "-j"],
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
def cluster(activity: Activity) -> list[str]:
    """Group httpx vhosts by (Title, Content-Length, Webserver) into scans/<app_id>/.

    Port of surfagr.sh. Each distinct signature becomes one application-group
    workspace with meta.json (identity) + hosts.txt (the group's URLs — the input
    the per-app enum phase consumes). Returns the sorted app_ids.
    """
    records = tools.read_jsonl(activity.asset_discovery_canonical("httpx_full_metadata.jsonl"))
    groups: dict[str, dict] = {}
    for r in records:
        url = r.get("url")
        if not url:
            continue
        signature = f"{r.get('title') or ''}|{r.get('content_length')}|{r.get('webserver') or ''}"
        group = groups.setdefault(_app_id(signature), {"signature": signature, "rep": r, "urls": []})
        group["urls"].append(url)

    for app_id, group in groups.items():
        ws = activity.app(app_id).ensure()
        rep = group["rep"]
        members = tools.dedupe(group["urls"])
        workspace.write_meta(
            ws.meta,
            {
                "app_id": app_id,
                "signature": group["signature"],
                "title": rep.get("title"),
                "webserver": rep.get("webserver"),
                "content_length": rep.get("content_length"),
                "status_code": rep.get("status_code"),
                "tech": rep.get("tech") or [],
                "hosts": members,
            },
        )
        tools.write_lines(ws.hosts, members)
        log.info("  → app %s [%s] — %d host(s)", app_id, group["signature"], len(members))
    return sorted(groups)


# --- depth sub-phases (per app group; chain via the app workspace on disk) ---
def screenshot(activity: Activity, app_id: str) -> None:
    """LOOP 1 (first step) — root-page screenshot of the cluster's best host.

    Picks one URL per app (non-IP preferred; see best_host) and captures its root page
    with system Chrome via httpx -screenshot. httpx names the PNG under raw/; it's
    promoted to the canonical scans/<app_id>/screenshot.png, or a screenshot.failed
    marker on miss. No needs — runs right after cluster fan-out, ∥ the other loop-1 steps.
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


def passive_probe(activity: Activity, app_id: str) -> None:
    """DEPTH 1 — passive URL discovery (gau + urlfinder) → endpoints_passive.txt."""
    ws = activity.app(app_id)
    domains = tools.dedupe([url_host(u) for u in tools.read_lines(ws.hosts)])
    gau = _lines(_run("gau", ["gau", "--threads", GAU_THREADS],
                      stdin="\n".join(domains), dest=ws.raw("gau") / "out.txt", label=app_id))
    urls = _lines(_run("urlfinder", ["urlfinder", "-silent"],
                       stdin="\n".join(domains), dest=ws.raw("urlfinder") / "out.txt", label=app_id))
    tools.write_lines(ws.canonical("endpoints_passive.txt"), [*gau, *urls])


def crawl(activity: Activity, app_id: str) -> None:
    """DEPTH 2 — active crawl that fetches the linked surface ONCE and keeps it.

    katana with -jc/-jsl (parse JS endpoints), -kf all (robots.txt/sitemap.xml) and
    -srd (store every response). Its URL output already contains JS-discovered and
    known-file paths, so endpoints.txt is the JS-enriched corpus; the stored bodies
    under responses/ are the per-app corpus that offline steps mine WITHOUT
    re-fetching (the crawler is the downloader for the linked surface). Clusters whose
    detected tech is a JS SPA (is_spa) also get -headless to render the app. Merges with
    passive + denoise → endpoints.txt.
    """
    ws = activity.app(app_id)
    hosts = tools.read_lines(ws.hosts)
    if hosts:
        ws.responses.mkdir(parents=True, exist_ok=True)
    katana = ["katana", "-silent", "-jc", "-jsl", "-kf", "all", "-d", KATANA_DEPTH, "-c", KATANA_CONC,
              "-srd", str(ws.responses)]
    if is_spa(workspace.read_meta(ws.meta).get("tech") or []):
        katana += ["-headless", "-system-chrome"]  # render JS SPAs (detected framework)
    crawled = _lines(_run("katana", katana, stdin="\n".join(hosts),
                          dest=ws.raw("katana") / "out.txt", label=app_id))
    passive = tools.read_lines(ws.canonical("endpoints_passive.txt"))
    tools.write_lines(ws.canonical("endpoints.txt"), denoise(tools.dedupe([*passive, *crawled])))


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
    """LOOP 2.1 — synthesize a custom per-app wordlist (wl/seed.txt) OFFLINE.

    No fetching: the crawl (loop 1) already downloaded and JS-parsed the linked
    surface — its JS-discovered endpoints and robots/sitemap paths are already in
    endpoints.txt, and the bodies are under responses/. This step tokenizes
    endpoints.txt into path segments, filename basenames and parameter names
    (tokenize_urls) and merges any tech-specific static lists keyed on the cluster's
    detected tech. Output: scans/<app_id>/wl/seed.txt (the activity wl/ holds
    shared/global lists instead). Reads loop-1 artifacts directly — the cross-loop
    barrier guarantees they exist.
    """
    ws = activity.app(app_id)
    words = tokenize_urls(tools.read_lines(ws.canonical("endpoints.txt")))

    tech = workspace.read_meta(ws.meta).get("tech") or []
    static: list[str] = []
    for wl in select_tech_wordlists(tech, TECH_WORDLISTS, WORDLIST_DIR):
        static += tools.read_lines(wl)

    n = tools.write_lines(ws.wl / "seed.txt", [*words, *static])
    log.info("  → wordlist (%s) — %d term(s) (+%d tech), offline → wl/seed.txt", app_id, n, len(static))


def fetch_delta(activity: Activity, app_id: str) -> None:
    """LOOP 2.2 — download the OSINT delta into the response store (∥ wordlist).

    passive_probe's URLs (endpoints_passive.txt) that the crawl never fetched are
    the only ones a separate downloader needs — the crawler already downloaded the
    linked surface. httpx fetches the live ones (it drops dead hosts) and stores
    their bodies under responses/osint/, so offline body-mining covers archived/OSINT
    URLs too. Reads loop-1 artifacts directly — the barrier guarantees they exist.
    """
    ws = activity.app(app_id)
    delta = passive_delta(
        tools.read_lines(ws.canonical("endpoints_passive.txt")),
        tools.read_lines(ws.raw("katana") / "out.txt"),
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

    Reads the stored HTTP responses (crawl + fetch_delta -srd) WITHOUT re-fetching:
    extracts each JS body (http_body) and runs jsluice for endpoints (→ endpoints_js.txt,
    folded into the content_discovery wordlist) and secrets (→ secrets.jsonl). Needs
    fetch_delta so the OSINT bodies are present; the crawl bodies are guaranteed by the
    loop barrier. Port of run-web-sast.sh, but AST-based via jsluice.
    """
    ws = activity.app(app_id)
    js_dir = ws.raw("js")
    js_files: list[str] = []
    for index in (ws.responses / "index.txt", ws.responses / "osint" / "response" / "index.txt"):
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


def _shortscan_surface(ws: AppWorkspace, app_id: str) -> list[str]:
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
    rainbow_src = ws.wl / "rainbow_src.txt"
    tools.write_lines(rainbow_src, [
        *tools.read_lines(ws.wl / "seed.txt"),
        *(tools.read_lines(CONTENT_WORDLIST) if CONTENT_WORDLIST.is_file() else []),
    ])
    rainbow = ws.wl / "rainbow.txt"
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
    wl/shortnames.txt, which content_discovery merges into its wordlist. Scanners whose
    output is findings-only (wpprobe, nuclei, …) belong to tech_vulnscan / loop 3.

    Today: shortscan (IIS/ASP.NET 8.3 short-name enumeration). Reads loop-1 hosts
    across the barrier; needs the wordlist seed for the shortutil rainbow table.
    """
    ws = activity.app(app_id)
    tech = " ".join(workspace.read_meta(ws.meta).get("tech") or []).lower()
    surface: list[str] = []
    if any(k in tech for k in ("iis", "asp.net", "microsoft-iis")):
        surface += _shortscan_surface(ws, app_id)
    n = tools.write_lines(ws.wl / "shortnames.txt", surface)
    log.info("  → tech_enum (%s) — %d surface term(s) → wl/shortnames.txt", app_id, n)


def content_discovery(activity: Activity, app_id: str) -> None:
    """LOOP 2.3 — forced browsing (feroxbuster) seeded by the custom wordlist.

    Discovers UNLINKED paths/files — the one thing reusing downloaded bodies can't
    do, so it must make new requests. feroxbuster --smart brings auto-tune (soft-404
    calibration), collect-words/backups and link extraction/recursion for free, so
    the wordlist-feedback loop is built in. Targets the app's hosts with a combined
    wordlist (per-app wl/seed.txt first, then a global SecLists list) and tech-derived
    extensions. Output: scans/<app_id>/content_discovery.jsonl.

    feroxbuster writes JSON to -o (not stdout), so it bypasses _run.
    """
    ws = activity.app(app_id)
    hosts = tools.read_lines(ws.hosts)
    if not hosts:
        log.debug("  · skip content_discovery (no hosts) for %s", app_id)
        return

    # combined wordlist = per-app seed + tech_enum surface + JS-mined paths, then global SecLists
    seed = tools.read_lines(ws.wl / "seed.txt")
    shortnames = tools.read_lines(ws.wl / "shortnames.txt")  # tech_enum surface (8.3 names)
    js_tokens = tokenize_urls(tools.read_lines(ws.canonical("endpoints_js.txt")))  # mine_responses
    global_wl = tools.read_lines(CONTENT_WORDLIST) if CONTENT_WORDLIST.is_file() else []
    wordlist = ws.wl / "combined.txt"
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
           "-d", FEROX_DEPTH, "-w", str(wordlist), *ext_args]
    tools.run(cmd, stdin="\n".join(hosts), stream_stderr=is_verbose())
    records = parse_ferox(out_file.read_text(encoding="utf-8") if out_file.exists() else "")
    n = tools.write_jsonl(ws.canonical("content_discovery.jsonl"), records)
    log.info("    feroxbuster (%s) → %d result(s) → content_discovery.jsonl", app_id, n)
