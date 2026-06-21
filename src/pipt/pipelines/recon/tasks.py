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
import logging
import shlex
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from pipt.core import scope, tools, workspace
from pipt.core.log import get_logger

if TYPE_CHECKING:
    from pipt.core.paths import Activity
    from pipt.core.scope import Target

log = get_logger()

# --- tunables (mirror scope2surface.sh; conservative — live infra) ---
NAABU_TLS_TOP_PORTS = "1000"
NAABU_TLS_RATE = "1000"
NAABU_TLS_CONC = "50"
HONEYPOT_MIN_OPEN_PORTS = 15      # >= this many open ports => suspected honeypot
RESOLVERS = "/opt/resolvers/resolvers-trusted.txt"

# per-app enum (depth) — mirror run-passive-probe / run-crawler / run-takeover-discovered
GAU_THREADS = "5"
KATANA_DEPTH = "3"
KATANA_CONC = "2"
SUBJACK_THREADS = "100"
SUBJACK_TIMEOUT = "30"
NOISE_EXTENSIONS = frozenset({
    "jpg", "jpeg", "png", "gif", "svg", "bmp", "webp", "ico",
    "woff", "woff2", "ttf", "eot", "otf", "css",
    "mp3", "mp4", "wav", "avi", "mov", "webm",
})

# `httpx` on PATH is the pyenv shim; the ProjectDiscovery binary lives in ~/go/bin.
_HTTPX_BIN = Path.home() / "go" / "bin" / "httpx"
HTTPX = str(_HTTPX_BIN) if _HTTPX_BIN.exists() else "httpx"


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


def denoise(urls: list[str]) -> list[str]:
    """Drop URLs to static assets (extensions in NOISE_EXTENSIONS)."""
    out: list[str] = []
    for u in urls:
        last = u.split("?", 1)[0].rsplit("/", 1)[-1]
        ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
        if ext not in NOISE_EXTENSIONS:
            out.append(u)
    return out


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
    verbose = log.isEnabledFor(logging.DEBUG)
    if verbose:
        log.debug("    $ %s", shlex.join(cmd))
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
    """DEPTH 2 — active crawl (katana); merge with passive + denoise → endpoints.txt."""
    ws = activity.app(app_id)
    crawled = _lines(_run("katana", ["katana", "-silent", "-d", KATANA_DEPTH, "-c", KATANA_CONC],
                          stdin="\n".join(tools.read_lines(ws.hosts)),
                          dest=ws.raw("katana") / "out.txt", label=app_id))
    passive = tools.read_lines(ws.canonical("endpoints_passive.txt"))
    tools.write_lines(ws.canonical("endpoints.txt"), denoise(tools.dedupe([*passive, *crawled])))


def subenum(activity: Activity, app_id: str) -> None:
    """DEPTH 3 — passive subdomain enum (subfinder + dnsx live filter) → subs.txt."""
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
        stream_stderr=log.isEnabledFor(logging.DEBUG),
    )
    raw_out = ws.raw("subjack") / "out.txt"
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    raw_out.write_text(out, encoding="utf-8")
    findings = [ln for ln in _lines(out) if "Not Vulnerable" not in ln]
    tools.write_lines(ws.canonical("takeover.txt"), findings)
