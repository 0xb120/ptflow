"""Real asset_discovery (breadth) — faithful port of scope2surface.sh.

Each tool's output is written ONCE. Intermediate steps that only feed later
steps go to scans/asset_discovery/raw/<tool>/ (provenance). A tool whose output
IS a final artifact is written straight to its canonical name — no duplicate raw
copy. Derived artifacts (unique IPs, honeypots, unique webapps) are computed in
memory. Pure transforms are module-level so they can be unit-tested.
"""

from __future__ import annotations

import json
import logging
import shlex
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from pipt.core import tools
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


# --- helpers ---
def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


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


# --- the breadth stage ---
def asset_discovery(activity: Activity, targets: list[Target]) -> None:
    """Expand the scope into the full attack surface (scope2surface.sh port)."""
    urls, dns, wildcards, ips_cidr = split_scope(targets)
    tools.write_lines(activity.scope_urls, urls)
    tools.write_lines(activity.scope_dns, [*dns, *wildcards])
    tools.write_lines(activity.scope_ip, ips_cidr)

    def raw(tool: str, label: str) -> Path:
        return activity.asset_discovery_raw(tool) / f"{label}.txt"

    canon = activity.asset_discovery_canonical
    dns_names = list(dns)

    log.info(" · scope expansion (DNS/TLS/PTR/wildcards)")
    scope_ips = _lines(
        _run("mapcidr", ["mapcidr", "-silent"],
             stdin="\n".join(ips_cidr), dest=raw("mapcidr", "expand"), label="expand")
    ) or ips_cidr

    naabu_tls = _lines(
        _run("naabu",
             ["naabu", "-silent", "-top-ports", NAABU_TLS_TOP_PORTS, "-exclude-cdn",
              "-c", NAABU_TLS_CONC, "-rate", NAABU_TLS_RATE],
             stdin="\n".join(scope_ips), dest=raw("naabu", "tls_ports"), label="tls_ports")
    )
    tls_names = _lines(
        _run("tlsx", ["tlsx", "-san", "-cn", "-silent", "-resp-only"],
             stdin="\n".join(naabu_tls), dest=canon("tlsx_raw.txt"), label="from_ports")
    )
    dns_names += _lines(
        _run("dnsx", ["dnsx", "-silent"],
             stdin="\n".join(tls_names), dest=raw("dnsx", "tls_resolve"), label="tls_resolve")
    )
    dns_names += _lines(
        _run("dnsx", ["dnsx", "-ptr", "-resp-only", "-silent"],
             stdin="\n".join(scope_ips), dest=raw("dnsx", "ptr"), label="ptr")
    )
    for wc in wildcards:
        dns_names += _lines(
            _run("assetfinder", ["assetfinder", "-subs-only"],
                 stdin=wc, dest=raw("assetfinder", wc), label=wc)
        )
    if wildcards:
        dns_names += _lines(
            _run("subfinder", ["subfinder", "-silent"],
                 stdin="\n".join(wildcards), dest=raw("subfinder", "wildcards"), label="wildcards")
        )

    log.info(" · resolve subdomains + consolidate IPs")
    all_dns = "\n".join(tools.dedupe(dns_names))
    subdomains = _lines(
        _run("shuffledns",
             ["shuffledns", "-mode", "resolve", "-r", RESOLVERS, "-silent"],
             stdin=all_dns, dest=canon("subdomains.txt"), label="resolve")
    )
    if not subdomains:
        subdomains = _lines(
            _run("dnsx", ["dnsx", "-silent"],
                 stdin=all_dns, dest=canon("subdomains.txt"), label="resolve_fallback")
        )

    a_input = "\n".join([*subdomains, *tls_names])
    resolved_ips = _lines(
        _run("dnsx", ["dnsx", "-a", "-resp-only", "-silent"],
             stdin=a_input, dest=raw("dnsx", "a_responly"), label="a_responly")
    )
    unique_ips = tools.dedupe([*resolved_ips, *scope_ips])
    tools.write_lines(canon("unique_ips.txt"), unique_ips)
    _run("dnsx", ["dnsx", "-a", "-resp", "-nc", "-silent"],
         stdin=a_input, dest=canon("domain_ip_map.txt"), label="a_resp")

    log.info(" · port scan (tiered) + honeypot filter")
    naabu_1k = _lines(
        _run("naabu", ["naabu", "-silent", "-top-ports", "1000", "-exclude-cdn"],
             stdin="\n".join(unique_ips), dest=canon("naabu_1k.txt"), label="top1k")
    )
    valid_ips, honeypots = honeypot_split(naabu_1k)
    tools.write_lines(canon("honeypots.txt"), honeypots)
    naabu_full = _lines(
        _run("naabu", ["naabu", "-silent", "-top-ports", "full", "-exclude-cdn"],
             stdin="\n".join(valid_ips), dest=canon("naabu_full.txt"), label="full")
    )

    log.info(" · fingerprinting (httpx / nerva)")
    httpx_input = "\n".join(tools.dedupe([*tls_names, *subdomains, *naabu_full, *honeypots]))
    httpx_out = _run(
        "httpx",
        [HTTPX, "-silent", "-sc", "-cl", "-td", "-title", "-ip", "-hash", "sha256",
         "-location", "-fr", "-j"],
        stdin=httpx_input, dest=canon("httpx_full_metadata.jsonl"), label="fingerprint",
    )
    _run("nerva", ["nerva", "--json"],
         stdin="\n".join(naabu_full), dest=canon("nerva_full_metadata.jsonl"), label="json")

    httpx_records = [json.loads(ln) for ln in httpx_out.splitlines() if ln.strip()]
    tools.write_lines(canon("unique_webapps.txt"), select_unique_webapps(httpx_records))
