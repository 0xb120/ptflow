"""Real asset_discovery (breadth) — faithful port of scope2surface.sh.

Each external tool writes its raw output to scans/asset_discovery/raw/<tool>/,
and consolidated results are promoted to fixed canonical names under
scans/asset_discovery/. Pure transforms (scope split, honeypot filter, unique
webapp selection) are module-level functions so they can be unit-tested.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from pipt.core import tools

if TYPE_CHECKING:
    from pipt.core.paths import Activity
    from pipt.core.scope import Target

# --- tunables (mirror scope2surface.sh 1:1; conservative — live infra) ---
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
    """Return (urls, dns_names, wildcards, ips_cidr) from classified targets.

    URL hosts are folded into dns_names (their normalized form is the host).
    """
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


def _tool(activity: Activity, tool: str, cmd: list[str], *, stdin: str, label: str) -> str:
    """Run a tool over `stdin`, persist its raw output, return stdout. No-op on empty input."""
    if not stdin.strip():
        return ""
    out = tools.run(cmd, stdin=stdin)
    raw_dir = activity.asset_discovery_raw(tool)
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / f"{label}.txt").write_text(out, encoding="utf-8")
    return out


# --- the breadth stage ---
def asset_discovery(activity: Activity, targets: list[Target]) -> None:
    """Expand the scope into the full attack surface (scope2surface.sh port)."""
    urls, dns, wildcards, ips_cidr = split_scope(targets)
    tools.write_lines(activity.scope_urls, urls)
    tools.write_lines(activity.scope_dns, [*dns, *wildcards])
    tools.write_lines(activity.scope_ip, ips_cidr)

    dns_names: list[str] = list(dns)
    tlsx_names: list[str] = []

    # expand IPs / CIDRs
    scope_ips = _lines(
        _tool(activity, "mapcidr", ["mapcidr", "-silent"], stdin="\n".join(ips_cidr), label="expand")
    ) or ips_cidr

    # TLS-cert harvest from open ports on scope IPs
    naabu_tls = _lines(
        _tool(
            activity, "naabu",
            ["naabu", "-silent", "-top-ports", NAABU_TLS_TOP_PORTS, "-exclude-cdn",
             "-c", NAABU_TLS_CONC, "-rate", NAABU_TLS_RATE],
            stdin="\n".join(scope_ips), label="tls_ports",
        )
    )
    tls_from_ports = _lines(
        _tool(activity, "tlsx", ["tlsx", "-san", "-cn", "-silent", "-resp-only"],
              stdin="\n".join(naabu_tls), label="from_ports")
    )
    tlsx_names += tls_from_ports
    dns_names += _lines(
        _tool(activity, "dnsx", ["dnsx", "-silent"], stdin="\n".join(tls_from_ports), label="tls_resolve")
    )

    # reverse-DNS (PTR) harvest
    dns_names += _lines(
        _tool(activity, "dnsx", ["dnsx", "-ptr", "-resp-only", "-silent"],
              stdin="\n".join(scope_ips), label="ptr")
    )

    # wildcard expansion (passive subdomain enum)
    for wc in wildcards:
        dns_names += _lines(
            _tool(activity, "assetfinder", ["assetfinder", "-subs-only"], stdin=wc, label=wc)
        )
    if wildcards:
        dns_names += _lines(
            _tool(activity, "subfinder", ["subfinder", "-silent"],
                  stdin="\n".join(wildcards), label="wildcards")
        )

    tools.write_lines(activity.asset_discovery_canonical("tlsx_raw.txt"), tlsx_names)

    # resolve every candidate name to live subdomains (shuffledns; dnsx fallback)
    all_dns = "\n".join(tools.dedupe(dns_names))
    resolved = _lines(
        _tool(activity, "shuffledns",
              ["shuffledns", "-mode", "resolve", "-r", RESOLVERS, "-silent"],
              stdin=all_dns, label="resolve")
    )
    if not resolved:
        resolved = _lines(
            _tool(activity, "dnsx", ["dnsx", "-silent"], stdin=all_dns, label="resolve_fallback")
        )
    subdomains = tools.dedupe(resolved)
    tools.write_lines(activity.asset_discovery_canonical("subdomains.txt"), subdomains)

    # consolidate unique IPs + domain:ip map
    a_input = "\n".join([*subdomains, *tlsx_names])
    resolved_ips = _lines(
        _tool(activity, "dnsx", ["dnsx", "-a", "-resp-only", "-silent"], stdin=a_input, label="a_responly")
    )
    unique_ips = tools.dedupe([*resolved_ips, *scope_ips])
    tools.write_lines(activity.asset_discovery_canonical("unique_ips.txt"), unique_ips)
    dmap = _tool(activity, "dnsx", ["dnsx", "-a", "-resp", "-nc", "-silent"], stdin=a_input, label="a_resp")
    activity.asset_discovery_canonical("domain_ip_map.txt").write_text(dmap, encoding="utf-8")

    # tiered port scan + honeypot filter
    naabu_1k = _lines(
        _tool(activity, "naabu", ["naabu", "-silent", "-top-ports", "1000", "-exclude-cdn"],
              stdin="\n".join(unique_ips), label="top1k")
    )
    tools.write_lines(activity.asset_discovery_canonical("naabu_1k.txt"), naabu_1k)
    valid_ips, honeypots = honeypot_split(naabu_1k)
    tools.write_lines(activity.asset_discovery_canonical("honeypots.txt"), honeypots)
    naabu_full = _lines(
        _tool(activity, "naabu", ["naabu", "-silent", "-top-ports", "full", "-exclude-cdn"],
              stdin="\n".join(valid_ips), label="full")
    )
    tools.write_lines(activity.asset_discovery_canonical("naabu_full.txt"), naabu_full)

    # HTTP fingerprinting (httpx) — the rich per-vhost metadata clustering will consume
    httpx_input = "\n".join(tools.dedupe([*tlsx_names, *subdomains, *naabu_full, *honeypots]))
    httpx_out = _tool(
        activity, "httpx",
        [HTTPX, "-silent", "-sc", "-cl", "-td", "-title", "-ip", "-hash", "sha256",
         "-location", "-fr", "-j"],
        stdin=httpx_input, label="fingerprint",
    )
    activity.asset_discovery_canonical("httpx_full_metadata.jsonl").write_text(httpx_out, encoding="utf-8")

    # non-HTTP service fingerprinting
    activity.asset_discovery_canonical("fingerprintx_full_metadata.jsonl").write_text(
        _tool(activity, "fingerprintx", ["fingerprintx", "--json"],
              stdin="\n".join(naabu_full), label="json"),
        encoding="utf-8",
    )
    activity.asset_discovery_canonical("nerva_full_metadata.jsonl").write_text(
        _tool(activity, "nerva", ["nerva", "--json"], stdin="\n".join(naabu_full), label="json"),
        encoding="utf-8",
    )

    # unique web applications (dedup by Title+CL+Webserver) — clustering input next round
    httpx_records = [json.loads(ln) for ln in httpx_out.splitlines() if ln.strip()]
    tools.write_lines(
        activity.asset_discovery_canonical("unique_webapps.txt"), select_unique_webapps(httpx_records)
    )
