"""Internal-network pentest pipeline tasks.

Scope is IP/CIDR only. The flow mirrors the pipt breadth → cluster → per-app-loop grammar, but
the fan-out unit is a **scope subnet**, not a web app:

  BREADTH (whole-scope, one rate-controlled pass)
    expand    — mapcidr: CIDR → candidate IP list                  → scope/scope_ip.txt
    discover  — nmap -sn ping sweep: which IPs are live            → asset_discovery/live_hosts.txt
    portscan  — naabu over a curated internal-service port set     → asset_discovery/ports.jsonl

  cluster()   — partition the LIVE hosts by the scope entry that contains them (longest-prefix
                wins on overlap; a bare IP is a /32). One scans/<subnet>/ group per entry that
                has ≥1 live host → the per-subnet compartmentalisation.

  LOOP 1 — inventory (per-subnet)
    fingerprint — nerva over the group's ip:port set (nmap -sV is the drop-in alternative)
                                                                    → scans/<subnet>/services.jsonl

  LOOP 2 — low-hanging fruit (per-subnet, gated on the service found in loop 1)
    cve_lookup  — search_vulns over the service banners (OFFLINE)  → findings/cve.jsonl
    smb_checks  — netexec: signing / null-session / guest          → findings/smb.jsonl
    snmp_checks — onesixtyone: default community strings           → findings/snmp.jsonl
    ldap_checks — ldapsearch: anonymous bind                       → findings/ldap.jsonl
    nuclei_net  — nuclei network templates                         → findings/nuclei_net.jsonl

  consolidate — lift the per-subnet findings/<type>.jsonl to the activity level, one file per type.

Every tool output is written ONCE (raw/<tool>/ for provenance, canonical name for a downstream-read
artifact). The loop-2 checks are BEST-EFFORT: a gated-out port, a missing binary, or a tool error
degrades that check to "no finding" — it never aborts the run (failures are isolated by the
orchestrator anyway). Pure transforms are module-level so they can be unit-tested apart from the
subprocess plumbing.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
from typing import TYPE_CHECKING

from pipt.core import scope, tools, workspace
from pipt.core.log import get_logger, is_verbose
from pipt.core.stage import Followup

if TYPE_CHECKING:
    from pathlib import Path

    from pipt.core.paths import Activity, AppWorkspace

log = get_logger()


# --- tool paths (resolve ~/go/bin · ~/.local/bin · PATH; env override wins) ----------------------
def _resolve(env_var: str, *candidates: str) -> str:
    """Resolve a tool: env override > first existing candidate path > the last candidate (bare name,
    left for PATH lookup). Best-effort callers still shutil.which() before use, so an unresolved tool
    simply skips its stage."""
    from pathlib import Path  # noqa: PLC0415 — local so the module has no path literal at import

    if (override := os.environ.get(env_var)):
        return override
    for c in candidates:
        if Path(c).exists():
            return c
    return candidates[-1]


_HOME = os.path.expanduser("~")  # noqa: PTH111 — plain string join for the candidate paths below
MAPCIDR = _resolve("PIPT_MAPCIDR", f"{_HOME}/go/bin/mapcidr", "mapcidr")
NAABU = _resolve("PIPT_NAABU", f"{_HOME}/go/bin/naabu", "naabu")
NMAP = _resolve("PIPT_NMAP", "nmap")
NERVA = _resolve("PIPT_NERVA", f"{_HOME}/go/bin/nerva", "nerva")
NUCLEI = _resolve("PIPT_NUCLEI", f"{_HOME}/go/bin/nuclei", "nuclei")
NXC = _resolve("PIPT_NETEXEC", f"{_HOME}/.local/bin/nxc", "nxc")
SEARCH_VULNS = _resolve("PIPT_SEARCH_VULNS", f"{_HOME}/.local/bin/search_vulns", "search_vulns")
ONESIXTYONE = _resolve("PIPT_ONESIXTYONE", "onesixtyone")
LDAPSEARCH = _resolve("PIPT_LDAPSEARCH", "ldapsearch")

_CORE_TOOLS = {"mapcidr": MAPCIDR, "naabu": NAABU, "nmap": NMAP, "nerva": NERVA}
_OPTIONAL_TOOLS = {"nuclei": NUCLEI, "netexec": NXC, "search_vulns": SEARCH_VULNS,
                   "onesixtyone": ONESIXTYONE, "ldapsearch": LDAPSEARCH}

# --- tunables (rates conservative for live internal infra — legacy/OT gear is fragile) -----------
# Aggregate load ~= concurrency x rate; a full connect-scan flood can knock over old devices and
# saturate a switch, so one global rate-controlled sweep (breadth) beats N per-subnet floods.
_HOME_NAABU = ("300", "20")   # (rate pkts/s, concurrency) — gentle for a domestic/constrained line
_WIDE_NAABU = ("1000", "50")  # real bandwidth
NAABU_RATE, NAABU_CONC = (
    _HOME_NAABU if os.environ.get("PIPT_PROFILE", "").lower().strip() == "home" else _WIDE_NAABU)

CHECK_TIMEOUT = 300   # per-invocation wall-clock cap (s) for the bounded loop-2 checks (a slow host
                      # must not hang the per-subnet chain; the long breadth scans stay timeout-free)
CVE_TOOL_TIMEOUT = 90
_CVE_DESC_MAX = 300

# curated internal-service TCP ports for the fast portscan (naabu -p). Not nmap's generic top-1k —
# this leans to the services an internal first-check cares about (SMB/LDAP/RDP/DB/mgmt UIs). SNMP is
# UDP/161 (not here — snmp_checks sweeps it directly). A full 65535 pass is a natural future spanning
# stage; the fast set keeps breadth quick.
INTERNAL_PORTS = (
    "21,22,23,25,53,79,80,88,110,111,113,119,135,137,139,143,161,389,443,445,464,465,512,513,514,"
    "515,543,544,548,554,587,593,623,636,873,902,993,995,1025,1080,1099,1194,1433,1434,1521,1723,"
    "2049,2082,2083,2181,2222,2375,2376,3000,3128,3268,3269,3306,3389,4444,4786,5000,5060,5432,"
    "5555,5601,5900,5901,5985,5986,6379,6443,7001,8000,8008,8009,8080,8081,8089,8161,8443,8500,"
    "8888,9000,9090,9100,9200,9300,9418,10000,11211,27017,27018,50000"
)

# gates for the loop-2 checks (named so ruff's magic-number rule stays happy)
PORT_SMB = 445
PORT_LDAP = 389
PORT_LDAPS = 636

# Web-service detection for the external hand-off (aggregate_web_targets). A socket is a web target if its
# port is a known HTTP(S) port OR nerva's banner says http; the scheme is https for the TLS ports / a
# tls|ssl|https banner. Port-based is a heuristic — the nerva banner (when present) refines it.
HTTP_PORTS = frozenset({
    80, 81, 88, 280, 443, 591, 593, 2082, 2083, 3000, 5000, 5601, 5985, 5986, 7001, 7070, 7080,
    8000, 8008, 8080, 8081, 8082, 8083, 8085, 8088, 8089, 8090, 8161, 8180, 8200, 8280, 8443, 8500,
    8834, 8880, 8888, 8983, 9000, 9080, 9090, 9200, 9443, 10000, 15672, 50000,
})
HTTPS_PORTS = frozenset({443, 2083, 5986, 6443, 8443, 9443, 10000, 10443})

# Web hand-off (pipeline composition) — after the low-hanging-fruit sweep, aggregate every web service
# and (opt-in) run the `webscan` pipeline on them as a nested sub-activity. `webscan` is external's web-DEPTH
# loops (crawl/catalog/DAST/fuzz) WITHOUT the scope-expansion + active-network-scan + OSINT stages, so it
# fits an internal engagement (largely egress-free; see the webscan module note on trufflehog). OPT-IN
# regardless because it can spawn a long run per web service. The aggregation artifact (web_targets.txt)
# is ALWAYS written; only the auto-run is gated.
WEB_HANDOFF_ENV = "PIPT_INTERNAL_WEB_HANDOFF"
WEB_SCOPE_FILE = "web_targets.txt"
WEB_HANDOFF_PIPELINE = "webscan"
WEB_RECON_ACTIVITY = "web_recon"

# SNMP default community strings tried by the (UDP) sweep — the classic first-check leak
SNMP_COMMUNITIES = ("public", "private", "community", "manager", "cisco")

# search_vulns query cache (process-wide, so the per-subnet fan-out doesn't re-query the same product)
_CVE_CACHE: dict[tuple[str, str], list[dict]] = {}
_CVE_CACHE_LOCK = threading.Lock()


# --- stdout parsing helpers ----------------------------------------------------------------------
def _lines(text: str) -> list[str]:
    """Non-blank, stripped lines of a tool's stdout."""
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _jsonl(text: str) -> list[dict]:
    """Parse JSONL stdout, skipping unparseable lines (a tool's banner/progress note must not crash
    the stage — mirrors tools.read_jsonl's tolerance for RAW tool output)."""
    out: list[dict] = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


# --- pure transforms (unit-tested) ---------------------------------------------------------------
def scope_entries(text: str) -> list[str]:
    """The raw IP/CIDR scope tokens (kind ip|cidr), in file order, deduped by scope.parse_scope."""
    return [t.raw for t in scope.parse_scope(text) if t.kind in ("ip", "cidr")]


def subnet_slug(entry: str) -> str:
    """Filesystem-safe, human-readable group id for a scope entry: '10.0.1.0/24' → '10.0.1.0-24',
    '192.168.5.10' → '192.168.5.10-32'. Normalised via ip_network so host bits don't leak; ':' in an
    IPv6 network address becomes '_'. Returns '' for an unparseable entry."""
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return ""
    return f"{net.network_address}-{net.prefixlen}".replace(":", "_")


def assign_hosts(entries: list[str], hosts: list[str]) -> dict[str, list[str]]:
    """Partition live host IPs by the scope entry that CONTAINS them, most-specific (longest-prefix)
    wins on overlap; a bare IP is a /32. Returns {subnet_slug: sorted hosts} for entries with ≥1
    host only (no empty groups for dead ranges); hosts outside every entry are dropped. Pure."""
    nets: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
    for e in entries:
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            continue
        if (slug := subnet_slug(e)):
            nets.append((net, slug))
    nets.sort(key=lambda ns: ns[0].prefixlen, reverse=True)  # longest prefix first → first match wins
    groups: dict[str, list[str]] = {}
    for h in hosts:
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            continue
        for net, slug in nets:
            if ip in net:
                groups.setdefault(slug, []).append(h)
                break
    return {slug: sorted(set(hs)) for slug, hs in sorted(groups.items())}


def parse_nmap_up(grepable: str) -> list[str]:
    """Live hosts from `nmap -sn -oG -` output: the IP of each 'Host: <ip> (...)\\tStatus: Up' line."""
    out: list[str] = []
    for line in grepable.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            parts = line.split()
            if len(parts) >= 2:  # noqa: PLR2004 — "Host:" + the address token
                out.append(parts[1])
    return tools.dedupe(out)


def parse_naabu(lines: list[str]) -> list[dict]:
    """naabu '-silent' ip:port lines → [{ip, port}] (port int). Skips malformed lines. Pure."""
    out: list[dict] = []
    for ln in lines:
        ip, _, port = ln.strip().rpartition(":")
        if ip and port.isdigit():
            out.append({"ip": ip, "port": int(port)})
    return out


def web_targets_from(ports: list[dict], services: list[dict]) -> list[str]:
    """Aggregate open sockets into web-service URLs 'scheme://ip:port' (pure, deterministic). A socket
    is a web target if its port is a known HTTP(S) port OR the nerva banner says http; scheme is https
    for a TLS port or a tls|ssl|https banner. Deduped + sorted."""
    banner_by_sock: dict[tuple[str, int], str] = {}
    for r in services:
        ip = str(r.get("ip") or r.get("host") or "")
        port = r.get("port")
        if not ip or not isinstance(port, int):
            continue
        meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
        info = " ".join(str(r.get(k) or "") for k in ("service", "name", "transport")).lower()
        banner_by_sock[ip, port] = f"{info} {str((meta or {}).get('banner') or '').lower()}"
    urls: set[str] = set()
    for r in ports:
        ip = str(r.get("ip") or "")
        port = r.get("port")
        if not ip or not isinstance(port, int):
            continue
        info = banner_by_sock.get((ip, port), "")
        if not (port in HTTP_PORTS or "http" in info):
            continue
        https = port in HTTPS_PORTS or any(t in info for t in ("https", "ssl", "tls"))
        urls.add(f"{'https' if https else 'http'}://{ip}:{port}")
    return sorted(urls)


def software_from_services(records: list[dict]) -> list[dict]:
    """Best-effort (product, version) leads from service records → [{product, version, hosts}].
    Uses an explicit product+version when nerva provides them, else a conservative banner regex
    (a token immediately followed by a dotted version). Version-pinned only. Pure."""
    banner_re = re.compile(r"([A-Za-z][A-Za-z0-9.+_-]*?)[ /]v?(\d+\.\d[\w.]*)")
    by_pv: dict[tuple[str, str], set[str]] = {}
    for r in records:
        host = str(r.get("host") or r.get("ip") or "")
        where = f"{host}:{r.get('port')}" if host else ""
        product, version = r.get("product"), r.get("version")
        if not (product and version):
            meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
            banner = str((meta or {}).get("banner") or r.get("banner") or "")
            if (m := banner_re.search(banner)):
                product, version = m.group(1), m.group(2)
        if product and version:
            by_pv.setdefault((str(product).lower(), str(version)), set()).add(where)
    return [{"product": p, "version": v, "hosts": sorted(w for w in hs if w)}
            for (p, v), hs in sorted(by_pv.items())]


def parse_search_vulns(out: str, product: str, version: str) -> list[dict]:
    """Parse `search_vulns -f json` for one query into CVE records ([] on no-match/no-vuln). Pure."""
    try:
        data = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict) or not data:
        return []
    entry = next(iter(data.values()))
    if not isinstance(entry, dict):
        return []
    vulns = entry.get("vulns")
    if not isinstance(vulns, dict):
        return []
    recs: list[dict] = []
    for cve_id, v in vulns.items():
        if not isinstance(v, dict):
            continue
        sev = v.get("severity")
        sev = sev if isinstance(sev, dict) else {}
        cvss = sev.get("CVSS")
        cvss = cvss if isinstance(cvss, dict) else {}
        exploits = v.get("exploits") or []
        kev = bool(v.get("cisa_kev"))
        desc = v.get("description")
        recs.append({
            "cve": cve_id, "product": product, "version": version,
            "cvss": cvss.get("score"), "kev": kev, "exploited": bool(exploits) or kev,
            "cwe": v.get("cwe_ids") or [],
            "description": (desc if isinstance(desc, str) else "")[:_CVE_DESC_MAX],
        })
    return recs


_SNMP_HIT = re.compile(r"^(\S+)\s+\[([^\]]+)\]\s*(.*)$")


def parse_onesixtyone(out: str) -> list[dict]:
    """onesixtyone output → SNMP default-community findings. A genuine hit is 'ip [community] sysDescr'
    — the '[community]' bracket is required, so error/progress lines never become findings. Pure."""
    findings: list[dict] = []
    for raw in out.splitlines():
        line = raw.strip()
        if (m := _SNMP_HIT.match(line)):
            findings.append({"type": "snmp-default-community", "severity": "medium",
                             "host": m.group(1), "community": m.group(2), "evidence": line})
    return findings


# netexec smb lines are "SMB  <ip>  <port>  <name>  <message>"; the message carries the signal.
_NXC_SMB_LINE = re.compile(r"^SMB\s+(\S+)\s+\d+\s+\S+\s+(.*)$")
_NXC_SIGNING = re.compile(r"signing:(True|False)", re.IGNORECASE)
_NXC_SMBV1 = re.compile(r"SMBv1:(True|False)", re.IGNORECASE)


def parse_nxc_smb(out: str) -> list[dict]:
    """netexec smb output → SMB first-check findings (pure). Per host line:
    - the '[*]' host banner → 'signing:False' (NTLM-relay surface) and 'SMBv1:True' (EternalBlue
      surface) become medium findings;
    - a '[+]' auth-success line → admin access ('Pwn3d!', high) or a valid/null/guest session (medium).
    '[-]' failures and non-SMB lines are ignored."""
    findings: list[dict] = []
    for raw in out.splitlines():
        m = _NXC_SMB_LINE.match(raw.strip())
        if not m:
            continue
        host, rest = m.group(1), m.group(2).strip()
        if rest.startswith("[*]"):
            sig = _NXC_SIGNING.search(rest)
            if sig and sig.group(1).lower() == "false":
                findings.append({"type": "smb-signing-not-required", "severity": "medium",
                                 "host": host, "evidence": rest})
            v1 = _NXC_SMBV1.search(rest)
            if v1 and v1.group(1).lower() == "true":
                findings.append({"type": "smbv1-enabled", "severity": "medium",
                                 "host": host, "evidence": rest})
        elif rest.startswith("[+]"):
            admin = "Pwn3d!" in rest
            findings.append({"type": "smb-admin-access" if admin else "smb-valid-auth",
                             "severity": "high" if admin else "medium",
                             "host": host, "evidence": rest})
    return findings


# --- breadth stages (activity scope) -------------------------------------------------------------
def _raw(activity: Activity, tool: str, label: str) -> Path:
    return activity.asset_discovery_raw(tool) / f"{label}.txt"


def expand(activity: Activity) -> None:
    """BREADTH — expand the IP/CIDR scope into a candidate host list (mapcidr) → scope/scope_ip.txt."""
    entries = scope_entries(activity.scope_init.read_text(encoding="utf-8", errors="replace"))
    ips = entries
    if entries and shutil.which(MAPCIDR):
        out = _run([MAPCIDR, "-silent"], stdin="\n".join(entries),
                   dest=_raw(activity, "mapcidr", "expand"), label="expand")
        ips = _lines(out) or entries
    tools.write_lines(activity.scope_ip, ips)
    log.info("  → expand — %d scope entr(ies) → %d candidate host(s)", len(entries), len(ips))


def discover(activity: Activity) -> None:
    """BREADTH — nmap -sn ping sweep to find LIVE hosts → asset_discovery/live_hosts.txt.
    Falls back to the full candidate list if nmap is absent or the sweep yields nothing (so a
    filtered-ICMP environment still gets scanned by portscan)."""
    canon = activity.asset_discovery_canonical
    candidates = tools.read_lines(activity.scope_ip)
    live: list[str] = []
    if candidates and shutil.which(NMAP):
        out = _run([NMAP, "-sn", "-n", "-oG", "-", "-iL", "-"], stdin="\n".join(candidates),
                   dest=_raw(activity, "nmap", "discover"), label="discover")
        live = parse_nmap_up(out)
    if not live:
        log.info("  → discover — no live-host signal (nmap absent/filtered) — using all candidates")
        live = candidates
    tools.write_lines(canon("live_hosts.txt"), live)
    log.info("  → discover — %d live host(s)", len(live))


def portscan(activity: Activity) -> None:
    """BREADTH — fast naabu scan of the curated internal port set over the live hosts →
    asset_discovery/ports.jsonl ({ip, port}). Whole-scope + rate-controlled; cluster() slices it
    per subnet afterwards."""
    canon = activity.asset_discovery_canonical
    live = tools.read_lines(canon("live_hosts.txt"))
    records: list[dict] = []
    if live and shutil.which(NAABU):
        out = _run([NAABU, "-silent", "-p", INTERNAL_PORTS, "-c", NAABU_CONC, "-rate", NAABU_RATE],
                   stdin="\n".join(live), dest=_raw(activity, "naabu", "ports"), label="ports")
        records = parse_naabu(_lines(out))
    tools.write_jsonl(canon("ports.jsonl"), records)
    log.info("  → portscan — %d open (ip,port) across %d host(s)",
             len(records), len({r["ip"] for r in records}))


# --- cluster (fan-out pivot) — partition live hosts by scope subnet ------------------------------
def cluster(activity: Activity) -> list[str]:
    """Group live hosts by the scope entry that contains them → scans/<subnet_slug>/. Writes each
    group's meta.json (id + cidr + hosts), hosts.txt, and its slice of the open-port records
    (ports.jsonl). Returns the sorted subnet slugs. Deterministic (assign_hosts is pure)."""
    canon = activity.asset_discovery_canonical
    entries = scope_entries(activity.scope_init.read_text(encoding="utf-8", errors="replace"))
    live = tools.read_lines(canon("live_hosts.txt"))
    ports = tools.read_jsonl(canon("ports.jsonl"))
    groups = assign_hosts(entries, live)
    # map each entry's slug back to the original CIDR string, for meta.json provenance
    slug_to_cidr = {subnet_slug(e): e for e in entries if subnet_slug(e)}
    for slug, hosts in groups.items():
        ws = activity.app(slug).ensure()
        hostset = set(hosts)
        workspace.write_meta(ws.meta, {"app_id": slug, "cidr": slug_to_cidr.get(slug, slug),
                                       "hosts": hosts})
        tools.write_lines(ws.hosts, hosts)
        tools.write_jsonl(ws.canonical("ports.jsonl"),
                          [r for r in ports if str(r.get("ip")) in hostset])
    log.info("  → cluster — %d subnet group(s): %s", len(groups), ", ".join(sorted(groups)) or "none")
    return sorted(groups)


# --- loop helpers --------------------------------------------------------------------------------
def _hosts_with_port(ws: AppWorkspace, port: int) -> list[str]:
    return sorted({str(r["ip"]) for r in tools.read_jsonl(ws.canonical("ports.jsonl"))
                   if r.get("port") == port and r.get("ip")})


def _host_ports(ws: AppWorkspace) -> list[str]:
    """The group's open sockets as 'ip:port' lines (fingerprint / nuclei input)."""
    return [f"{r['ip']}:{r['port']}" for r in tools.read_jsonl(ws.canonical("ports.jsonl"))
            if r.get("ip") and r.get("port")]


def _run(cmd: list[str], *, stdin: str, dest: Path, label: str) -> str:
    """Run a tool over stdin, persist its stdout to `dest` exactly once, return stdout. No-op on
    empty input. Best-effort: a spawn/timeout error degrades to '' (never aborts the stage)."""
    if not stdin.strip():
        log.debug("  · skip %s (no input)", label)
        return ""
    try:
        out = tools.run(cmd, stdin=stdin, stream_stderr=is_verbose())
    except (OSError, subprocess.SubprocessError, tools.AbortedError) as exc:
        log.debug("  · %s failed: %s", label, exc)
        return ""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(out, encoding="utf-8")
    return out


def _capture(cmd: list[str], *, dest: Path, label: str) -> str:
    """Best-effort arg-based tool run with a wall-clock cap → stdout ('' on any error/timeout),
    persisted to `dest` (raw provenance). For the bounded loop-2 checks."""
    try:
        out = tools.run(cmd, stream_stderr=is_verbose(), timeout=CHECK_TIMEOUT)
    except (OSError, subprocess.SubprocessError, tools.AbortedError) as exc:
        log.debug("  · %s failed: %s", label, exc)
        return ""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(out, encoding="utf-8")
    return out


# --- loop 1: service inventory -------------------------------------------------------------------
def fingerprint(activity: Activity, app_id: str) -> None:
    """LOOP 1 — service fingerprint of the group's open sockets (nerva --json; nmap -sV is the
    drop-in alternative) → scans/<subnet>/services.jsonl. Best-effort."""
    ws = activity.app(app_id)
    sockets = _host_ports(ws)
    records: list[dict] = []
    if sockets and shutil.which(NERVA):
        out = _run([NERVA, "--json"], stdin="\n".join(sockets),
                   dest=ws.raw("nerva") / "fingerprint.jsonl", label="fingerprint")
        records = _jsonl(out)
    tools.write_jsonl(ws.canonical("services.jsonl"), records)
    log.info("  → fingerprint [%s] — %d service(s)", app_id, len(records))


# --- loop 2: low-hanging fruit -------------------------------------------------------------------
def _cve_sort_key(f: dict) -> tuple:
    """Triage order: known-exploited first, then CVSS desc, then CVE id. Pure; cvss-coercion safe."""
    try:
        cvss = float(f.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    return (not f.get("exploited"), -cvss, f.get("cve") or "")


def _query_cve(product: str, version: str) -> list[dict]:
    """search_vulns for the exact (product, version), memoised process-wide. Offline; [] on error."""
    key = (product.lower(), version)
    with _CVE_CACHE_LOCK:
        if key in _CVE_CACHE:
            return _CVE_CACHE[key]
    result: list[dict] = []
    try:
        out = tools.run([SEARCH_VULNS, "-q", f"{product} {version}", "-f", "json",
                         "--ignore-general-product-vulns", "--use-created-product-ids"],
                        timeout=CVE_TOOL_TIMEOUT)
        result = parse_search_vulns(out, product, version)
    except (OSError, subprocess.SubprocessError):
        pass
    with _CVE_CACHE_LOCK:
        _CVE_CACHE[key] = result
    return result


def cve_lookup(activity: Activity, app_id: str) -> None:
    """LOOP 2 — known-CVE correlation of the fingerprinted software against search_vulns' LOCAL DB.
    OFFLINE (net=False, no target traffic). Best-effort: skips if search_vulns/its DB is absent."""
    ws = activity.app(app_id)
    if shutil.which(SEARCH_VULNS) is None:
        log.debug("  · skip cve_lookup [%s] (search_vulns absent)", app_id)
        return
    software = software_from_services(tools.read_jsonl(ws.canonical("services.jsonl")))
    findings: list[dict] = []
    for sw in software:
        findings += [{**cve, "hosts": sw["hosts"]} for cve in _query_cve(sw["product"], sw["version"])]
    findings.sort(key=_cve_sort_key)
    tools.write_jsonl(ws.findings / "cve.jsonl", findings)
    log.info("  → cve_lookup [%s] — %d software → %d CVE(s)", app_id, len(software), len(findings))


def smb_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — SMB first-checks via netexec on hosts with 445 open: signing not required, guest /
    null-session access. Best-effort → findings/smb.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_SMB)
    if not hosts or shutil.which(NXC) is None:
        log.debug("  · skip smb_checks [%s] (no 445 / netexec absent)", app_id)
        return
    out = _capture([NXC, "smb", *hosts, "-u", "", "-p", ""],
                   dest=ws.raw("netexec") / "smb.txt", label="smb")
    findings = parse_nxc_smb(out)
    tools.write_jsonl(ws.findings / "smb.jsonl", findings)
    log.info("  → smb_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def snmp_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — SNMP default-community sweep (UDP/161) via onesixtyone over ALL group hosts (161 is
    UDP so it's not in the TCP portscan). A responding community is a finding. Best-effort."""
    ws = activity.app(app_id)
    hosts = tools.read_lines(ws.hosts)
    if not hosts or shutil.which(ONESIXTYONE) is None:
        log.debug("  · skip snmp_checks [%s] (no hosts / onesixtyone absent)", app_id)
        return
    comm_file = ws.raw("onesixtyone") / "communities.txt"  # onesixtyone -c wants a FILE of communities
    host_file = ws.raw("onesixtyone") / "hosts.txt"
    tools.write_lines(comm_file, SNMP_COMMUNITIES)
    tools.write_lines(host_file, hosts)
    out = _capture([ONESIXTYONE, "-c", str(comm_file), "-i", str(host_file)],
                   dest=ws.raw("onesixtyone") / "snmp.txt", label="snmp")
    findings = parse_onesixtyone(out)
    tools.write_jsonl(ws.findings / "snmp.jsonl", findings)
    log.info("  → snmp_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def ldap_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — LDAP anonymous-bind check via ldapsearch on hosts with 389/636 open. A rootDSE that
    returns naming contexts anonymously is a finding. Best-effort → findings/ldap.jsonl."""
    ws = activity.app(app_id)
    hosts = sorted(set(_hosts_with_port(ws, PORT_LDAP)) | set(_hosts_with_port(ws, PORT_LDAPS)))
    if not hosts or shutil.which(LDAPSEARCH) is None:
        log.debug("  · skip ldap_checks [%s] (no 389/636 / ldapsearch absent)", app_id)
        return
    findings: list[dict] = []
    for host in hosts:
        out = _capture([LDAPSEARCH, "-x", "-H", f"ldap://{host}", "-s", "base", "-b", "",
                        "namingContexts"], dest=ws.raw("ldapsearch") / f"{host}.txt", label="ldap")
        if "namingContexts:" in out:
            findings.append({"type": "ldap-anonymous-bind", "severity": "medium", "host": host,
                             "evidence": next((ln.strip() for ln in out.splitlines()
                                               if ln.startswith("namingContexts:")), "")})
    tools.write_jsonl(ws.findings / "ldap.jsonl", findings)
    log.info("  → ldap_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def nuclei_net(activity: Activity, app_id: str) -> None:
    """LOOP 2 — nuclei network/default-login templates over the group's open sockets → findings/
    nuclei_net.jsonl. Best-effort (skips if nuclei absent)."""
    ws = activity.app(app_id)
    sockets = _host_ports(ws)
    if not sockets or shutil.which(NUCLEI) is None:
        log.debug("  · skip nuclei_net [%s] (no sockets / nuclei absent)", app_id)
        return
    out = _run([NUCLEI, "-silent", "-duc", "-j", "-tags", "network,default-login"],
               stdin="\n".join(sockets), dest=ws.raw("nuclei") / "net.jsonl", label="nuclei_net")
    findings = _jsonl(out)
    tools.write_jsonl(ws.findings / "nuclei_net.jsonl", findings)
    log.info("  → nuclei_net [%s] — %d finding(s)", app_id, len(findings))


# --- consolidate (terminal fan-in) ---------------------------------------------------------------
_CONSOLIDATE_SOURCES: dict[str, tuple[str, ...]] = {
    "cve.jsonl": ("findings/cve.jsonl",),
    "smb.jsonl": ("findings/smb.jsonl",),
    "snmp.jsonl": ("findings/snmp.jsonl",),
    "ldap.jsonl": ("findings/ldap.jsonl",),
    "nuclei_net.jsonl": ("findings/nuclei_net.jsonl",),
}


def aggregate_web_targets(activity: Activity) -> list[str]:
    """Aggregate every subnet group's web services into <activity>/web_targets.txt (scheme://ip:port),
    the scope artifact the external hand-off consumes. Reads each group's ports.jsonl + services.jsonl.
    Idempotent. Returns the URL list."""
    urls = tools.dedupe(
        u for ws in activity.list_apps()
        for u in web_targets_from(tools.read_jsonl(ws.canonical("ports.jsonl")),
                                  tools.read_jsonl(ws.canonical("services.jsonl"))))
    tools.write_lines(activity.base / WEB_SCOPE_FILE, urls)
    return urls


def consolidate(activity: Activity) -> dict[str, int]:
    """TERMINAL fan-in (deterministic, OFFLINE) — lift every subnet group's per-app findings into
    <activity>/findings/<type>.jsonl, one file per finding TYPE, each record stamped with its app_id
    (the subnet slug). Also aggregates the web services into <activity>/web_targets.txt (the external
    hand-off scope). Empty types write no file. Idempotent: overwrites each run / --resume."""
    apps = activity.list_apps()
    counts: dict[str, int] = {}
    for out_name, sources in _CONSOLIDATE_SOURCES.items():
        records = [{"app_id": ws.root.name, **rec}
                   for ws in apps for src in sources
                   for rec in tools.read_jsonl(ws.root / src)]
        if records:
            counts[out_name.removesuffix(".jsonl")] = tools.write_jsonl(
                activity.findings / out_name, records)
    web = aggregate_web_targets(activity)
    log.info("  → consolidate — %s · %d web service(s) → %s",
             ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no per-subnet findings",
             len(web), WEB_SCOPE_FILE)
    return counts


def followups(activity: Activity) -> list[Followup]:
    """Pipeline composition — after the low-hanging-fruit sweep, hand the aggregated web services to the
    `webscan` pipeline as a nested sub-activity (<activity>/web_recon/). OPT-IN via PIPT_INTERNAL_WEB_
    HANDOFF (a full web-depth scan per service is long — see WEB_HANDOFF_ENV note). No-op (→ []) when the
    flag is off or no web service was found. Read via getattr by the CLI, like consolidate/preflight."""
    if os.environ.get(WEB_HANDOFF_ENV, "").lower().strip() not in {"1", "on", "true", "yes"}:
        return []
    scope_file = activity.base / WEB_SCOPE_FILE
    targets = tools.read_lines(scope_file)
    if not targets:
        log.info("  · web hand-off enabled but no web service found — skipping")
        return []
    log.info("  → web hand-off: %s on %d web service(s) → %s/", WEB_HANDOFF_PIPELINE, len(targets),
             WEB_RECON_ACTIVITY)
    return [Followup(pipeline=WEB_HANDOFF_PIPELINE, activity=WEB_RECON_ACTIVITY, scope=str(scope_file))]


def preflight() -> None:
    """Log which external tools resolve at run start (best-effort — never aborts). A missing CORE
    tool means its breadth stage produces nothing; a missing OPTIONAL tool skips its loop-2 check."""
    core_missing = sorted(n for n, cmd in _CORE_TOOLS.items() if shutil.which(cmd) is None)
    opt_missing = sorted(n for n, cmd in _OPTIONAL_TOOLS.items() if shutil.which(cmd) is None)
    log.info("  → preflight: core %d/%d · optional %d/%d",
             len(_CORE_TOOLS) - len(core_missing), len(_CORE_TOOLS),
             len(_OPTIONAL_TOOLS) - len(opt_missing), len(_OPTIONAL_TOOLS))
    if core_missing:
        log.warning("  ⚠ preflight: missing CORE tool(s) — those stages produce nothing: %s",
                    ", ".join(core_missing))
    if opt_missing:
        log.info("    optional tools absent (their checks skip): %s", ", ".join(opt_missing))
