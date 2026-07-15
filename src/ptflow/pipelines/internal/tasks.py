"""Internal-network pentest pipeline tasks.

Scope is IP/CIDR only. The flow mirrors the ptflow breadth → cluster → per-app-loop grammar, but
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

  portscan_full  — SPANNING (whole-scope): full 65535-port naabu → asset_discovery/ports_full.jsonl.
  nuclei_scope   — SPANNING (whole-scope): full-template nuclei over every discovered socket (FULL-port
                   set), ONE rate-controlled process ∥ the loops → <activity>/findings/nuclei_scope.jsonl.
  fingerprint_full — SPANNING (whole-scope): nerva over the FULL-port DELTA (sockets beyond the fast
                   set) → asset_discovery/services_full.jsonl (banners for non-standard-port services).
  cve_lookup_full — SPANNING (whole-scope, OFFLINE): search_vulns over the full-port delta software →
                   <activity>/findings/cve_full.jsonl (activity-level, like nuclei_scope).

  LOOP 2 — low-hanging fruit + enumeration (per-subnet, gated on the ports found in the breadth scan;
           all ∥, best-effort, NON-destructive — no credentialed/brute-force checks, those are future)
    cve_lookup     — search_vulns over the service banners (OFFLINE)   → findings/cve.jsonl
    smb_checks     — netexec: signing/null-session/guest + share enum + metadata spider → findings/smb.jsonl
    ad_enum        — netexec null-session RID cycling + password policy → findings/ad_enum.jsonl
    adcs_checks    — netexec enum_ca: anonymous CA discovery + ESC8      → findings/adcs.jsonl
    kerberoast_asrep — nxc ldap --asreproast (no-cred, needs ad_enum's userlist) → findings/asrep.jsonl
    datastore_checks — nmap NSE: unauth Redis/MongoDB/Memcached + MSSQL exposure → findings/datastore.jsonl
    snmp_checks    — onesixtyone default community + snmpwalk loot      → findings/snmp.jsonl
    ldap_checks    — nxc ldap signing/channel-binding + ldapsearch anon bind/account dump → findings/ldap.jsonl
    ftp_checks     — netexec: anonymous FTP login                      → findings/ftp.jsonl
    telnet_checks  — nmap -sV: exposed cleartext telnet + banner       → findings/telnet.jsonl
    nfs_checks     — showmount -e: anonymously-readable NFS exports    → findings/nfs.jsonl
    rsync_checks   — rsync ://host/: anonymous rsync modules           → findings/rsync.jsonl
    netbios_checks — nmap nbstat (137/UDP): hostname/user/MAC          → findings/netbios.jsonl
    dns_checks     — dig axfr: reverse-zone transfer (subnet PTR map)  → findings/dns.jsonl
    remote_desktop — scrying: RDP/VNC screenshots of exposed services  → findings/remote_desktop.jsonl
                     (+ scans/<subnet>/screenshots/*.png)

  consolidate — lift the per-subnet findings/<type>.jsonl to the activity level, one file per type.
                (nuclei_scope is already an activity-level finding and is left untouched.)

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

from ptflow.core import scope, tools, workspace
from ptflow.core.log import get_logger, is_verbose
from ptflow.core.requirements import Requirement, check
from ptflow.core.stage import Followup

if TYPE_CHECKING:
    from pathlib import Path

    from ptflow.core.paths import Activity, AppWorkspace

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
MAPCIDR = _resolve("PTFLOW_MAPCIDR", f"{_HOME}/go/bin/mapcidr", "mapcidr")
NAABU = _resolve("PTFLOW_NAABU", f"{_HOME}/go/bin/naabu", "naabu")
NMAP = _resolve("PTFLOW_NMAP", "nmap")
NERVA = _resolve("PTFLOW_NERVA", f"{_HOME}/go/bin/nerva", "nerva")
NUCLEI = _resolve("PTFLOW_NUCLEI", f"{_HOME}/go/bin/nuclei", "nuclei")
NXC = _resolve("PTFLOW_NETEXEC", f"{_HOME}/.local/bin/nxc", "nxc")
SEARCH_VULNS = _resolve("PTFLOW_SEARCH_VULNS", f"{_HOME}/.local/bin/search_vulns", "search_vulns")
ONESIXTYONE = _resolve("PTFLOW_ONESIXTYONE", "onesixtyone")
LDAPSEARCH = _resolve("PTFLOW_LDAPSEARCH", "ldapsearch")
SCRYING = _resolve("PTFLOW_SCRYING", "scrying")                          # RDP/VNC screenshotter
RSYNC = _resolve("PTFLOW_RSYNC", "rsync")
SHOWMOUNT = _resolve("PTFLOW_SHOWMOUNT", "/usr/sbin/showmount", "showmount")  # nfs-utils (often /usr/sbin)
SNMPWALK = _resolve("PTFLOW_SNMPWALK", "snmpwalk")                       # net-snmp (post-hit walk)
DIG = _resolve("PTFLOW_DIG", "dig")                                       # DNS zone-transfer (AXFR)

_CORE_TOOLS = {"mapcidr": MAPCIDR, "naabu": NAABU, "nmap": NMAP, "nerva": NERVA}
_OPTIONAL_TOOLS = {"nuclei": NUCLEI, "netexec": NXC, "search_vulns": SEARCH_VULNS,
                   "onesixtyone": ONESIXTYONE, "ldapsearch": LDAPSEARCH,
                   "scrying": SCRYING, "rsync": RSYNC, "showmount": SHOWMOUNT, "snmpwalk": SNMPWALK,
                   "dig": DIG}

# --- tunables (rates conservative for live internal infra — legacy/OT gear is fragile) -----------
# Aggregate load ~= concurrency x rate; a full connect-scan flood can knock over old devices and
# saturate a switch, so one global rate-controlled sweep (breadth) beats N per-subnet floods.
_HOME_NAABU = ("300", "20")   # (rate pkts/s, concurrency) — gentle for a domestic/constrained line
_WIDE_NAABU = ("1000", "50")  # real bandwidth
_IS_HOME = os.environ.get("PTFLOW_PROFILE", "").lower().strip() == "home"
NAABU_RATE, NAABU_CONC = _HOME_NAABU if _IS_HOME else _WIDE_NAABU
NUCLEI_RL = "50" if _IS_HOME else "150"   # whole-scope nuclei -rl (req/s, global) — profile-driven,
                                          # same lever as external: gentler on fragile internal gear

CHECK_TIMEOUT = 300   # per-invocation wall-clock cap (s) for the bounded loop-2 checks (a slow host
                      # must not hang the per-subnet chain; the long breadth scans stay timeout-free)
SCRYING_TIMEOUT = 600  # one scrying run screenshots all a subnet's RDP/VNC sockets — give it headroom
CVE_TOOL_TIMEOUT = 90
_CVE_DESC_MAX = 300

# --- loot tunables (point 4 — turn a fase-2 hit into read-only loot; all bounded/non-destructive) ---
LDAP_MAX_ENTRIES = "500"   # ldapsearch -z size cap for the anonymous account dump
# curated high-value OIDs for the post-hit SNMP walk: system · running processes · ARP table
SNMP_WALK_OIDS = ("1.3.6.1.2.1.1", "1.3.6.1.2.1.25.4.2.1.2", "1.3.6.1.2.1.4.22.1.2")
# SMB share hygiene: null-session noise never becomes a finding; default/admin shares are never spidered.
_SMB_NOISE_SHARES = frozenset({"IPC$", "PRINT$"})
_SMB_SKIP_SPIDER = frozenset({"IPC$", "PRINT$", "ADMIN$", "C$"})
# interesting-filename patterns for the SMB spider (metadata only — no content download)
_SMB_INTERESTING = re.compile(
    r"(?i)(pass|secret|cred|backup|\.bak|\.kdbx|\.key|\.pem|id_rsa|\.ppk|\.config|unattend|\.ovpn|"
    r"\.sql|shadow|\.vmdk|\.ps1|\.ini)")

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
PORT_FTP = 21
PORT_TELNET = 23
PORT_DNS = 53
PORT_NFS = 2049
PORT_RSYNC = 873
PORT_NETBIOS = 137
PORT_RDP = 3389
PORT_KERBEROS = 88                                # KDC — a host with 88 open is a domain controller
VNC_PORTS = frozenset(range(5900, 5907))          # VNC displays :0-:6 (5900-5906)
_RD_PORTS = frozenset({PORT_RDP}) | VNC_PORTS     # remote-desktop sockets scrying screenshots

# unauthenticated-datastore ports (datastore_checks) — all already in the fast INTERNAL_PORTS set, so
# the per-subnet loop gates on them directly. Elasticsearch (9200/9300) is HTTP → left to the web
# hand-off + nuclei_scope, not here.
PORT_REDIS = 6379
PORT_MEMCACHED = 11211
PORT_MSSQL = 1433
MONGODB_PORTS = frozenset({27017, 27018})
DATASTORE_PORTS = frozenset({PORT_REDIS, PORT_MEMCACHED, PORT_MSSQL}) | MONGODB_PORTS

# Web-service detection for the external hand-off (aggregate_web_targets). A socket is a web target if its
# port is a known HTTP(S) port OR nerva's banner says http; the scheme is https for the TLS ports / a
# tls|ssl|https banner. Port-based is a heuristic — the nerva banner (when present) refines it.
HTTP_PORTS = frozenset({
    # 88 (Kerberos) deliberately EXCLUDED — every DC has it open, and it's not HTTP; promoting it would
    # send the webscan hand-off crawling/DAST-ing the KDC. Only a real 'http' nerva banner promotes it.
    80, 81, 280, 443, 591, 593, 2082, 2083, 3000, 5000, 5601, 5985, 5986, 7001, 7070, 7080,
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
WEB_HANDOFF_ENV = "PTFLOW_INTERNAL_WEB_HANDOFF"
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


def delta_sockets(full: list[dict], fast: list[dict]) -> list[str]:
    """Sockets in the FULL-port scan but NOT in the fast curated set, as sorted 'ip:port' lines (pure).
    The fast set is already fingerprinted per-subnet (loop 1), so fingerprint_full covers only this
    delta — services on non-standard ports. Malformed records (missing ip / non-int port) are dropped."""
    def socks(records: list[dict]) -> set[tuple[str, int]]:
        return {(str(r["ip"]), int(r["port"])) for r in records
                if r.get("ip") and isinstance(r.get("port"), int)}
    return [f"{ip}:{port}" for ip, port in sorted(socks(full) - socks(fast))]


# Curated banner → (product, version) patterns for the non-HTTP services nerva fingerprints on the
# internal network. Tried BEFORE the generic 'token<sep>version' regex: service banners use an '_'
# separator the generic pattern can't anchor — on 'SSH-2.0-OpenSSH_8.9p1' the generic regex matches
# nothing (no space/slash) → every SSH CVE lost, and naively adding '_' would grab the whole
# 'SSH-2.0-OpenSSH' prefix as the product. Anchored per-product patterns avoid both. Precision-first,
# version-pinned (≥ X.Y). Mirrors external's _BANNER_PATTERNS deliberately (internal stays decoupled).
_BANNER_PRODUCTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"OpenSSH[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"vsFTPd[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"ProFTPD[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "ProFTPD"),
    (re.compile(r"Exim[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "Exim"),
    (re.compile(r"Sendmail[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "Sendmail"),
    (re.compile(r"MariaDB[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "MariaDB"),
    (re.compile(r"MySQL[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "MySQL"),
    (re.compile(r"PostgreSQL[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"Redis(?:[_/ -]?server)?[_/ -]?v?(\d+\.\d[\w.]*)", re.IGNORECASE), "Redis"),
)
_BANNER_GENERIC_RE = re.compile(r"([A-Za-z][A-Za-z0-9.+_-]*?)[ /]v?(\d+\.\d[\w.]*)")


def _banner_product(banner: str) -> tuple[str | None, str | None]:
    """(product, version) from a non-HTTP service banner: curated patterns first (they anchor the
    '_'-separated forms like 'OpenSSH_8.9p1' the generic regex can't), else a generic 'token<space|/>
    version' fallback (e.g. 'Apache/2.4.49'). (None, None) if no version. Pure, precision-first."""
    for rx, product in _BANNER_PRODUCTS:
        if (m := rx.search(banner)):
            return product, m.group(1)
    if (m := _BANNER_GENERIC_RE.search(banner)):
        return m.group(1), m.group(2)
    return None, None


def software_from_services(records: list[dict]) -> list[dict]:
    """Best-effort (product, version) leads from service records → [{product, version, hosts}].
    Uses an explicit product+version when nerva provides them, else a banner match (_banner_product:
    curated non-HTTP patterns first, then a generic 'token version' regex). Version-pinned only. Pure."""
    by_pv: dict[tuple[str, str], set[str]] = {}
    for r in records:
        host = str(r.get("host") or r.get("ip") or "")
        where = f"{host}:{r.get('port')}" if host else ""
        product, version = r.get("product"), r.get("version")
        if not (product and version):
            meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
            banner = str((meta or {}).get("banner") or r.get("banner") or "")
            product, version = _banner_product(banner)
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


# netexec ftp lines are "FTP  <ip>  21  <host>  <message>"; a '[+]' message = anon login succeeded.
_NXC_FTP_LINE = re.compile(r"^FTP\s+(\S+)\s+\d+\s+\S+\s+(.*)$")


def parse_nxc_ftp(out: str) -> list[dict]:
    """netexec ftp output → anonymous-FTP findings (pure). We only try `-u anonymous -p ''`, so a
    '[+]' line on an FTP host means the anonymous login succeeded → one 'ftp-anonymous' finding per
    host. '[-]' failures and '[*]' banner lines are ignored."""
    findings: list[dict] = []
    for raw in out.splitlines():
        m = _NXC_FTP_LINE.match(raw.strip())
        if m and m.group(2).strip().startswith("[+]"):
            findings.append({"type": "ftp-anonymous", "severity": "medium",
                             "host": m.group(1), "evidence": m.group(2).strip()})
    return findings


def parse_showmount(out: str, host: str) -> list[dict]:
    """showmount -e output → NFS export findings (pure). A real export line is '<path> <clients>' (the
    path starts with '/'); the 'Export list for …' header and 'clnt_create: RPC …' error lines are
    skipped. A world-readable export (clients '*'/'0.0.0.0', or none shown) is HIGH, a scoped one MEDIUM."""
    findings: list[dict] = []
    for raw in out.splitlines():
        line = raw.strip()
        if not line.startswith("/"):
            continue
        path, _, clients = line.partition(" ")
        clients = clients.strip()
        world = not clients or "*" in clients or "0.0.0.0/0" in clients
        findings.append({"type": "nfs-export", "severity": "high" if world else "medium",
                         "host": host, "export": path, "clients": clients or "*", "evidence": line})
    return findings


def parse_rsync_modules(out: str, host: str) -> list[dict]:
    """`rsync rsync://host/` module listing → anonymous rsync-module findings (pure). Each line is
    '<module><whitespace><comment>'; '@ERROR'/'rsync: …' status lines are skipped. Anonymously
    listable modules frequently expose a filesystem tree to unauthenticated readers."""
    findings: list[dict] = []
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.startswith("@") or line.lower().startswith("rsync"):
            continue
        parts = line.split(None, 1)
        module = parts[0]
        findings.append({"type": "rsync-module", "severity": "medium", "host": host,
                         "module": module, "comment": parts[1].strip() if len(parts) > 1 else "",
                         "evidence": line})
    return findings


def parse_telnet(grepable: str) -> list[dict]:
    """nmap '-sV -p23 -oG -' output → telnet-exposed findings (pure). A Host line whose Ports field
    carries '23/open/tcp' is exposed cleartext telnet — a finding on its own (credentials travel in
    the clear); the version token from the grepable field (`23/open/tcp//telnet//<banner>/`) is kept
    as evidence."""
    findings: list[dict] = []
    for line in grepable.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        ip = line.split()[1]
        for entry in line.split("Ports:", 1)[1].split(","):
            fields = entry.strip().split("/")
            if len(fields) >= 7 and fields[0] == str(PORT_TELNET) and fields[1] == "open":  # noqa: PLR2004
                banner = fields[6] or fields[4] or "telnet"
                findings.append({"type": "telnet-exposed", "severity": "medium",
                                 "host": ip, "evidence": f"telnet open — {banner}"})
    return findings


_SCRYING_PNG = re.compile(r"^(?P<host>.+)-(?P<port>\d+)\.png$")
_RD_SEVERITY = {"vnc": "high", "rdp": "info"}   # a captured VNC desktop ⇒ reachable; RDP login = recon


def parse_scrying(pngs: list[Path]) -> list[dict]:
    """scrying's captured PNGs → RDP/VNC screenshot findings (pure). Each png lives under
    <out>/<proto>/<host>-<port>.png; only rdp/vnc are kept (web is screenshotted elsewhere). A captured
    VNC framebuffer usually means the desktop is reachable without auth (HIGH); an RDP login screen is a
    recon/exposure artifact (info). `screenshot` is the source png path — the stage re-homes it."""
    findings: list[dict] = []
    for png in pngs:
        proto = png.parent.name
        m = _SCRYING_PNG.match(png.name)
        if proto not in _RD_SEVERITY or not m:
            continue
        findings.append({"type": f"{proto}-screenshot", "severity": _RD_SEVERITY[proto],
                         "host": m.group("host"), "port": int(m.group("port")),
                         "protocol": proto, "screenshot": str(png)})
    return findings


def parse_nxc_shares(out: str) -> list[dict]:
    """netexec `--shares` output → SMB share-access findings (pure). Share rows are
    'SMB <ip> <port> <host> <share> <perms> [remark]'; the perms column carries READ / WRITE /
    READ,WRITE. A WRITE share is HIGH, READ MEDIUM; null-session noise (IPC$/PRINT$), shares with no
    access, and the banner/header rows are skipped."""
    findings: list[dict] = []
    for raw in out.splitlines():
        m = _NXC_SMB_LINE.match(raw.strip())
        if not m:
            continue
        host, rest = m.group(1), m.group(2).strip()
        if not rest or rest.startswith(("[", "Share", "---")):
            continue
        parts = rest.split()
        share = parts[0]
        perm = parts[1].upper() if len(parts) > 1 else ""
        writable, readable = "WRITE" in perm, "READ" in perm
        if share.upper() in _SMB_NOISE_SHARES or not (readable or writable):
            continue
        findings.append({"type": "smb-share-writable" if writable else "smb-share-readable",
                         "severity": "high" if writable else "medium", "host": host,
                         "share": share, "permissions": perm, "evidence": rest})
    return findings


def spider_interesting(spider: dict, host: str) -> list[dict]:
    """spider_plus JSON ({share: {relpath: meta}}) → smb-interesting-file findings (pure). Only paths
    whose name matches _SMB_INTERESTING (passwords/keys/backups/configs/…) are kept — the JSON is
    metadata only (spider_plus does not download content by default)."""
    return [{"type": "smb-interesting-file", "severity": "medium", "host": host, "share": share,
             "path": path, "evidence": f"//{host}/{share}/{path}"}
            for share, files in (spider or {}).items()
            for path in (files or {})
            if _SMB_INTERESTING.search(path)]


def parse_naming_contexts(out: str) -> list[str]:
    """ldapsearch rootDSE output → the base DNs from the 'namingContexts:' lines (pure, in order)."""
    return [ln.split(":", 1)[1].strip() for ln in out.splitlines()
            if ln.startswith("namingContexts:")]


def parse_ldap_accounts(out: str) -> list[str]:
    """ldapsearch entries → account names from the sAMAccountName / uid attributes (pure, sorted-unique)."""
    names: set[str] = set()
    for ln in out.splitlines():
        attr, _, value = ln.partition(":")
        if attr.strip().lower() in ("samaccountname", "uid") and value.strip():
            names.add(value.strip())
    return sorted(names)


def parse_snmpwalk(out: str) -> dict:
    """snmpwalk output → a small summary (pure): the sysDescr string + the count of walked entries."""
    lines = [ln for ln in out.splitlines() if ln.strip()]
    sysdescr = next((ln.split("STRING:", 1)[1].strip() for ln in lines
                     if "sysDescr" in ln and "STRING:" in ln), "")
    return {"entries": len(lines), "sysdescr": sysdescr}


_RID_RE = re.compile(r"\b(\d+):\s+\S+\\([^()]+?)\s+\(SidType(\w+)\)")


def parse_nxc_rid_brute(out: str) -> dict:
    """netexec `--rid-brute` output → {users, groups} (pure). Lines are '<rid>: <DOMAIN>\\<name>
    (SidType<X>)'; SidTypeUser → users, SidTypeGroup/Alias → groups. Domain-wide, deduped+sorted."""
    users: list[str] = []
    groups: list[str] = []
    for raw in out.splitlines():
        m = _RID_RE.search(raw)
        if not m:
            continue
        name, sid_type = m.group(2).strip(), m.group(3)
        if sid_type == "User":
            users.append(name)
        elif sid_type in ("Group", "Alias"):
            groups.append(name)
    return {"users": sorted(set(users)), "groups": sorted(set(groups))}


def parse_enum_ca(out: str) -> list[dict]:
    """netexec `-M enum_ca` output → ADCS findings (pure). The module highlights 'Active Directory
    Certificate Services Found.' per CA host and 'Web enrollment found on HTTP (ESC8).' when the CA
    exposes HTTP web enrollment (the NTLM-relay-to-CA surface). Deduped per (host, kind)."""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for raw in out.splitlines():
        m = _NXC_SMB_LINE.match(raw.strip())
        if not m:
            continue
        host, msg = m.group(1), m.group(2).strip()
        if "Certificate Services Found" in msg and (host, "ca") not in seen:
            seen.add((host, "ca"))
            findings.append({"type": "adcs-ca-found", "severity": "info", "host": host, "evidence": msg})
        elif "ESC8" in msg and (host, "esc8") not in seen:
            seen.add((host, "esc8"))
            findings.append({"type": "adcs-esc8-web-enrollment", "severity": "high", "host": host,
                             "evidence": "HTTP web enrollment (ESC8) — NTLM relay to CA → cert → DC auth"})
    return findings


_ASREP_HASH = re.compile(r"\$krb5asrep\$\d+\$([^@\s]+)@\S+")
_LDAP_HOST_PREFIX = re.compile(r"^LDAP\s+(\S+)\s+\d+")


def parse_asrep_roast(out: str) -> list[dict]:
    """netexec `nxc ldap --asreproast` (or GetNPUsers) output → asrep-roastable findings (pure). Each
    roastable account yields a '$krb5asrep$<etype>$<user>@<REALM>:<hash>' token; the user is the
    principal before '@' and the whole token is kept as loot. The host is read from netexec's
    'LDAP <ip> <port> …' line prefix when present ('' for a bare GetNPUsers line — the stage fills it).
    AS-REP roasting is a no-cred attack (accounts flagged DONT_REQ_PREAUTH)."""
    findings: list[dict] = []
    for raw in out.splitlines():
        line = raw.strip()
        m = _ASREP_HASH.search(line)
        if not m:
            continue
        hp = _LDAP_HOST_PREFIX.match(line)
        findings.append({"type": "asrep-roastable", "severity": "high",
                         "host": hp.group(1) if hp else "", "account": m.group(1),
                         "hash": m.group(0), "evidence": f"AS-REP roastable account: {m.group(1)}"})
    return findings


def _dedup_asrep(findings: list[dict]) -> list[dict]:
    """Dedup AS-REP findings by hash token, preferring a record that already carries a host (netexec's
    'LDAP <ip> …' stdout prefix) over a bare one (from the -o hash file). Pure, order-preserving."""
    best: dict[str, dict] = {}
    for f in findings:
        key = f.get("hash", "")
        if key not in best or (not best[key].get("host") and f.get("host")):
            best[key] = f
    return list(best.values())


# datastore NSE → (service family, finding type, severity). A datastore script that returns data at all
# usually means the store answered WITHOUT auth; ms-sql-info is exposure only. mongodb-databases (an
# unauth DB listing) outranks mongodb-info — the strongest signal per (host, family) wins.
_DATASTORE_NSE = "redis-info,mongodb-info,mongodb-databases,memcached-info,ms-sql-info"
_DATASTORE_SIGNALS: dict[str, tuple[str, str, str]] = {
    "redis-info": ("redis", "redis-unauth-access", "high"),
    "mongodb-databases": ("mongodb", "mongodb-unauth-access", "high"),
    "mongodb-info": ("mongodb", "mongodb-exposed", "medium"),
    "memcached-info": ("memcached", "memcached-unauth-access", "medium"),
    "ms-sql-info": ("mssql", "mssql-exposed", "info"),
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_NSE_LINE = re.compile(r"^\|_?\s*([a-z0-9-]+):")


def parse_datastore_nse(out: str) -> list[dict]:
    """nmap NSE output (`-oN -`) → unauthenticated-datastore findings (pure). Tracks the current host
    ('Nmap scan report for <ip>') and maps each datastore script-result line ('| <script>:' /
    '|_<script>:') to a finding via _DATASTORE_SIGNALS, keeping the STRONGEST signal per (host, service
    family). Non-datastore scripts and value sub-lines are ignored."""
    best: dict[tuple[str, str], dict] = {}
    host = ""
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("Nmap scan report for"):
            host = line.rsplit(" ", 1)[-1].strip("()")
            continue
        m = _NSE_LINE.match(line)
        if not m or m.group(1) not in _DATASTORE_SIGNALS:
            continue
        family, ftype, sev = _DATASTORE_SIGNALS[m.group(1)]
        key = (host, family)
        prev = best.get(key)
        if prev is None or _SEV_RANK[sev] > _SEV_RANK[prev["severity"]]:
            best[key] = {"type": ftype, "severity": sev, "host": host, "service": family,
                         "evidence": f"{m.group(1)} responded (nmap NSE)"}
    return sorted(best.values(), key=lambda f: (f["host"], f["service"]))


def parse_nxc_pass_pol(out: str) -> dict:
    """netexec `--pass-pol` output → the password-policy fields that matter for safe spraying (pure):
    minimum length + account-lockout threshold/duration."""
    pol: dict[str, str] = {}
    for raw in out.splitlines():
        low = raw.lower()
        if "minimum password length" in low:
            pol["min_length"] = raw.split(":")[-1].strip()
        elif "account lockout threshold" in low:
            pol["lockout_threshold"] = raw.split(":")[-1].strip()
        elif "lockout duration" in low:
            pol["lockout_duration"] = raw.split(":")[-1].strip()
    return pol


_LDAP_BANNER = re.compile(r"^LDAPS?\s+(\S+)\s+\d+\s+\S+\s+(.*)$")
_LDAP_SIGNING = re.compile(r"signing:(\w+)", re.IGNORECASE)
_LDAP_CBT = re.compile(r"channel binding:([^)]+)", re.IGNORECASE)


def parse_nxc_ldap_signing(out: str) -> list[dict]:
    """netexec core `nxc ldap` banner → LDAP signing / channel-binding findings (pure). The banner
    carries '(signing:None|Enforced) (channel binding:Always|When Supported|Never|Unknown)'. signing:None
    → ldap-signing-not-required (NTLM-relay-to-LDAP surface); channel binding ≠ Always/Unknown →
    ldaps-no-channel-binding. Deduped per (host, kind) since a host may appear on 389 and 636."""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for raw in out.splitlines():
        m = _LDAP_BANNER.match(raw.strip())
        if not m:
            continue
        host, rest = m.group(1), m.group(2)
        sig = _LDAP_SIGNING.search(rest)
        if sig and sig.group(1).lower() == "none" and (host, "sign") not in seen:
            seen.add((host, "sign"))
            findings.append({"type": "ldap-signing-not-required", "severity": "high",
                             "host": host, "evidence": rest.strip()})
        cbt = _LDAP_CBT.search(rest)
        if cbt and (status := cbt.group(1).strip()).lower() not in ("always", "unknown") \
                and (host, "cbt") not in seen:
            seen.add((host, "cbt"))
            findings.append({"type": "ldaps-no-channel-binding", "severity": "medium",
                             "host": host, "channel_binding": status, "evidence": rest.strip()})
    return findings


def parse_ldap_descriptions(out: str) -> list[dict]:
    """ldapsearch entries → [{account, description}] for accounts carrying a non-empty description
    (pure; descriptions often leak temp passwords). Pairs sAMAccountName/uid with description per entry."""
    entries: list[dict] = []
    acct, desc = "", ""
    for raw in [*out.splitlines(), ""]:            # trailing "" flushes the last entry
        if not raw.strip():
            if acct and desc:
                entries.append({"account": acct, "description": desc})
            acct, desc = "", ""
            continue
        attr, _, val = raw.partition(":")
        key = attr.strip().lower()
        if key in ("samaccountname", "uid"):
            acct = val.strip()
        elif key == "description":
            desc = val.strip()
    return entries


def _nb_field(line: str, key: str) -> str:
    m = re.search(rf"{re.escape(key)}:\s*([^,]+)", line)
    return m.group(1).strip() if m else ""


def parse_nbstat(out: str) -> list[dict]:
    """nmap `--script nbstat` output → NetBIOS identity records (pure): name, logged-on user, MAC per
    host. Tracks 'Nmap scan report for <ip>' for the host and reads the '| nbstat:' line."""
    findings: list[dict] = []
    host = ""
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("Nmap scan report for"):
            host = line.rsplit(" ", 1)[-1].strip("()")
        elif "nbstat:" in line:
            findings.append({"type": "netbios-info", "severity": "info", "host": host,
                             "name": _nb_field(line, "NetBIOS name"),
                             "nb_user": _nb_field(line, "NetBIOS user"),
                             "mac": _nb_field(line, "NetBIOS MAC"), "evidence": line})
    return findings


def reverse_zones(cidr: str) -> list[str]:
    """The in-addr.arpa reverse zone(s) for a CIDR (pure): /24+ → 3 octets, /16 → 2, /8 → 1 (host
    prefixes fall back to the /24 zone). E.g. 10.0.1.0/24 → ['1.0.10.in-addr.arpa']. [] if unparseable."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.version != 4:  # noqa: PLR2004 — IPv6 reverse zones (ip6.arpa) are out of scope for v1
        return []
    octets = 3 if net.prefixlen >= 24 else (2 if net.prefixlen >= 16 else 1)  # noqa: PLR2004
    parts = str(net.network_address).split(".")[:octets]
    return [".".join(reversed(parts)) + ".in-addr.arpa"]


def parse_dig_axfr(out: str) -> list[dict]:
    """`dig axfr` output → [{name, rtype, value}] records (pure). BIND-format lines are
    '<name> <ttl> IN <type> <value…>'; comment (';') and non-record lines are skipped. [] on a refused
    transfer (the presence of records IS the success signal)."""
    recs: list[dict] = []
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[2].upper() == "IN":  # noqa: PLR2004
            recs.append({"name": parts[0], "rtype": parts[3], "value": " ".join(parts[4:])})
    return recs


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


# --- spanning (whole-scope) — full-port scan + full-template nuclei ∥ the per-subnet loops --------
def portscan_full(activity: Activity) -> None:
    """SPANNING — full 65535-port naabu over the live hosts → asset_discovery/ports_full.jsonl. Off the
    critical path (∥ cluster + loops): the per-subnet loot checks run on the fast curated set, while the
    full scan feeds nuclei_scope so it sees services on non-standard ports. Same rate profile."""
    canon = activity.asset_discovery_canonical
    live = tools.read_lines(canon("live_hosts.txt"))
    records: list[dict] = []
    if live and shutil.which(NAABU):
        out = _run([NAABU, "-silent", "-p", "-", "-c", NAABU_CONC, "-rate", NAABU_RATE],
                   stdin="\n".join(live), dest=_raw(activity, "naabu", "ports_full"), label="ports_full")
        records = parse_naabu(_lines(out))
    tools.write_jsonl(canon("ports_full.jsonl"), records)
    log.info("  → portscan_full — %d open (ip,port) across %d host(s)",
             len(records), len({r["ip"] for r in records}))


def nuclei_scope(activity: Activity) -> None:
    """SPANNING (whole-scope) — full-template nuclei over every discovered socket. ONE process with a
    single global rate cap (-rl) — the internal pipeline's own principle (one gentle global sweep beats
    N per-subnet floods on fragile legacy/OT gear), and the analog of external's nuclei_scope. Reads the
    FULL-port set (portscan_full, fallback to the fast set), runs ∥ cluster + all per-subnet loops,
    joined at the fan-in → <activity>/findings/nuclei_scope.jsonl. Best-effort: skips if nuclei absent."""
    canon = activity.asset_discovery_canonical
    ports = tools.read_jsonl(canon("ports_full.jsonl")) or tools.read_jsonl(canon("ports.jsonl"))
    targets = tools.dedupe(f"{r['ip']}:{r['port']}" for r in ports if r.get("ip") and r.get("port"))
    if not targets or shutil.which(NUCLEI) is None:
        log.debug("  · skip nuclei_scope (no sockets / nuclei absent)")
        return
    try:  # best-effort template update — skips cleanly on an air-gapped internal network
        tools.run([NUCLEI, "-ut"], stream_stderr=is_verbose(), timeout=CHECK_TIMEOUT)
    except (OSError, subprocess.SubprocessError, tools.AbortedError) as exc:
        log.debug("  · nuclei -ut skipped: %s", exc)
    out = _run([NUCLEI, "-silent", "-duc", "-j", "-stats", "-rl", NUCLEI_RL],
               stdin="\n".join(targets), dest=activity.findings / "nuclei_scope.jsonl",
               label="nuclei_scope")
    log.info("  → nuclei_scope — %d finding(s) over %d socket(s)", len(_jsonl(out)), len(targets))


def fingerprint_full(activity: Activity) -> None:
    """SPANNING — fingerprint the FULL-port DELTA (sockets portscan_full found beyond the fast curated
    set) whole-scope with nerva → asset_discovery/services_full.jsonl. Runs ∥ cluster + the loops
    (joined at the fan-in), so a service on a non-standard port gets a banner without serialising a
    full-scan fingerprint in front of the per-subnet work. Those banners feed cve_lookup_full AND the
    web-service detection for the external hand-off (a web server on an odd port is recognised via its
    banner). Best-effort: skips if nerva is absent or there is no delta."""
    canon = activity.asset_discovery_canonical
    sockets = delta_sockets(tools.read_jsonl(canon("ports_full.jsonl")),
                            tools.read_jsonl(canon("ports.jsonl")))
    records: list[dict] = []
    if sockets and shutil.which(NERVA):
        out = _run([NERVA, "--json"], stdin="\n".join(sockets),
                   dest=activity.asset_discovery_raw("nerva") / "fingerprint_full.jsonl",
                   label="fingerprint_full")
        records = _jsonl(out)
    tools.write_jsonl(canon("services_full.jsonl"), records)
    log.info("  → fingerprint_full — %d non-standard-port service(s) over %d delta socket(s)",
             len(records), len(sockets))


def cve_lookup_full(activity: Activity) -> None:
    """SPANNING — known-CVE correlation of the FULL-port delta software (fingerprint_full's
    services_full.jsonl) against search_vulns' LOCAL DB → <activity>/findings/cve_full.jsonl. An
    activity-level finding (whole-scope, like nuclei_scope — NOT lifted by consolidate), the delta of
    the per-subnet cve_lookup (non-standard ports it never saw). OFFLINE (net=False); the process-wide
    memo makes the overlap with cve_lookup free. Runs ∥ everything, joined at the fan-in. Best-effort:
    skips if search_vulns / its DB is absent."""
    canon = activity.asset_discovery_canonical
    if shutil.which(SEARCH_VULNS) is None:
        log.debug("  · skip cve_lookup_full (search_vulns absent)")
        return
    software = software_from_services(tools.read_jsonl(canon("services_full.jsonl")))
    findings: list[dict] = []
    for sw in software:
        findings += [{**cve, "hosts": sw["hosts"]} for cve in _query_cve(sw["product"], sw["version"])]
    findings.sort(key=_cve_sort_key)
    tools.write_jsonl(activity.findings / "cve_full.jsonl", findings)
    log.info("  → cve_lookup_full — %d software → %d CVE(s) (full-port delta)",
             len(software), len(findings))


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


def _sockets_with_ports(ws: AppWorkspace, ports: frozenset[int]) -> list[tuple[str, int]]:
    """The group's open sockets whose port ∈ `ports`, as sorted (ip, port) tuples."""
    return sorted({(str(r["ip"]), int(r["port"]))
                   for r in tools.read_jsonl(ws.canonical("ports.jsonl"))
                   if r.get("ip") and isinstance(r.get("port"), int) and r["port"] in ports})


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
    tools.write_text(dest, out)
    return out


def _capture(cmd: list[str], *, dest: Path, label: str) -> str:
    """Best-effort arg-based tool run with a wall-clock cap → stdout ('' on any error/timeout),
    persisted to `dest` (raw provenance). For the bounded loop-2 checks."""
    try:
        out = tools.run(cmd, stream_stderr=is_verbose(), timeout=CHECK_TIMEOUT)
    except (OSError, subprocess.SubprocessError, tools.AbortedError) as exc:
        log.debug("  · %s failed: %s", label, exc)
        return ""
    tools.write_text(dest, out)
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


def _smb_spider(ws: AppWorkspace, hosts: list[str]) -> list[dict]:
    """Metadata-only SMB spider (spider_plus) over `hosts` → smb-interesting-file findings. spider_plus
    writes one <host>.json of file METADATA (no content download) into OUTPUT_FOLDER; each is filtered
    for interesting filenames. Read-only, best-effort ([] on any failure)."""
    outdir = ws.raw("netexec") / "spider"
    outdir.mkdir(parents=True, exist_ok=True)
    _capture([NXC, "smb", *hosts, "-u", "", "-p", "", "-M", "spider_plus",
              "-o", f"OUTPUT_FOLDER={outdir}"], dest=ws.raw("netexec") / "spider.txt", label="smb-spider")
    findings: list[dict] = []
    for jf in sorted(outdir.glob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        findings += spider_interesting(data if isinstance(data, dict) else {}, jf.stem)
    return findings


def smb_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — SMB first-checks + LOOT via netexec on hosts with 445 open. Posture (signing not
    required / SMBv1 / null-session / guest / admin), then — from the SAME anonymous session — share
    enumeration (READ/WRITE) and a metadata-only spider of readable non-default shares flagging
    interesting filenames. All read-only, best-effort → findings/smb.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_SMB)
    if not hosts or shutil.which(NXC) is None:
        log.debug("  · skip smb_checks [%s] (no 445 / netexec absent)", app_id)
        return
    findings = parse_nxc_smb(_capture([NXC, "smb", *hosts, "-u", "", "-p", ""],
                                      dest=ws.raw("netexec") / "smb.txt", label="smb"))
    shares = parse_nxc_shares(_capture([NXC, "smb", *hosts, "-u", "", "-p", "", "--shares"],
                                       dest=ws.raw("netexec") / "shares.txt", label="smb-shares"))
    findings += shares
    # spider only the hosts that exposed a readable, non-default share (keeps the load down)
    loot_hosts = sorted({f["host"] for f in shares if f["share"].upper() not in _SMB_SKIP_SPIDER})
    if loot_hosts:
        findings += _smb_spider(ws, loot_hosts)
    tools.write_jsonl(ws.findings / "smb.jsonl", findings)
    log.info("  → smb_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def _snmp_walk(ws: AppWorkspace, hits: list[dict]) -> list[dict]:
    """For each SNMP community hit, snmpwalk the curated OIDs (system · processes · ARP) → an snmp-info
    finding + a network-map loot file. Read-only, bounded per OID, best-effort ([] on nothing)."""
    out_findings: list[dict] = []
    for hit in hits:
        host, community = hit.get("host"), hit.get("community")
        if not host or not community:
            continue
        combined = "".join(
            _capture([SNMPWALK, "-v2c", "-c", community, "-t", "2", "-r", "1", host, oid],
                     dest=ws.raw("snmpwalk") / f"{host}_{oid}.txt", label="snmpwalk")
            for oid in SNMP_WALK_OIDS)
        summary = parse_snmpwalk(combined)
        if summary["entries"]:
            out_findings.append({"type": "snmp-info", "severity": "medium", "host": host,
                                 "community": community, "sysdescr": summary["sysdescr"],
                                 "entries": summary["entries"],
                                 "evidence": f"snmpwalk via '{community}' — {summary['entries']} OID value(s)"})
    return out_findings


def snmp_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — SNMP default-community sweep + LOOT (UDP/161) via onesixtyone over ALL group hosts (161
    is UDP so it's not in the TCP portscan). A responding community is a finding; from that community we
    then snmpwalk a curated OID set (system/processes/ARP) into a network-map loot. Best-effort."""
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
    if findings and shutil.which(SNMPWALK):   # post-hit walk: turn a community hit into a network map
        findings += _snmp_walk(ws, findings)
    tools.write_jsonl(ws.findings / "snmp.jsonl", findings)
    log.info("  → snmp_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def ad_enum(activity: Activity, app_id: str) -> None:
    """LOOP 2 — Active Directory enumeration WITHOUT credentials via netexec on hosts with 445 open:
    RID cycling (`--rid-brute`, SAMR lookupsids works over a null session even when RestrictAnonymous
    blocks `--users`) → domain users/groups loot, and the password policy (`--pass-pol`) whose lockout
    threshold is the safe-spraying gate. Domain-wide, best-effort → findings/ad_enum.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_SMB)
    if not hosts or shutil.which(NXC) is None:
        log.debug("  · skip ad_enum [%s] (no 445 / netexec absent)", app_id)
        return
    findings: list[dict] = []
    accounts = parse_nxc_rid_brute(_capture([NXC, "smb", *hosts, "-u", "", "-p", "", "--rid-brute"],
                                            dest=ws.raw("netexec") / "rid_brute.txt", label="ad-rid"))
    if accounts["users"] or accounts["groups"]:
        tools.write_lines(ws.raw("netexec") / "domain_users.txt", accounts["users"])
        tools.write_lines(ws.raw("netexec") / "domain_groups.txt", accounts["groups"])
        findings.append({"type": "ad-users-enumerated", "severity": "high", "host": hosts[0],
                         "users": len(accounts["users"]), "groups": len(accounts["groups"]),
                         "sample": accounts["users"][:10],
                         "evidence": f"{len(accounts['users'])} user(s) + {len(accounts['groups'])} "
                                     "group(s) via null-session RID cycling"})
    pol = parse_nxc_pass_pol(_capture([NXC, "smb", *hosts, "-u", "", "-p", "", "--pass-pol"],
                                      dest=ws.raw("netexec") / "pass_pol.txt", label="ad-passpol"))
    if pol:
        findings.append({"type": "ad-password-policy", "severity": "info", "host": hosts[0], **pol,
                         "evidence": f"password policy: {pol}"})
    tools.write_jsonl(ws.findings / "ad_enum.jsonl", findings)
    log.info("  → ad_enum [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def adcs_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — ADCS enumeration WITHOUT credentials via netexec `-M enum_ca` on hosts with 445 open:
    anonymous CA discovery (RPC epmapper) + ESC8 detection (the module itself probes /certsrv for HTTP
    web enrollment). ESC8 is the relay-based ESC — pairs with the smb/ldap-signing surface. The
    template ESCs (ESC1-7) need an authenticated bind → deferred to the credentialed phase.
    Best-effort → findings/adcs.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_SMB)
    if not hosts or shutil.which(NXC) is None:
        log.debug("  · skip adcs_checks [%s] (no 445 / netexec absent)", app_id)
        return
    out = _capture([NXC, "smb", *hosts, "-u", "", "-p", "", "-M", "enum_ca"],
                   dest=ws.raw("netexec") / "enum_ca.txt", label="adcs")
    findings = parse_enum_ca(out)
    tools.write_jsonl(ws.findings / "adcs.jsonl", findings)
    log.info("  → adcs_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def kerberoast_asrep(activity: Activity, app_id: str) -> None:
    """LOOP 2 — AS-REP roasting WITHOUT credentials via netexec on the group's KDC(s) (hosts with 88
    open). Feeds `nxc ldap --asreproast` the domain user list ad_enum already produced (needs=ad_enum,
    an intra-loop dependency) and requests an AS-REP for accounts flagged DONT_REQ_PREAUTH — no
    password is sent and no login is attempted. The '$krb5asrep$…' hashes are offline-crackable loot.
    Best-effort → findings/asrep.jsonl (skips with no KDC / empty userlist / netexec absent)."""
    ws = activity.app(app_id)
    dcs = _hosts_with_port(ws, PORT_KERBEROS)
    userfile = ws.raw("netexec") / "domain_users.txt"          # written by ad_enum (same phase)
    if not dcs or not tools.read_lines(userfile) or shutil.which(NXC) is None:
        log.debug("  · skip kerberoast_asrep [%s] (no KDC / no userlist / netexec absent)", app_id)
        return
    hashfile = ws.raw("netexec") / "asrep_hashes.txt"
    out = _capture([NXC, "ldap", *dcs, "-u", str(userfile), "-p", "", "--asreproast", str(hashfile)],
                   dest=ws.raw("netexec") / "asreproast.txt", label="asrep")
    # netexec version-dependently writes the '$krb5asrep$…' hashes to stdout, the -o file, or both →
    # parse BOTH and dedup by hash (a stdout line carries the KDC host prefix; a bare -o line doesn't).
    findings = _dedup_asrep(parse_asrep_roast("\n".join([out, *tools.read_lines(hashfile)])))
    for f in findings:                                         # attribute a bare (prefix-less) hash to the KDC
        f["host"] = f["host"] or dcs[0]
    tools.write_jsonl(ws.findings / "asrep.jsonl", findings)
    log.info("  → kerberoast_asrep [%s] — %d KDC(s) → %d roastable account(s)",
             app_id, len(dcs), len(findings))


def _ldap_dump(ws: AppWorkspace, host: str, contexts: list[str]) -> list[dict]:
    """Bounded anonymous account dump (ldapsearch -z LDAP_MAX_ENTRIES) over the first DOMAIN naming
    context → an ldap-anon-users finding + a users loot file. Read-only, best-effort ([] on nothing)."""
    base = next((c for c in contexts if "DC=" in c.upper()), contexts[0])
    out = _capture([LDAPSEARCH, "-x", "-H", f"ldap://{host}", "-b", base, "-z", LDAP_MAX_ENTRIES,
                    "(|(objectClass=user)(objectClass=person)(objectClass=inetOrgPerson))",
                    "sAMAccountName", "uid", "description"],
                   dest=ws.raw("ldapsearch") / f"{host}_dump.txt", label="ldap-dump")
    accounts = parse_ldap_accounts(out)
    findings: list[dict] = []
    if accounts:
        tools.write_lines(ws.raw("ldapsearch") / f"{host}_accounts.txt", accounts)
        findings.append({"type": "ldap-anon-users", "severity": "high", "host": host,
                         "count": len(accounts), "sample": accounts[:10],
                         "evidence": f"{len(accounts)} account(s) via anonymous bind"})
    # account descriptions often leak temp passwords → surface each one
    findings += [{"type": "ldap-user-description", "severity": "medium", "host": host,
                  "account": d["account"], "description": d["description"],
                  "evidence": f"{d['account']}: {d['description']}"}
                 for d in parse_ldap_descriptions(out)]
    return findings


def ldap_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — LDAP posture + LOOT on hosts with 389/636 open, no credentials. Two independent,
    best-effort passes → findings/ldap.jsonl:
    (1) signing / channel binding via the netexec core `nxc ldap` banner (the NTLM-relay-to-LDAP
        surface — signing:None → ldap-signing-not-required, channel binding ≠ Always → ldaps-no-cbt);
    (2) anonymous bind via ldapsearch → rootDSE naming contexts + a bounded account/description dump."""
    ws = activity.app(app_id)
    hosts = sorted(set(_hosts_with_port(ws, PORT_LDAP)) | set(_hosts_with_port(ws, PORT_LDAPS)))
    if not hosts:
        log.debug("  · skip ldap_checks [%s] (no 389/636)", app_id)
        return
    findings: list[dict] = []
    if shutil.which(NXC):  # (1) signing / channel binding — netexec core banner, no module, no creds
        findings += parse_nxc_ldap_signing(
            _capture([NXC, "ldap", *hosts, "-u", "", "-p", ""],
                     dest=ws.raw("netexec") / "ldap.txt", label="ldap-sign"))
    if shutil.which(LDAPSEARCH):  # (2) anonymous bind + account/description dump
        for host in hosts:
            out = _capture([LDAPSEARCH, "-x", "-H", f"ldap://{host}", "-s", "base", "-b", "",
                            "namingContexts"], dest=ws.raw("ldapsearch") / f"{host}.txt", label="ldap")
            contexts = parse_naming_contexts(out)
            if not contexts:
                continue
            findings.append({"type": "ldap-anonymous-bind", "severity": "medium", "host": host,
                             "evidence": f"namingContexts: {contexts[0]}"})
            findings += _ldap_dump(ws, host, contexts)
    tools.write_jsonl(ws.findings / "ldap.jsonl", findings)
    log.info("  → ldap_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def ftp_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — anonymous-FTP login via netexec on hosts with 21 open (`-u anonymous -p ''`). A '[+]'
    success is a finding. Best-effort → findings/ftp.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_FTP)
    if not hosts or shutil.which(NXC) is None:
        log.debug("  · skip ftp_checks [%s] (no 21 / netexec absent)", app_id)
        return
    out = _capture([NXC, "ftp", *hosts, "-u", "anonymous", "-p", ""],
                   dest=ws.raw("netexec") / "ftp.txt", label="ftp")
    findings = parse_nxc_ftp(out)
    tools.write_jsonl(ws.findings / "ftp.jsonl", findings)
    log.info("  → ftp_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def telnet_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — exposed cleartext telnet on hosts with 23 open (nmap -sV for the banner). An open
    telnet port is a finding on its own (credentials travel in the clear). Best-effort → findings/
    telnet.jsonl. NOTE: reliable no-auth detection needs a login attempt (opt-in/future); v1 reports
    the exposure + banner."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_TELNET)
    if not hosts or shutil.which(NMAP) is None:
        log.debug("  · skip telnet_checks [%s] (no 23 / nmap absent)", app_id)
        return
    out = _capture([NMAP, "-Pn", "-n", "-sV", "-p", str(PORT_TELNET), "-oG", "-", *hosts],
                   dest=ws.raw("nmap") / "telnet.txt", label="telnet")
    findings = parse_telnet(out)
    tools.write_jsonl(ws.findings / "telnet.jsonl", findings)
    log.info("  → telnet_checks [%s] — %d host(s) → %d finding(s)", app_id, len(hosts), len(findings))


def nfs_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — anonymously-readable NFS exports via showmount -e on hosts with 2049 open. A
    world-readable export is high-value LHF (backups/home dirs). Best-effort → findings/nfs.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_NFS)
    if not hosts or shutil.which(SHOWMOUNT) is None:
        log.debug("  · skip nfs_checks [%s] (no 2049 / showmount absent)", app_id)
        return
    findings: list[dict] = []
    for host in hosts:
        out = _capture([SHOWMOUNT, "-e", host], dest=ws.raw("showmount") / f"{host}.txt", label="nfs")
        findings += parse_showmount(out, host)
    tools.write_jsonl(ws.findings / "nfs.jsonl", findings)
    log.info("  → nfs_checks [%s] — %d host(s) → %d export(s)", app_id, len(hosts), len(findings))


def rsync_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — anonymous rsync modules via `rsync rsync://host/` on hosts with 873 open. Anonymously
    listable modules often expose a filesystem tree. Best-effort → findings/rsync.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_RSYNC)
    if not hosts or shutil.which(RSYNC) is None:
        log.debug("  · skip rsync_checks [%s] (no 873 / rsync absent)", app_id)
        return
    findings: list[dict] = []
    for host in hosts:
        out = _capture([RSYNC, "--contimeout=10", f"rsync://{host}/"],
                       dest=ws.raw("rsync") / f"{host}.txt", label="rsync")
        findings += parse_rsync_modules(out, host)
    tools.write_jsonl(ws.findings / "rsync.jsonl", findings)
    log.info("  → rsync_checks [%s] — %d host(s) → %d module(s)", app_id, len(hosts), len(findings))


def datastore_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — unauthenticated datastore exposure on the group's datastore sockets (Redis 6379 /
    MongoDB 27017-8 / Memcached 11211 / MSSQL 1433 — all in the fast port set). ONE nmap NSE run whose
    scripts return data only when the store answers WITHOUT auth (redis-info / mongodb-databases /
    memcached-info; ms-sql-info is exposure-only). Elasticsearch (9200) is HTTP → left to the web
    hand-off + nuclei_scope. Non-destructive (no login attempt). Best-effort → findings/datastore.jsonl."""
    ws = activity.app(app_id)
    sockets = _sockets_with_ports(ws, DATASTORE_PORTS)
    if not sockets or shutil.which(NMAP) is None:
        log.debug("  · skip datastore_checks [%s] (no datastore port / nmap absent)", app_id)
        return
    hosts = sorted({ip for ip, _ in sockets})
    ports = ",".join(str(p) for p in sorted({p for _, p in sockets}))
    out = _capture([NMAP, "-Pn", "-n", "-sV", "-p", ports, "--script", _DATASTORE_NSE,
                    "-oN", "-", *hosts], dest=ws.raw("nmap") / "datastore.txt", label="datastore")
    findings = parse_datastore_nse(out)
    tools.write_jsonl(ws.findings / "datastore.jsonl", findings)
    log.info("  → datastore_checks [%s] — %d socket(s) → %d finding(s)",
             app_id, len(sockets), len(findings))


def netbios_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — NetBIOS identity enumeration (137/UDP, so it runs over ALL group hosts like SNMP, not
    the TCP portscan). nmap `nbstat` yields hostname, logged-on user and MAC/vendor per host — cheap,
    no-cred identity data. Best-effort → findings/netbios.jsonl."""
    ws = activity.app(app_id)
    hosts = tools.read_lines(ws.hosts)
    if not hosts or shutil.which(NMAP) is None:
        log.debug("  · skip netbios_checks [%s] (no hosts / nmap absent)", app_id)
        return
    out = _capture([NMAP, "-sU", "-Pn", "-n", "-p", str(PORT_NETBIOS), "--script", "nbstat",
                    "-oN", "-", *hosts], dest=ws.raw("nmap") / "nbstat.txt", label="netbios")
    findings = parse_nbstat(out)
    tools.write_jsonl(ws.findings / "netbios.jsonl", findings)
    log.info("  → netbios_checks [%s] — %d host(s) → %d record(s)", app_id, len(hosts), len(findings))


def dns_checks(activity: Activity, app_id: str) -> None:
    """LOOP 2 — DNS zone transfer (AXFR) against hosts with 53 open. Attempts the subnet's REVERSE
    zone(s) — derived deterministically from the group CIDR — so a permissive server hands back the
    PTR map of the whole subnet (a host inventory). Best-effort → findings/dns.jsonl."""
    ws = activity.app(app_id)
    hosts = _hosts_with_port(ws, PORT_DNS)
    zones = reverse_zones(workspace.read_meta(ws.meta).get("cidr") or "")
    if not hosts or not zones or shutil.which(DIG) is None:
        log.debug("  · skip dns_checks [%s] (no 53 / no zone / dig absent)", app_id)
        return
    findings: list[dict] = []
    for host in hosts:
        for zone in zones:
            recs = parse_dig_axfr(_capture([DIG, "+time=5", "+tries=1", "axfr", zone, f"@{host}"],
                                           dest=ws.raw("dig") / f"{host}_{zone}.txt", label="dns-axfr"))
            if recs:
                tools.write_jsonl(ws.raw("dig") / f"{host}_{zone}.jsonl", recs)
                findings.append({"type": "dns-zone-transfer", "severity": "high", "host": host,
                                 "zone": zone, "records": len(recs),
                                 "evidence": f"AXFR of {zone} from {host} → {len(recs)} record(s)"})
    tools.write_jsonl(ws.findings / "dns.jsonl", findings)
    log.info("  → dns_checks [%s] — %d DNS host(s) → %d transfer(s)", app_id, len(hosts), len(findings))


def remote_desktop(activity: Activity, app_id: str) -> None:
    """LOOP 2 — screenshot exposed RDP/VNC with scrying (no credentials). One scrying run over the
    group's RDP (3389) + VNC (5900-5906) sockets captures each exposed login screen / desktop; a
    captured VNC framebuffer usually means the desktop is reachable without auth. The shots are
    re-homed to scans/<subnet>/screenshots/ and referenced from findings/remote_desktop.jsonl.
    Best-effort → skips if scrying is absent or the group has no RDP/VNC socket."""
    from pathlib import Path  # noqa: PLC0415 — local so the module keeps no path literal at import

    ws = activity.app(app_id)
    sockets = _sockets_with_ports(ws, _RD_PORTS)
    if not sockets or shutil.which(SCRYING) is None:
        log.debug("  · skip remote_desktop [%s] (no RDP/VNC / scrying absent)", app_id)
        return
    outdir = ws.raw("scrying")
    outdir.mkdir(parents=True, exist_ok=True)
    targets = [f"{'rdp' if port == PORT_RDP else 'vnc'}://{ip}:{port}" for ip, port in sockets]
    tfile = outdir / "targets.txt"
    tools.write_lines(tfile, targets)
    try:
        tools.run([SCRYING, "-f", str(tfile), "-o", str(outdir), "--silent", "--disable-report"],
                  timeout=SCRYING_TIMEOUT, stream_stderr=is_verbose())
    except (OSError, subprocess.SubprocessError, tools.AbortedError) as exc:
        log.debug("  · remote_desktop [%s] scrying failed: %s", app_id, exc)
    findings = parse_scrying(sorted(outdir.glob("*/*.png")))
    shots = ws.root / "screenshots"
    for f in findings:  # re-home each capture next to the group's data, path relative to the activity
        dst = shots / f"{f['protocol']}-{f['host']}-{f['port']}.png"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(f["screenshot"]), dst)
        f["screenshot"] = str(dst.relative_to(activity.base))
    tools.write_jsonl(ws.findings / "remote_desktop.jsonl", findings)
    log.info("  → remote_desktop [%s] — %d RDP/VNC socket(s) → %d screenshot(s)",
             app_id, len(sockets), len(findings))


# --- consolidate (terminal fan-in) ---------------------------------------------------------------
_CONSOLIDATE_SOURCES: dict[str, tuple[str, ...]] = {
    "cve.jsonl": ("findings/cve.jsonl",),
    "smb.jsonl": ("findings/smb.jsonl",),
    "snmp.jsonl": ("findings/snmp.jsonl",),
    "ldap.jsonl": ("findings/ldap.jsonl",),
    "ftp.jsonl": ("findings/ftp.jsonl",),
    "telnet.jsonl": ("findings/telnet.jsonl",),
    "nfs.jsonl": ("findings/nfs.jsonl",),
    "rsync.jsonl": ("findings/rsync.jsonl",),
    "ad_enum.jsonl": ("findings/ad_enum.jsonl",),
    "adcs.jsonl": ("findings/adcs.jsonl",),
    "asrep.jsonl": ("findings/asrep.jsonl",),
    "datastore.jsonl": ("findings/datastore.jsonl",),
    "netbios.jsonl": ("findings/netbios.jsonl",),
    "dns.jsonl": ("findings/dns.jsonl",),
    "remote_desktop.jsonl": ("findings/remote_desktop.jsonl",),
}
# nuclei_scope AND cve_full are written whole-scope at the activity level (like external) — not lifted
# here (the full-port CVE delta is activity-scoped, the gemini of the whole-scope nuclei_scope).


def aggregate_web_targets(activity: Activity) -> list[str]:
    """Aggregate every web service into <activity>/web_targets.txt (scheme://ip:port), the scope
    artifact the external hand-off consumes. Two sources, unioned: (1) each subnet group's fast-set
    ports.jsonl + services.jsonl (per-subnet); (2) the whole-scope FULL-port scan (ports_full.jsonl +
    fingerprint_full's services_full.jsonl), so a web server on a NON-standard port — recognised only
    via its fingerprint banner — reaches the hand-off too. Idempotent, sorted. Returns the URL list."""
    canon = activity.asset_discovery_canonical
    per_subnet = [u for ws in activity.list_apps()
                  for u in web_targets_from(tools.read_jsonl(ws.canonical("ports.jsonl")),
                                            tools.read_jsonl(ws.canonical("services.jsonl")))]
    full_port = web_targets_from(tools.read_jsonl(canon("ports_full.jsonl")),
                                 tools.read_jsonl(canon("services_full.jsonl")))
    urls = sorted({*per_subnet, *full_port})
    tools.write_lines(activity.base / WEB_SCOPE_FILE, urls)
    return urls


def consolidate(activity: Activity) -> dict[str, int]:
    """TERMINAL fan-in (deterministic, OFFLINE) — lift every subnet group's per-app findings into
    <activity>/findings/<type>.jsonl, one file per finding TYPE, each record stamped with its app_id
    (the subnet slug). Also aggregates the web services into <activity>/web_targets.txt (the external
    hand-off scope). A type with no results this run LEAVES any prior findings/<type>.jsonl UNTOUCHED:
    --resume MUST NOT destroy prior findings (precious in a pentest; skipped stages keep their per-app
    files, so a resume reproduces the same aggregate) — for a clean aggregate, consolidate into a fresh
    activity dir. Empty types write no file. Idempotent overwrite of a non-empty type."""
    apps = activity.list_apps()
    counts: dict[str, int] = {}
    for out_name, sources in _CONSOLIDATE_SOURCES.items():
        records = [{"app_id": ws.root.name, **rec}
                   for ws in apps for src in sources
                   for rec in tools.read_jsonl(ws.root / src)]
        if records:                            # never delete on empty — see docstring (--resume safety)
            counts[out_name.removesuffix(".jsonl")] = tools.write_jsonl(
                activity.findings / out_name, records)
    web = aggregate_web_targets(activity)
    log.info("  → consolidate — %s · %d web service(s) → %s",
             ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no per-subnet findings",
             len(web), WEB_SCOPE_FILE)
    return counts


def followups(activity: Activity) -> list[Followup]:
    """Pipeline composition — after the low-hanging-fruit sweep, hand the aggregated web services to the
    `webscan` pipeline as a nested sub-activity (<activity>/web_recon/). OPT-IN via PTFLOW_INTERNAL_WEB_
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


def requirements() -> list[Requirement]:
    """The internal pipeline's host requirement manifest — the SINGLE source of truth that both
    `preflight` and `ptflow doctor` render from. Its OWN toolset (nmap/naabu/netexec/onesixtyone/
    ldapsearch/…), NOT external's web toolchain. Best-effort: a missing CORE tool warns, an OPTIONAL
    one just skips its check."""
    reqs = [Requirement(name, cmd, "core") for name, cmd in _CORE_TOOLS.items()]
    reqs += [Requirement(name, cmd, "optional") for name, cmd in _OPTIONAL_TOOLS.items()]
    return reqs


def preflight() -> None:
    """Log which external tools resolve at run start (best-effort — never aborts). A missing CORE
    tool means its breadth stage produces nothing; a missing OPTIONAL tool skips its loop-2 check.
    Renders from the same `requirements()` manifest as `ptflow doctor`."""
    report = check(requirements())
    core = [r for r in report.results if r.req.kind == "core"]
    opt = [r for r in report.results if r.req.kind == "optional"]
    log.info("  → preflight: core %d/%d · optional %d/%d",
             sum(1 for r in core if r.ok), len(core), sum(1 for r in opt if r.ok), len(opt))
    if report.core_missing:
        log.warning("  ⚠ preflight: missing CORE tool(s) — those stages produce nothing: %s",
                    ", ".join(r.req.name for r in report.core_missing))
    opt_missing = [r.req.name for r in opt if not r.ok]
    if opt_missing:
        log.info("    optional tools absent (their checks skip): %s", ", ".join(opt_missing))
