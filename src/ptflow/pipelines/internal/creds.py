"""Opt-in default-credential testing for the internal pipeline.

Phase-3 per-subnet stages that try the research agent's source-grounded default-credential candidates
(``credential_candidates.jsonl``) against the concrete services they were proposed for. Non-HTTP + HTTP
Basic auth via Brutus (``creds_test_brutus``); HTTP form-based login via a Playwright ``FormLoginProbe``
(``creds_test_forms``). Curated pairs only — never Brutus's embedded defaults or ``--experimental-ai``.
Opt-in (``PTFLOW_CREDS_TEST``), best-effort, lockout-aware.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ptflow.core.log import get_logger
from ptflow.pipelines.internal.tasks import _banner_product, web_targets_from

log = get_logger()

CREDS_TEST_ENV = "PTFLOW_CREDS_TEST"
CREDS_MODE_ENV = "PTFLOW_CREDS_MODE"
LOCKOUT_DEFAULT_ENV = "PTFLOW_CREDS_LOCKOUT_DEFAULT"
_TRUTHY = frozenset({"1", "on", "true", "yes"})
DEFAULT_MODE = "cautious"
DEFAULT_LOCKOUT = 3
BRUTUS_TIMEOUT = 120  # per single-target invocation wall-clock cap (one pair, one socket)

# PTFLOW_CREDS_MODE → real Brutus flags (the installed build has no --mode).
_MODE_FLAGS: dict[str, list[str]] = {
    "cautious": ["-t", "5", "--rate-limit", "2", "--retries", "1", "--timeout", "15s"],
    "default": ["-t", "10", "--retries", "2"],
    "aggressive": ["-t", "20", "--retries", "3"],
}

_LOCKOUT_PROTOCOLS = frozenset({"smb", "ldap", "rdp", "winrm"})

_BRUTUS_PROTO = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet", "vnc": "vnc",
    "rdp": "rdp", "ms-wbt-server": "rdp", "snmp": "snmp",
    "smb": "smb", "microsoft-ds": "smb", "netbios-ssn": "smb", "cifs": "smb",
    "ldap": "ldap", "ldaps": "ldap", "winrm": "winrm", "wsman": "winrm",
    "mysql": "mysql", "mariadb": "mysql", "postgresql": "postgres", "postgres": "postgres",
    "mssql": "mssql", "ms-sql-s": "mssql", "mongodb": "mongodb", "mongod": "mongodb", "mongo": "mongodb",
    "redis": "redis", "oracle": "oracle", "oracle-tns": "oracle",
    "neo4j": "neo4j", "cassandra": "cassandra", "couchdb": "couchdb",
    "elasticsearch": "elasticsearch", "influxdb": "influxdb",
    "smtp": "smtp", "imap": "imap", "pop3": "pop3",
}
_PORT_PROTO: dict[int, str] = {
    22: "ssh", 21: "ftp", 23: "telnet", 3389: "rdp", 161: "snmp",
    445: "smb", 139: "smb", 389: "ldap", 636: "ldap", 3306: "mysql",
    5432: "postgres", 1433: "mssql", 6379: "redis", 27017: "mongodb", 27018: "mongodb",
    1521: "oracle", 5985: "winrm", 5986: "winrm", 25: "smtp", 143: "imap", 110: "pop3",
    **dict.fromkeys(range(5900, 5907), "vnc"),
}


def creds_test_enabled() -> bool:
    return os.getenv(CREDS_TEST_ENV, "").strip().lower() in _TRUTHY


def resolve_mode() -> str:
    mode = os.getenv(CREDS_MODE_ENV, "").strip().lower()
    return mode if mode in _MODE_FLAGS else DEFAULT_MODE


def mode_flags() -> list[str]:
    """The Brutus performance/politeness flags for the configured mode (default cautious)."""
    return list(_MODE_FLAGS[resolve_mode()])


def _lockout_default() -> int:
    raw = os.getenv(LOCKOUT_DEFAULT_ENV, "").strip()
    return int(raw) if raw.isdigit() else DEFAULT_LOCKOUT


@dataclass(frozen=True)
class ServiceSocket:
    host: str
    port: int
    product: str
    service: str
    banner: str


def service_sockets(services: list[dict]) -> list[ServiceSocket]:
    """Flatten ``services.jsonl`` into per-socket identities; product from the field else the banner.
    Records missing host or an int port are dropped. Pure."""
    out: list[ServiceSocket] = []
    for r in services:
        host = str(r.get("ip") or r.get("host") or "").strip()
        port = r.get("port")
        if not host or not isinstance(port, int):
            continue
        meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
        banner = str((meta or {}).get("banner") or r.get("banner") or "")
        product = str(r.get("product") or "").strip() or (_banner_product(banner)[0] or "")
        service = str(r.get("service") or r.get("name") or r.get("protocol") or "").strip().lower()
        out.append(ServiceSocket(host, port, product, service, banner))
    return out


def _product_matches(candidate_product: str, socket_product: str) -> bool:
    a, b = candidate_product.casefold().strip(), socket_product.casefold().strip()
    return bool(a) and bool(b) and (a in b or b in a)


def socket_proto(sock: ServiceSocket) -> str | None:
    """Brutus ``--protocol`` for a NON-web socket: nerva service name then well-known port; None if
    unmapped (precision-first)."""
    return _BRUTUS_PROTO.get(sock.service) or _PORT_PROTO.get(sock.port)


def web_urls(services: list[dict]) -> dict[tuple[str, int], str]:
    """(host, port) → ``scheme://host:port`` for every web socket, via the tested ``web_targets_from``."""
    ports = [{"ip": r.get("ip") or r.get("host"), "port": r.get("port")} for r in services]
    out: dict[tuple[str, int], str] = {}
    for url in web_targets_from(ports, services):
        host, _, port = url.split("://", 1)[-1].rpartition(":")
        if host and port.isdigit():
            out[host, int(port)] = url
    return out


def parse_lockout_threshold(records: list[dict]) -> int | None:
    """Account-lockout threshold from ``findings/ad_enum.jsonl``'s ``ad-password-policy`` record. None
    when no policy was enumerated (caller uses the default); 0 for None/Disabled (unlimited). Pure."""
    for r in records:
        if r.get("type") == "ad-password-policy":
            raw = str(r.get("lockout_threshold", "")).strip().lower()
            digits = "".join(ch for ch in raw if ch.isdigit())
            if not digits or raw in ("none", "disabled"):
                return 0
            return int(digits)
    return None


def account_budget(threshold: int | None, default: int) -> int | None:
    """Max login attempts per single account: None = unlimited; 0 = must skip; N = cap. Unknown
    threshold uses ``default``."""
    t = default if threshold is None else threshold
    return None if t <= 0 else t - 1


def _apply_lockout(
    net_attempts: list[dict], threshold: int | None, default: int,
) -> tuple[list[dict], list[dict]]:
    """Cap attempts on domain-lockout protocols to ``account_budget`` per (host, protocol, username),
    highest-confidence first. Non-lockout protocols pass through. Returns (kept, skips)."""
    budget = account_budget(threshold, default)
    kept = [a for a in net_attempts if a["protocol"] not in _LOCKOUT_PROTOCOLS]
    skips: list[dict] = []
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for a in net_attempts:
        if a["protocol"] in _LOCKOUT_PROTOCOLS:
            groups.setdefault((a["host"], a["protocol"], a["username"]), []).append(a)
    for (host, proto, user), atts in groups.items():
        ordered = sorted(atts, key=lambda a: (a.get("confidence") or 0), reverse=True)
        if budget is None:
            kept += ordered
            continue
        kept += ordered[:budget]
        reason = "lockout_policy" if budget == 0 else "lockout_budget"
        skips += [{"product": a["product"], "reason": reason, "via": "brutus", "host": host,
                   "port": a["port"], "protocol": proto, "username": user} for a in ordered[budget:]]
    return kept, skips


def parse_brutus_jsonl(text: str) -> list[dict]:
    """Brutus ``--json`` stdout → success records (dict lines with a ``username``); noise skipped. Pure."""
    hits: list[dict] = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and rec.get("username"):
            hits.append(rec)
    return hits


def redact(record: dict) -> dict:
    """Shallow copy with a non-empty ``password`` masked, for any rendered report. Pure."""
    out = dict(record)
    if out.get("password"):
        out["password"] = "****"  # noqa: S105
    return out


def _split_target(target: str) -> tuple[str, int]:
    tail = target.split("://", 1)[-1]
    host, _, port = tail.rpartition(":")
    return (host, int(port)) if host and port.isdigit() else (tail, 0)
