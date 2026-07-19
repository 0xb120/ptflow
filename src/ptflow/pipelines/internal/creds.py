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
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ptflow.core import tools
from ptflow.core.agents.form_login import FormLoginProbe
from ptflow.core.log import get_logger, is_verbose
from ptflow.core.stage import Stage
from ptflow.pipelines.internal.tasks import BRUTUS, _banner_product, web_targets_from

if TYPE_CHECKING:
    from ptflow.core.paths import Activity

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


def _place_candidate(
    candidate: dict, sockets: list[ServiceSocket], web_map: dict[tuple[str, int], str],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Route one candidate's pair onto matching sockets: web sockets → a Brutus http/https (Basic) attempt
    AND a form attempt; mapped non-web sockets → a Brutus attempt; unmapped → skip; no match → no_match."""
    product = str(candidate.get("product") or "")
    base = {"product": product, "username": str(candidate.get("username") or ""),
            "password": str(candidate.get("password") or ""), "confidence": candidate.get("confidence"),
            "source_urls": list(candidate.get("source_urls") or []),
            "rationale": str(candidate.get("rationale") or "")}
    matched = [s for s in sockets if _product_matches(product, s.product)]
    if not matched:
        return [], [], [{"product": product, "reason": "no_match", "via": "brutus"}]
    brutus, forms, skips = [], [], []
    for s in matched:
        if (url := web_map.get((s.host, s.port))):
            scheme = url.split("://", 1)[0]
            brutus.append({**base, "protocol": scheme, "host": s.host, "port": s.port})
            forms.append({**base, "url": url, "host": s.host, "port": s.port})
        elif (proto := socket_proto(s)):
            brutus.append({**base, "protocol": proto, "host": s.host, "port": s.port})
        else:
            skips.append({"product": product, "reason": "unmapped_protocol", "via": "brutus",
                          "host": s.host, "port": s.port})
    return brutus, forms, skips


def plan_attempts(
    candidates: list[dict], services: list[dict], *,
    lockout_threshold: int | None, lockout_default: int,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Curated candidates + fingerprinted services → concrete Brutus/form attempts, applying the
    per-account lockout budget to the Brutus set. Pure."""
    sockets = service_sockets(services)
    web_map = web_urls(services)
    brutus_attempts: list[dict] = []
    form_attempts: list[dict] = []
    skips: list[dict] = []
    for c in candidates:
        b, f, s = _place_candidate(c, sockets, web_map)
        brutus_attempts += b
        form_attempts += f
        skips += s
    brutus_attempts, lockout_skips = _apply_lockout(brutus_attempts, lockout_threshold, lockout_default)
    return brutus_attempts, form_attempts, skips + lockout_skips


def group_forms(form_attempts: list[dict]) -> list[dict]:
    """One browser session per web panel URL; try all its pairs, keeping per-pair metadata for finding
    attribution."""
    jobs: dict[str, dict] = {}
    for a in form_attempts:
        job = jobs.setdefault(a["url"], {"url": a["url"], "host": a["host"], "port": a["port"],
                                         "pairs": [], "by_pair": {}})
        pair = (a["username"], a["password"])
        if pair not in job["pairs"]:
            job["pairs"].append(pair)
        job["by_pair"][pair] = {"confidence": a["confidence"], "source_urls": a["source_urls"],
                                "rationale": a["rationale"], "product": a["product"]}
    return list(jobs.values())


def _run_brutus(cmd: list[str], *, dest, label: str) -> str:  # noqa: ANN001
    """Best-effort Brutus run (bounded), stdout persisted to ``dest``. '' on any error."""
    try:
        out = tools.run(cmd, stream_stderr=is_verbose(), timeout=BRUTUS_TIMEOUT)
    except (OSError, subprocess.SubprocessError, tools.AbortedError) as exc:
        log.debug("  · %s failed: %s", label, exc)
        return ""
    tools.write_text(dest, out)
    _chmod_600(dest)
    return out


def _chmod_600(path) -> None:  # noqa: ANN001
    try:
        path.chmod(0o600)
    except OSError as exc:  # pragma: no cover
        log.debug("  · chmod 600 failed on %s: %s", path, exc)


def _enrich_brutus(hits: list[dict], attempt: dict, app_id: str) -> list[dict]:
    out: list[dict] = []
    for h in hits:
        host, port = _split_target(str(h.get("target", "")))
        out.append({
            "app_id": app_id, "type": "default-credentials", "severity": "high", "via": "brutus",
            "tool": "brutus", "host": host or attempt["host"], "port": port or attempt["port"],
            "protocol": attempt["protocol"], "product": attempt["product"],
            "username": h.get("username", attempt["username"]),
            "password": h.get("password", attempt["password"]), "confidence": attempt["confidence"],
            "source_urls": attempt["source_urls"], "rationale": attempt["rationale"],
            "banner": h.get("banner", ""),
            "evidence": f"default credentials accepted on {attempt['protocol']}"})
    return out


def _load(activity: Activity, app_id: str) -> tuple:  # type: ignore[type-arg]
    ws = activity.app(app_id)
    if shutil.which(BRUTUS) is None:
        return ws, None, None
    return (ws, tools.read_jsonl(ws.canonical("credential_candidates.jsonl")),
            tools.read_jsonl(ws.canonical("services.jsonl")))


def creds_test_brutus(activity: Activity, app_id: str) -> None:
    """LOOP 3 (opt-in) — try curated default credentials on non-HTTP services and HTTP Basic-auth panels
    via Brutus (one invocation per pair x socket). Lockout-aware, best-effort -> findings/creds_brutus.jsonl
    (0600)."""
    ws, candidates, services = _load(activity, app_id)
    if not candidates or not services:
        log.debug("  · skip creds_test_brutus [%s] (brutus/candidates/services absent)", app_id)
        return
    threshold = parse_lockout_threshold(tools.read_jsonl(ws.findings / "ad_enum.jsonl"))
    brutus_attempts, _forms, skips = plan_attempts(
        candidates, services, lockout_threshold=threshold, lockout_default=_lockout_default())
    flags = mode_flags()
    findings: list[dict] = []
    for i, a in enumerate(brutus_attempts):
        out = _run_brutus(
            [BRUTUS, "--target", f'{a["host"]}:{a["port"]}', "--protocol", a["protocol"],
             "-u", a["username"], "-p", a["password"], "--json", *flags],
            dest=ws.raw("brutus") / f'{a["protocol"]}-{i}.jsonl', label=f'creds-{a["protocol"]}')
        findings += _enrich_brutus(parse_brutus_jsonl(out), a, app_id)
    hits = len(findings)
    findings += [{"app_id": app_id, "skipped": True, **s} for s in skips if s.get("via") == "brutus"]
    tools.write_jsonl(ws.findings / "creds_brutus.jsonl", findings)
    _chmod_600(ws.findings / "creds_brutus.jsonl")
    log.info("  → creds_test_brutus [%s] — %d attempt(s) → %d hit(s)", app_id, len(brutus_attempts), hits)


def _enrich_form(  # noqa: PLR0913
    outcome,  # noqa: ANN001
    url: str,
    host: str,
    port: int,
    pair,  # noqa: ANN001
    meta: dict,
    app_id: str,
) -> dict:
    return {
        "app_id": app_id,
        "type": "default-credentials",
        "severity": "high",
        "via": "form",
        "tool": "form-login",
        "host": host,
        "port": port,
        "protocol": "http",
        "url": url,
        "product": meta.get("product", ""),
        "username": pair[0],
        "password": pair[1],
        "confidence": outcome.confidence or meta.get("confidence"),
        "source_urls": meta.get("source_urls", []),
        "rationale": meta.get("rationale", ""),
        "evidence": f"default credentials accepted on web login form ({outcome.reason})",
    }


def creds_test_forms(activity: Activity, app_id: str) -> None:
    """LOOP 3 (opt-in) — try curated default credentials on HTTP FORM login panels via the Playwright
    FormLoginProbe (provider-agnostic, no Anthropic key). Best-effort → findings/creds_forms.jsonl (0600)."""
    ws = activity.app(app_id)
    candidates = tools.read_jsonl(ws.canonical("credential_candidates.jsonl"))
    services = tools.read_jsonl(ws.canonical("services.jsonl"))
    if not candidates or not services:
        log.debug("  · skip creds_test_forms [%s] (no candidates/services)", app_id)
        return
    probe = FormLoginProbe(settle_ms=2000 if resolve_mode() == "cautious" else 1000)
    if not probe.available:
        log.debug("  · skip creds_test_forms [%s] (playwright absent)", app_id)
        return
    threshold = parse_lockout_threshold(tools.read_jsonl(ws.findings / "ad_enum.jsonl"))
    _brutus, form_attempts, _skips = plan_attempts(
        candidates, services, lockout_threshold=threshold, lockout_default=_lockout_default())
    findings: list[dict] = []
    for job in group_forms(form_attempts):
        for pair in job["pairs"]:
            outcome = probe.attempt(job["url"], pair[0], pair[1])
            if outcome.success:
                findings.append(_enrich_form(outcome, job["url"], job["host"], job["port"], pair,
                                             job["by_pair"][pair], app_id))
    tools.write_jsonl(ws.findings / "creds_forms.jsonl", findings)
    _chmod_600(ws.findings / "creds_forms.jsonl")
    log.info("  → creds_test_forms [%s] — %d panel(s) → %d hit(s)",
             app_id, len(group_forms(form_attempts)), len(findings))


def per_app_stages() -> tuple[Stage, ...]:
    """The opt-in phase-3 credential-testing stages (spliced by pipeline.py only when enabled)."""
    return (
        Stage("creds_test_brutus", creds_test_brutus, per_app=True, phase=3, net=True),
        Stage("creds_test_forms", creds_test_forms, per_app=True, phase=3, net=True),
    )
