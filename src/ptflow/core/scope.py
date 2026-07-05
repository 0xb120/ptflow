"""Scope parsing: turn raw scope tokens into stable Target records."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str
    normalized: str
    tid: str


def classify(token: str) -> str:
    t = token.strip()
    if t.startswith(("http://", "https://")):
        return "url"
    if t.startswith("*."):
        return "wildcard"
    try:
        ipaddress.ip_network(t, strict=False)
    except ValueError:
        return "domain"
    return "cidr" if "/" in t else "ip"


def normalize(token: str, kind: str) -> str:
    t = token.strip().lower()
    if kind == "url":
        # bare host only: drop scheme, path AND any :port — a host:port (https://h:8443/x → h) is not a
        # resolvable DNS name, so the port must not leak into scope_dns (it would fail to resolve). The
        # specific port isn't honored for scanning anyway (portscan covers the curated WEB_PORTS).
        return t.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    if kind == "wildcard":
        return t[2:]
    return t


def target_id(normalized: str) -> str:
    return "t_" + hashlib.sha1(normalized.encode()).hexdigest()[:6]  # noqa: S324


def parse_scope(text: str) -> list[Target]:
    seen: dict[str, Target] = {}
    for line in text.splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        kind = classify(token)
        norm = normalize(token, kind)
        tid = target_id(norm)
        if tid not in seen:
            seen[tid] = Target(raw=token, kind=kind, normalized=norm, tid=tid)
    return list(seen.values())


def target_from_meta(meta: dict) -> Target:
    return Target(
        raw=meta["raw"],
        kind=meta["kind"],
        normalized=meta["normalized"],
        tid=meta["tid"],
    )


@dataclass(frozen=True)
class Allowlist:
    exact_hosts: frozenset[str]
    wildcard_apexes: frozenset[str]
    nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


def norm_host(host: str) -> str:
    """Canonical host for scope comparison: lower-case, no trailing dot, IDN→punycode."""
    h = host.strip().lower().rstrip(".")
    try:
        return h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return h


def build_allowlist(targets: list[Target]) -> Allowlist:
    """Bucket classified scope targets into the authorization allowlist. domain/url → exact host;
    *.x → wildcard apex; ip/cidr → an ipaddress network (bad entries skipped)."""
    exact: set[str] = set()
    wild: set[str] = set()
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for t in targets:
        if t.kind in ("domain", "url"):
            exact.add(norm_host(t.normalized))
        elif t.kind == "wildcard":
            wild.add(norm_host(t.normalized))
        elif t.kind in ("ip", "cidr"):
            try:
                nets.append(ipaddress.ip_network(t.raw, strict=False))
            except ValueError:
                continue
    return Allowlist(frozenset(exact), frozenset(wild), tuple(nets))


def host_in_scope(host: str, allow: Allowlist) -> bool:
    """Rules 1+2: exact-host match, or a suffix match under a *.apex (apex included)."""
    h = norm_host(host)
    if h in allow.exact_hosts:
        return True
    return any(h == w or h.endswith("." + w) for w in allow.wildcard_apexes)


def ip_in_scope(ip: str, allow: Allowlist) -> bool:
    """Rule 3: the IP is inside an explicitly-listed scope network (v4 or v6)."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return any(addr in net for net in allow.nets)
