"""Scope parsing: turn raw scope tokens into stable Target records."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CIDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")


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
    if _CIDR.match(t):
        return "cidr"
    if _IP.match(t):
        return "ip"
    return "domain"


# TODO(domain): normalize() keeps :port in URL hosts; _IP/_CIDR don't validate  # noqa: TD003,FIX002
# octet ranges. Acceptable for the stub scaffolding; tighten when wiring a real toolset.
def normalize(token: str, kind: str) -> str:
    t = token.strip().lower()
    if kind == "url":
        return t.split("://", 1)[1].split("/", 1)[0]
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
