"""Stub tools: no external scanners. Deterministic, so tests are stable."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from pipt.core import scope, tools, workspace

if TYPE_CHECKING:
    from pipt.core.paths import Activity


def fake_ip(seed: str) -> str:
    h = hashlib.sha1(seed.encode()).digest()  # noqa: S324
    return f"10.{h[0]}.{h[1]}.{h[2]}"


def _app_id(signature: str) -> str:
    return hashlib.sha1(signature.encode()).hexdigest()[:12]  # noqa: S324


def discover(activity: Activity) -> None:
    """BREADTH stub: expand the scope into scope/ and discover hosts.

    Reads the scope from scope/scope_init.txt; writes scope/scope_{urls,dns,ip}.txt
    (split by kind) and the canonical asset_discovery/hosts.jsonl (apex + www host).
    """
    targets = scope.parse_scope(activity.scope_init.read_text(encoding="utf-8"))
    tools.write_lines(activity.scope_urls, [t.raw for t in targets if t.kind == "url"])
    tools.write_lines(
        activity.scope_dns, [t.normalized for t in targets if t.kind in ("domain", "wildcard")]
    )
    tools.write_lines(
        activity.scope_ip, [t.normalized for t in targets if t.kind in ("ip", "cidr")]
    )

    records: list[dict] = []
    for t in targets:
        ip = fake_ip(t.normalized)
        records.append({"name": t.normalized, "ip": ip, "source": "stub"})
        records.append({"name": f"www.{t.normalized}", "ip": ip, "source": "stub"})
    tools.write_jsonl(activity.asset_discovery_raw("discover") / "out.jsonl", records)
    tools.write_jsonl(activity.asset_discovery_canonical("hosts.jsonl"), records)


def cluster(activity: Activity) -> list[str]:
    """Group discovered hosts into 'equal application' groups.

    Stub signature: an apex and its www host are the same app. The real
    pipeline would key on httpx (Title, Content-Length, Webserver).
    """
    hosts = tools.read_jsonl(activity.asset_discovery_canonical("hosts.jsonl"))
    groups: dict[str, dict] = {}
    for h in hosts:
        apex = h["name"].removeprefix("www.")
        signature = f"app:{apex}"            # fabricated app signature
        app_id = _app_id(signature)
        g = groups.setdefault(app_id, {"signature": signature, "hosts": []})
        g["hosts"].append(h["name"])

    for app_id, g in groups.items():
        ws = activity.app(app_id).ensure()
        members = sorted(set(g["hosts"]))
        workspace.write_meta(ws.meta, {"app_id": app_id, "signature": g["signature"], "hosts": members})
        tools.write_lines(ws.hosts, members)
    return sorted(groups)


def enum(activity: Activity, app_id: str) -> None:
    """DEPTH stub: 'fingerprint' each host of the app group into a service row."""
    ws = activity.app(app_id).ensure()
    records = [
        {
            "ip": fake_ip(h.removeprefix("www.")),
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "version": "stub/1.0",
            "source": "stub",
        }
        for h in tools.read_lines(ws.hosts)
    ]
    tools.write_jsonl(ws.raw("enum") / "out.jsonl", records)
    tools.write_jsonl(ws.canonical("services.jsonl"), records)
