"""Stub tools: no external scanners. Deterministic, so tests are stable."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from pipt.core import tools, workspace

if TYPE_CHECKING:
    from pipt.core.paths import Engagement
    from pipt.core.scope import Target


def fake_ip(seed: str) -> str:
    h = hashlib.sha1(seed.encode()).digest()  # noqa: S324
    return f"10.{h[0]}.{h[1]}.{h[2]}"


def _dump_jsonl(records: list[dict]) -> str:
    return "\n".join(json.dumps(r) for r in records) + ("\n" if records else "")


def discover(eng: Engagement, targets: list[Target]) -> None:
    """BREADTH stub: derive apex + www host per target, with target provenance."""
    records: list[dict] = []
    for t in targets:
        ip = fake_ip(t.normalized)
        records.append({"name": t.normalized, "ip": ip, "source": "stub", "targets": [t.tid]})
        records.append(
            {"name": f"www.{t.normalized}", "ip": ip, "source": "stub", "targets": [t.tid]}
        )
    raw = eng.surface_raw("discover")
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "out.jsonl").write_text(_dump_jsonl(records), encoding="utf-8")
    out = eng.surface_canonical("hosts.jsonl")
    out.write_text(_dump_jsonl(records), encoding="utf-8")
    workspace.record(eng.surface_manifest, role="hosts", path=out, tool="discover", inputs="scope")


def enum(eng: Engagement, target: Target) -> None:
    """DEPTH stub: 'fingerprint' each assigned host into a service row."""
    ws = eng.target(target.tid).ensure()
    hosts = tools.read_lines(ws.canonical("hosts.txt"))
    records = [
        {
            "ip": fake_ip(h.removeprefix("www.")),
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "version": "stub/1.0",
            "source": "stub",
        }
        for h in hosts
    ]
    raw = ws.raw("enum")
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "out.jsonl").write_text(_dump_jsonl(records), encoding="utf-8")
    out = ws.canonical("services.jsonl")
    out.write_text(_dump_jsonl(records), encoding="utf-8")
    workspace.record(ws.manifest, role="services", path=out, tool="enum", inputs="hosts.txt")
