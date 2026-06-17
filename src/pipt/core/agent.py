# src/pipt/core/agent.py
"""Vuln/exploitation hypothesis stage — seam + stub provider.

Input: inventory queried from the DB. Output: a raw JSONL artifact (role
'hypotheses') keyed by the service NATURAL key (ip:port). The serialized ingest
projects this into the `hypothesis` table, so a rebuild from raw reproduces it
faithfully.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from pipt.core import db, workspace

if TYPE_CHECKING:
    from pipt.core.paths import Engagement


@dataclass(frozen=True)
class HypothesisDraft:
    title: str
    service_id: int | None = None
    subject: str | None = None
    rationale: str | None = None
    technique: str | None = None
    confidence: str | None = None


class HypothesisProvider(Protocol):
    name: str

    def propose(
        self,
        hosts: Sequence[sqlite3.Row],
        services: Sequence[sqlite3.Row],
    ) -> list[HypothesisDraft]: ...


class StubProvider:
    """Placeholder provider: one low-confidence draft per service."""

    name = "stub"

    def propose(
        self,
        hosts: Sequence[sqlite3.Row],  # noqa: ARG002
        services: Sequence[sqlite3.Row],
    ) -> list[HypothesisDraft]:
        drafts: list[HypothesisDraft] = []
        for s in services:
            svc = s["service"] or "unknown"
            drafts.append(
                HypothesisDraft(
                    title=f"{svc} on {s['ip']}:{s['port']} — review for known CVEs",
                    service_id=s["id"],
                    technique="version-based CVE lookup",
                    confidence="low",
                )
            )
        return drafts


def propose_hypotheses(
    conn: sqlite3.Connection,
    eng: Engagement,
    provider: HypothesisProvider | None = None,
) -> int:
    """Read inventory from the DB, ask the provider for drafts, and persist them
    to a raw JSONL artifact (role 'hypotheses') keyed by the service NATURAL key
    (ip:port), NOT the surrogate id. The serialized ingest projects this into the
    `hypothesis` table, so a rebuild from raw reproduces it faithfully.
    Returns the number of drafts written.
    """
    prov = provider or StubProvider()
    services = db.list_services(conn)
    id_to_key = {s["id"]: f'{s["ip"]}:{s["port"]}' for s in services}
    drafts = prov.propose(db.list_hosts(conn), services)
    records = [
        {
            "title": d.title,
            "service_key": id_to_key.get(d.service_id) if d.service_id is not None else None,
            "subject": d.subject,
            "rationale": d.rationale,
            "technique": d.technique,
            "confidence": d.confidence,
            "source": prov.name,
        }
        for d in drafts
    ]
    out = eng.surface_canonical("hypotheses.jsonl")
    out.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    workspace.record(
        eng.surface_manifest, role="hypotheses", path=out, tool=prov.name, inputs="db:service,host"
    )
    return len(records)
