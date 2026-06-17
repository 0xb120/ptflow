# src/pipt/core/agent.py
"""Vuln/exploitation hypothesis stage — seam + stub provider.

Input: inventory queried from the DB. Output: rows in `hypothesis`. The real
Claude-backed provider is a future drop-in behind HypothesisProvider.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pipt.core import db


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
    provider: HypothesisProvider | None = None,
) -> int:
    prov = provider or StubProvider()
    drafts = prov.propose(db.list_hosts(conn), db.list_services(conn))
    for d in drafts:
        db.insert_hypothesis(
            conn,
            title=d.title,
            service_id=d.service_id,
            subject=d.subject,
            rationale=d.rationale,
            technique=d.technique,
            confidence=d.confidence,
            source=prov.name,
        )
    conn.commit()
    return len(drafts)
