"""Vuln/exploitation hypothesis stage — seam + stub provider (file-based, no DB).

Input: the per-app `services.jsonl` artifacts read from disk. Output: a
consolidated `findings/hypotheses.jsonl` at the activity root. The real
Claude-backed provider is a future drop-in behind HypothesisProvider.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from pipt.core import tools

if TYPE_CHECKING:
    from pipt.core.paths import Activity


@dataclass(frozen=True)
class HypothesisDraft:
    title: str
    subject: str | None = None
    rationale: str | None = None
    technique: str | None = None
    confidence: str | None = None


class HypothesisProvider(Protocol):
    name: str

    def propose(self, services: Sequence[dict]) -> list[HypothesisDraft]: ...


class StubProvider:
    """Placeholder provider: one low-confidence draft per service."""

    name = "stub"

    def propose(self, services: Sequence[dict]) -> list[HypothesisDraft]:
        drafts: list[HypothesisDraft] = []
        for s in services:
            svc = s.get("service") or "unknown"
            subject = f"{s.get('ip')}:{s.get('port')}"
            drafts.append(
                HypothesisDraft(
                    title=f"{svc} on {subject} — review for known CVEs",
                    subject=subject,
                    technique="version-based CVE lookup",
                    confidence="low",
                )
            )
        return drafts


def propose_hypotheses(activity: Activity, provider: HypothesisProvider | None = None) -> int:
    """Read every app group's services.jsonl, ask the provider, and write the
    consolidated findings/hypotheses.jsonl. Returns the number of hypotheses.
    """
    prov = provider or StubProvider()
    services: list[dict] = []
    for ws in activity.list_apps():
        services.extend(tools.read_jsonl(ws.canonical("services.jsonl")))
    drafts = prov.propose(services)
    records = [
        {
            "title": d.title,
            "subject": d.subject,
            "rationale": d.rationale,
            "technique": d.technique,
            "confidence": d.confidence,
            "source": prov.name,
        }
        for d in drafts
    ]
    return tools.write_jsonl(activity.findings / "hypotheses.jsonl", records)
