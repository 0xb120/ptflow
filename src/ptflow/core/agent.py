"""Vuln/exploitation hypothesis stage — seam + stub provider (file-based, no DB).

Input: the CONSOLIDATED activity findings (`<activity>/findings/<type>.jsonl`, written by the
pipeline's `consolidate` terminal step, which runs first) plus any per-app `services.jsonl`. Output: a
consolidated `findings/hypotheses.jsonl` at the activity root. The real Claude-backed provider drops in
behind `HypothesisProvider` when the run is `--ai` (see pipelines/external/ai.py); otherwise the
dormant `StubProvider` runs.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ptflow.core import tools

if TYPE_CHECKING:
    from ptflow.core.paths import Activity


@dataclass(frozen=True)
class HypothesisDraft:
    title: str
    subject: str | None = None
    rationale: str | None = None
    technique: str | None = None
    confidence: str | None = None


class HypothesisProvider(Protocol):
    name: str

    def propose(self, records: Sequence[dict]) -> list[HypothesisDraft]: ...


def _subject(rec: dict) -> str | None:
    if rec.get("ip") and rec.get("port"):
        return f"{rec['ip']}:{rec['port']}"
    return rec.get("app_id") or rec.get("host") or rec.get("matched-at")


class StubProvider:
    """Placeholder provider: one low-confidence draft per finding/service record."""

    name = "stub"

    def propose(self, records: Sequence[dict]) -> list[HypothesisDraft]:
        drafts: list[HypothesisDraft] = []
        for r in records:
            subj = _subject(r)
            typ = r.get("type") or r.get("service") or "finding"
            drafts.append(
                HypothesisDraft(
                    title=f"review {typ} on {subj or 'target'} — known CVEs / manual follow-up",
                    subject=subj,
                    technique="version-based CVE lookup",
                    confidence="low",
                )
            )
        return drafts


def gather_records(activity: Activity) -> list[dict]:
    """The consolidated activity findings (each record stamped `type` from its filename, skipping the
    agent's own hypotheses.jsonl) plus any per-app services.jsonl (stamped type=service). This is the
    provider's input — the correlation surface for the real agent, and the stub's per-record source."""
    records: list[dict] = []
    if activity.findings.exists():
        for f in sorted(activity.findings.glob("*.jsonl")):
            if f.name == "hypotheses.jsonl":
                continue
            records += [{"type": f.stem, **rec} for rec in tools.read_jsonl(f)]
    for ws in activity.list_apps():
        records += [{"type": "service", "app_id": ws.root.name, **rec}
                    for rec in tools.read_jsonl(ws.canonical("services.jsonl"))]
    return records


def propose_hypotheses(activity: Activity, provider: HypothesisProvider | None = None) -> int:
    """Gather the consolidated findings, ask the provider, write findings/hypotheses.jsonl. Returns the
    number of hypotheses. Never reads its own output (hypotheses.jsonl is excluded)."""
    prov = provider or StubProvider()
    drafts = prov.propose(gather_records(activity))
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
