"""Optional AI stages for the external pipeline (opt-in via PTFLOW_AI).

Each function is best-effort: it fetches a client via make_client() (None ⇒ no-op) and never raises out
to the orchestrator. Terminal AI: ClaudeHypothesisProvider (findings triage → hypotheses.jsonl, via the
agent seam) + report() (narrative report.md). Per-app AI (ai_wordlist / ai_secret_triage) is in the
second half of this module.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel

from ptflow.core import tools
from ptflow.core.agent import HypothesisDraft
from ptflow.core.ai.client import make_client
from ptflow.core.log import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ptflow.core.ai.client import LLMClient
    from ptflow.core.paths import Activity

log = get_logger()

_MAX_FINDINGS = 400  # cap the triage/report prompt input

# --- ai_triage (agent seam) ------------------------------------------------------------------------

TRIAGE_SYSTEM = (
    "You are a senior penetration tester triaging the consolidated findings of an automated external "
    "recon run. Correlate findings ACROSS types (a CVE on a component + an exposed path + a leaked "
    "secret can chain), flag likely false positives, and propose concrete, testable exploitation "
    "hypotheses. Be precise and conservative: only propose a hypothesis you could actually verify. "
    "Return at most 30 hypotheses, highest-impact first."
)

REPORT_SYSTEM = (
    "You are a penetration tester writing the findings section of an external assessment report. "
    "Given the consolidated findings and the triage hypotheses, write clean GitHub-flavored Markdown: "
    "an executive summary, then findings grouped and ordered by severity, each with evidence, impact, "
    "and remediation. Do not invent findings not present in the input."
)


class Hypothesis(BaseModel):
    title: str
    subject: str | None = None
    rationale: str | None = None
    technique: str | None = None
    confidence: Literal["low", "medium", "high"] = "low"


class HypothesesOut(BaseModel):
    hypotheses: list[Hypothesis]


def _triage_user(records: Sequence[dict]) -> str:
    return ("Consolidated findings (JSON lines, one per finding, `type` is the finding class):\n"
            + "\n".join(json.dumps(r) for r in records[:_MAX_FINDINGS]))


class ClaudeHypothesisProvider:
    """Claude-backed HypothesisProvider: correlate consolidated findings into exploitation hypotheses."""

    name = "claude"

    def __init__(self, client: LLMClient) -> None:
        self._client = client

    def propose(self, records: Sequence[dict]) -> list[HypothesisDraft]:
        if not records:
            return []
        out = self._client.complete_json(TRIAGE_SYSTEM, _triage_user(records), HypothesesOut)
        if out is None:
            return []
        return [HypothesisDraft(title=h.title, subject=h.subject, rationale=h.rationale,
                                technique=h.technique, confidence=h.confidence)
                for h in out.hypotheses]


def _report_user(records: Sequence[dict], hypotheses: Sequence[dict]) -> str:
    return ("## Consolidated findings\n"
            + "\n".join(json.dumps(r) for r in records[:_MAX_FINDINGS])
            + "\n\n## Triage hypotheses\n"
            + "\n".join(json.dumps(h) for h in hypotheses))


def report(activity: Activity) -> None:
    """Terminal AI report hook: consolidated findings + hypotheses → <activity>/report.md. No-op when
    the AI layer is off/unavailable or there is nothing to report."""
    client = make_client()
    if client is None:
        return
    from ptflow.core.agent import gather_records  # noqa: PLC0415 (avoid an import cycle at load)

    records = gather_records(activity)
    hyps = tools.read_jsonl(activity.findings / "hypotheses.jsonl")
    if not records and not hyps:
        return
    text = client.complete_text(REPORT_SYSTEM, _report_user(records, hyps))
    if text:
        (activity.base / "report.md").write_text(text, encoding="utf-8")
        log.info("  → report.md (%d findings, %d hypotheses)", len(records), len(hyps))
