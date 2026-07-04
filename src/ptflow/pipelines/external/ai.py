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

from ptflow.core import tools, workspace
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
    from ptflow.core.agent import gather_records  # noqa: PLC0415 (lazy — load-time hygiene)

    records = gather_records(activity)
    hyps = tools.read_jsonl(activity.findings / "hypotheses.jsonl")
    if not records and not hyps:
        return
    text = client.complete_text(REPORT_SYSTEM, _report_user(records, hyps))
    if text:
        (activity.base / "report.md").write_text(text, encoding="utf-8")
        log.info("  → report.md (%d findings, %d hypotheses)", len(records), len(hyps))


# --- ai_wordlist (phase 2, net=False) --------------------------------------------------------------

_WORDLIST_MAX_ENDPOINTS = 200
_WORDLIST_MAX_CANDIDATES = 300

WORDLIST_SYSTEM = (
    "You generate content-discovery wordlist candidates for a web app. Given a sample of its observed "
    "endpoints and detected tech stack, propose likely UNLINKED path segments, file names, and "
    "parameter names to brute-force — tailored to what the app appears to do (e.g. an e-commerce app: "
    "coupon, voucher, giftcard, promo). Output single tokens only (no slashes, no scheme, no host), "
    "lowercase, deduplicated. Be specific to this app; do not emit generic filler."
)


class WordlistOut(BaseModel):
    candidates: list[str]


def _wordlist_user(endpoints: list[str], tech: list[str], apex: str | None) -> str:
    return (f"apex: {apex or 'unknown'}\ntech: {', '.join(tech) or 'unknown'}\n"
            "observed endpoints:\n" + "\n".join(endpoints[:_WORDLIST_MAX_ENDPOINTS]))


def ai_wordlist(activity: Activity, app_id: str) -> None:
    """PHASE 2 (net=False) — contextual content-discovery seed. Reads the phase-1 corpus (endpoints +
    tech) and asks the model for app-specific candidate tokens → wl_custom/ai_seed.txt. The phase-3
    barrier guarantees this file exists before build_content_wordlist folds it in. Best-effort no-op
    when AI is off/unavailable or there is nothing to seed from."""
    client = make_client()
    if client is None:
        return
    ws = activity.app(app_id)
    endpoints = tools.read_lines(ws.canonical("endpoints.txt"))
    meta = workspace.read_meta(ws.meta)
    tech = meta.get("tech") or []
    hosts = meta.get("hosts") or []
    if not endpoints and not tech:
        return
    apex = hosts[0] if hosts else None
    out = client.complete_json(WORDLIST_SYSTEM, _wordlist_user(endpoints, tech, apex), WordlistOut)
    if out is None:
        return
    n = tools.write_lines(ws.wl_custom / "ai_seed.txt", out.candidates[:_WORDLIST_MAX_CANDIDATES])
    log.info("  → ai_wordlist (%s) — %d candidate token(s) → ai_seed.txt", app_id, n)


# --- ai_secret_triage (phase 4, net=False) ---------------------------------------------------------

_SECRETS_MAX = 100

SECRET_SYSTEM = (
    "You triage secret-scanner leads from a web recon run. For each numbered secret, judge whether it "  # noqa: S105
    "is a REAL live credential, a TEST/example/placeholder value, or NOISE (false positive). Use the "
    "kind, value shape, and any context. Return one verdict per input index."
)


class SecretVerdict(BaseModel):
    index: int
    verdict: Literal["real", "test", "noise"]
    rationale: str


class SecretTriageOut(BaseModel):
    verdicts: list[SecretVerdict]


def _secret_user(secrets: list[dict]) -> str:
    return "\n".join(f"[{i}] {json.dumps(s)}" for i, s in enumerate(secrets))


def ai_secret_triage(activity: Activity, app_id: str) -> None:
    """PHASE 4 (net=False) — classify the secret-scanner leads (real/test/noise). Reads secrets.jsonl
    (guaranteed present by the phase-4 barrier), writes the SIDECAR findings/secrets_triage.jsonl
    (never mutates secrets.jsonl → write-once). Best-effort no-op when AI is off or there are no
    secrets."""
    client = make_client()
    if client is None:
        return
    ws = activity.app(app_id)
    secrets = tools.read_jsonl(ws.canonical("secrets.jsonl"))[:_SECRETS_MAX]
    if not secrets:
        return
    out = client.complete_json(SECRET_SYSTEM, _secret_user(secrets), SecretTriageOut)
    if out is None:
        return
    verdicts = [{"index": v.index, "verdict": v.verdict, "rationale": v.rationale,
                 "secret": secrets[v.index]}
                for v in out.verdicts if 0 <= v.index < len(secrets)]
    n = tools.write_jsonl(ws.findings / "secrets_triage.jsonl", verdicts)
    real = sum(1 for v in verdicts if v["verdict"] == "real")
    log.info("  → ai_secret_triage (%s) — %d verdict(s) (%d real) → secrets_triage.jsonl",
             app_id, n, real)
