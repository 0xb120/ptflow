"""Source-grounded default-credential proposal use-case for the ResearchAgent."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path

from pydantic import BaseModel, Field

from ptflow.core import tools
from ptflow.core.agents.research import ResearchAgent, ResearchRun
from ptflow.core.log import get_logger

log = get_logger()

_SYSTEM = (
    "Extract documented factory/default login credentials for the observed products. Return only "
    "credentials explicitly supported by fetched source documents, never search snippets alone. "
    "Each proposal must cite exact source "
    "URLs, identify the product/version/protocol, and state conditions such as factory-reset-only or "
    "first-login-only. Do not generate weak-password guesses and do not infer credentials from product "
    "names. An empty proposals list is correct when evidence is insufficient."
)
_BLANK_PASSWORD_PHRASES = ("blank password", "no password", "password is blank", "empty password")


class CredentialProposal(BaseModel):
    product: str
    version: str | None = None
    protocol: str
    username: str
    password: str
    source_urls: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    rationale: str
    conditions: list[str] = []


class CredentialResearchOut(BaseModel):
    proposals: list[CredentialProposal]


def normalize_observations(records: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    """Keep only non-sensitive product/version/protocol identity; never send target addresses."""
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for record in records:
        product = str(
            record.get("product") or record.get("canonical_product")
            or record.get("name") or record.get("technology") or ""
        ).strip()
        if not product:
            continue
        version = str(record.get("version") or record.get("canonical_version") or "").strip()
        protocol = str(record.get("protocol") or record.get("service") or "unknown").strip().lower()
        key = (product.casefold(), version.casefold(), protocol)
        unique[key] = {"product": product, "version": version, "protocol": protocol}
    return list(unique.values())[:20]


def _product_is_observed(product: str, observations: list[dict[str, str]]) -> bool:
    candidate = product.casefold()
    return any(
        candidate in observed["product"].casefold()
        or observed["product"].casefold() in candidate
        for observed in observations
    )


def _literal_evidence(proposal: CredentialProposal, run: ResearchRun[CredentialResearchOut]) -> bool:
    username = proposal.username.casefold()
    password = proposal.password.casefold()
    for url in proposal.source_urls:
        for document in run.documents:
            if document.url != url:
                continue
            evidence = document.text.casefold()
            if not evidence or username not in evidence:
                continue
            if password and password in evidence:
                return True
            if not password and any(phrase in evidence for phrase in _BLANK_PASSWORD_PHRASES):
                return True
    return False


def validate_proposals(
    run: ResearchRun[CredentialResearchOut], observations: list[dict[str, str]],
) -> list[CredentialProposal]:
    """Reject hallucinated/unattributed credentials unless a fetched source contains them."""
    if run.output is None:
        return []
    known_urls = run.source_urls()
    accepted: dict[tuple[str, str, str, str], CredentialProposal] = {}
    for proposal in run.output.proposals:
        if not _product_is_observed(proposal.product, observations):
            continue
        if not proposal.source_urls or any(url not in known_urls for url in proposal.source_urls):
            continue
        if not _literal_evidence(proposal, run):
            continue
        key = (
            proposal.product.casefold(), proposal.protocol.casefold(),
            proposal.username, proposal.password,
        )
        accepted[key] = proposal
    return list(accepted.values())


def research_default_credentials(
    agent: ResearchAgent, observations: list[dict[str, str]],
) -> tuple[ResearchRun[CredentialResearchOut], list[CredentialProposal]]:
    products = normalize_observations(observations)
    objective = (
        "Find documented factory/default credentials for these fingerprinted products. Do not include "
        "target hostnames or infer weak passwords. Observations:\n"
        + json.dumps(products, sort_keys=True)
    )
    run = agent.research(objective, CredentialResearchOut, output_system=_SYSTEM)
    return run, validate_proposals(run, products)


def write_credential_research(
    root: Path, observations: list[dict[str, str]],
    run: ResearchRun[CredentialResearchOut], proposals: list[CredentialProposal],
) -> int:
    """Persist a reproducible audit trail and a private canonical candidate file."""
    raw = root / "raw" / "research"
    tools.write_jsonl(root / "credential_research_observations.jsonl", observations)
    tools.write_jsonl(raw / "search_results.jsonl", [hit.model_dump() for hit in run.hits])
    tools.write_jsonl(raw / "sources.jsonl", [doc.model_dump() for doc in run.documents])
    trace = [item.model_dump() for item in run.trace]
    if run.error:
        trace.append({"step": 0, "action": "research", "status": "unavailable", "detail": run.error})
    tools.write_jsonl(raw / "trace.jsonl", trace)
    candidate_path = root / "credential_candidates.jsonl"
    count = tools.write_jsonl(candidate_path, [proposal.model_dump() for proposal in proposals])
    candidate_path.chmod(0o600)
    log.info("  → credential research — %d source-grounded candidate(s)", count)
    return count
