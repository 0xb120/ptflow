"""Optional agent-backed stages for the internal pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ptflow.core import tools
from ptflow.core.agents.credential_research import (
    normalize_observations,
    research_default_credentials,
    write_credential_research,
)
from ptflow.core.agents.research import ResearchAgent, ResearchRun
from ptflow.core.ai.client import stage_enabled
from ptflow.core.stage import Stage
from ptflow.pipelines.internal import tasks

if TYPE_CHECKING:
    from ptflow.core.agents import AgentAccess
    from ptflow.core.paths import Activity


def _credential_observations(activity: Activity, app_id: str) -> list[dict[str, str]]:
    ws = activity.app(app_id)
    services = tools.read_jsonl(ws.canonical("services.jsonl"))
    software = tasks.software_from_services(services)
    observed = [
        {"product": item.get("product", ""), "version": item.get("version", ""),
         "protocol": item.get("product", "")}
        for item in software
    ]
    observed += [
        {"product": record.get("product") or record.get("service") or "",
         "version": record.get("version") or "",
         "protocol": record.get("service") or record.get("protocol") or "unknown"}
        for record in services
    ]
    return normalize_observations(observed)


def ai_credential_research(
    activity: Activity, app_id: str, *, agents: AgentAccess,
) -> None:
    """Research documented product defaults after the phase-1 service fingerprint."""
    ws = activity.app(app_id)
    observations = _credential_observations(activity, app_id)
    agent = agents.require("research", ResearchAgent)
    if not observations:
        run = ResearchRun(
            objective="", output=None, hits=(), documents=(), trace=(), error="no_observations",
        )
        write_credential_research(ws.root, observations, run, [])
        return
    run, proposals = research_default_credentials(agent, observations)
    write_credential_research(ws.root, observations, run, proposals)


def per_app_stages() -> tuple[Stage, ...]:
    return (
        Stage("ai_credential_research", ai_credential_research, per_app=True, phase=2,
              net=True, agents=("research",)),
    ) if stage_enabled("research") else ()
