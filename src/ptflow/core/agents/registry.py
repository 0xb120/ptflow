"""Resolve only the agents explicitly declared by a Stage."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, TypeVar, cast

if TYPE_CHECKING:
    from ptflow.core.paths import Activity
    from ptflow.core.stage import Pipeline, Stage


class RuntimeAgent(Protocol):
    name: str
    available: bool


@dataclass(frozen=True)
class AgentBuildContext:
    pipeline_name: str
    stage_name: str
    activity: Activity


class AgentFactory(Protocol):
    def __call__(self, context: AgentBuildContext) -> RuntimeAgent: ...


A = TypeVar("A", bound=RuntimeAgent)


class AgentAccess(Mapping[str, RuntimeAgent]):
    """The least-privilege agent view injected into one stage invocation."""

    def __init__(self, agents: Mapping[str, RuntimeAgent] | None = None) -> None:
        self._agents = dict(agents or {})

    def __getitem__(self, name: str) -> RuntimeAgent:
        return self._agents[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._agents)

    def __len__(self) -> int:
        return len(self._agents)

    def require(self, name: str, expected: type[A] | None = None) -> A:
        """Return a declared agent, optionally asserting its concrete runtime type."""
        try:
            agent = self._agents[name]
        except KeyError as exc:
            msg = f"stage did not declare agent {name!r}"
            raise LookupError(msg) from exc
        if expected is not None and not isinstance(agent, expected):
            msg = f"agent {name!r} is {type(agent).__name__}, expected {expected.__name__}"
            raise TypeError(msg)
        return cast("A", agent)


def _research_factory(context: AgentBuildContext) -> RuntimeAgent:
    from ptflow.core.agents.research import ResearchAgent  # noqa: PLC0415

    return ResearchAgent.from_env(context.activity)


def _builtin_factories() -> dict[str, AgentFactory]:
    return {"research": _research_factory}


def build_agent_access(pipeline: Pipeline, stage: Stage, activity: Activity) -> AgentAccess:
    """Build the exact agents declared by ``stage``.

    A pipeline may expose an optional ``agent_factories()`` hook to add or replace factories.  The
    hook keeps custom/plugin agents out of the core registry while preserving deterministic Stage
    metadata and the existing file-only communication contract.
    """
    if not stage.agents:
        return AgentAccess()
    factories = _builtin_factories()
    hook = getattr(pipeline, "agent_factories", None)
    if callable(hook):
        factories.update(hook())
    missing = [name for name in stage.agents if name not in factories]
    if missing:
        msg = f"unknown agent(s) for stage {stage.name!r}: {', '.join(missing)}"
        raise LookupError(msg)
    context = AgentBuildContext(
        pipeline_name=pipeline.name,
        stage_name=stage.name,
        activity=activity,
    )
    return AgentAccess({name: factories[name](context) for name in stage.agents})
