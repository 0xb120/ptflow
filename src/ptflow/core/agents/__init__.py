"""Stage-scoped, capability-limited agents.

The legacy terminal hypothesis seam remains in :mod:`ptflow.core.agent`.  This package hosts agents
that participate *inside* the DAG: a Stage declares the names it needs and the orchestrator injects an
``AgentAccess`` containing only those agents.  Factories are lazy so optional AI dependencies and
network clients are not imported for ordinary runs.
"""

from ptflow.core.agents.registry import (
    AgentAccess,
    AgentBuildContext,
    AgentFactory,
    build_agent_access,
)

__all__ = ["AgentAccess", "AgentBuildContext", "AgentFactory", "build_agent_access"]
