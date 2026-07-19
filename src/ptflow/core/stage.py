"""Stage abstraction (dependency DAG) + Pipeline protocol."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NamedTuple, Protocol

if TYPE_CHECKING:
    from ptflow.core.agent import HypothesisProvider
    from ptflow.core.paths import Activity


@dataclass(frozen=True)
class Stage:
    """A pipeline phase — a node in the dependency DAG.

    Stages communicate only via on-disk artifacts. Execution order and
    concurrency come from `needs`: a stage runs once every stage it names has
    finished, and stages with no dependency between them run in parallel.

    Call convention:
      - activity stage (per_app=False): ``run(activity)`` — runs once over the scope.
      - per-app stage  (per_app=True):  ``run(activity, app_id)`` — once per app group.

    `needs` references stage names in the SAME scope AND the SAME `phase` (the
    cluster step is the fan-out boundary between activity and per-app scopes).

    `phase` groups per-app stages into successive **loops**. All per-app stages
    sharing a phase run as one DAG; loops run in ascending phase order with a
    global barrier between them (every app finishes loop N before any app starts
    loop N+1). A later loop therefore reads an earlier loop's on-disk artifacts
    directly — cross-loop ordering is the barrier, NOT `needs`. `phase` is ignored
    for activity stages, which all run as the single pre-cluster DAG.

    `spanning` marks an activity-scope stage (per_app=False) that should NOT block the
    breadth→cluster barrier: it's launched once its breadth `needs` are done and awaited
    only at the terminal fan-in, so it overlaps clustering and all the per-app loops
    (e.g. a whole-scope nuclei scan running ∥ the rest of the pipeline).

    `cluster_scope` marks a "spanning post-cluster" activity-scope stage (per_app=False): it runs
    ONCE after `cluster` (so it can read every group's meta.json/hosts.txt via
    `activity.list_apps()`), ∥ the per-app loops, joined at the terminal fan-in. Unlike `spanning`
    (launched after breadth), it's launched after clustering — e.g. a single batched screenshot run
    over one candidate per group, producing one unified gallery.

    `after_phase` marks an activity-scope CHECKPOINT that runs after the global barrier at the end of
    that per-app phase and before the following phase starts. It is the aggregation seam for an early
    report/snapshot over every app group; unlike `spanning`, it is awaited immediately. Checkpoints are
    mutually exclusive with `per_app`, `spanning`, and `cluster_scope`.
    """

    name: str
    run: Callable[..., None]
    needs: tuple[str, ...] = field(default_factory=tuple)
    per_app: bool = False
    phase: int = 1
    spanning: bool = False
    cluster_scope: bool = False
    after_phase: int | None = None
    net: bool = True
    """Whether the stage does network I/O. Network stages are tagged ``net`` and counted against the
    global network-concurrency cap (``_NET_SLOTS``); set ``net=False`` for purely offline stages
    (wordlist tokenisation, response-store mining, wordlist provisioning) so they neither claim a
    network slot nor get the ``net`` tag."""
    agents: tuple[str, ...] = field(default_factory=tuple)
    """Named runtime agents injected into this stage through an ``agents=AgentAccess`` keyword.

    Agent declarations are metadata, not dependency edges: the orchestrator resolves only the named
    agents immediately before calling the stage, so existing stage signatures and pipelines stay
    unchanged. A stage that declares agents must accept the keyword argument explicitly (or through
    ``**kwargs``). Agent names are included in the resume contract and Prefect tags.
    """

    def __post_init__(self) -> None:
        if any(not name.strip() for name in self.agents) or len(set(self.agents)) != len(self.agents):
            msg = "agents must contain unique, non-blank names"
            raise ValueError(msg)
        if self.after_phase is None:
            return
        if self.after_phase < 1:
            msg = "after_phase must be >= 1"
            raise ValueError(msg)
        if self.per_app or self.spanning or self.cluster_scope:
            msg = "after_phase checkpoints must be activity-scope and non-spanning"
            raise ValueError(msg)


def stage_band(stage: Stage) -> str:
    """The stage's execution band (pure) — the SINGLE source for both the Prefect UI tags and the
    `ptflow steps` view, so the two can't diverge. breadth | spanning | post-cluster |
    loop:<phase> | checkpoint:<phase>."""
    if stage.spanning:
        return "spanning"
    if stage.cluster_scope:
        return "post-cluster"
    if stage.after_phase is not None:
        return f"checkpoint:{stage.after_phase}"
    if stage.per_app:
        return f"loop:{stage.phase}"
    return "breadth"


def enabled_stages(stages: Sequence[Stage], disabled: Collection[str]) -> list[Stage]:
    """The stages left after removing the disabled ones (pure). Safe WITHOUT rewiring `needs`:
    topo_order/_submit_dag ignore a missing dependency name, and stages read on-disk inputs
    tolerantly — a surviving consumer of a removed stage just finds empty/absent inputs."""
    return [s for s in stages if s.name not in disabled]


def impacted_dependents(stages: Sequence[Stage], disabled: Collection[str]) -> list[str]:
    """Surviving stages that transitively depend (via `needs`) on a disabled stage — the ones that
    will run with empty/absent inputs (pure, sorted). Only `needs`-declared, same-scope edges are
    modeled; cross-loop consumers that read another loop's artifacts across the barrier are NOT
    declared in Stage metadata, so they aren't captured here."""
    by_name = {s.name: s for s in stages}
    disabled_set = set(disabled)
    memo: dict[str, bool] = {}

    def needs_disabled(name: str) -> bool:
        if name in memo:
            return memo[name]
        memo[name] = False  # cycle guard (the DAG shouldn't have any) — overwritten below
        stage = by_name.get(name)
        result = stage is not None and any(
            dep in disabled_set or needs_disabled(dep) for dep in stage.needs
        )
        memo[name] = result
        return result

    return sorted(s.name for s in stages if s.name not in disabled_set and needs_disabled(s.name))


class Followup(NamedTuple):
    """A chained pipeline run a Pipeline can request AFTER its own run finishes — pipeline composition.

    The CLI runs each Followup as a SEPARATE top-level ``orchestrate()`` (a sub-activity nested under the
    parent activity dir), NOT as a nested Prefect subflow — so every pipeline stays a clean top-level flow
    with its own task-runner/teardown, and the files-as-only-state invariant holds (the parent hands off
    via an on-disk scope artifact it wrote). The CLI persists lineage/state under the parent's
    ``reports/`` directory and maintains a summary-only composed report that links each authoritative
    child report. Same DUCK-TYPED convention as ``consolidate``/``preflight``:
    a Pipeline MAY define ``followups(self, activity) -> list[Followup]``; it's read via ``getattr`` and
    absent by default, so it stays off the Protocol and the core stays pipeline-agnostic.
    """

    pipeline: str   # a registered pipeline name (resolved with load_pipeline)
    activity: str   # sub-activity name, nested under the parent activity's dir
    scope: str      # path to the scope file the parent wrote (the hand-off artifact)


class Pipeline(Protocol):
    name: str
    stages: Sequence[Stage]

    def cluster(self, activity: Activity) -> list[str]:
        """Group asset-discovery output into app groups — the fan-out pivot."""
        ...

    def provider(self) -> HypothesisProvider: ...


def _callable_identity(value: object) -> str:
    """Stable import identity for a stage/hook callable; never hashes source or filesystem paths."""
    module = getattr(value, "__module__", type(value).__module__)
    qualname = getattr(value, "__qualname__", type(value).__qualname__)
    return f"{module}:{qualname}"


def resume_contract(pipeline: Pipeline) -> dict[str, object]:
    """Deterministic artifact contract used to decide whether completion markers are reusable.

    The live graph catches structural rewiring automatically. ``resume_epoch`` is the explicit escape
    hatch for semantic/output changes inside an otherwise-identical callable graph. It defaults to 1
    for third-party/test pipelines, while built-in pipelines declare it explicitly.
    """
    epoch = getattr(pipeline, "resume_epoch", 1)
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        msg = f"pipeline {pipeline.name!r} resume_epoch must be a positive integer"
        raise ValueError(msg)
    cluster = getattr(pipeline, "cluster", None)
    return {
        "contract_schema": 1,
        "pipeline": pipeline.name,
        "resume_epoch": epoch,
        "cluster": _callable_identity(cluster) if callable(cluster) else None,
        "stages": [
            {
                "name": stage.name,
                "run": _callable_identity(stage.run),
                "needs": list(stage.needs),
                "per_app": stage.per_app,
                "phase": stage.phase,
                "spanning": stage.spanning,
                "cluster_scope": stage.cluster_scope,
                "after_phase": stage.after_phase,
                "net": stage.net,
                "agents": list(stage.agents),
            }
            for stage in pipeline.stages
        ],
    }


def resume_contract_fingerprint(pipeline: Pipeline) -> str:
    """SHA-256 of ``resume_contract``; stable across processes and insensitive to docs/log changes."""
    encoded = json.dumps(
        resume_contract(pipeline), separators=(",", ":"), sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
