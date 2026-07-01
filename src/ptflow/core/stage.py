"""Stage abstraction (dependency DAG) + Pipeline protocol."""

from __future__ import annotations

from collections.abc import Callable, Sequence
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
    """

    name: str
    run: Callable[..., None]
    needs: tuple[str, ...] = field(default_factory=tuple)
    per_app: bool = False
    phase: int = 1
    spanning: bool = False
    cluster_scope: bool = False
    net: bool = True
    """Whether the stage does network I/O. Network stages are tagged ``net`` and counted against the
    global network-concurrency cap (``_NET_SLOTS``); set ``net=False`` for purely offline stages
    (wordlist tokenisation, response-store mining, wordlist provisioning) so they neither claim a
    network slot nor get the ``net`` tag."""


class Followup(NamedTuple):
    """A chained pipeline run a Pipeline can request AFTER its own run finishes — pipeline composition.

    The CLI runs each Followup as a SEPARATE top-level ``orchestrate()`` (a sub-activity nested under the
    parent activity dir), NOT as a nested Prefect subflow — so every pipeline stays a clean top-level flow
    with its own task-runner/teardown, and the files-as-only-state invariant holds (the parent hands off
    via an on-disk scope artifact it wrote). Same DUCK-TYPED convention as ``consolidate``/``preflight``:
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
