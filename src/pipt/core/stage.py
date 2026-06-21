"""Stage abstraction (dependency DAG) + Pipeline protocol."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pipt.core.agent import HypothesisProvider
    from pipt.core.paths import Activity


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
    """

    name: str
    run: Callable[..., None]
    needs: tuple[str, ...] = field(default_factory=tuple)
    per_app: bool = False
    phase: int = 1


class Pipeline(Protocol):
    name: str
    stages: Sequence[Stage]

    def cluster(self, activity: Activity) -> list[str]:
        """Group asset-discovery output into app groups — the fan-out pivot."""
        ...

    def provider(self) -> HypothesisProvider: ...
