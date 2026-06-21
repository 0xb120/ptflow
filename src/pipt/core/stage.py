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

    `needs` references stage names in the SAME scope (activity deps among activity
    stages; per-app deps among per-app stages). The cluster step is the fan-out
    boundary between the two scopes.
    """

    name: str
    run: Callable[..., None]
    needs: tuple[str, ...] = field(default_factory=tuple)
    per_app: bool = False


class Pipeline(Protocol):
    name: str
    stages: Sequence[Stage]

    def cluster(self, activity: Activity) -> list[str]:
        """Group asset-discovery output into app groups — the fan-out pivot."""
        ...

    def provider(self) -> HypothesisProvider: ...
