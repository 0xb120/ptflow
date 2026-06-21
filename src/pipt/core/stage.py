"""Stage abstraction (declarative breadth/depth) + Pipeline protocol."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pipt.core.agent import HypothesisProvider
    from pipt.core.paths import Activity


class Mode(Enum):
    BREADTH = "breadth"   # whole-scope phase, run once in order (barrier)
    DEPTH = "depth"       # per-app-group phase (fan-out)


@dataclass(frozen=True)
class Stage:
    """A pipeline phase. Stages communicate only via on-disk artifacts.

    Call convention (the orchestrator follows it):
      - BREADTH: ``run(activity)`` — reads/writes canonical files; sub-phases of
        the same pipeline chain through disk (e.g. expand → resolve → portscan).
      - DEPTH:   ``run(activity, app_id)`` — one fan-out invocation per app group.
    """

    name: str
    mode: Mode
    run: Callable[..., None]
    produces: tuple[str, ...] = field(default_factory=tuple)


class Pipeline(Protocol):
    name: str
    stages: Sequence[Stage]

    def cluster(self, activity: Activity) -> list[str]:
        """Group asset-discovery output into application groups.

        Creates one scans/<app_id>/ workspace per group (with meta.json +
        hosts.txt) and returns the list of app_ids. Runs between BREADTH and
        DEPTH stages.
        """
        ...

    def provider(self) -> HypothesisProvider: ...
