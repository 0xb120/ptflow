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
    BREADTH = "breadth"   # one invocation over all targets (barrier)
    DEPTH = "depth"       # per-app-group chain (fan-out)


@dataclass(frozen=True)
class Stage:
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
