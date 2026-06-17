"""Stage abstraction (declarative breadth/depth) + Pipeline protocol."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol

from pipt.core.ingest import Handler

if TYPE_CHECKING:
    from pipt.core.agent import HypothesisProvider


class Mode(Enum):
    BREADTH = "breadth"   # one invocation over all targets (barrier)
    DEPTH = "depth"       # per-target chain (fan-out)


@dataclass(frozen=True)
class Stage:
    name: str
    mode: Mode
    run: Callable[..., None]
    produces: tuple[str, ...] = field(default_factory=tuple)


class Pipeline(Protocol):
    name: str
    stages: Sequence[Stage]

    def extension_schema(self) -> str: ...
    def ingest_handlers(self) -> dict[str, Handler]: ...
    def provider(self) -> HypothesisProvider: ...
