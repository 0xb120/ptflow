"""Agent and hypothesis provider abstractions (TBD in later task)."""

from __future__ import annotations

from typing import Protocol


class HypothesisProvider(Protocol):
    """Protocol for hypothesis providers (TBD)."""

    def __call__(self) -> None: ...
