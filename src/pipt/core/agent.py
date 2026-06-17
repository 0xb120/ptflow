"""Temporary stub — the real agent module is built in Task 10.

Exists only so pipt.core.stage can resolve the HypothesisProvider type under
TYPE_CHECKING before Task 10 lands.
"""

from __future__ import annotations

from typing import Protocol


class HypothesisProvider(Protocol):
    name: str
