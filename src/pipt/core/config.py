"""Centralized configuration — every tunable here, nothing hardcoded in tasks."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FanOut:
    max_workers: int = 3       # concurrent per-target depth chains (xargs -P 3 equivalent)
    net_limit: int = 10        # optional global Prefect concurrency limit on tag "net"


@dataclass(frozen=True)
class Retries:
    tool_retries: int = 2
    tool_retry_delay_s: int = 10


@dataclass(frozen=True)
class DB:
    busy_timeout_ms: int = 5000


@dataclass(frozen=True)
class Config:
    fanout: FanOut = field(default_factory=FanOut)
    retries: Retries = field(default_factory=Retries)
    db: DB = field(default_factory=DB)


CONFIG = Config()
"""Module-level singleton. Import and read; construct Config() to override in tests."""
