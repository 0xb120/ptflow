"""Run logging for the pipt CLI: per-step visibility + a verbose mode.

The CLI calls setup_logging(); library code just calls get_logger().info/debug.
When invoked without setup (e.g. tests calling orchestrate directly) the logger
has no handler, so it stays silent.
"""

from __future__ import annotations

import logging
import sys

_LOGGER = logging.getLogger("pipt")


def get_logger() -> logging.Logger:
    return _LOGGER


def setup_logging(*, verbose: bool = False) -> None:
    """INFO = per-step progress; DEBUG (verbose) = exact commands + full tool output."""
    level = logging.DEBUG if verbose else logging.INFO
    _LOGGER.setLevel(level)
    if not _LOGGER.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        _LOGGER.addHandler(handler)
    for handler in _LOGGER.handlers:
        handler.setLevel(level)
    _LOGGER.propagate = False
