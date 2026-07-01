"""Run logging for the ptflow CLI: per-step visibility, a verbose mode, and a
persistent per-run file log.

The CLI calls setup_logging(); orchestrate() calls add_file_handler() once the
activity dir exists. Library code just calls get_logger().info/debug. When invoked
without setup (e.g. tests calling orchestrate directly) the logger has no console
handler, so it stays quiet.

The logger level is always DEBUG; the *console* handler is what gets raised to INFO
without --verbose. That split lets the file handler persist the full record (every
command + verbose output) regardless of how quiet the console is.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOGGER = logging.getLogger("ptflow")


def get_logger() -> logging.Logger:
    return _LOGGER


def _is_console(h: logging.Handler) -> bool:
    return isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)


def is_verbose() -> bool:
    """Whether the console shows DEBUG (--verbose). Derived from the console handler,
    so it stays correct even though the logger level is always DEBUG (for the file)."""
    return any(_is_console(h) and h.level <= logging.DEBUG for h in _LOGGER.handlers)


def setup_logging(*, verbose: bool = False) -> None:
    """Console = per-step progress: INFO, or DEBUG (commands + tool output) with
    --verbose. The logger itself always passes DEBUG so add_file_handler() can persist
    the full record independent of console verbosity."""
    _LOGGER.setLevel(logging.DEBUG)
    if not any(_is_console(h) for h in _LOGGER.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        _LOGGER.addHandler(handler)
    for handler in _LOGGER.handlers:
        if _is_console(handler):
            handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    _LOGGER.propagate = False


def add_file_handler(path: Path) -> None:
    """Persist the full run log (DEBUG: every command + verbose output) to `path`,
    independent of console verbosity. Replaces any prior file handler so reruns and
    tests never accumulate handlers."""
    for h in list(_LOGGER.handlers):
        if isinstance(h, logging.FileHandler):
            h.close()
            _LOGGER.removeHandler(h)
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
    _LOGGER.addHandler(fh)
