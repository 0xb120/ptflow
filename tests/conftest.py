"""Pytest configuration for the PIPT test suite."""

import os

# Suppress the "I/O operation on closed file" ValueError from Prefect's
# subprocess-server logger during pytest teardown.  Prefect emits an INFO log
# ("Stopping temporary server …") after pytest has already closed the captured
# streams; setting the log level to WARNING prevents that record from reaching
# PrefectConsoleHandler altogether.
os.environ.setdefault("PREFECT_LOGGING_LEVEL", "WARNING")
