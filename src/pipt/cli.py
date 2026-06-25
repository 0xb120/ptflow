"""pipt CLI: run a pipeline over a scope, and serve the Prefect UI for observability."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

from pipt.core.log import setup_logging
from pipt.core.orchestrator import orchestrate
from pipt.pipelines import load_pipeline

_UI_URL = "http://127.0.0.1:4200"
_DEFAULT_API_URL = f"{_UI_URL}/api"


def _serve() -> int:
    """Start the Prefect server (UI + API) for observability — foreground/long-running, so run it in
    its own terminal. Then `pipt run … --observe` makes a run show up in the UI at the URL below.
    The server is pure telemetry (run graph, states, timings, logs); the pipeline's state stays on
    disk, and runs without it work exactly the same (ephemeral)."""
    prefect = "prefect" if shutil.which("prefect") else None
    cmd = ([prefect] if prefect else [sys.executable, "-m", "prefect"]) + [
        "server", "start", "--host", "127.0.0.1", "--port", "4200",
    ]
    print(f"Prefect UI → {_UI_URL}   ·   then in another terminal: pipt run … --observe")  # noqa: T201
    return subprocess.run(cmd, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pipt")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run a pipeline over a scope")
    run.add_argument("pipeline")
    run.add_argument("activity")
    run.add_argument("scope")
    run.add_argument("--root", default=None, help="parent dir for the activity (default: cwd)")
    run.add_argument(
        "-v", "--verbose", action="store_true",
        help="show the exact command and full output of every tool invoked",
    )
    run.add_argument(
        "--resume", action="store_true",
        help="skip stages already completed in a prior run of this activity (same scope)",
    )
    run.add_argument(
        "--observe", nargs="?", const=_DEFAULT_API_URL, default=None, metavar="API_URL",
        help="send this run to the Prefect UI (default: the local server) — start it with `pipt serve`",
    )

    sub.add_parser("serve", help="start the Prefect server + UI for observability (foreground)")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        return _serve()

    if args.cmd == "run":
        setup_logging(verbose=args.verbose)
        base, failures = orchestrate(
            load_pipeline(args.pipeline), args.activity, args.scope, root=args.root,
            resume=args.resume, observe=args.observe,
        )
        print(base)  # noqa: T201
        return 1 if failures else 0  # non-zero exit when any stage failed (CI/automation signal)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
