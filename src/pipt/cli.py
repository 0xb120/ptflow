"""pipt CLI: run a pipeline over a scope, and serve the Prefect UI for observability."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from pipt.core import runconfig
from pipt.core.log import setup_logging

# NB: orchestrator/pipelines are imported INSIDE main() — their constants read PIPT_* at import, so the
# run config must populate os.environ first (see _run).

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
    run.add_argument(
        "--config", default=None, metavar="PATH",
        help="TOML file of operator knobs (profile, oast, tool paths, …); see pipt.toml.example",
    )
    run.add_argument(
        "--set", action="append", default=None, metavar="KEY=VALUE", dest="overrides",
        help="override one config knob, repeatable (e.g. --set oast=on --set profile=home)",
    )

    sub.add_parser("serve", help="start the Prefect server + UI for observability (foreground)")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        return _serve()

    if args.cmd == "run":
        return _run(args)

    return 1


def _run(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose)
    # Resolve operator config (--set > env > file) and write it into os.environ BEFORE importing the
    # pipeline — its module-level constants read PIPT_* at import time.
    try:
        resolved = runconfig.resolve(runconfig.load_config(args.config), os.environ, args.overrides)
    except runconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)  # noqa: T201
        return 2
    runconfig.apply(resolved)

    from pipt.core.orchestrator import orchestrate  # noqa: PLC0415 — must follow runconfig.apply()
    from pipt.core.paths import Activity  # noqa: PLC0415
    from pipt.pipelines import load_pipeline  # noqa: PLC0415 — (constants read PIPT_* at import)

    pipeline = load_pipeline(args.pipeline)
    base, failures = orchestrate(
        pipeline, args.activity, args.scope, root=args.root,
        resume=args.resume, observe=args.observe,
    )
    runconfig.snapshot(Path(base), resolved)  # reproducibility: effective knobs next to the run
    print(base)  # noqa: T201
    if failures < 0:
        return 130  # interrupted (SIGINT) — partial results saved; resume with --resume
    exit_code = 1 if failures else 0  # non-zero exit when any stage failed (CI/automation signal)

    # Pipeline COMPOSITION: run any follow-on pipelines this one declares (e.g. internal → webscan on the
    # aggregated web services), each as a SEPARATE top-level run nested under this activity's dir — NOT a
    # nested Prefect subflow. Duck-typed like consolidate/preflight; absent by default.
    get_followups = getattr(pipeline, "followups", None)
    if callable(get_followups):
        for fu in get_followups(Activity(Path(base))):
            fu_base, fu_failures = orchestrate(
                load_pipeline(fu.pipeline), fu.activity, fu.scope, root=str(base),
                resume=args.resume, observe=args.observe,
            )
            runconfig.snapshot(Path(fu_base), resolved)
            print(fu_base)  # noqa: T201
            if fu_failures < 0:
                return 130
            exit_code = exit_code or (1 if fu_failures else 0)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
