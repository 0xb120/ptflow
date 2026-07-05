"""ptflow CLI: run a pipeline over a scope, and serve the Prefect UI for observability."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ptflow.core import runconfig
from ptflow.core.log import setup_logging

# NB: orchestrator/pipelines are imported INSIDE main() — their constants read PTFLOW_* at import, so the
# run config must populate os.environ first (see _run).

_UI_URL = "http://127.0.0.1:4200"
_DEFAULT_API_URL = f"{_UI_URL}/api"


def _serve() -> int:
    """Start the Prefect server (UI + API) for observability — foreground/long-running, so run it in
    its own terminal. Then `ptflow run … --observe` makes a run show up in the UI at the URL below.
    The server is pure telemetry (run graph, states, timings, logs); the pipeline's state stays on
    disk, and runs without it work exactly the same (ephemeral)."""
    prefect = "prefect" if shutil.which("prefect") else None
    cmd = ([prefect] if prefect else [sys.executable, "-m", "prefect"]) + [
        "server", "start", "--host", "127.0.0.1", "--port", "4200",
    ]
    print(f"Prefect UI → {_UI_URL}   ·   then in another terminal: ptflow run … --observe")  # noqa: T201
    return subprocess.run(cmd, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ptflow")
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
        help="send this run to the Prefect UI (default: the local server) — start it with `ptflow serve`",
    )
    run.add_argument(
        "--config", default=None, metavar="PATH",
        help="TOML file of operator knobs (profile, oast, tool paths, …); see ptflow.toml.example",
    )
    run.add_argument(
        "--set", action="append", default=None, metavar="KEY=VALUE", dest="overrides",
        help="override one config knob, repeatable (e.g. --set oast=on --set profile=home)",
    )
    run.add_argument(
        "--ai", action="store_true",
        help="enable the optional AI layer (triage/report/secret-triage/wordlist); requires the "
             "'ai' extra + ANTHROPIC_API_KEY. Equivalent to --set ai=on.",
    )

    sub.add_parser("serve", help="start the Prefect server + UI for observability (foreground)")

    doctor = sub.add_parser(
        "doctor", help="check that a pipeline's external tools + datasets are installed",
    )
    doctor.add_argument(
        "pipeline", nargs="?", default="external",
        help="which pipeline's requirements to check (default: external)",
    )

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        return _serve()

    if args.cmd == "run":
        return _run(args)

    if args.cmd == "doctor":
        return _doctor(args.pipeline)

    return 1


def _doctor(pipeline_name: str) -> int:
    """Verify a pipeline's host dependencies (external tools + datasets) are installed, from the same
    `requirements()` manifest `preflight` uses. Prints a grouped report; exit 0 iff every CORE tool is
    present (missing optional tools/datasets are warnings). Honours PTFLOW_* env overrides (the
    pipeline's tool-path constants read them at import); a pipeline with no `requirements()` hook is a
    graceful no-op pass."""
    from ptflow.core import requirements as reqmod  # noqa: PLC0415
    from ptflow.pipelines import load_pipeline  # noqa: PLC0415 (constants read PTFLOW_* at import)

    pipeline = load_pipeline(pipeline_name)
    get_reqs = getattr(pipeline, "requirements", None)
    if not callable(get_reqs):
        print(f"pipeline '{pipeline_name}' declares no requirements — nothing to check")  # noqa: T201
        return 0
    report = reqmod.check(get_reqs())
    print(reqmod.render_report(report, pipeline=pipeline_name))  # noqa: T201
    return report.exit_code


def _apply_ai_flag(overrides: list[str], *, ai: bool) -> list[str]:
    """Append ``ai=on`` for the ``--ai`` convenience flag — but only when the user did not already
    pass an explicit ``ai=`` via ``--set``. ``--set`` must win over the flag (documented precedence:
    ``--set`` > env > config; ``--ai`` is sugar for ``--set ai=on``, not a higher-precedence override)."""
    if ai and not any(o.split("=", 1)[0].strip() == "ai" for o in overrides):
        return [*overrides, "ai=on"]
    return overrides


def _run(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose)
    # Resolve operator config (--set > env > file) and write it into os.environ BEFORE importing the
    # pipeline — its module-level constants read PTFLOW_* at import time.
    try:
        overrides = _apply_ai_flag(list(args.overrides or []), ai=args.ai)
        config = runconfig.load_config(args.config)
        resolved = runconfig.resolve(config, os.environ, overrides)
    except runconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)  # noqa: T201
        return 2
    runconfig.apply(resolved)

    from ptflow.core.orchestrator import orchestrate  # noqa: PLC0415 (after runconfig.apply)
    from ptflow.core.paths import Activity  # noqa: PLC0415
    from ptflow.pipelines import load_pipeline  # noqa: PLC0415 (constants read PTFLOW_* at import)

    pipeline = load_pipeline(args.pipeline)
    try:
        disabled = runconfig.resolve_disabled_steps(
            config, overrides, pipeline.name, {s.name for s in pipeline.stages})
    except runconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)  # noqa: T201
        return 2
    base, failures = orchestrate(
        pipeline, args.activity, args.scope, root=args.root,
        resume=args.resume, observe=args.observe, disabled_steps=disabled,
    )
    runconfig.snapshot(Path(base), resolved,
                       disabled_keys=[f"steps.{pipeline.name}.{n}" for n in sorted(disabled)])
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
            fu_pipeline = load_pipeline(fu.pipeline)
            try:
                fu_disabled = runconfig.resolve_disabled_steps(
                    config, overrides, fu_pipeline.name, {s.name for s in fu_pipeline.stages})
            except runconfig.ConfigError as e:
                print(f"config error: {e}", file=sys.stderr)  # noqa: T201
                return 2
            fu_base, fu_failures = orchestrate(
                fu_pipeline, fu.activity, fu.scope, root=str(base),
                resume=args.resume, observe=args.observe, disabled_steps=fu_disabled,
            )
            runconfig.snapshot(Path(fu_base), resolved,
                               disabled_keys=[f"steps.{fu_pipeline.name}.{n}" for n in sorted(fu_disabled)])
            print(fu_base)  # noqa: T201
            if fu_failures < 0:
                return 130
            exit_code = exit_code or (1 if fu_failures else 0)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
