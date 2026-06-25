"""pipt CLI: run a pipeline over a scope."""

from __future__ import annotations

import argparse

from pipt.core.log import setup_logging
from pipt.core.orchestrator import orchestrate
from pipt.pipelines import load_pipeline


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

    args = parser.parse_args(argv)

    if args.cmd == "run":
        setup_logging(verbose=args.verbose)
        base, failures = orchestrate(
            load_pipeline(args.pipeline), args.activity, args.scope, root=args.root,
            resume=args.resume,
        )
        print(base)  # noqa: T201
        return 1 if failures else 0  # non-zero exit when any stage failed (CI/automation signal)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
