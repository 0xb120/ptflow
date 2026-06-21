"""pipt CLI: run a pipeline over a scope."""

from __future__ import annotations

import argparse

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

    args = parser.parse_args(argv)

    if args.cmd == "run":
        base = orchestrate(load_pipeline(args.pipeline), args.activity, args.scope, root=args.root)
        print(base)  # noqa: T201
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
