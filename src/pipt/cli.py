# src/pipt/cli.py
"""pipt CLI: run a pipeline, or rebuild the DB from raw."""

from __future__ import annotations

import argparse

from pipt.core.orchestrator import orchestrate, rebuild_db
from pipt.pipelines import load_pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pipt")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run a pipeline over a scope")
    run.add_argument("pipeline")
    run.add_argument("scan_id")
    run.add_argument("scope")
    run.add_argument("--root", default=None)
    run.add_argument("--no-aggregate", action="store_true", help="enumerate overlapping assets per target")

    ing = sub.add_parser("ingest", help="rebuild the SQLite DB from raw/manifests")
    ing.add_argument("scan_id")
    ing.add_argument("--root", default=None)
    ing.add_argument("--pipeline", default="example")

    args = parser.parse_args(argv)

    if args.cmd == "run":
        base = orchestrate(
            load_pipeline(args.pipeline),
            args.scan_id,
            args.scope,
            root=args.root,
            aggregate=not args.no_aggregate,
        )
        print(base)  # noqa: T201
        return 0

    if args.cmd == "ingest":
        base = rebuild_db(args.scan_id, root=args.root, pipeline_name=args.pipeline)
        print(base)  # noqa: T201
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
