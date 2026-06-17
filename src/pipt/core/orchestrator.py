# src/pipt/core/orchestrator.py
"""Phased-hybrid orchestration: breadth (barrier) -> [dedup] -> depth (fan-out) -> ingest -> agent.

Only strings cross the Prefect task boundary: depth workers reconstruct the
Engagement, Target and Pipeline from (pipeline_name, scan_id, root, tid).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from prefect import flow, task
from prefect.task_runners import ThreadPoolTaskRunner

from pipt.core import db, ingest, scope, workspace
from pipt.core.agent import propose_hypotheses
from pipt.core.config import CONFIG
from pipt.core.paths import Engagement
from pipt.core.stage import Mode, Pipeline, Stage
from pipt.core.tools import write_lines
from pipt.pipelines import load_pipeline


def split_stages(stages: list[Stage]) -> tuple[list[Stage], list[Stage]]:
    breadth = [s for s in stages if s.mode is Mode.BREADTH]
    depth = [s for s in stages if s.mode is Mode.DEPTH]
    return breadth, depth


def assign_enum_hosts(conn: sqlite3.Connection, *, aggregate: bool) -> dict[str, list[str]]:
    rows = conn.execute(
        "SELECT h.name AS name, t.tid AS tid FROM host h "
        "JOIN host_target ht ON ht.host_id = h.id "
        "JOIN target t ON t.id = ht.target_id"
    ).fetchall()
    by_host: dict[str, list[str]] = {}
    for r in rows:
        by_host.setdefault(r["name"], []).append(r["tid"])
    assignment: dict[str, list[str]] = {}
    for host, tids in by_host.items():
        chosen = [min(tids)] if aggregate else tids
        for tid in chosen:
            assignment.setdefault(tid, []).append(host)
    return assignment


@task(tags=["net"])
def _run_depth_chain(pipeline_name: str, scan_id: str, root: str | None, tid: str) -> str:
    pipeline = load_pipeline(pipeline_name)
    eng = Engagement.for_scan(scan_id, Path(root) if root else None)
    target = scope.target_from_meta(workspace.read_meta(eng.target(tid).meta))
    _, depth = split_stages(list(pipeline.stages))
    for stage in depth:
        stage.run(eng, target)
    return tid


@flow(task_runner=ThreadPoolTaskRunner(max_workers=CONFIG.fanout.max_workers))  # ty: ignore[no-matching-overload]
def _depth_flow(pipeline_name: str, scan_id: str, root: str | None, tids: list[str]) -> None:
    futures = [_run_depth_chain.submit(pipeline_name, scan_id, root, tid) for tid in tids]
    for fut in futures:
        fut.result(raise_on_failure=False)


def orchestrate(
    pipeline: Pipeline,
    scan_id: str,
    scope_file: str,
    *,
    root: str | None = None,
    aggregate: bool = True,
) -> Path:
    eng = Engagement.for_scan(scan_id, Path(root) if root else None).ensure()
    eng.scope.write_text(Path(scope_file).read_text(encoding="utf-8"), encoding="utf-8")
    targets = scope.parse_scope(eng.scope.read_text(encoding="utf-8"))

    conn = db.connect(eng.db)
    db.init_schema(conn, db.core_schema(), pipeline.extension_schema())
    for t in targets:
        db.upsert_target(conn, tid=t.tid, raw=t.raw, kind=t.kind)
        ws = eng.target(t.tid).ensure()
        workspace.write_meta(ws.meta, t.__dict__)
    conn.commit()

    handlers = {**ingest.CORE_HANDLERS, **pipeline.ingest_handlers()}
    breadth, _ = split_stages(list(pipeline.stages))

    # 1. BREADTH stages (single invocation over all targets) + ingest
    for stage in breadth:
        stage.run(eng, targets)
    ingest.ingest_manifest(conn, eng.surface_manifest, handlers)

    # 2. Pre-enum dedup barrier: write each target's enum input (hosts.txt)
    assignment = assign_enum_hosts(conn, aggregate=aggregate)
    for tid, hosts in assignment.items():
        ws = eng.target(tid)
        out = ws.canonical("hosts.txt")
        write_lines(out, hosts)
        workspace.record(ws.manifest, role="enum_input", path=out, tool="dedup", inputs="db:host")

    # 3. DEPTH fan-out per target (Prefect), then ingest
    _depth_flow(pipeline.name, scan_id, root, [t.tid for t in targets])
    for ws in eng.list_targets():
        ingest.ingest_manifest(conn, ws.manifest, handlers)

    # 4. Agent stage (terminal)
    propose_hypotheses(conn, pipeline.provider())

    conn.close()
    return eng.base


def rebuild_db(scan_id: str, *, root: str | None = None, pipeline_name: str = "example") -> Path:
    pipeline = load_pipeline(pipeline_name)
    eng = Engagement.for_scan(scan_id, Path(root) if root else None)
    if eng.db.exists():
        eng.db.unlink()
    conn = db.connect(eng.db)
    db.init_schema(conn, db.core_schema(), pipeline.extension_schema())
    for ws in eng.list_targets():
        if ws.meta.exists():
            t = scope.target_from_meta(workspace.read_meta(ws.meta))
            db.upsert_target(conn, tid=t.tid, raw=t.raw, kind=t.kind)
    conn.commit()
    handlers = {**ingest.CORE_HANDLERS, **pipeline.ingest_handlers()}
    ingest.ingest_manifest(conn, eng.surface_manifest, handlers)
    for ws in eng.list_targets():
        ingest.ingest_manifest(conn, ws.manifest, handlers)
    conn.close()
    return eng.base
