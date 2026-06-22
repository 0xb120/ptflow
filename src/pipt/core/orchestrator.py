"""Dependency-DAG orchestration: activity stages → cluster → per-app stages → agent.

Stages declare `needs` (same-scope dependencies); the scheduler runs them with
parallelism (independent stages run together, capped by max_workers) via Prefect
`wait_for`. Only strings cross the Prefect task boundary — `_run_stage`
reconstructs the Activity/Pipeline and runs a single stage by name.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from prefect import flow, task
from prefect.task_runners import ThreadPoolTaskRunner

from pipt.core.agent import propose_hypotheses
from pipt.core.config import CONFIG
from pipt.core.log import add_file_handler, get_logger
from pipt.core.paths import Activity
from pipt.core.stage import Pipeline, Stage
from pipt.pipelines import load_pipeline

if TYPE_CHECKING:
    from prefect.futures import PrefectFuture

log = get_logger()


def topo_order(stages: list[Stage]) -> list[Stage]:
    """Dependency-respecting order (DFS topo sort). Only same-scope `needs` count."""
    by_name = {s.name: s for s in stages}
    seen: set[str] = set()
    ordered: list[Stage] = []

    def visit(stage: Stage) -> None:
        if stage.name in seen:
            return
        seen.add(stage.name)
        for dep in stage.needs:
            if dep in by_name:
                visit(by_name[dep])
        ordered.append(stage)

    for stage in stages:
        visit(stage)
    return ordered


def per_app_loops(stages: list[Stage]) -> list[tuple[int, list[Stage]]]:
    """Group per-app stages into successive loops by `phase`, ascending.

    Each (phase, stages) loop runs as its own per-app DAG; the orchestrator puts a
    global barrier between loops. Activity stages are not loops and are excluded.
    """
    app_stages = [s for s in stages if s.per_app]
    return [
        (phase, [s for s in app_stages if s.phase == phase])
        for phase in sorted({s.phase for s in app_stages})
    ]


def _submit_dag(
    stages: list[Stage],
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    app_id: str | None,
) -> list[PrefectFuture]:
    """Submit one scope's stages as a DAG, wiring `needs` → `wait_for`."""
    futs: dict[str, PrefectFuture] = {}
    for stage in topo_order(stages):
        deps = [futs[n] for n in stage.needs if n in futs]
        futs[stage.name] = _run_stage.submit(  # ty: ignore[no-matching-overload]
            pipeline_name, activity_name, root, stage.name, app_id, wait_for=deps
        )
    return list(futs.values())


@task(tags=["net"])
def _run_stage(
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    stage_name: str,
    app_id: str | None,
) -> str:
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    stage = next(s for s in pipeline.stages if s.name == stage_name)
    log.info("  ▶ %s%s", stage_name, f" [{app_id}]" if app_id else "")
    if app_id is None:
        stage.run(activity)
    else:
        stage.run(activity, app_id)
    return stage_name


@flow(task_runner=ThreadPoolTaskRunner(max_workers=CONFIG.fanout.max_workers))  # ty: ignore[no-matching-overload]
def _run_dag(pipeline_name: str, activity_name: str, root: str | None) -> None:
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    activity_stages = [s for s in pipeline.stages if not s.per_app]

    # 1. activity-scope DAG (independent stages run in parallel)
    log.info("▶ activity stages")
    for fut in _submit_dag(activity_stages, pipeline_name, activity_name, root, None):
        fut.result(raise_on_failure=False)

    # 2. cluster — fan-out pivot
    log.info("▶ cluster")
    app_ids = pipeline.cluster(activity)
    log.info("  → %d application group(s)", len(app_ids))

    # 3. per-app loops — each phase is a loop: fan-out across groups + intra-app
    #    parallelism (capped by max_workers), with a global barrier between loops.
    if app_ids:
        for phase, loop_stages in per_app_loops(list(pipeline.stages)):
            log.info("▶ per-app loop %d: %s", phase, ", ".join(s.name for s in loop_stages))
            pending: list[PrefectFuture] = []
            for app_id in app_ids:
                pending += _submit_dag(loop_stages, pipeline_name, activity_name, root, app_id)
            for fut in pending:
                fut.result(raise_on_failure=False)

    # 4. agent — fan-in, once
    log.info("▶ agent")
    n = propose_hypotheses(activity, pipeline.provider())
    log.info("  → %d hypothesis(es)", n)
    log.info("✓ done → %s", activity.base)


def orchestrate(
    pipeline: Pipeline,
    activity_name: str,
    scope_file: str,
    *,
    root: str | None = None,
) -> Path:
    """Run the full pipeline for one activity. Returns the activity base dir."""
    activity = Activity.named(activity_name, Path(root) if root else None).ensure()
    add_file_handler(activity.logs / "run.log")  # persist the full run log (every command + output)
    scope_text = Path(scope_file).read_text(encoding="utf-8")
    activity.scope.write_text(scope_text, encoding="utf-8")
    activity.scope_init.write_text(scope_text, encoding="utf-8")
    log.info("▶ pipeline '%s' on '%s' → %s", pipeline.name, activity_name, activity.base)
    _run_dag(pipeline.name, activity_name, root)
    return activity.base
