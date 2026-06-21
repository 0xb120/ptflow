"""Phased-hybrid orchestration: asset_discovery (breadth) -> cluster -> enum (depth) -> agent.

No database: artifacts on disk are the only state. Only strings cross the
Prefect task boundary — depth workers reconstruct the Activity and Pipeline
from (pipeline_name, activity_name, root, app_id).
"""

from __future__ import annotations

from pathlib import Path

from prefect import flow, task
from prefect.task_runners import ThreadPoolTaskRunner

from pipt.core.agent import propose_hypotheses
from pipt.core.config import CONFIG
from pipt.core.log import get_logger
from pipt.core.paths import Activity
from pipt.core.stage import Mode, Pipeline, Stage
from pipt.pipelines import load_pipeline

log = get_logger()


def split_stages(stages: list[Stage]) -> tuple[list[Stage], list[Stage]]:
    breadth = [s for s in stages if s.mode is Mode.BREADTH]
    depth = [s for s in stages if s.mode is Mode.DEPTH]
    return breadth, depth


@task(tags=["net"])
def _run_depth_chain(pipeline_name: str, activity_name: str, root: str | None, app_id: str) -> str:
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    _, depth = split_stages(list(pipeline.stages))
    for stage in depth:
        stage.run(activity, app_id)
    return app_id


@flow(task_runner=ThreadPoolTaskRunner(max_workers=CONFIG.fanout.max_workers))  # ty: ignore[no-matching-overload]
def _depth_flow(pipeline_name: str, activity_name: str, root: str | None, app_ids: list[str]) -> None:
    futures = [_run_depth_chain.submit(pipeline_name, activity_name, root, a) for a in app_ids]
    for fut in futures:
        fut.result(raise_on_failure=False)


def orchestrate(
    pipeline: Pipeline,
    activity_name: str,
    scope_file: str,
    *,
    root: str | None = None,
) -> Path:
    """Run the full pipeline for one activity. Returns the activity base dir."""
    activity = Activity.named(activity_name, Path(root) if root else None).ensure()
    scope_text = Path(scope_file).read_text(encoding="utf-8")
    activity.scope.write_text(scope_text, encoding="utf-8")
    activity.scope_init.write_text(scope_text, encoding="utf-8")
    log.info("▶ pipeline '%s' on '%s' → %s", pipeline.name, activity_name, activity.base)

    breadth, depth = split_stages(list(pipeline.stages))

    # 1. breadth phases (asset discovery sub-stages): each reads/writes via disk
    for stage in breadth:
        log.info("▶ breadth stage: %s", stage.name)
        stage.run(activity)

    # 2. cluster discovery output into application groups
    log.info("▶ cluster")
    app_ids = pipeline.cluster(activity)
    log.info("  → %d application group(s)", len(app_ids))

    # 3. depth fan-out per app group (Prefect)
    if app_ids and depth:
        log.info("▶ depth (%s) over %d group(s)", ", ".join(s.name for s in depth), len(app_ids))
        _depth_flow(pipeline.name, activity_name, root, app_ids)

    # 4. agent stage (terminal): file-based hypotheses -> findings/
    log.info("▶ agent")
    n = propose_hypotheses(activity, pipeline.provider())
    log.info("  → %d hypothesis(es)", n)

    log.info("✓ done → %s", activity.base)
    return activity.base
