"""Dependency-DAG orchestration: activity stages → cluster → per-app stages → agent.

Stages declare `needs` (same-scope dependencies); the scheduler runs them with
parallelism (independent stages run together, capped by max_workers) via Prefect
`wait_for`. Only strings cross the Prefect task boundary — `_run_stage`
reconstructs the Activity/Pipeline and runs a single stage by name.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from prefect import flow, task
from prefect.task_runners import ThreadPoolTaskRunner

from pipt.core import tools
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


def _submit_dag(  # noqa: PLR0913
    stages: list[Stage],
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    app_id: str | None,
    *,
    resume: bool,
) -> dict[str, PrefectFuture]:
    """Submit one scope's stages as a DAG, wiring `needs` → `wait_for`. Returns the
    futures keyed by stage name so the caller can label failures."""
    futs: dict[str, PrefectFuture] = {}
    for stage in topo_order(stages):
        deps = [futs[n] for n in stage.needs if n in futs]
        futs[stage.name] = _run_stage.submit(  # ty: ignore[no-matching-overload]
            pipeline_name, activity_name, root, stage.name, app_id, resume=resume, wait_for=deps
        )
    return futs


def _await(fut: PrefectFuture, label: str, failures: list[str]) -> None:
    """Await one stage future, ISOLATING its failure: a fault is logged and recorded in
    `failures` instead of propagating, so one bad stage (or app) never aborts the whole
    run. The error is surfaced (not silently swallowed) and folded into the final summary."""
    try:
        fut.result()
    except Exception:  # resilience boundary: a stage fault must not abort the whole run
        log.exception("⚠ stage failed: %s", label)
        failures.append(label)


def _marker(activity: Activity, stage_name: str, app_id: str | None) -> Path:
    """Resume completion marker for a stage: <app>/.state/<stage>.done (per-app) or
    <activity>/.state/<stage>.done (activity/spanning). Written on success, checked with --resume."""
    base = activity.app(app_id).state if app_id else activity.state
    return base / f"{stage_name}.done"


@task(tags=["net"])
def _run_stage(  # noqa: PLR0913
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    stage_name: str,
    app_id: str | None,
    *,
    resume: bool,
) -> str:
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    marker = _marker(activity, stage_name, app_id)
    if resume and marker.exists():  # already finished cleanly in a prior run → skip
        log.info("  ↺ skip %s%s (done)", stage_name, f" [{app_id}]" if app_id else "")
        return stage_name
    stage = next(s for s in pipeline.stages if s.name == stage_name)
    log.info("  ▶ %s%s", stage_name, f" [{app_id}]" if app_id else "")
    if app_id is None:
        stage.run(activity)
    else:
        stage.run(activity, app_id)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("", encoding="utf-8")  # mark done only AFTER success → failed stages re-run
    return stage_name


def _run_loops(  # noqa: PLR0913
    stages: list[Stage],
    app_ids: list[str],
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    failures: list[str],
    *,
    resume: bool,
) -> None:
    """Run each per-app phase as a fan-out DAG with a global barrier between phases;
    every stage failure is isolated (logged + recorded), never aborting the run."""
    for phase, loop_stages in per_app_loops(stages):
        log.info("▶ per-app loop %d: %s", phase, ", ".join(s.name for s in loop_stages))
        pending: list[tuple[str, PrefectFuture]] = []
        for app_id in app_ids:
            submitted = _submit_dag(loop_stages, pipeline_name, activity_name, root, app_id, resume=resume)
            pending += [(f"{name}[{app_id}]", fut) for name, fut in submitted.items()]
        for label, fut in pending:
            _await(fut, label, failures)


@flow(task_runner=ThreadPoolTaskRunner(max_workers=CONFIG.fanout.max_workers))  # ty: ignore[no-matching-overload]
def _run_dag(pipeline_name: str, activity_name: str, root: str | None, *, resume: bool) -> int:
    """Drive the full DAG. Returns the number of stage failures (0 = clean).

    The whole body runs under a `finally` that calls tools.terminate_all(): on any abort
    (an error, or Ctrl-C) it kills the still-running scans — and their grandchildren — so the
    flow tears down promptly instead of blocking forever on a long subprocess in Prefect's
    ThreadPoolTaskRunner shutdown (the nuclei teardown-hang). On a clean run it's a no-op.
    With `resume`, stages with a completion marker are skipped (only failed/incomplete ones rerun).
    """
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    activity_stages = [s for s in pipeline.stages
                       if not s.per_app and not s.spanning and not s.cluster_scope]
    spanning_stages = [s for s in pipeline.stages if s.spanning]
    cluster_scope_stages = [s for s in pipeline.stages if s.cluster_scope]
    failures: list[str] = []
    try:
        # 1. activity-scope (breadth) DAG — barrier before cluster
        log.info("▶ activity stages")
        for name, fut in _submit_dag(activity_stages, pipeline_name, activity_name, root, None, resume=resume).items():
            _await(fut, name, failures)

        # 1b. spanning stages — breadth deps are done; launch now and await only at the
        #     fan-in, so they overlap clustering + the per-app loops (e.g. whole-scope nuclei)
        spanning: dict[str, PrefectFuture] = {}
        if spanning_stages:
            log.info("▶ spanning (∥): %s", ", ".join(s.name for s in spanning_stages))
            spanning = _submit_dag(spanning_stages, pipeline_name, activity_name, root, None, resume=resume)

        # 2. cluster — fan-out pivot
        log.info("▶ cluster")
        app_ids = pipeline.cluster(activity)
        log.info("  → %d application group(s)", len(app_ids))

        # 2b. post-cluster spanning — launched now that the groups exist; runs ∥ the per-app loops and
        #     is awaited only at the fan-in (e.g. a single batched screenshot over one host per group).
        cluster_spanning: dict[str, PrefectFuture] = {}
        if cluster_scope_stages and app_ids:
            log.info("▶ post-cluster spanning (∥): %s", ", ".join(s.name for s in cluster_scope_stages))
            cluster_spanning = _submit_dag(cluster_scope_stages, pipeline_name, activity_name, root, None, resume=resume)

        # 3. per-app loops — each phase is a loop: fan-out across groups + intra-app
        #    parallelism (capped by max_workers), with a global barrier between loops.
        if app_ids:
            _run_loops(list(pipeline.stages), app_ids,
                       pipeline_name, activity_name, root, failures, resume=resume)

        # 4. join the spanning + post-cluster-spanning stages (ran ∥ everything above), then agent fan-in
        for label, fut in {**spanning, **cluster_spanning}.items():
            _await(fut, label, failures)
        log.info("▶ agent")
        n = propose_hypotheses(activity, pipeline.provider())
        log.info("  → %d hypothesis(es)", n)
    finally:
        killed = tools.terminate_all()
        if killed:
            log.warning("⚠ teardown: killed %d still-running tool process(es)", killed)

    if failures:
        log.warning("⚠ done with %d stage failure(s) [%s] → %s",
                    len(failures), ", ".join(failures), activity.base)
    else:
        log.info("✓ done → %s", activity.base)
    return len(failures)


def _resume_ok(activity: Activity, scope_text: str, *, resume: bool) -> bool:
    """Honour --resume only if the scope is UNCHANGED. The current scope hash is recorded under
    .state/scope.sha; if a prior run's hash differs, the stage markers are stale → ignore them
    (full rerun) and warn, so resuming never silently reuses results computed for a different scope."""
    sha = hashlib.sha256(scope_text.encode()).hexdigest()
    sha_file = activity.state / "scope.sha"
    if resume and sha_file.exists() and sha_file.read_text(encoding="utf-8").strip() != sha:
        log.warning("⚠ resume: scope changed since last run — ignoring stage markers (full rerun)")
        resume = False
    activity.state.mkdir(parents=True, exist_ok=True)
    sha_file.write_text(sha, encoding="utf-8")
    return resume


def orchestrate(
    pipeline: Pipeline,
    activity_name: str,
    scope_file: str,
    *,
    root: str | None = None,
    resume: bool = False,
) -> tuple[Path, int]:
    """Run the full pipeline for one activity. Returns (activity base dir, stage-failure count);
    the count is 0 on a clean run and >0 when one or more stages failed (the CLI maps it to its
    exit code). With `resume`, stages that completed cleanly in a prior run of this activity are
    skipped (only failed/incomplete ones rerun) — auto-invalidated if scope.txt changed."""
    activity = Activity.named(activity_name, Path(root) if root else None).ensure()
    add_file_handler(activity.logs / "run.log")  # persist the full run log (every command + output)
    scope_text = Path(scope_file).read_text(encoding="utf-8")
    activity.scope.write_text(scope_text, encoding="utf-8")
    activity.scope_init.write_text(scope_text, encoding="utf-8")
    resume = _resume_ok(activity, scope_text, resume=resume)
    log.info("▶ pipeline '%s' on '%s'%s → %s", pipeline.name, activity_name,
             " [resume]" if resume else "", activity.base)
    failures = _run_dag(pipeline.name, activity_name, root, resume=resume)
    return activity.base, failures
