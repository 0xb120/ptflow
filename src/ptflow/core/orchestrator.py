"""Dependency-DAG orchestration: activity stages → cluster → per-app stages → agent.

Stages declare `needs` (same-scope dependencies); the scheduler runs them with
parallelism (independent stages run together, capped by max_workers) via Prefect
`wait_for`. Only strings cross the Prefect task boundary — `_run_stage`
reconstructs the Activity/Pipeline and runs a single stage by name.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import threading
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from prefect import flow, task
from prefect.settings import PREFECT_API_URL, PREFECT_LOGGING_EXTRA_LOGGERS, temporary_settings
from prefect.task_runners import ThreadPoolTaskRunner

from ptflow.core import reporting, telemetry, tools
from ptflow.core.agent import propose_hypotheses
from ptflow.core.config import CONFIG
from ptflow.core.log import add_file_handler, get_logger
from ptflow.core.paths import Activity
from ptflow.core.stage import (
    Pipeline,
    Stage,
    enabled_stages,
    impacted_dependents,
    resume_contract_fingerprint,
    stage_band,
)
from ptflow.pipelines import load_pipeline

if TYPE_CHECKING:
    from prefect.futures import PrefectFuture

log = get_logger()

# Per-app fan-out cap. The flow pool is sized to fanout + spanning headroom (see _pool_size) so the
# spanning/cluster_scope stages run ∥ the loops instead of stealing their workers; this process-wide
# semaphore re-imposes the real fan-out limit on the per-app chains, so they never over-parallelize
# once the spanning stages free the pool. (The ThreadPoolTaskRunner runs every stage in one process,
# so a module semaphore caps them across all app groups — same pattern as the headless RAM cap.)
_FANOUT_SLOTS = threading.BoundedSemaphore(CONFIG.fanout.max_workers)

# Global NETWORK-concurrency cap. Bounds how many `net` stages (per-app AND spanning) run at once, so
# the aggregate uplink load stays bounded (a home line / consumer router can choke on too much at
# once). Resolved at import from PTFLOW_NET_LIMIT, else a profile-aware default: PTFLOW_PROFILE=home → a
# gentle 4, else CONFIG.fanout.net_limit (non-binding for real bandwidth). Complements the per-tool
# rate profile — aggregate load ≈ concurrency x rate, so both levers matter.
_NET_LIMIT = int(os.environ.get(
    "PTFLOW_NET_LIMIT",
    "4" if os.environ.get("PTFLOW_PROFILE", "").lower().strip() == "home" else str(CONFIG.fanout.net_limit),
))
_NET_SLOTS = threading.BoundedSemaphore(_NET_LIMIT)


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


def phase_checkpoints(stages: list[Stage], phase: int) -> list[Stage]:
    """Activity-scope checkpoints scheduled after `phase`, in declaration order."""
    return [stage for stage in stages if stage.after_phase == phase]


def _pool_size(stages: Sequence[Stage], fanout: int) -> int:
    """Flow pool size = fan-out cap + one slot per spanning/cluster_scope stage. Those background
    stages (whole-scope nuclei, full-port scan, batched screenshot) then run ∥ the per-app loops
    instead of starving the pool — while _FANOUT_SLOTS keeps the per-app fan-out itself at `fanout`.
    Pure. Without this, 2 long spanning stages + a wait_for'd one saturate a 3-worker pool and the
    loops never start until they finish (observed: 17.5 min of nothing-but-spanning)."""
    n_span = sum(1 for s in stages if s.spanning or s.cluster_scope)
    return fanout + n_span


def _stage_tags(stage: Stage) -> list[str]:
    """Band tag for the Prefect UI (so task runs group/filter by phase in the dashboard), plus the
    `net` tag for network stages (offline ones omit it). Pure — derived from the Stage's flags."""
    band = stage_band(stage)
    return ["net", band] if stage.net else [band]


def _filter_disabled(pipeline: Pipeline, disabled: set[str]) -> list[Stage]:
    """Drop the disabled stages from the pipeline (logging which, and WARNING which surviving stages
    depend on a removed one and will run on absent inputs). Returns the enabled stage list."""
    if disabled:
        log.info("▶ steps disabled: %s", ", ".join(sorted(disabled)))
        impacted = impacted_dependents(pipeline.stages, disabled)
        if impacted:
            log.warning("⚠ these steps depend on a disabled step and will run with absent inputs: %s",
                        ", ".join(impacted))
    return enabled_stages(pipeline.stages, disabled)


def _submit_dag(  # noqa: PLR0913
    stages: list[Stage],
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    app_id: str | None,
    run_id: str | None,
    *,
    resume: bool,
) -> dict[str, PrefectFuture]:
    """Submit one scope's stages as a DAG, wiring `needs` → `wait_for`. Returns the
    futures keyed by stage name so the caller can label failures.

    Each task is given a per-stage `name` + `task_run_name` (`crawl[<app_id>]`) and a band tag via
    with_options, so the Prefect UI renders the run graph as readable, phase-grouped nodes (instead
    of one opaque `_run_stage` repeated). Cosmetic in ephemeral mode; the payoff is with `--observe`."""
    futs: dict[str, PrefectFuture] = {}
    for stage in topo_order(stages):
        deps = [futs[n] for n in stage.needs if n in futs]
        label = f"{stage.name}[{app_id}]" if app_id else stage.name
        task = _run_stage.with_options(name=stage.name, task_run_name=label, tags=_stage_tags(stage))
        futs[stage.name] = task.submit(  # ty: ignore[no-matching-overload]
            pipeline_name, activity_name, root, stage.name, app_id, run_id,
            resume=resume, wait_for=deps,
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


def _clear_resume_markers(activity: Activity) -> int:
    """Delete stale completion markers before a full rerun; keep hashes and all scan artifacts."""
    markers = [*activity.state.glob("*.done")]
    for app in activity.list_apps():
        markers.extend(app.state.glob("*.done"))
    for marker in markers:
        marker.unlink(missing_ok=True)
    return len(markers)


@task(tags=["net"])
def _run_stage(  # noqa: PLR0913
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    stage_name: str,
    app_id: str | None,
    run_id: str | None,
    *,
    resume: bool,
) -> str:
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    marker = _marker(activity, stage_name, app_id)
    stage = next(s for s in pipeline.stages if s.name == stage_name)
    if resume and marker.exists():  # already finished cleanly in a prior run → skip
        log.info("  ↺ skip %s%s (done)", stage_name, f" [{app_id}]" if app_id else "")
        telemetry.write_skipped(
            activity, run_id, stage=stage.name, app_id=app_id, band=stage_band(stage),
            needs=stage.needs, net=stage.net, reason="resume-skipped",
        )
        return stage_name

    def _execute() -> None:
        # Acquire slots in a FIXED order (net → fanout) so multi-slot stages can't deadlock.
        with contextlib.ExitStack() as slots:
            if stage.net:
                slots.enter_context(_NET_SLOTS)
            if app_id is not None:
                slots.enter_context(_FANOUT_SLOTS)
            log.info("  ▶ %s%s", stage_name, f" [{app_id}]" if app_id else "")
            if app_id is None:
                stage.run(activity)
            else:
                stage.run(activity, app_id)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("", encoding="utf-8")  # only AFTER success → failed stages re-run

    telemetry.trace_call(
        activity, run_id, stage=stage.name, app_id=app_id, band=stage_band(stage),
        needs=stage.needs, net=stage.net, call=_execute,
    )
    return stage_name


def _run_loops(  # noqa: PLR0913
    stages: list[Stage],
    app_ids: list[str],
    pipeline_name: str,
    activity_name: str,
    root: str | None,
    failures: list[str],
    run_id: str | None,
    *,
    resume: bool,
) -> None:
    """Run each per-app phase as a fan-out DAG with a global barrier between phases;
    every stage failure is isolated (logged + recorded), never aborting the run."""
    for phase, loop_stages in per_app_loops(stages):
        log.info("▶ per-app loop %d: %s", phase, ", ".join(s.name for s in loop_stages))
        pending: list[tuple[str, PrefectFuture]] = []
        for app_id in app_ids:
            submitted = _submit_dag(
                loop_stages, pipeline_name, activity_name, root, app_id, run_id, resume=resume,
            )
            pending += [(f"{name}[{app_id}]", fut) for name, fut in submitted.items()]
        for label, fut in pending:
            _await(fut, label, failures)
        checkpoints = phase_checkpoints(stages, phase)
        if checkpoints:
            log.info("▶ checkpoint after loop %d: %s", phase,
                     ", ".join(stage.name for stage in checkpoints))
            # Checkpoints are cheap derived snapshots and MUST be regenerated on resume: a failed
            # phase stage may have succeeded on this continuation, making the prior snapshot stale.
            submitted = _submit_dag(
                checkpoints, pipeline_name, activity_name, root, None, run_id, resume=False,
            )
            for name, fut in submitted.items():
                _await(fut, name, failures)


def _terminal_fanin(
    pipeline: Pipeline, activity: Activity, failures: list[str], run_id: str | None = None,
) -> None:
    """Terminal fan-in, run after every loop + spanning join: (1) `consolidate` — an
    OPTIONAL pipeline hook (like preflight) that lifts per-app findings into <activity>/findings/<type>
    .jsonl; (2) the deterministic offline report; (3) the agent seam (`propose_hypotheses`); and (4)
    the optional AI `report(activity)` hook. Every terminal step is failure-isolated."""
    do_consolidate = getattr(pipeline, "consolidate", None)
    if callable(do_consolidate):
        log.info("▶ consolidate")
        try:
            telemetry.trace_call(
                activity, run_id, stage="consolidate", app_id=None, band="terminal",
                call=lambda: do_consolidate(activity),
            )
        except Exception:  # terminal aggregation must not abort the whole run
            log.exception("⚠ consolidate failed")
            failures.append("consolidate")
    log.info("▶ deterministic report")
    try:
        report = telemetry.trace_call(
            activity, run_id, stage="deterministic_report", app_id=None, band="terminal",
            call=lambda: reporting.write_report(activity),
        )
        log.info("  → reports/report.md + reports/report.json (%d finding(s))",
                 report["summary"]["total"])
    except Exception:  # reporting remains failure-isolated like the rest of the terminal fan-in
        log.exception("⚠ deterministic report failed")
        failures.append("deterministic_report")
    log.info("▶ agent")
    try:
        n = telemetry.trace_call(
            activity, run_id, stage="agent", app_id=None, band="terminal",
            call=lambda: propose_hypotheses(activity, pipeline.provider()),
        )
        log.info("  → %d hypothesis(es)", n)
    except Exception:  # an LLM-backed provider can raise; must not abort the run
        log.exception("⚠ agent failed")
        failures.append("agent")
    do_report = getattr(pipeline, "report", None)  # optional AI report hook (duck-typed like consolidate)
    if callable(do_report):
        log.info("▶ report")
        try:
            telemetry.trace_call(
                activity, run_id, stage="ai_report", app_id=None, band="terminal",
                call=lambda: do_report(activity),
            )
        except Exception:  # terminal reporting must not abort the whole run
            log.exception("⚠ report failed")
            failures.append("report")


@flow(task_runner=ThreadPoolTaskRunner(max_workers=CONFIG.fanout.max_workers))  # ty: ignore[no-matching-overload]
def _run_dag(  # noqa: PLR0913
    pipeline_name: str, activity_name: str, root: str | None, *,
    resume: bool, disabled: tuple[str, ...] = (), run_id: str | None = None,
) -> tuple[str, ...]:
    """Drive the full DAG. Returns the failed stage labels (empty = clean).

    The whole body runs under a `finally` that calls tools.terminate_all(): on any abort
    (an error, or Ctrl-C) it kills the still-running scans — and their grandchildren — so the
    flow tears down promptly instead of blocking forever on a long subprocess in Prefect's
    ThreadPoolTaskRunner shutdown (the nuclei teardown-hang). On a clean run it's a no-op.
    With `resume`, stages with a completion marker are skipped (only failed/incomplete ones rerun).
    """
    tools.clear_abort()  # fresh run (a prior aborted run in this process must not poison this one)
    os.environ["PTFLOW_ACTIVE_PIPELINE"] = pipeline_name
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    stages = _filter_disabled(pipeline, set(disabled))
    activity_stages = [s for s in stages
                       if not s.per_app and not s.spanning and not s.cluster_scope
                       and s.after_phase is None]
    spanning_stages = [s for s in stages if s.spanning]
    cluster_scope_stages = [s for s in stages if s.cluster_scope]
    failures: list[str] = []
    try:
        # 1. activity-scope (breadth) DAG — barrier before cluster
        log.info("▶ activity stages")
        for name, fut in _submit_dag(
            activity_stages, pipeline_name, activity_name, root, None, run_id, resume=resume,
        ).items():
            _await(fut, name, failures)

        # 1b. spanning stages — breadth deps are done; launch now and await only at the
        #     fan-in, so they overlap clustering + the per-app loops (e.g. whole-scope nuclei)
        spanning: dict[str, PrefectFuture] = {}
        if spanning_stages:
            log.info("▶ spanning (∥): %s", ", ".join(s.name for s in spanning_stages))
            spanning = _submit_dag(
                spanning_stages, pipeline_name, activity_name, root, None, run_id, resume=resume,
            )

        # 2. cluster — fan-out pivot
        log.info("▶ cluster")
        app_ids = telemetry.trace_call(
            activity, run_id, stage="cluster", app_id=None, band="cluster",
            call=lambda: pipeline.cluster(activity),
        )
        log.info("  → %d application group(s)", len(app_ids))

        # 2b. post-cluster spanning — launched now that the groups exist; runs ∥ the per-app loops and
        #     is awaited only at the fan-in (e.g. a single batched screenshot over one host per group).
        cluster_spanning: dict[str, PrefectFuture] = {}
        if cluster_scope_stages and app_ids:
            log.info("▶ post-cluster spanning (∥): %s", ", ".join(s.name for s in cluster_scope_stages))
            cluster_spanning = _submit_dag(
                cluster_scope_stages, pipeline_name, activity_name, root, None, run_id, resume=resume,
            )

        # 3. per-app loops — each phase is a loop: fan-out across groups + intra-app
        #    parallelism (capped by max_workers), with a global barrier between loops.
        if app_ids:
            _run_loops(stages, app_ids,
                       pipeline_name, activity_name, root, failures, run_id, resume=resume)

        # 4. join the spanning + post-cluster-spanning stages (ran ∥ everything above), then fan-in
        for label, fut in {**spanning, **cluster_spanning}.items():
            _await(fut, label, failures)
        _terminal_fanin(pipeline, activity, failures, run_id)
    except KeyboardInterrupt:  # Ctrl-C/SIGINT: stop the draining workers from spawning new tools
        tools.signal_abort()   # (feroxbuster r+1, downloads, trufflehog…) → network goes quiet fast
        raise
    finally:
        killed = tools.terminate_all()
        if killed:
            log.warning("⚠ teardown: killed %d still-running tool process(es)", killed)

    if failures:
        log.warning("⚠ done with %d stage failure(s) [%s] → %s",
                    len(failures), ", ".join(failures), activity.base)
    else:
        log.info("✓ done → %s", activity.base)
    return tuple(failures)


_RESUME_INVALIDATION_MESSAGES = {
    "scope_changed": "scope changed since last run",
    "legacy_config_missing": "prior run predates config fingerprints",
    "config_changed": "effective configuration changed since last run",
    "legacy_pipeline_contract_missing": "prior run predates pipeline contract fingerprints",
    "pipeline_contract_changed": "pipeline contract changed since last run",
}


def _fingerprint_invalidation_reason(
    config_file: Path, config_fingerprint: str | None,
    pipeline_file: Path, pipeline_fingerprint: str | None,
) -> str | None:
    for path, current, legacy_reason, changed_reason in (
        (config_file, config_fingerprint, "legacy_config_missing", "config_changed"),
        (pipeline_file, pipeline_fingerprint,
         "legacy_pipeline_contract_missing", "pipeline_contract_changed"),
    ):
        if current is None:
            continue
        if not path.exists():
            return legacy_reason
        if path.read_text(encoding="utf-8", errors="replace").strip() != current:
            return changed_reason
    return None


def _resume_ok(activity: Activity, scope_text: str, *, resume: bool,
               config_fingerprint: str | None = None,
               pipeline_fingerprint: str | None = None) -> tuple[bool, str | None]:
    """Honour ``--resume`` only when scope, effective config and pipeline contract are unchanged.

    Hashes live under ``.state/{scope,config,pipeline}.sha``. A workspace predating either optional
    fingerprint is invalidated once and migrated. Returns ``(effective, invalidation_reason)`` so the
    coverage manifest explains why a requested resume became a full rerun.
    """
    sha = hashlib.sha256(scope_text.encode()).hexdigest()
    sha_file = activity.state / "scope.sha"
    config_file = activity.state / "config.sha"
    pipeline_file = activity.state / "pipeline.sha"
    prior_run = sha_file.exists()
    invalidation_reason: str | None = None
    if resume and prior_run:
        if sha_file.read_text(encoding="utf-8", errors="replace").strip() != sha:
            invalidation_reason = "scope_changed"
        else:
            invalidation_reason = _fingerprint_invalidation_reason(
                config_file, config_fingerprint, pipeline_file, pipeline_fingerprint,
            )
        if invalidation_reason:
            log.warning("⚠ resume: %s — ignoring stage markers%s (full rerun)",
                        _RESUME_INVALIDATION_MESSAGES[invalidation_reason],
                        " once" if invalidation_reason.startswith("legacy_") else "")
            resume = False
    activity.state.mkdir(parents=True, exist_ok=True)
    sha_file.write_text(sha, encoding="utf-8")
    if config_fingerprint is not None:
        config_file.write_text(config_fingerprint, encoding="utf-8")
    if pipeline_fingerprint is not None:
        pipeline_file.write_text(pipeline_fingerprint, encoding="utf-8")
    if not resume:
        cleared = _clear_resume_markers(activity)
        if cleared:
            log.info("  → resume: cleared %d stale completion marker(s) before full rerun", cleared)
    return resume, invalidation_reason


def _server_reachable(api_url: str, timeout: float = 2.0) -> bool:
    """True if the Prefect API at `api_url` answers /health — so --observe can fall back to ephemeral
    instead of stalling/erroring on a dead server. Localhost probe; never raises."""
    try:
        with urllib.request.urlopen(  # noqa: S310 — localhost Prefect health probe
            f"{api_url.rstrip('/')}/health", timeout=timeout,
        ) as resp:
            return 200 <= resp.status < 300  # noqa: PLR2004
    except (urllib.error.URLError, OSError, ValueError):
        return False


def orchestrate(  # noqa: PLR0913
    pipeline: Pipeline,
    activity_name: str,
    scope_file: str,
    *,
    root: str | None = None,
    resume: bool = False,
    observe: str | None = None,
    disabled_steps: frozenset[str] = frozenset(),
    config_fingerprint: str | None = None,
) -> tuple[Path, int]:
    """Run the full pipeline for one activity. Returns (activity base dir, stage-failure count);
    the count is 0 on a clean run and >0 when one or more stages failed (the CLI maps it to its
    exit code). With `resume`, stages that completed cleanly in a prior run of this activity are
    skipped (only failed/incomplete ones rerun) — auto-invalidated if scope, the supplied effective
    configuration fingerprint, or the pipeline's live artifact contract changed. With
    `observe` (a Prefect API URL), the run streams to that server's UI (run graph, states, timings,
    logs) instead of spinning a throwaway ephemeral server — pure telemetry, the pipeline is
    unchanged. temporary_settings applies the redirect at runtime (env set post-import is too late).
    `disabled_steps` names stages to filter out of this run (a debug knob resolved from
    `[steps.<pipeline>]` / `--set steps.<pipeline>.<step>=off`); its dependents still run (degrading on
    absent inputs)."""
    activity = Activity.named(activity_name, Path(root) if root else None).ensure()
    add_file_handler(activity.logs / "run.log")  # persist the full run log (every command + output)
    scope_text = Path(scope_file).read_text(encoding="utf-8", errors="replace")
    activity.scope.write_text(scope_text, encoding="utf-8")
    activity.scope_init.write_text(scope_text, encoding="utf-8")
    resume_requested = resume
    pipeline_fingerprint = resume_contract_fingerprint(pipeline)
    resume, resume_invalidation_reason = _resume_ok(
        activity, scope_text, resume=resume, config_fingerprint=config_fingerprint,
        pipeline_fingerprint=pipeline_fingerprint,
    )
    if observe and not _server_reachable(observe):
        log.warning("⚠ observe: Prefect server unreachable at %s — falling back to ephemeral "
                    "(start it with `ptflow serve`)", observe)
        observe = None
    log.info("▶ pipeline '%s' on '%s'%s%s → %s", pipeline.name, activity_name,
             " [resume]" if resume else "", f" [observe→{observe}]" if observe else "", activity.base)
    preflight = getattr(pipeline, "preflight", None)  # log present/missing external tools (best-effort)
    if callable(preflight):
        preflight()
    log.info("  → concurrency: fan-out %d · network cap %d", CONFIG.fanout.max_workers, _NET_LIMIT)
    disabled = tuple(sorted(disabled_steps))
    run_trace = telemetry.begin_run(
        activity, pipeline, scope_text=scope_text, resume_requested=resume_requested,
        resume_effective=resume, disabled=disabled, fanout=CONFIG.fanout.max_workers,
        net_limit=_NET_LIMIT, config_fingerprint=config_fingerprint,
        pipeline_fingerprint=pipeline_fingerprint,
        resume_invalidation_reason=resume_invalidation_reason,
    )
    # name the flow run after the activity (UI), and size the pool to fan-out + spanning headroom so
    # the spanning stages run ∥ the loops instead of starving them (_FANOUT_SLOTS holds the fan-out cap)
    pool = ThreadPoolTaskRunner(max_workers=_pool_size(pipeline.stages, CONFIG.fanout.max_workers))
    run = _run_dag.with_options(flow_run_name=f"{pipeline.name}:{activity_name}", task_runner=pool)

    def _go() -> tuple[str, ...]:
        if observe:
            # redirect this run to the persistent server + let it capture the `ptflow` logger, scoped to
            # the run (no global profile/env mutation). temporary_settings overrides at runtime.
            with temporary_settings({PREFECT_API_URL: observe, PREFECT_LOGGING_EXTRA_LOGGERS: ["ptflow"]}):
                return run(
                    pipeline.name, activity_name, root, resume=resume, disabled=disabled,
                    run_id=run_trace.run_id,
                )
        return run(
            pipeline.name, activity_name, root, resume=resume, disabled=disabled,
            run_id=run_trace.run_id,
        )

    try:
        failure_labels = _go()
    except (KeyboardInterrupt, Exception) as exc:
        # a Ctrl-C (or the Prefect ConnectError cascade after the ephemeral server dies with it) →
        # clean exit, not a traceback. tools.is_aborting() was set by _run_dag's KeyboardInterrupt
        # handler; a genuine error (not aborting) is re-raised so it still surfaces.
        if isinstance(exc, KeyboardInterrupt) or tools.is_aborting():
            telemetry.finalize_run(
                activity, run_trace, pipeline.stages, status="interrupted",
                failures=("interrupted",), disabled=disabled,
            )
            log.warning("⚠ interrupted — partial results in %s; rerun with --resume", activity.base)
            return activity.base, -1  # sentinel: interrupted (CLI → exit 130)
        telemetry.finalize_run(
            activity, run_trace, pipeline.stages, status="failed",
            failures=(type(exc).__name__,), disabled=disabled,
        )
        raise
    coverage = telemetry.finalize_run(
        activity, run_trace, pipeline.stages,
        status="completed" if not failure_labels else "completed-with-failures",
        failures=failure_labels, disabled=disabled,
    )
    if coverage["status"] == "completed-degraded":
        log.warning(
            "⚠ run completed with degraded detector coverage — inspect %s",
            activity.base / "coverage.json",
        )
    return activity.base, len(failure_labels)
