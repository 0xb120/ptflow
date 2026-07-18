"""Run/stage coverage telemetry stored alongside the activity artifacts."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from ptflow.core.paths import Activity
    from ptflow.core.stage import Pipeline, Stage

T = TypeVar("T")
_CURRENT: contextvars.ContextVar[StageTrace | None] = contextvars.ContextVar(
    "ptflow_stage_trace", default=None
)
_SAFE_NAME = re.compile(r"[^a-zA-Z0-9_.-]+")
_SENSITIVE_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "HTTP_HEADER")
_MAX_ERROR = 500


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _error_summary(error: BaseException) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        return f"CalledProcessError: command exited {error.returncode}"
    if isinstance(error, subprocess.TimeoutExpired):
        return "TimeoutExpired: command timed out"
    message = str(error)
    for name, value in os.environ.items():
        if value and any(marker in name.upper() for marker in _SENSITIVE_ENV_MARKERS):
            message = message.replace(value, "<redacted>")
    message = message if len(message) <= _MAX_ERROR else f"{message[: _MAX_ERROR - 3]}..."
    return f"{type(error).__name__}: {message}"


@dataclass
class StageTrace:
    run_id: str
    activity_root: Path
    stage: str
    app_id: str | None
    band: str
    needs: tuple[str, ...]
    net: bool
    started_at: str = field(default_factory=_now)
    status: str = "running"
    reads: list[dict[str, Any]] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)
    commands: list[dict[str, Any]] = field(default_factory=list)
    caps: list[dict[str, Any]] = field(default_factory=list)
    drops: Counter[str] = field(default_factory=Counter)
    error: str | None = None
    _started: float = field(default_factory=time.monotonic, repr=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def finish(self, status: str, error: BaseException | None = None) -> dict[str, Any]:
        self.status = status
        self.error = _error_summary(error) if error else None
        return {
            "stage": self.stage,
            "app_id": self.app_id,
            "scope": "app" if self.app_id else "activity",
            "band": self.band,
            "needs": list(self.needs),
            "network": self.net,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": _now(),
            "duration_seconds": round(time.monotonic() - self._started, 3),
            "reads": _coalesce_io(self.reads),
            "writes": _coalesce_io(self.writes),
            "commands": self.commands,
            "caps": self.caps,
            "drops": dict(sorted(self.drops.items())),
            "error": self.error,
        }


@dataclass(frozen=True)
class RunTrace:
    run_id: str
    started_at: str
    directory: Path
    initial: dict[str, Any]


def _coalesce_io(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        key = (record["path"], record["kind"])
        merged[key] = record
    return [merged[key] for key in sorted(merged)]


@contextlib.contextmanager
def activate(trace: StageTrace) -> Iterator[StageTrace]:
    token = _CURRENT.set(trace)
    try:
        yield trace
    finally:
        _CURRENT.reset(token)


def _trace() -> StageTrace | None:
    return _CURRENT.get()


def submit(executor: Any, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> Any:
    """Submit work to a thread pool while preserving the active stage trace context."""
    context = contextvars.copy_context()
    return executor.submit(context.run, fn, *args, **kwargs)


def record_read(path: Path, *, kind: str, count: int, present: bool = True) -> None:
    if trace := _trace():
        with trace.lock:
            trace.reads.append(
                {
                    "path": _relative(path, trace.activity_root),
                    "kind": kind,
                    "count": count,
                    "present": present,
                }
            )


def record_write(path: Path, *, kind: str, count: int) -> None:
    if trace := _trace():
        with trace.lock:
            trace.writes.append(
                {"path": _relative(path, trace.activity_root), "kind": kind, "count": count}
            )


def record_drop(reason: str, count: int = 1) -> None:
    if count > 0 and (trace := _trace()):
        with trace.lock:
            trace.drops[reason] += count


def record_cap(name: str, *, limit: int, observed: int, selected: int) -> None:
    """Record a bounded candidate set; `applied` tells whether coverage was truncated."""
    if trace := _trace():
        with trace.lock:
            trace.caps.append(
                {
                    "name": name,
                    "limit": limit,
                    "observed": observed,
                    "selected": selected,
                    "applied": observed > selected,
                }
            )


def record_command(  # noqa: PLR0913
    *,
    tool: str,
    status: str,
    return_code: int | None,
    duration: float,
    timeout: int | None = None,
    pipeline_length: int = 1,
) -> None:
    if trace := _trace():
        with trace.lock:
            trace.commands.append(
                {
                    "tool": tool,
                    "status": status,
                    "return_code": return_code,
                    "duration_seconds": round(duration, 3),
                    "timeout_seconds": timeout,
                    "pipeline_length": pipeline_length,
                }
            )


def record_missing_tools(names: Sequence[str]) -> None:
    if trace := _trace():
        with trace.lock:
            for name in names:
                trace.commands.append(
                    {
                        "tool": name,
                        "status": "missing",
                        "return_code": None,
                        "duration_seconds": 0.0,
                        "timeout_seconds": None,
                        "pipeline_length": 1,
                    }
                )


def _fragment_dir(activity: Activity, run_id: str) -> Path:
    return activity.state / "coverage" / run_id


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_stage(activity: Activity, run_id: str, record: dict[str, Any]) -> None:
    app = record.get("app_id") or "activity"
    stem = _SAFE_NAME.sub("_", f"{app}--{record['stage']}")
    _write_json(_fragment_dir(activity, run_id) / f"{stem}.json", record)


def trace_call(  # noqa: PLR0913
    activity: Activity,
    run_id: str | None,
    *,
    stage: str,
    app_id: str | None,
    band: str,
    needs: tuple[str, ...] = (),
    net: bool = False,
    call: Callable[[], T],
) -> T:
    """Run one callable under telemetry, persist success/failure, and preserve its exception."""
    if run_id is None:
        return call()
    trace = StageTrace(run_id, activity.base, stage, app_id, band, needs, net)
    with activate(trace):
        try:
            result = call()
        except BaseException as exc:
            status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
            write_stage(activity, run_id, trace.finish(status, exc))
            raise
    write_stage(activity, run_id, trace.finish("success"))
    return result


def write_skipped(  # noqa: PLR0913
    activity: Activity,
    run_id: str | None,
    *,
    stage: str,
    app_id: str | None,
    band: str,
    needs: tuple[str, ...],
    net: bool,
    reason: str,
) -> None:
    if run_id is None:
        return
    trace = StageTrace(run_id, activity.base, stage, app_id, band, needs, net)
    write_stage(activity, run_id, trace.finish(reason))


def _requirements(pipeline: Pipeline) -> list[dict[str, Any]]:
    get_requirements = getattr(pipeline, "requirements", None)
    if not callable(get_requirements):
        return []
    from ptflow.core.requirements import check  # noqa: PLC0415

    try:
        report = check(get_requirements())
    except Exception as exc:  # noqa: BLE001
        # Coverage must not turn a best-effort requirements hook into a run failure.
        return [{"error": _error_summary(exc)}]
    return [
        {
            "name": result.req.name,
            "kind": result.req.kind,
            "category": result.req.category,
            "found": result.found,
            "version": result.version,
            "minimum_version": result.req.min_version,
            "ok": result.ok,
        }
        for result in report.results
    ]


def begin_run(  # noqa: PLR0913
    activity: Activity,
    pipeline: Pipeline,
    *,
    scope_text: str,
    resume_requested: bool,
    resume_effective: bool,
    disabled: Sequence[str],
    fanout: int,
    net_limit: int,
    config_fingerprint: str | None = None,
    pipeline_fingerprint: str | None = None,
    resume_invalidation_reason: str | None = None,
) -> RunTrace:
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    started = _now()
    initial = {
        "schema_version": 1,
        "run_id": run_id,
        "pipeline": pipeline.name,
        "activity": activity.base.name,
        "scope_sha256": hashlib.sha256(scope_text.encode()).hexdigest(),
        "config_sha256": config_fingerprint,
        "pipeline_sha256": pipeline_fingerprint,
        "started_at": started,
        "finished_at": None,
        "status": "running",
        "resume": {
            "requested": resume_requested,
            "effective": resume_effective,
            "invalidation_reason": resume_invalidation_reason,
        },
        "disabled_steps": sorted(disabled),
        "limits": {
            "fanout_workers": fanout,
            "network_stages": net_limit,
            "profile": os.environ.get("PTFLOW_PROFILE", "wide"),
        },
        "requirements": _requirements(pipeline),
        "summary": {},
        "failures": [],
        "stages": [],
    }
    directory = _fragment_dir(activity, run_id)
    _write_json(activity.base / "coverage.json", initial)
    return RunTrace(run_id, started, directory, initial)


def finalize_run(  # noqa: PLR0913
    activity: Activity,
    trace: RunTrace,
    stages: Sequence[Stage],
    *,
    status: str,
    failures: Sequence[str],
    disabled: Sequence[str],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    fragment_errors: list[str] = []
    for path in sorted(trace.directory.glob("*.json")):
        try:
            records.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            fragment_errors.append(f"{path.name}: {_error_summary(exc)}")
    disabled_set = set(disabled)
    records.extend(
        {
            "stage": stage.name,
            "app_id": None,
            "scope": "all-apps" if stage.per_app else "activity",
            "band": _stage_band(stage),
            "needs": list(stage.needs),
            "network": stage.net,
            "status": "disabled",
            "started_at": None,
            "finished_at": None,
            "duration_seconds": 0.0,
            "reads": [],
            "writes": [],
            "commands": [],
            "caps": [],
            "drops": {},
            "error": None,
        }
        for stage in sorted(
            (item for item in stages if item.name in disabled_set),
            key=lambda item: item.name,
        )
    )
    records.sort(
        key=lambda item: (item["started_at"] or "", item["stage"], item.get("app_id") or "")
    )
    status_counts = Counter(record["status"] for record in records)
    commands = [command for record in records for command in record["commands"]]
    caps = [cap for record in records for cap in record["caps"]]
    drops = Counter()
    for record in records:
        drops.update(record["drops"])
    manifest = {
        **trace.initial,
        "finished_at": _now(),
        "status": status,
        "failures": list(failures),
        "summary": {
            "stage_statuses": dict(sorted(status_counts.items())),
            "commands": {
                "total": len(commands),
                "nonzero": sum(command["status"] == "nonzero" for command in commands),
                "timed_out": sum(command["status"] == "timeout" for command in commands),
                "missing": sum(command["status"] == "missing" for command in commands),
            },
            "caps": {
                "observed": len(caps),
                "applied": sum(cap["applied"] for cap in caps),
            },
            "observed_reads": sum(len(record["reads"]) for record in records),
            "observed_writes": sum(len(record["writes"]) for record in records),
            "drops": dict(sorted(drops.items())),
            "fragment_errors": fragment_errors,
        },
        "stages": records,
    }
    _write_json(activity.base / "coverage.json", manifest)
    return manifest


def _stage_band(stage: Stage) -> str:
    if stage.spanning:
        return "spanning"
    if stage.cluster_scope:
        return "post-cluster"
    if stage.after_phase is not None:
        return f"checkpoint:{stage.after_phase}"
    if stage.per_app:
        return f"loop:{stage.phase}"
    return "breadth"
